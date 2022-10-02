package gokcp

import (
	"crypto/rand"
	"encoding/binary"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Conn struct {
	conn  net.PacketConn
	isOwn bool
	kcp   *KCP
	l     *Listener

	recvbuf []byte
	bufptr  []byte

	// settings
	remote     net.Addr  // remote peer address
	rd         time.Time // read deadline
	wd         time.Time // write deadline
	ackNoDelay bool      // send ack immediately for each incoming packet(testing purpose)
	writeDelay bool      // delay kcp.flush() for Write() for bulk transfer
	dup        int       // duplicate udp packets(testing purpose)

	die        *Cancel // notify the listener has closed
	readError  *Cancel // socket error handling
	writeError *Cancel // socket error handling

	chReadEvent  chan struct{} // notify Read() can be called without blocking
	chWriteEvent chan struct{} // notify Write() can be called without blocking

	// nonce generator
	// packets waiting to be sent on wire
	txqueue         []ipv4.Message
	xconn           batchConn // for x/net
	xconnWriteError error

	//绑定的数据
	Context   any
	IsConnect bool
	OnClose   func()
	mu        sync.Mutex
}

func newUDPConn(conv uint32, l *Listener, conn net.PacketConn, isOwn bool, remote net.Addr) *Conn {
	co := new(Conn)
	co.die = NewCancel()
	co.readError = NewCancel()
	co.writeError = NewCancel()
	co.chReadEvent = make(chan struct{}, 1)
	co.chWriteEvent = make(chan struct{}, 1)
	co.remote = remote
	co.conn = conn
	co.isOwn = isOwn
	co.IsConnect = true
	co.l = l
	co.recvbuf = make([]byte, mtuLimit)
	// cast to writebatch conn
	if _, ok := conn.(*net.UDPConn); ok {
		addr, err := net.ResolveUDPAddr("udp", conn.LocalAddr().String())
		if err == nil {
			if addr.IP.To4() != nil {
				co.xconn = ipv4.NewPacketConn(conn)
			} else {
				co.xconn = ipv6.NewPacketConn(conn)
			}
		}
	}
	co.kcp = NewKCP(conv, func(buf []byte, size int) {
		if size >= IKCP_OVERHEAD {
			co.output(buf[:size])
		}
	})
	co.kcp.ReserveBytes(0)
	if co.l == nil { // it's a client connection
		go co.defaultReadLoop()
		atomic.AddUint64(&DefaultSnmp.ActiveOpens, 1)
	} else {
		atomic.AddUint64(&DefaultSnmp.PassiveOpens, 1)
	}
	// start per-session updater
	SystemTimedSched.Put(co.update, time.Now())
	currestab := atomic.AddUint64(&DefaultSnmp.CurrEstab, 1)
	maxconn := atomic.LoadUint64(&DefaultSnmp.MaxConn)
	if currestab > maxconn {
		atomic.CompareAndSwapUint64(&DefaultSnmp.MaxConn, maxconn, currestab)
	}
	return co
}

func (c *Conn) defaultReadLoop() {
	buf := make([]byte, mtuLimit)
	var src string
	for {
		if n, addr, err := c.conn.ReadFrom(buf); err == nil {
			// make sure the packet is from the same source
			if src == "" { // set source address
				src = addr.String()
			} else if addr.String() != src {
				atomic.AddUint64(&DefaultSnmp.InErrs, 1)
				continue
			}
			c.packetInput(buf[:n])
		} else {
			c.notifyReadError(err)
			return
		}
	}
}

func (c *Conn) Read(b []byte) (n int, err error) {
	for {
		c.mu.Lock()
		if len(c.bufptr) > 0 { // copy from buffer into b
			n = copy(b, c.bufptr)
			c.bufptr = c.bufptr[n:]
			c.mu.Unlock()
			atomic.AddUint64(&DefaultSnmp.BytesReceived, uint64(n))
			return n, nil
		}

		if size := c.kcp.PeekSize(); size > 0 { // peek data size from kcp
			if len(b) >= size { // receive data into 'b' directly
				c.kcp.Recv(b)
				c.mu.Unlock()
				atomic.AddUint64(&DefaultSnmp.BytesReceived, uint64(size))
				return size, nil
			}
			// if necessary resize the stream buffer to guarantee a sufficient buffer space
			if cap(c.recvbuf) < size {
				c.recvbuf = make([]byte, size)
			}
			// resize the length of recvbuf to correspond to data size
			c.recvbuf = c.recvbuf[:size]
			c.kcp.Recv(c.recvbuf)
			n = copy(b, c.recvbuf)   // copy to 'b'
			c.bufptr = c.recvbuf[n:] // pointer update
			c.mu.Unlock()
			atomic.AddUint64(&DefaultSnmp.BytesReceived, uint64(n))
			return n, nil
		}
		// deadline for current reading operation
		var timeout *time.Timer
		var tc <-chan time.Time
		if !c.rd.IsZero() {
			if time.Now().After(c.rd) {
				c.mu.Unlock()
				return 0, errTimeout
			}
			delay := time.Until(c.rd)
			timeout = time.NewTimer(delay)
			tc = timeout.C
		}
		c.mu.Unlock()
		// wait for read event or timeout or error
		select {
		case <-c.chReadEvent:
			if timeout != nil {
				timeout.Stop()
			}
		case <-tc:
			return 0, errTimeout
		case <-c.readError.Done():
			return 0, c.readError.Err()
		case <-c.die.Done():
			return 0, c.die.Err()
		}
	}
}

// Write implements net.Conn
func (c *Conn) Write(b []byte) (n int, err error) { return c.WriteBuffers([][]byte{b}) }

// WriteBuffers write a vector of byte slices to the underlying connection
func (c *Conn) WriteBuffers(v [][]byte) (n int, err error) {
	for {
		select {
		case <-c.writeError.Done():
			return 0, c.writeError.Err()
		case <-c.die.Done():
			return 0, c.die.Err()
		default:
		}
		c.mu.Lock()
		// make sure write do not overflow the max sliding window on both side
		waitsnd := c.kcp.WaitSnd()
		if waitsnd < int(c.kcp.snd_wnd) && waitsnd < int(c.kcp.rmt_wnd) {
			for _, b := range v {
				n += len(b)
				for {
					if len(b) <= int(c.kcp.mss) {
						c.kcp.Send(b)
						break
					} else {
						c.kcp.Send(b[:c.kcp.mss])
						b = b[c.kcp.mss:]
					}
				}
			}

			waitsnd = c.kcp.WaitSnd()
			if waitsnd >= int(c.kcp.snd_wnd) || waitsnd >= int(c.kcp.rmt_wnd) || !c.writeDelay {
				c.kcp.flush(false)
				c.uncork()
			}
			c.mu.Unlock()
			atomic.AddUint64(&DefaultSnmp.BytesSent, uint64(n))
			return n, nil
		}
		var timeout *time.Timer
		var tc <-chan time.Time
		if !c.wd.IsZero() {
			if time.Now().After(c.wd) {
				c.mu.Unlock()
				return 0, errTimeout
			}
			delay := time.Until(c.wd)
			timeout = time.NewTimer(delay)
			tc = timeout.C
		}
		c.mu.Unlock()

		select {
		case <-c.chWriteEvent:
			if timeout != nil {
				timeout.Stop()
			}
		case <-tc:
			return 0, errTimeout
		case <-c.writeError.Done():
			return 0, c.writeError.Err()
		case <-c.die.Done():
			return 0, c.die.Err()
		}
	}
}

// uncork sends data in txqueue if there is any
func (c *Conn) uncork() {
	if len(c.txqueue) > 0 {
		c.tx(c.txqueue)
		// recycle
		for k := range c.txqueue {
			xmitBuf.Put(c.txqueue[k].Buffers[0])
			c.txqueue[k].Buffers = nil
		}
		c.txqueue = c.txqueue[:0]
	}
}

func (c *Conn) tx(txqueue []ipv4.Message) {
	c.defaultTx(txqueue)
}

func (c *Conn) defaultTx(txqueue []ipv4.Message) {
	nbytes := 0
	npkts := 0
	for k := range txqueue {
		if n, err := c.conn.WriteTo(txqueue[k].Buffers[0], txqueue[k].Addr); err == nil {
			nbytes += n
			npkts++
		} else {
			c.notifyWriteError(err)
			break
		}
	}
	atomic.AddUint64(&DefaultSnmp.OutPkts, uint64(npkts))
	atomic.AddUint64(&DefaultSnmp.OutBytes, uint64(nbytes))
}

func (c *Conn) Close() error {
	var once bool
	c.die.Do(io.ErrClosedPipe, func() {
		once = true
	})
	if once {
		if c.OnClose != nil {
			c.OnClose()
		}
		c.IsConnect = false

		atomic.AddUint64(&DefaultSnmp.CurrEstab, ^uint64(0))
		// try best to send all queued messages
		c.mu.Lock()
		c.kcp.flush(false)
		c.uncork()
		// release pending segments
		c.kcp.ReleaseTX()
		c.mu.Unlock()
		if c.l != nil { // belongs to listener
			c.l.closeSession(c.remote)
			return nil
		} else if c.isOwn { // client socket close
			return c.conn.Close()
		} else {
			return nil
		}
	} else {
		return io.ErrClosedPipe
	}
}

// LocalAddr returns the local network address. The Addr returned is shared by all invocations of LocalAddr, so do not modify it.
func (c *Conn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

// RemoteAddr returns the remote network address. The Addr returned is shared by all invocations of RemoteAddr, so do not modify it.
func (c *Conn) RemoteAddr() net.Addr { return c.remote }

// SetDeadline sets the deadline associated with the listener. A zero time value disables the deadline.
func (c *Conn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rd = t
	c.wd = t
	c.notifyReadEvent()
	c.notifyWriteEvent()
	return nil
}

// SetReadDeadline implements the Conn SetReadDeadline method.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rd = t
	c.notifyReadEvent()
	return nil
}

// SetWriteDeadline implements the Conn SetWriteDeadline method.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wd = t
	c.notifyWriteEvent()
	return nil
}

// SetWriteDelay delays write for bulk transfer until the next update interval
func (c *Conn) SetWriteDelay(delay bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDelay = delay
}

// SetWindowSize set maximum window size
func (c *Conn) SetWindowSize(sndwnd, rcvwnd int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.kcp.WndSize(sndwnd, rcvwnd)
}

// SetMtu sets the maximum transmission unit(not including UDP header)
func (c *Conn) SetMtu(mtu int) bool {
	if mtu > mtuLimit {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.kcp.SetMtu(mtu)
	return true
}

// SetStreamMode toggles the stream mode on/off
func (c *Conn) SetStreamMode(enable bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if enable {
		c.kcp.stream = 1
	} else {
		c.kcp.stream = 0
	}
}

// SetACKNoDelay changes ack flush option, set true to flush ack immediately,
func (c *Conn) SetACKNoDelay(nodelay bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ackNoDelay = nodelay
}

func (c *Conn) SetDUP(dup int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dup = dup
}

// SetNoDelay calls nodelay() of kcp
// https://github.com/skywind3000/kcp/blob/master/README.en.md#protocol-configuration
func (c *Conn) SetNoDelay(nodelay, interval, resend, nc int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.kcp.NoDelay(nodelay, interval, resend, nc)
}

func (c *Conn) SetDSCP(dscp int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.l != nil {
		return errInvalidOperation
	}

	// interface enabled
	if ts, ok := c.conn.(setDSCP); ok {
		return ts.SetDSCP(dscp)
	}

	if nc, ok := c.conn.(net.Conn); ok {
		var succeed bool
		if err := ipv4.NewConn(nc).SetTOS(dscp << 2); err == nil {
			succeed = true
		}
		if err := ipv6.NewConn(nc).SetTrafficClass(dscp); err == nil {
			succeed = true
		}

		if succeed {
			return nil
		}
	}
	return errInvalidOperation
}

func (c *Conn) SetReadBuffer(bytes int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.l == nil {
		if nc, ok := c.conn.(setReadBuffer); ok {
			return nc.SetReadBuffer(bytes)
		}
	}
	return errInvalidOperation
}

func (c *Conn) SetWriteBuffer(bytes int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.l == nil {
		if nc, ok := c.conn.(setWriteBuffer); ok {
			return nc.SetWriteBuffer(bytes)
		}
	}
	return errInvalidOperation
}

func (c *Conn) update() {
	select {
	case <-c.die.Done():
	default:
		c.mu.Lock()
		interval := c.kcp.flush(false)
		waitsnd := c.kcp.WaitSnd()
		if waitsnd < int(c.kcp.snd_wnd) && waitsnd < int(c.kcp.rmt_wnd) {
			c.notifyWriteEvent()
		}
		c.uncork()
		c.mu.Unlock()
		// self-synchronized timed scheduling
		SystemTimedSched.Put(c.update, time.Now().Add(time.Duration(interval)*time.Millisecond))
	}
}

func (c *Conn) GetConv() uint32 { return c.kcp.conv }

func (c *Conn) GetRTO() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.kcp.rx_rto
}

func (c *Conn) GetSRTT() int32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.kcp.rx_srtt
}

func (c *Conn) GetSRTTVar() int32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.kcp.rx_rttvar
}

func (c *Conn) notifyReadEvent() {
	select {
	case c.chReadEvent <- struct{}{}:
	default:
	}
}

func (c *Conn) notifyWriteEvent() {
	select {
	case c.chWriteEvent <- struct{}{}:
	default:
	}
}

func (c *Conn) notifyReadError(err error) {
	c.readError.Cancel(err)
}

func (c *Conn) notifyWriteError(err error) {
	c.writeError.Cancel(err)
}

func (c *Conn) output(buf []byte) {
	var ecc [][]byte
	var msg ipv4.Message
	for i := 0; i < c.dup+1; i++ {
		bts := xmitBuf.Get().([]byte)[:len(buf)]
		copy(bts, buf)
		msg.Buffers = [][]byte{bts}
		msg.Addr = c.remote
		c.txqueue = append(c.txqueue, msg)
	}
	for k := range ecc {
		bts := xmitBuf.Get().([]byte)[:len(ecc[k])]
		copy(bts, ecc[k])
		msg.Buffers = [][]byte{bts}
		msg.Addr = c.remote
		c.txqueue = append(c.txqueue, msg)
	}
}

func (c *Conn) packetInput(data []byte) {
	if len(data) >= IKCP_OVERHEAD {
		c.kcpInput(data)
	}
}

func (c *Conn) kcpInput(data []byte) {
	var kcpInErrors uint64
	c.mu.Lock()
	if ret := c.kcp.Input(data, true, c.ackNoDelay); ret != 0 {
		kcpInErrors++
	}
	if n := c.kcp.PeekSize(); n > 0 {
		c.notifyReadEvent()
	}
	waitsnd := c.kcp.WaitSnd()
	if waitsnd < int(c.kcp.snd_wnd) && waitsnd < int(c.kcp.rmt_wnd) {
		c.notifyWriteEvent()
	}
	c.uncork()
	c.mu.Unlock()
	atomic.AddUint64(&DefaultSnmp.InPkts, 1)
	atomic.AddUint64(&DefaultSnmp.InBytes, uint64(len(data)))
	if kcpInErrors > 0 {
		atomic.AddUint64(&DefaultSnmp.KCPInErrors, kcpInErrors)
	}
}

func Dial(raddr string) (*Conn, error) {
	udpaddr, err := net.ResolveUDPAddr("udp", raddr)
	if err != nil {
		return nil, err
	}
	network := "udp4"
	if udpaddr.IP.To4() == nil {
		network = "udp"
	}
	conn, err := net.ListenUDP(network, nil)
	if err != nil {
		return nil, err
	}
	var convid uint32
	binary.Read(rand.Reader, binary.LittleEndian, &convid)
	return newUDPConn(convid, nil, conn, true, udpaddr), nil
}

func DialByListener(raddr string, l *Listener) (*Conn, error) {
	udpaddr, err := net.ResolveUDPAddr("udp", raddr)
	if err != nil {
		return nil, err
	}
	var convid uint32
	binary.Read(rand.Reader, binary.LittleEndian, &convid)
	s := newUDPConn(convid, l, l.conn, false, udpaddr)
	l.Manager.Store(raddr, s)
	return s, nil
}
