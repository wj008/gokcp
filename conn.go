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

	mu sync.Mutex
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

func (s *Conn) defaultReadLoop() {
	buf := make([]byte, mtuLimit)
	var src string
	for {
		if n, addr, err := s.conn.ReadFrom(buf); err == nil {
			// make sure the packet is from the same source
			if src == "" { // set source address
				src = addr.String()
			} else if addr.String() != src {
				atomic.AddUint64(&DefaultSnmp.InErrs, 1)
				continue
			}
			s.packetInput(buf[:n])
		} else {
			s.notifyReadError(err)
			return
		}
	}
}

func (s *Conn) Read(b []byte) (n int, err error) {
	for {
		s.mu.Lock()
		if len(s.bufptr) > 0 { // copy from buffer into b
			n = copy(b, s.bufptr)
			s.bufptr = s.bufptr[n:]
			s.mu.Unlock()
			atomic.AddUint64(&DefaultSnmp.BytesReceived, uint64(n))
			return n, nil
		}

		if size := s.kcp.PeekSize(); size > 0 { // peek data size from kcp
			if len(b) >= size { // receive data into 'b' directly
				s.kcp.Recv(b)
				s.mu.Unlock()
				atomic.AddUint64(&DefaultSnmp.BytesReceived, uint64(size))
				return size, nil
			}
			// if necessary resize the stream buffer to guarantee a sufficient buffer space
			if cap(s.recvbuf) < size {
				s.recvbuf = make([]byte, size)
			}
			// resize the length of recvbuf to correspond to data size
			s.recvbuf = s.recvbuf[:size]
			s.kcp.Recv(s.recvbuf)
			n = copy(b, s.recvbuf)   // copy to 'b'
			s.bufptr = s.recvbuf[n:] // pointer update
			s.mu.Unlock()
			atomic.AddUint64(&DefaultSnmp.BytesReceived, uint64(n))
			return n, nil
		}
		// deadline for current reading operation
		var timeout *time.Timer
		var c <-chan time.Time
		if !s.rd.IsZero() {
			if time.Now().After(s.rd) {
				s.mu.Unlock()
				return 0, errTimeout
			}
			delay := time.Until(s.rd)
			timeout = time.NewTimer(delay)
			c = timeout.C
		}
		s.mu.Unlock()
		// wait for read event or timeout or error
		select {
		case <-s.chReadEvent:
			if timeout != nil {
				timeout.Stop()
			}
		case <-c:
			return 0, errTimeout
		case <-s.readError.Done():
			return 0, s.readError.Err()
		case <-s.die.Done():
			return 0, s.die.Err()
		}
	}
}

// Write implements net.Conn
func (s *Conn) Write(b []byte) (n int, err error) { return s.WriteBuffers([][]byte{b}) }

// WriteBuffers write a vector of byte slices to the underlying connection
func (s *Conn) WriteBuffers(v [][]byte) (n int, err error) {
	for {
		select {
		case <-s.writeError.Done():
			return 0, s.writeError.Err()
		case <-s.die.Done():
			return 0, s.die.Err()
		default:
		}

		s.mu.Lock()
		// make sure write do not overflow the max sliding window on both side
		waitsnd := s.kcp.WaitSnd()
		if waitsnd < int(s.kcp.snd_wnd) && waitsnd < int(s.kcp.rmt_wnd) {
			for _, b := range v {
				n += len(b)
				for {
					if len(b) <= int(s.kcp.mss) {
						s.kcp.Send(b)
						break
					} else {
						s.kcp.Send(b[:s.kcp.mss])
						b = b[s.kcp.mss:]
					}
				}
			}

			waitsnd = s.kcp.WaitSnd()
			if waitsnd >= int(s.kcp.snd_wnd) || waitsnd >= int(s.kcp.rmt_wnd) || !s.writeDelay {
				s.kcp.flush(false)
				s.uncork()
			}
			s.mu.Unlock()
			atomic.AddUint64(&DefaultSnmp.BytesSent, uint64(n))
			return n, nil
		}
		var timeout *time.Timer
		var c <-chan time.Time
		if !s.wd.IsZero() {
			if time.Now().After(s.wd) {
				s.mu.Unlock()
				return 0, errTimeout
			}
			delay := time.Until(s.wd)
			timeout = time.NewTimer(delay)
			c = timeout.C
		}
		s.mu.Unlock()

		select {
		case <-s.chWriteEvent:
			if timeout != nil {
				timeout.Stop()
			}
		case <-c:
			return 0, errTimeout
		case <-s.writeError.Done():
			return 0, s.writeError.Err()
		case <-s.die.Done():
			return 0, s.die.Err()
		}
	}
}

// uncork sends data in txqueue if there is any
func (s *Conn) uncork() {
	if len(s.txqueue) > 0 {
		s.tx(s.txqueue)
		// recycle
		for k := range s.txqueue {
			xmitBuf.Put(s.txqueue[k].Buffers[0])
			s.txqueue[k].Buffers = nil
		}
		s.txqueue = s.txqueue[:0]
	}
}

func (s *Conn) tx(txqueue []ipv4.Message) {
	s.defaultTx(txqueue)
}

func (s *Conn) defaultTx(txqueue []ipv4.Message) {
	nbytes := 0
	npkts := 0
	for k := range txqueue {
		if n, err := s.conn.WriteTo(txqueue[k].Buffers[0], txqueue[k].Addr); err == nil {
			nbytes += n
			npkts++
		} else {
			s.notifyWriteError(err)
			break
		}
	}
	atomic.AddUint64(&DefaultSnmp.OutPkts, uint64(npkts))
	atomic.AddUint64(&DefaultSnmp.OutBytes, uint64(nbytes))
}

func (s *Conn) Close() error {
	var once bool
	s.die.Do(io.ErrClosedPipe, func() {
		once = true
	})
	if once {
		atomic.AddUint64(&DefaultSnmp.CurrEstab, ^uint64(0))
		// try best to send all queued messages
		s.mu.Lock()
		s.kcp.flush(false)
		s.uncork()
		// release pending segments
		s.kcp.ReleaseTX()
		s.mu.Unlock()
		if s.l != nil { // belongs to listener
			s.l.closeSession(s.remote)
			return nil
		} else if s.isOwn { // client socket close
			return s.conn.Close()
		} else {
			return nil
		}
	} else {
		return io.ErrClosedPipe
	}
}

// LocalAddr returns the local network address. The Addr returned is shared by all invocations of LocalAddr, so do not modify it.
func (s *Conn) LocalAddr() net.Addr { return s.conn.LocalAddr() }

// RemoteAddr returns the remote network address. The Addr returned is shared by all invocations of RemoteAddr, so do not modify it.
func (s *Conn) RemoteAddr() net.Addr { return s.remote }

// SetDeadline sets the deadline associated with the listener. A zero time value disables the deadline.
func (s *Conn) SetDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rd = t
	s.wd = t
	s.notifyReadEvent()
	s.notifyWriteEvent()
	return nil
}

// SetReadDeadline implements the Conn SetReadDeadline method.
func (s *Conn) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rd = t
	s.notifyReadEvent()
	return nil
}

// SetWriteDeadline implements the Conn SetWriteDeadline method.
func (s *Conn) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wd = t
	s.notifyWriteEvent()
	return nil
}

// SetWriteDelay delays write for bulk transfer until the next update interval
func (s *Conn) SetWriteDelay(delay bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeDelay = delay
}

// SetWindowSize set maximum window size
func (s *Conn) SetWindowSize(sndwnd, rcvwnd int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kcp.WndSize(sndwnd, rcvwnd)
}

// SetMtu sets the maximum transmission unit(not including UDP header)
func (s *Conn) SetMtu(mtu int) bool {
	if mtu > mtuLimit {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kcp.SetMtu(mtu)
	return true
}

// SetStreamMode toggles the stream mode on/off
func (s *Conn) SetStreamMode(enable bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if enable {
		s.kcp.stream = 1
	} else {
		s.kcp.stream = 0
	}
}

// SetACKNoDelay changes ack flush option, set true to flush ack immediately,
func (s *Conn) SetACKNoDelay(nodelay bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ackNoDelay = nodelay
}

func (s *Conn) SetDUP(dup int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dup = dup
}

// SetNoDelay calls nodelay() of kcp
// https://github.com/skywind3000/kcp/blob/master/README.en.md#protocol-configuration
func (s *Conn) SetNoDelay(nodelay, interval, resend, nc int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kcp.NoDelay(nodelay, interval, resend, nc)
}

func (s *Conn) SetDSCP(dscp int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.l != nil {
		return errInvalidOperation
	}

	// interface enabled
	if ts, ok := s.conn.(setDSCP); ok {
		return ts.SetDSCP(dscp)
	}

	if nc, ok := s.conn.(net.Conn); ok {
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

func (s *Conn) SetReadBuffer(bytes int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.l == nil {
		if nc, ok := s.conn.(setReadBuffer); ok {
			return nc.SetReadBuffer(bytes)
		}
	}
	return errInvalidOperation
}

func (s *Conn) SetWriteBuffer(bytes int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.l == nil {
		if nc, ok := s.conn.(setWriteBuffer); ok {
			return nc.SetWriteBuffer(bytes)
		}
	}
	return errInvalidOperation
}

func (s *Conn) update() {
	select {
	case <-s.die.Done():
	default:
		s.mu.Lock()
		interval := s.kcp.flush(false)
		waitsnd := s.kcp.WaitSnd()
		if waitsnd < int(s.kcp.snd_wnd) && waitsnd < int(s.kcp.rmt_wnd) {
			s.notifyWriteEvent()
		}
		s.uncork()
		s.mu.Unlock()
		// self-synchronized timed scheduling
		SystemTimedSched.Put(s.update, time.Now().Add(time.Duration(interval)*time.Millisecond))
	}
}

func (s *Conn) GetConv() uint32 { return s.kcp.conv }

func (s *Conn) GetRTO() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kcp.rx_rto
}

func (s *Conn) GetSRTT() int32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kcp.rx_srtt
}

func (s *Conn) GetSRTTVar() int32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kcp.rx_rttvar
}

func (s *Conn) notifyReadEvent() {
	select {
	case s.chReadEvent <- struct{}{}:
	default:
	}
}

func (s *Conn) notifyWriteEvent() {
	select {
	case s.chWriteEvent <- struct{}{}:
	default:
	}
}

func (s *Conn) notifyReadError(err error) {
	s.readError.Cancel(err)
}

func (s *Conn) notifyWriteError(err error) {
	s.writeError.Cancel(err)
}

func (s *Conn) output(buf []byte) {
	var ecc [][]byte
	var msg ipv4.Message
	for i := 0; i < s.dup+1; i++ {
		bts := xmitBuf.Get().([]byte)[:len(buf)]
		copy(bts, buf)
		msg.Buffers = [][]byte{bts}
		msg.Addr = s.remote
		s.txqueue = append(s.txqueue, msg)
	}
	for k := range ecc {
		bts := xmitBuf.Get().([]byte)[:len(ecc[k])]
		copy(bts, ecc[k])
		msg.Buffers = [][]byte{bts}
		msg.Addr = s.remote
		s.txqueue = append(s.txqueue, msg)
	}
}

func (s *Conn) packetInput(data []byte) {
	if len(data) >= IKCP_OVERHEAD {
		s.kcpInput(data)
	}
}

func (s *Conn) kcpInput(data []byte) {
	var kcpInErrors uint64
	s.mu.Lock()
	if ret := s.kcp.Input(data, true, s.ackNoDelay); ret != 0 {
		kcpInErrors++
	}
	if n := s.kcp.PeekSize(); n > 0 {
		s.notifyReadEvent()
	}
	waitsnd := s.kcp.WaitSnd()
	if waitsnd < int(s.kcp.snd_wnd) && waitsnd < int(s.kcp.rmt_wnd) {
		s.notifyWriteEvent()
	}
	s.uncork()
	s.mu.Unlock()
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
	l.manager.Store(raddr, s)
	return s, nil
}
