package gokcp

import (
	"encoding/binary"
	"errors"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"io"
	"log"
	"net"
	"sync/atomic"
	"time"
)

var (
	errInvalidOperation = errors.New("invalid operation")
	errTimeout          = errors.New("timeout")
)

type setReadBuffer interface {
	SetReadBuffer(bytes int) error
}

type setWriteBuffer interface {
	SetWriteBuffer(bytes int) error
}

type setDSCP interface {
	SetDSCP(int) error
}

type Listener struct {
	conn         net.PacketConn
	manager      *ConnManager
	chAccepts    chan *Conn    // Listen() backlog
	chConnClosed chan net.Addr // session close queue
	die          *Cancel       // notify the listener has closed
	readError    *Cancel       // socket error handling
	rd           atomic.Value  // read deadline for Accept()
}

func (l *Listener) packetInput(data []byte, addr net.Addr) {
	if len(data) >= IKCP_OVERHEAD {
		s, ok := l.manager.Load(addr.String())
		var conv, sn uint32
		conv = binary.LittleEndian.Uint32(data)
		sn = binary.LittleEndian.Uint32(data[IKCP_SN_OFFSET:])
		if ok { // existing connection
			if conv == s.kcp.conv { // parity data or valid conversation
				s.kcpInput(data)
			} else if sn == 0 { // should replace current connection
				s.Close()
				s = nil
			}
		}
		if s == nil { // new session
			if len(l.chAccepts) < cap(l.chAccepts) { // do not let the new sessions overwhelm accept queue
				s := newUDPConn(conv, l, l.conn, false, addr)
				s.kcpInput(data)
				l.manager.Store(addr.String(), s)
				l.chAccepts <- s
			}
		}
	}
}

func (l *Listener) notifyReadError(err error) {
	l.readError.Do(err, func() {
		l.manager.Range(func(_ string, conn *Conn) bool {
			conn.notifyReadError(err)
			return true
		})
	})
}

func (l *Listener) SetReadBuffer(bytes int) error {
	if nc, ok := l.conn.(setReadBuffer); ok {
		return nc.SetReadBuffer(bytes)
	}
	return errInvalidOperation
}

func (l *Listener) SetWriteBuffer(bytes int) error {
	if nc, ok := l.conn.(setWriteBuffer); ok {
		return nc.SetWriteBuffer(bytes)
	}
	return errInvalidOperation
}

func (l *Listener) SetDSCP(dscp int) error {
	// interface enabled
	if ts, ok := l.conn.(setDSCP); ok {
		return ts.SetDSCP(dscp)
	}
	if nc, ok := l.conn.(net.Conn); ok {
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

func (l *Listener) AcceptKCP() (*Conn, error) {
	var timeout <-chan time.Time
	if deadline, ok := l.rd.Load().(time.Time); ok && !deadline.IsZero() {
		timeout = time.After(time.Until(deadline))
	}
	select {
	case <-timeout:
		return nil, errTimeout
	case c := <-l.chAccepts:
		return c, nil
	case <-l.readError.Done():
		return nil, l.readError.Err()
	case <-l.die.Done():
		return nil, l.die.Err()
	}
}

func (l *Listener) SetDeadline(t time.Time) error {
	l.SetReadDeadline(t)
	l.SetWriteDeadline(t)
	return nil
}

func (l *Listener) SetReadDeadline(t time.Time) error {
	l.rd.Store(t)
	return nil
}

func (l *Listener) SetWriteDeadline(t time.Time) error { return errInvalidOperation }

func (l *Listener) Close() error {
	var once bool
	l.die.Do(io.ErrClosedPipe, func() {
		once = true
	})
	var err error
	if once {
		err = l.conn.Close()
	} else {
		err = io.ErrClosedPipe
	}
	return err
}

func (l *Listener) closeSession(remote net.Addr) (ret bool) {
	log.Println("链接关闭", remote)
	addr := remote.String()
	if _, ok := l.manager.Load(addr); ok {
		l.manager.Delete(addr)
		return true
	}
	return false
}

func (l *Listener) Addr() net.Addr { return l.conn.LocalAddr() }

func (l *Listener) monitor() {
	buf := make([]byte, mtuLimit)
	for {
		if n, from, err := l.conn.ReadFrom(buf); err == nil {
			l.packetInput(buf[:n], from)
		} else {
			l.notifyReadError(err)
			return
		}
	}
}

func Listen(laddr string) (*Listener, error) {
	udpaddr, err := net.ResolveUDPAddr("udp", laddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpaddr)
	if err != nil {
		return nil, err
	}
	l := new(Listener)
	l.conn = conn
	l.manager = new(ConnManager)
	l.chAccepts = make(chan *Conn, 128)
	l.chConnClosed = make(chan net.Addr)
	l.die = NewCancel()
	l.readError = NewCancel()
	go l.monitor()
	return l, nil
}
