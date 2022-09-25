package gokcp

import "net"

type Client struct {
	net.Conn
	Context   any
	IsConnect bool
	closeFunc func()
}
