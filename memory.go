package gokcp

import "sync"

// maximum packet size
const mtuLimit = 1500

// a system-wide packet buffer shared among sending, receiving and FEC
// to mitigate high-frequency memory allocation for packets, bytes from xmitBuf
// is aligned to 64bit
var xmitBuf sync.Pool

func init() {
	xmitBuf.New = func() interface{} {
		return make([]byte, mtuLimit)
	}
}
