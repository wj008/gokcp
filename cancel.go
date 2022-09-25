package gokcp

import (
	"sync"
	"sync/atomic"
)

type Cancel struct {
	err  atomic.Value
	once sync.Once
	done chan struct{}
}

func NewCancel() *Cancel {
	return &Cancel{
		done: make(chan struct{}),
	}
}

func (r *Cancel) Err() error {
	return r.err.Load().(error)
}

func (r *Cancel) Do(err error, fn func()) {
	r.once.Do(func() {
		if fn != nil {
			fn()
		}
		r.err.Store(err)
		close(r.done)
	})
}

func (r *Cancel) Cancel(err error) {
	r.Do(err, nil)
}

func (r *Cancel) Done() <-chan struct{} {
	return r.done
}
