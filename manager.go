package gokcp

import "sync"

type ConnManager struct {
	sync.Map
}

func (m *ConnManager) Load(key string) (conn *Conn, ok bool) {
	v, ok := m.Map.Load(key)
	if ok {
		conn, ok = v.(*Conn)
	}
	return
}

func (m *ConnManager) Has(key string) (ok bool) {
	_, ok = m.Map.Load(key)
	return ok
}

func (m *ConnManager) Store(key string, conn *Conn) {
	m.Map.Store(key, conn)
}

func (m *ConnManager) Delete(key string) {
	m.Map.Delete(key)
}

func (m *ConnManager) Range(f func(key string, value *Conn) bool) {
	m.Map.Range(func(k, v any) bool {
		return f(k.(string), v.(*Conn))
	})
}
