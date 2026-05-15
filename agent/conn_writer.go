package main

import (
	"net"
	"sync"
	"time"
)

type connWriter struct {
	conn      net.Conn
	ch        chan []byte
	closeOnce sync.Once
	done      chan struct{}
}

func newConnWriter(conn net.Conn) *connWriter {
	w := &connWriter{
		conn: conn,
		ch:   make(chan []byte, 4096),
		done: make(chan struct{}),
	}
	go w.run()
	return w
}

func (w *connWriter) run() {
	defer close(w.done)
	for data := range w.ch {
		w.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		_, err := w.conn.Write(data)
		w.conn.SetWriteDeadline(time.Time{})
		if err != nil {
			w.conn.Close()
			return
		}
	}
}

func (w *connWriter) write(data []byte) bool {
	dataCopy := append([]byte(nil), data...)
	select {
	case w.ch <- dataCopy:
		return true
	case <-time.After(5 * time.Second):
		w.close()
		return false
	}
}

func (w *connWriter) close() {
	w.closeOnce.Do(func() {
		close(w.ch)
		w.conn.Close()
	})
}
