// Rosemary - Cross-platform transparent tunneling platform
// Copyright (C) 2026 Chokri Hammedi (blue0x1)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"io"
	"net"
	"time"

	"github.com/gorilla/websocket"
)

type wsNetConn struct {
	ws     *websocket.Conn
	reader io.Reader
	mu     chan struct{}
}

func newWSNetConn(ws *websocket.Conn) net.Conn {
	return &wsNetConn{ws: ws, mu: make(chan struct{}, 1)}
}

func (c *wsNetConn) Read(b []byte) (int, error) {
	for {
		if c.reader != nil {
			n, err := c.reader.Read(b)
			if err == io.EOF {
				c.reader = nil
				continue
			}
			return n, err
		}
		_, r, err := c.ws.NextReader()
		if err != nil {
			return 0, err
		}
		c.reader = r
	}
}

func (c *wsNetConn) Write(b []byte) (int, error) {
	c.mu <- struct{}{}
	defer func() { <-c.mu }()
	err := c.ws.WriteMessage(websocket.BinaryMessage, b)
	return len(b), err
}

func (c *wsNetConn) Close() error                       { return c.ws.Close() }
func (c *wsNetConn) LocalAddr() net.Addr                { return c.ws.LocalAddr() }
func (c *wsNetConn) RemoteAddr() net.Addr               { return c.ws.RemoteAddr() }
func (c *wsNetConn) SetDeadline(t time.Time) error      { return nil }
func (c *wsNetConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *wsNetConn) SetWriteDeadline(t time.Time) error { return nil }
