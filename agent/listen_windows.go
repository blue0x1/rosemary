//go:build windows

package main

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/windows"
)

const soExclusiveAddrUse = -5

func listenAgentTCP(addr string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var controlErr error
			if err := c.Control(func(fd uintptr) {
				controlErr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, soExclusiveAddrUse, 1)
			}); err != nil {
				return err
			}
			return controlErr
		},
	}
	return lc.Listen(context.Background(), "tcp", addr)
}
