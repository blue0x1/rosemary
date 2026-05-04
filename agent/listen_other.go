//go:build !windows

package main

import "net"

func listenAgentTCP(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}
