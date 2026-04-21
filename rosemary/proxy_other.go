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

//go:build !linux && !windows && !darwin && !freebsd && !openbsd
// +build !linux,!windows,!darwin,!freebsd,!openbsd

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

var (
	proxyPort    = 1080
	udpProxyPort = 1081
	dnsLocalPort = 5300
	tcpStopChan  chan struct{}
	udpStopChan  chan struct{}
)

func startTransparentProxy() {
	log.Println("Transparent TCP proxy is only supported on Linux/Windows")
}

func startUDPProxy() {
	log.Println("Transparent UDP proxy is only supported on Linux/Windows")
}

func handleProxyConnection(localConn net.Conn) {
	log.Println("Proxy connection handler only supported on Linux/Windows")
}

func addIptablesRule(subnet string, gw string) error {
	return fmt.Errorf("iptables is only supported on Linux/Windows")
}

func removeIptablesRule(subnet string) error {
	return fmt.Errorf("iptables is only supported on Linux/Windows")
}

func addUdpIptablesRule(subnet string) error {
	return fmt.Errorf("UDP iptables is only supported on Linux/Windows")
}

func removeUdpIptablesRule(subnet string) error {
	return fmt.Errorf("UDP iptables is only supported on Linux/Windows")
}

func sendUDPResponse(clientAddr *net.UDPAddr, sourceIP net.IP, sourcePort int, data []byte) {

}

func sendUDPResponse6(clientAddr *net.UDPAddr, sourceIP net.IP, sourcePort int, data []byte) {

}

func addIcmpIptablesRule(subnet string) error    { return nil }
func removeIcmpIptablesRule(subnet string) error { return nil }
func startICMPInterceptor()                      {}

func startDNSProxy() {
	log.Println("DNS proxy is only supported on Linux/Windows")
}

func stopDNSProxy() {

}

func getOriginalDest(conn net.Conn) (net.IP, int, error) {
	return nil, 0, fmt.Errorf("getOriginalDest only supported on Linux/Windows")
}

func addDNSRedirectRule() error {
	return fmt.Errorf("DNS redirect only supported on Linux/Windows")
}

func removeDNSRedirectRule() error {
	return fmt.Errorf("DNS redirect only supported on Linux/Windows")
}

func startSocksProxy(agentID string, port int, username, password string) string {
	return "SOCKS5 proxy only supported on Linux/Windows\n"
}

func listSocksProxies(out *strings.Builder) {
	fmt.Fprintln(out, "SOCKS5 proxy only supported on Linux/Windows")
}

func stopSocksProxy(id string, out *strings.Builder) {
	fmt.Fprintln(out, "SOCKS5 proxy only supported on Linux/Windows")
}

func notifyShutdownSignals(c chan<- os.Signal) {
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
}
func stopProxies()                   {}            // no-op on unsupported platforms
func setBSDLoopbackRouting()         {}            // no-op on unsupported platforms
func getFreeBSDEpairGateway() string { return "" } // no-op on unsupported platforms

func sendUDPPortUnreachable(clientIP net.IP, target *net.UDPAddr) {} // no-op on this platform

func reloadDefaultEgressRules() error { return nil } // no-op on unsupported platforms
