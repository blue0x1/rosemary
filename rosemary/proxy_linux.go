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

//go:build linux

package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"github.com/miekg/dns"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
	"sync/atomic"
)

func iptCmd(bin string, args ...string) *exec.Cmd {
	return exec.Command(bin, append([]string{"-w", "10"}, args...)...)
}

const (
	IP_TRANSPARENT       = 19
	IPV6_TRANSPARENT     = 75
	soReusePort          = 0xf
	IPV6_RECVORIGDSTADDR = 74
	connIdleTimeout      = 5 * time.Minute
)

var tcpBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 64*1024)
		return &b
	},
}

func sendUDPPortUnreachable(clientIP net.IP, target *net.UDPAddr) {
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return
	}
	defer c.Close()
	msg := icmp.Message{
		Type: ipv4.ICMPTypeDestinationUnreachable,
		Code: 3,
		Body: &icmp.DstUnreach{},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return
	}
	c.WriteTo(b, &net.IPAddr{IP: clientIP})
}

var (
	proxyPort    = currentTCPPort
	udpProxyPort = currentUDPPort
	dnsLocalPort = currentDNSPort
)

var (
	tcpStopChan       chan struct{}
	udpStopChan       chan struct{}
	udpV6StopChan     chan struct{}
	icmpInterceptStop chan struct{}
)

var (
	_ = startTransparentProxy
	_ = startUDPProxy
	_ = addIptablesRule
	_ = removeIptablesRule
	_ = addUdpIptablesRule
	_ = removeUdpIptablesRule
	_ = sendUDPResponse

	dnsUDPServer *dns.Server
	dnsTCPServer *dns.Server
)

func initTProxyRoutes() error {
	for _, kv := range []string{
		"net.ipv4.ip_forward=1",
		"net.ipv4.conf.all.rp_filter=0",
		"net.ipv4.conf.default.rp_filter=0",
		"net.ipv4.conf.lo.rp_filter=0",
	} {
		if out, err := exec.Command("sysctl", "-w", kv).CombinedOutput(); err != nil {
			logVerbose("Warning: sysctl %s: %v %s", kv, err, out)
		}
	}

	ipv6Enabled := true
	if out, err := exec.Command("sysctl", "-n", "net.ipv6.conf.all.disable_ipv6").CombinedOutput(); err == nil {
		if strings.TrimSpace(string(out)) == "1" {
			ipv6Enabled = false
			logVerbose("IPv6 is disabled on this system; skipping IPv6 route/rule setup")
		}
	}

	if ipv6Enabled {
		if out, err := exec.Command("sysctl", "-w", "net.ipv6.conf.all.forwarding=1").CombinedOutput(); err != nil {
			logVerbose("Warning: failed to enable IPv6 forwarding: %v %s", err, out)
		}
	}

	if out, err := exec.Command("ip", "rule", "add", "fwmark", "1", "lookup", "100").CombinedOutput(); err != nil {
		if !strings.Contains(string(out), "exists") {
			return fmt.Errorf("failed to add ip rule: %v %s", err, out)
		}
	}
	if out, err := exec.Command("ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "100").CombinedOutput(); err != nil {
		if !strings.Contains(string(out), "exists") {
			return fmt.Errorf("failed to add ip route: %v %s", err, out)
		}
	}

	if ipv6Enabled {
		if out, err := exec.Command("ip", "-6", "rule", "add", "fwmark", "1", "lookup", "100").CombinedOutput(); err != nil {
			if !strings.Contains(string(out), "exists") {
				logVerbose("Warning: failed to add ip6 rule: %v %s", err, out)
			}
		}
		if out, err := exec.Command("ip", "-6", "route", "add", "local", "::/0", "dev", "lo", "table", "100").CombinedOutput(); err != nil {
			if !strings.Contains(string(out), "exists") {
				logVerbose("Warning: failed to add ip6 route: %v %s", err, out)
			}
		}
	}

	tproxyRule := []string{
		"-t", "mangle", "-I", "PREROUTING",
		"-p", "udp", "-m", "mark", "--mark", "1",
		"-j", "TPROXY", "--on-port", strconv.Itoa(udpProxyPort), "--on-ip", "127.0.0.1",
	}
	if out, err := iptCmd("iptables", tproxyRule...).CombinedOutput(); err != nil {
		logVerbose("Warning: failed to add IPv4 PREROUTING TPROXY rule (may exist): %v %s", err, out)
	}

	if ipv6Enabled {
		tproxy6Rule := []string{
			"-t", "mangle", "-I", "PREROUTING",
			"-p", "udp", "-m", "mark", "--mark", "1",
			"-j", "TPROXY", "--on-port", strconv.Itoa(udpProxyPort), "--on-ip", "::1",
		}
		if out, err := iptCmd("ip6tables", tproxy6Rule...).CombinedOutput(); err != nil {
			logVerbose("Warning: failed to add IPv6 PREROUTING TPROXY rule (may exist): %v %s", err, out)
		}
	}

	return nil
}

func startTransparentProxy() {
	if proxyStarted {
		return
	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", proxyPort))
	if err != nil {
		log.Printf("Failed to start transparent proxy on port %d: %v", proxyPort, err)
		return
	}
	proxyListener = ln
	proxyStarted = true
	logVerbose("Transparent TCP proxy listening on :%d", proxyPort)

	stop := make(chan struct{})
	tcpStopChan = stop

	go func() {
		<-stop
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-stop:
				return
			default:
				logVerbose("Proxy accept error: %v", err)
				continue
			}
		}
		go handleProxyConnection(conn)
	}
}

func startUDPProxy() {
	if err := initTProxyRoutes(); err != nil {
		log.Printf("Failed to initialize TPROXY routes: %v", err)
		return
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		log.Printf("Failed to create UDP socket: %v", err)
		return
	}

	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, IP_TRANSPARENT, 1); err != nil {
		log.Printf("Failed to set IP_TRANSPARENT: %v", err)
		syscall.Close(fd)
		return
	}

	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_RECVORIGDSTADDR, 1); err != nil {
		log.Printf("Failed to set IP_RECVORIGDSTADDR: %v", err)
		syscall.Close(fd)
		return
	}

	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		log.Printf("Failed to set SO_REUSEADDR: %v", err)
		syscall.Close(fd)
		return
	}

	sockaddr := &syscall.SockaddrInet4{Port: udpProxyPort}
	copy(sockaddr.Addr[:], net.ParseIP("0.0.0.0").To4())
	if err := syscall.Bind(fd, sockaddr); err != nil {
		log.Printf("Failed to bind UDP socket: %v", err)
		syscall.Close(fd)
		return
	}

	file := os.NewFile(uintptr(fd), "")
	conn, err := net.FilePacketConn(file)
	file.Close()
	if err != nil {
		log.Printf("Failed to convert UDP socket: %v", err)
		return
	}
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		log.Printf("Not a UDP connection")
		return
	}
	udpListener = udpConn
	logVerbose("UDP TPROXY listening on 0.0.0.0:%d", udpProxyPort)

	go startUDPProxyV6()

	stop := make(chan struct{})
	udpStopChan = stop

	if udpConn != nil {
		localConn := udpConn
		go func() {
			<-stop
			if localConn != nil {
				localConn.Close()
			}
		}()
	}

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				cleanupUDP()
			case <-stop:
				return
			}
		}
	}()

	buf := make([]byte, 65535)
	oob := make([]byte, 1024)
	for {
		n, oobn, flags, addr, err := udpConn.ReadMsgUDP(buf, oob)
		if err != nil {
			select {
			case <-stop:
				return
			default:
				logVerbose("UDP read error: %v", err)
				continue
			}
		}
		if flags&syscall.MSG_TRUNC != 0 {
			continue
		}

		var origDst *net.UDPAddr
		cm, err := syscall.ParseSocketControlMessage(oob[:oobn])
		if err == nil {
			for _, m := range cm {
				if m.Header.Level == syscall.IPPROTO_IP && m.Header.Type == syscall.IP_RECVORIGDSTADDR {
					var dst syscall.RawSockaddrInet4
					if uintptr(len(m.Data)) >= unsafe.Sizeof(dst) {
						copy((*[unsafe.Sizeof(dst)]byte)(unsafe.Pointer(&dst))[:], m.Data)
						port := int(dst.Port)
						port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)
						ip := net.IPv4(dst.Addr[0], dst.Addr[1], dst.Addr[2], dst.Addr[3])
						origDst = &net.UDPAddr{IP: ip, Port: port}
					}
				}
			}
		}

		if origDst == nil {
			continue
		}

		go handleUDPPacket(udpConn, addr, origDst, buf[:n])
	}
}

func cleanupUDP() {
	now := time.Now()
	pendingUDPConns.Range(func(key, value interface{}) bool {
		s := value.(*udpSession)
		if now.After(s.expire) {
			pendingUDPConns.Delete(key)
		}
		return true
	})
}

func handleUDPPacket(localConn *net.UDPConn, clientAddr *net.UDPAddr, origDst *net.UDPAddr, data []byte) {
	agentID, ok := routingTable.FindAgentForIP(origDst.IP)
	if !ok {
		egress := getDefaultEgressAgent()
		if egress == "" || isServerLocalIP(origDst.IP) {
			return
		}
		agentID = egress
	}

	sessionKey := clientAddr.String()
	var session *udpSession
	if val, ok := pendingUDPConns.Load(sessionKey); ok {
		session = val.(*udpSession)
	} else {

		connID := uuid.New().String()
		session = &udpSession{
			clientAddr: clientAddr,
			remoteAddr: origDst,
			agentID:    agentID,
			connID:     connID,
			expire:     time.Now().Add(udpTimeout),
		}

		responseChan := make(chan ConnectResponse, 1)
		respChanMap.Store(connID, responseChan)

		pendingUDPConns.Store(sessionKey, session)
		pendingUDPConns.Store(connID, session)

		req := ConnectRequest{
			TargetHost: origDst.IP.String(),
			TargetPort: origDst.Port,
			ConnID:     connID,
			Protocol:   "udp",
		}
		payload, _ := json.Marshal(req)
		msg := Message{
			Type:          "connect",
			Payload:       payload,
			TargetAgentID: agentID,
		}
		if err := sendControlMessageToAgent(agentID, msg); err != nil {
			logVerbose("Failed to send UDP connect request to agent %s: %v", agentID, err)
			respChanMap.Delete(connID)
			pendingUDPConns.Delete(sessionKey)
			pendingUDPConns.Delete(connID)
			return
		}

		select {
		case resp := <-responseChan:
			respChanMap.Delete(connID)
			if !resp.Success {
				logVerbose("Agent failed to open UDP to %s:%d: %s", origDst.IP, origDst.Port, resp.Error)
				sendUDPPortUnreachable(clientAddr.IP, origDst)
				pendingUDPConns.Delete(sessionKey)
				pendingUDPConns.Delete(connID)
				return
			}
		case <-time.After(5 * time.Second):
			logVerbose("Timeout waiting for UDP connect_response from agent %s connID %s", agentID, connID)
			respChanMap.Delete(connID)
			pendingUDPConns.Delete(sessionKey)
			pendingUDPConns.Delete(connID)
			return
		}
	}

	dataMsg := DataMessage{
		ConnID: session.connID,
		Data:   data,
		Close:  false,
	}
	payload, _ := json.Marshal(dataMsg)
	msg := Message{
		Type:          "data",
		Payload:       payload,
		TargetAgentID: agentID,
	}
	if err := sendControlMessageToAgent(agentID, msg); err != nil {
		logVerbose("Failed to send UDP data to agent: %v", err)
	}
	session.expire = time.Now().Add(udpTimeout)
}

func handleProxyConnection(localConn net.Conn) {
	defer localConn.Close()

	dstIP, dstPort, err := getOriginalDest(localConn)
	if err != nil {
		logVerbose("Failed to get original destination: %v", err)
		return
	}

	agentID, ok := routingTable.FindAgentForIP(dstIP)
	if !ok {
		egress := getDefaultEgressAgent()
		if egress == "" || isServerLocalIP(dstIP) {
			logVerbose("No agent found for IP %s", dstIP.String())
			return
		}
		agentID = egress
	}

	connID := uuid.New().String()

	responseChan := make(chan ConnectResponse, 1)
	respChanMap.Store(connID, responseChan)
	defer respChanMap.Delete(connID)

	req := ConnectRequest{
		TargetHost: dstIP.String(),
		TargetPort: dstPort,
		ConnID:     connID,
		Protocol:   "tcp",
	}
	payload, _ := json.Marshal(req)
	msg := Message{
		Type:          "connect",
		Payload:       payload,
		TargetAgentID: agentID,
	}
	if err := sendControlMessageToAgent(agentID, msg); err != nil {
		logVerbose("Failed to send connect request to agent %s: %v", agentID, err)
		return
	}

	resetConn := func() {
		if tc, ok := localConn.(*net.TCPConn); ok {
			tc.SetLinger(0)
		}
	}

	select {
	case resp := <-responseChan:
		if !resp.Success {
			resetConn()
			return
		}
	case <-time.After(10 * time.Second):
		logVerbose("Timeout waiting for connect_response for %s:%d", dstIP, dstPort)
		resetConn()
		return
	}

	pendingConns.Store(connID, &pendingConn{conn: localConn, agentID: agentID})
	defer pendingConns.Delete(connID)

	bufPtr := tcpBufPool.Get().(*[]byte)
	buf := *bufPtr
	defer tcpBufPool.Put(bufPtr)

	for {
		localConn.SetReadDeadline(time.Now().Add(connIdleTimeout))
		n, err := localConn.Read(buf)
		if err != nil {
			dataMsg := DataMessage{ConnID: connID, Close: true}
			payload, _ := json.Marshal(dataMsg)
			msg := Message{Type: "data", Payload: payload, TargetAgentID: agentID}
			sendControlMessageToAgent(agentID, msg)
			return
		}
		dataMsg := DataMessage{ConnID: connID, Data: buf[:n]}
		payload, _ := json.Marshal(dataMsg)
		msg := Message{Type: "data", Payload: payload, TargetAgentID: agentID}
		if err := sendControlMessageToAgent(agentID, msg); err != nil {
			return
		}
	}
}

func addIptablesRule(subnet string, gw string) error {
	ipt := "iptables"
	if isIPv6Subnet(subnet) {
		ipt = "ip6tables"
	}
	cmd := iptCmd(ipt, "-t", "nat", "-A", "OUTPUT",
		"-d", subnet, "-p", "tcp",
		"-j", "REDIRECT", "--to-port", strconv.Itoa(proxyPort))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s add failed: %v - %s", ipt, err, output)
	}
	logVerbose("%s: added TCP redirect for %s -> %d", ipt, subnet, proxyPort)
	return nil
}

func removeIptablesRule(subnet string) error {
	ipt := "iptables"
	if isIPv6Subnet(subnet) {
		ipt = "ip6tables"
	}
	cmd := iptCmd(ipt, "-t", "nat", "-D", "OUTPUT",
		"-d", subnet, "-p", "tcp",
		"-j", "REDIRECT", "--to-port", strconv.Itoa(proxyPort))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s remove failed: %v - %s", ipt, err, output)
	}
	logVerbose("%s: removed TCP redirect for %s", ipt, subnet)
	return nil
}

func addUdpIptablesRule(subnet string) error {
	ipt := "iptables"
	if isIPv6Subnet(subnet) {
		ipt = "ip6tables"
	}
	cmd := iptCmd(ipt, "-t", "mangle", "-A", "OUTPUT",
		"-d", subnet, "-p", "udp",
		"-j", "MARK", "--set-mark", "1")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s MARK add failed: %v - %s", ipt, err, output)
	}
	logVerbose("%s: added UDP MARK for %s", ipt, subnet)
	return nil
}

func removeUdpIptablesRule(subnet string) error {
	ipt := "iptables"
	if isIPv6Subnet(subnet) {
		ipt = "ip6tables"
	}
	cmd := iptCmd(ipt, "-t", "mangle", "-D", "OUTPUT",
		"-d", subnet, "-p", "udp",
		"-j", "MARK", "--set-mark", "1")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s MARK remove failed: %v - %s", ipt, err, output)
	}
	logVerbose("%s: removed UDP MARK for %s", ipt, subnet)
	return nil
}

func getOriginalDest(conn net.Conn) (net.IP, int, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, 0, fmt.Errorf("not a TCP connection")
	}
	file, err := tcpConn.File()
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()
	fd := int(file.Fd())
	const SO_ORIGINAL_DST = 80
	var addr syscall.RawSockaddrInet4
	addrLen := uint32(unsafe.Sizeof(addr))
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd),
		uintptr(syscall.IPPROTO_IP), uintptr(SO_ORIGINAL_DST),
		uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&addrLen)), 0)
	if errno == 0 && addrLen >= uint32(unsafe.Sizeof(addr)) {
		port := int(addr.Port)
		port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)
		ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
		return ip, port, nil
	}
	var addr6 syscall.RawSockaddrInet6
	addrLen6 := uint32(unsafe.Sizeof(addr6))
	_, _, errno = unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd),
		uintptr(syscall.IPPROTO_IPV6), uintptr(SO_ORIGINAL_DST),
		uintptr(unsafe.Pointer(&addr6)), uintptr(unsafe.Pointer(&addrLen6)), 0)
	if errno == 0 && addrLen6 >= uint32(unsafe.Sizeof(addr6)) {
		port := int(addr6.Port)
		port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)
		ip := net.IP(addr6.Addr[:])
		return ip, port, nil
	}
	return nil, 0, fmt.Errorf("failed to get original destination")
}

func sendUDPResponse(clientAddr *net.UDPAddr, sourceIP net.IP, sourcePort int, data []byte) {
	if sourceIP.To4() == nil {
		sendUDPResponse6(clientAddr, sourceIP, sourcePort, data)
		return
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		logVerbose("Failed to create response socket: %v", err)
		return
	}
	defer syscall.Close(fd)

	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, IP_TRANSPARENT, 1); err != nil {
		logVerbose("Failed to set IP_TRANSPARENT for response: %v", err)
		return
	}

	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, soReusePort, 1)

	spoofAddr := &syscall.SockaddrInet4{Port: sourcePort}
	copy(spoofAddr.Addr[:], sourceIP.To4())
	if err := syscall.Bind(fd, spoofAddr); err != nil {
		logVerbose("Failed to bind to spoofed address %s:%d: %v", sourceIP, sourcePort, err)
		return
	}

	dstAddr := &syscall.SockaddrInet4{Port: clientAddr.Port}
	copy(dstAddr.Addr[:], clientAddr.IP.To4())
	if err := syscall.Sendto(fd, data, 0, dstAddr); err != nil {
		logVerbose("Failed to send spoofed response: %v", err)
	}
}

func sendUDPResponse6(clientAddr *net.UDPAddr, sourceIP net.IP, sourcePort int, data []byte) {
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, 0)
	if err != nil {
		logVerbose("Failed to create IPv6 response socket: %v", err)
		return
	}
	defer syscall.Close(fd)

	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, IPV6_TRANSPARENT, 1); err != nil {
		logVerbose("Failed to set IPV6_TRANSPARENT for response: %v", err)
		return
	}
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, soReusePort, 1)

	spoofAddr := &syscall.SockaddrInet6{Port: sourcePort}
	copy(spoofAddr.Addr[:], sourceIP.To16())
	if err := syscall.Bind(fd, spoofAddr); err != nil {
		logVerbose("Failed to bind to spoofed IPv6 address %s:%d: %v", sourceIP, sourcePort, err)
		return
	}

	dstAddr := &syscall.SockaddrInet6{Port: clientAddr.Port}
	copy(dstAddr.Addr[:], clientAddr.IP.To16())
	if err := syscall.Sendto(fd, data, 0, dstAddr); err != nil {
		logVerbose("Failed to send spoofed IPv6 response: %v", err)
	}
}

func startUDPProxyV6() {
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, 0)
	if err != nil {
		log.Printf("Failed to create IPv6 UDP socket: %v", err)
		return
	}

	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, IPV6_TRANSPARENT, 1); err != nil {
		log.Printf("Failed to set IPV6_TRANSPARENT: %v", err)
		syscall.Close(fd)
		return
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, IPV6_RECVORIGDSTADDR, 1); err != nil {
		log.Printf("Failed to set IPV6_RECVORIGDSTADDR: %v", err)
		syscall.Close(fd)
		return
	}
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)

	sockaddr := &syscall.SockaddrInet6{Port: udpProxyPort}
	if err := syscall.Bind(fd, sockaddr); err != nil {
		log.Printf("Failed to bind IPv6 UDP socket: %v", err)
		syscall.Close(fd)
		return
	}

	file := os.NewFile(uintptr(fd), "")
	conn, err := net.FilePacketConn(file)
	file.Close()
	if err != nil {
		log.Printf("Failed to convert IPv6 UDP socket: %v", err)
		return
	}
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		log.Printf("IPv6 UDP: not a UDPConn")
		return
	}
	logVerbose("IPv6 UDP TPROXY listening on [::]:%d", udpProxyPort)

	stop := make(chan struct{})
	udpV6StopChan = stop

	localConn := udpConn
	go func() {
		<-stop
		localConn.Close()
	}()

	buf := make([]byte, 65535)
	oob := make([]byte, 1024)
	for {
		n, oobn, flags, addr, err := udpConn.ReadMsgUDP(buf, oob)
		if err != nil {
			select {
			case <-stop:
				return
			default:
				logVerbose("IPv6 UDP read error: %v", err)
				continue
			}
		}
		if flags&syscall.MSG_TRUNC != 0 {
			continue
		}

		var origDst *net.UDPAddr
		cm, err := syscall.ParseSocketControlMessage(oob[:oobn])
		if err == nil {
			for _, m := range cm {
				if m.Header.Level == syscall.IPPROTO_IPV6 && m.Header.Type == IPV6_RECVORIGDSTADDR {
					var dst syscall.RawSockaddrInet6
					if uintptr(len(m.Data)) >= unsafe.Sizeof(dst) {
						copy((*[unsafe.Sizeof(dst)]byte)(unsafe.Pointer(&dst))[:], m.Data)
						port := int(dst.Port)
						port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)
						ip := net.IP(dst.Addr[:])
						origDst = &net.UDPAddr{IP: ip, Port: port}
					}
				}
			}
		}

		if origDst == nil {
			continue
		}

		go handleUDPPacket(udpConn, addr, origDst, buf[:n])
	}
}

const dnsFallbackMark = 0x2345

func addDNSFallbackExclusion() {
	iptCmd("iptables", "-t", "nat", "-I", "OUTPUT", "1",
		"-p", "udp", "--dport", "53",
		"-m", "mark", "--mark", fmt.Sprintf("0x%x", dnsFallbackMark),
		"-j", "RETURN").CombinedOutput()
}

func removeDNSFallbackExclusion() {
	iptCmd("iptables", "-t", "nat", "-D", "OUTPUT",
		"-p", "udp", "--dport", "53",
		"-m", "mark", "--mark", fmt.Sprintf("0x%x", dnsFallbackMark),
		"-j", "RETURN").CombinedOutput()
}

var fallbackPublicDNS = []string{"8.8.8.8", "1.1.1.1", "8.8.4.4"}

func queryFallbackDNS(domain string, qtype uint16) *DNSResponseMessage {
	markedDialer := &net.Dialer{
		Timeout: 2 * time.Second,
		Control: func(network, address string, conn syscall.RawConn) error {
			return conn.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, dnsFallbackMark)
			})
		},
	}

	tryServer := func(server string) *DNSResponseMessage {
		c := &dns.Client{Net: "udp", Timeout: 2 * time.Second, Dialer: markedDialer}
		msg := new(dns.Msg)
		msg.SetQuestion(domain, qtype)
		msg.RecursionDesired = true
		resp, _, err := c.Exchange(msg, net.JoinHostPort(server, "53"))
		if err != nil || resp == nil {
			return nil
		}
		result := &DNSResponseMessage{RCode: resp.Rcode}
		for _, rr := range resp.Answer {
			ans := DNSAnswer{Name: rr.Header().Name, Type: rr.Header().Rrtype, TTL: rr.Header().Ttl}
			switch v := rr.(type) {
			case *dns.A:
				ans.Data = v.A.String()
			case *dns.AAAA:
				ans.Data = v.AAAA.String()
			case *dns.CNAME:
				ans.Data = v.Target
			default:
				continue
			}
			result.Answers = append(result.Answers, ans)
		}
		if resp.Rcode == dns.RcodeSuccess && len(result.Answers) > 0 {
			return result
		}
		return nil
	}

	for _, server := range getSavedSystemDNSServers() {
		if r := tryServer(server); r != nil {
			return r
		}
	}

	for _, server := range fallbackPublicDNS {
		if r := tryServer(server); r != nil {
			return r
		}
	}
	return nil
}

var egressDefaultRouteGW string

var egressLocalSubnets []string

func getLinuxLocalSubnets() []string {
	result := []string{"127.0.0.0/8"}
	seen := map[string]bool{"127.0.0.0/8": true}
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				_, network, err := net.ParseCIDR(ipnet.String())
				if err == nil {
					s := network.String()
					if !seen[s] {
						seen[s] = true
						result = append(result, s)
					}
				}
			}
		}
	}
	return result
}

func findRoutableGateway() string {
	out, err := exec.Command("ip", "route", "show").CombinedOutput()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "via" && i+1 < len(fields) {
				if ip := net.ParseIP(fields[i+1]); ip != nil && !ip.IsLoopback() {
					return fields[i+1]
				}
			}
		}
	}
	return ""
}

func reloadDefaultEgressRules() error {

	iptCmd("iptables", "-t", "nat", "-D", "OUTPUT",
		"-p", "tcp", "!", "-d", "127.0.0.0/8",
		"-j", "REDIRECT", "--to-port", strconv.Itoa(proxyPort)).CombinedOutput()
	iptCmd("iptables", "-t", "mangle", "-D", "OUTPUT",
		"-p", "udp", "!", "-d", "127.0.0.0/8",
		"!", "--dport", "53", "!", "--dport", "123",
		"-j", "MARK", "--set-mark", "1").CombinedOutput()

	for _, subnet := range egressLocalSubnets {
		iptCmd("iptables", "-t", "nat", "-D", "OUTPUT",
			"-p", "tcp", "-d", subnet, "-j", "RETURN").CombinedOutput()
		iptCmd("iptables", "-t", "mangle", "-D", "OUTPUT",
			"-p", "udp", "-d", subnet, "-j", "RETURN").CombinedOutput()
	}
	egressLocalSubnets = nil

	if getDefaultEgressAgent() == "" {

		if egressDefaultRouteGW != "" {
			exec.Command("ip", "route", "del", "default", "via", egressDefaultRouteGW).CombinedOutput()
			egressDefaultRouteGW = ""
		}
		return nil
	}

	localSubnets := getLinuxLocalSubnets()
	for _, subnet := range localSubnets {
		iptCmd("iptables", "-t", "nat", "-A", "OUTPUT",
			"-p", "tcp", "-d", subnet, "-j", "RETURN").CombinedOutput()
		iptCmd("iptables", "-t", "mangle", "-A", "OUTPUT",
			"-p", "udp", "-d", subnet, "-j", "RETURN").CombinedOutput()
	}
	egressLocalSubnets = localSubnets

	if out, err := iptCmd("iptables", "-t", "nat", "-A", "OUTPUT",
		"-p", "tcp", "!", "-d", "127.0.0.0/8",
		"-j", "REDIRECT", "--to-port", strconv.Itoa(proxyPort)).CombinedOutput(); err != nil {
		return fmt.Errorf("iptables catch-all TCP: %v - %s", err, out)
	}

	if out, err := iptCmd("iptables", "-t", "mangle", "-A", "OUTPUT",
		"-p", "udp", "!", "-d", "127.0.0.0/8",
		"!", "--dport", "53", "!", "--dport", "123",
		"-j", "MARK", "--set-mark", "1").CombinedOutput(); err != nil {
		return fmt.Errorf("iptables catch-all UDP: %v - %s", err, out)
	}

	existing, _ := exec.Command("ip", "route", "show", "default").CombinedOutput()
	if len(strings.TrimSpace(string(existing))) == 0 {
		if gw := findRoutableGateway(); gw != "" {
			if out, err := exec.Command("ip", "route", "add", "default", "via", gw).CombinedOutput(); err == nil {
				egressDefaultRouteGW = gw
				log.Printf("[+] Added default route via %s for egress internet traffic", gw)
			} else {
				log.Printf("Warning: could not add default route via %s: %s", gw, out)
			}
		}
	}
	return nil
}

func queryEgressDNS(domain string, qtype uint16) *DNSResponseMessage {
	servers := []string{"8.8.8.8", "1.1.1.1", "8.8.4.4"}
	for _, server := range servers {
		c := &dns.Client{Net: "tcp", Timeout: 5 * time.Second}
		msg := new(dns.Msg)
		msg.SetQuestion(domain, qtype)
		msg.RecursionDesired = true
		resp, _, err := c.Exchange(msg, net.JoinHostPort(server, "53"))
		if err != nil || resp == nil {
			continue
		}
		result := &DNSResponseMessage{RCode: resp.Rcode}
		for _, rr := range resp.Answer {
			ans := DNSAnswer{Name: rr.Header().Name, Type: rr.Header().Rrtype, TTL: rr.Header().Ttl}
			switch v := rr.(type) {
			case *dns.A:
				ans.Data = v.A.String()
			case *dns.AAAA:
				ans.Data = v.AAAA.String()
			case *dns.CNAME:
				ans.Data = v.Target
			default:
				continue
			}
			result.Answers = append(result.Answers, ans)
		}
		if resp.Rcode == dns.RcodeSuccess && len(result.Answers) > 0 {
			return result
		}
	}
	return nil
}

func addDNSRedirectRule() error {
	addDNSFallbackExclusion()
	cmd := iptCmd("iptables", "-t", "nat", "-A", "OUTPUT",
		"-p", "udp", "--dport", "53",
		"-j", "REDIRECT", "--to-port", strconv.Itoa(dnsLocalPort))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add DNS redirect rule: %v - %s", err, out)
	}
	logVerbose("iptables: added DNS redirect (UDP 53 -> %d)", dnsLocalPort)
	return nil
}

func removeDNSRedirectRule() error {
	removeDNSFallbackExclusion()
	cmd := iptCmd("iptables", "-t", "nat", "-D", "OUTPUT",
		"-p", "udp", "--dport", "53",
		"-j", "REDIRECT", "--to-port", strconv.Itoa(dnsLocalPort))
	if out, err := cmd.CombinedOutput(); err != nil {
		if !strings.Contains(string(out), "No chain/target/match") {
			return fmt.Errorf("failed to remove DNS redirect rule: %v - %s", err, out)
		}
	}
	logVerbose("iptables: removed DNS redirect rule")
	return nil
}

func startDNSProxy() {
	if err := addDNSRedirectRule(); err != nil {
		log.Printf("Failed to add DNS redirect rule: %v", err)
		return
	}

	addr := fmt.Sprintf(":%d", dnsLocalPort)

	udpServer := &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: dns.HandlerFunc(handleDNSRequest),
	}
	dnsUDPServer = udpServer
	go func() {
		logVerbose("DNS proxy listening on UDP %s", addr)
		if err := udpServer.ListenAndServe(); err != nil {
			logVerbose("DNS UDP server error: %v", err)
		}
	}()

	tcpServer := &dns.Server{
		Addr:    addr,
		Net:     "tcp",
		Handler: dns.HandlerFunc(handleDNSRequest),
	}
	dnsTCPServer = tcpServer
	go func() {
		logVerbose("DNS proxy listening on TCP %s", addr)
		if err := tcpServer.ListenAndServe(); err != nil {
			logVerbose("DNS TCP server error: %v", err)
		}
	}()
}

func handleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		return
	}
	q := req.Question[0]

	servfail := func() {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
	}

	connLock.Lock()
	agents := make([]string, 0, len(connections))
	for id := range connections {
		agents = append(agents, id)
	}
	connLock.Unlock()

	if len(agents) == 0 {

		if fb := queryFallbackDNS(q.Name, q.Qtype); fb != nil {
			buildAndSendDNSReplyLinux(w, req, fb)
			return
		}
		if getDefaultEgressAgent() != "" {
			if result := queryEgressDNS(q.Name, q.Qtype); result != nil {
				buildAndSendDNSReplyLinux(w, req, result)
				return
			}
		}
		servfail()
		return
	}

	reqID := uint16(atomic.AddUint32(&nextDNSRequestID, 1) % 65536)
	respChan := make(chan *DNSResponseMessage, len(agents))
	pendingDNSRequests.Store(reqID, respChan)
	defer pendingDNSRequests.Delete(reqID)

	dnsReq := DNSRequestMessage{RequestID: reqID, Domain: q.Name, QType: q.Qtype}
	payload, _ := json.Marshal(dnsReq)

	sent := 0
	for _, id := range agents {
		msg := Message{Type: "dns_request", Payload: payload, TargetAgentID: id}
		if err := sendControlMessageToAgent(id, msg); err == nil {
			sent++
		}
	}
	if sent == 0 {
		servfail()
		return
	}

	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()

	var bestResponse *DNSResponseMessage
	received := 0
	for received < sent {
		select {
		case resp := <-respChan:
			received++
			if resp.RCode == dns.RcodeSuccess && len(resp.Answers) > 0 {
				bestResponse = resp
				goto respond
			}
			if bestResponse == nil {
				bestResponse = resp
			}
		case <-deadline.C:
			goto respond
		}
	}

respond:
	if bestResponse == nil || (bestResponse.RCode != dns.RcodeSuccess && len(bestResponse.Answers) == 0) {

		if fb := queryFallbackDNS(q.Name, q.Qtype); fb != nil {
			bestResponse = fb
		} else if getDefaultEgressAgent() != "" {
			if result := queryEgressDNS(q.Name, q.Qtype); result != nil {
				bestResponse = result
			}
		}
	}
	if bestResponse == nil {
		servfail()
		return
	}
	buildAndSendDNSReplyLinux(w, req, bestResponse)
}

func buildAndSendDNSReplyLinux(w dns.ResponseWriter, req *dns.Msg, bestResponse *DNSResponseMessage) {
	reply := new(dns.Msg)
	reply.SetReply(req)
	reply.Rcode = bestResponse.RCode
	for _, ans := range bestResponse.Answers {
		hdr := dns.RR_Header{
			Name:   ans.Name,
			Rrtype: ans.Type,
			Class:  dns.ClassINET,
			Ttl:    ans.TTL,
		}
		var rr dns.RR
		switch ans.Type {
		case dns.TypeA:
			rr = &dns.A{Hdr: hdr, A: net.ParseIP(ans.Data)}
		case dns.TypeAAAA:
			rr = &dns.AAAA{Hdr: hdr, AAAA: net.ParseIP(ans.Data)}
		case dns.TypeCNAME:
			rr = &dns.CNAME{Hdr: hdr, Target: ans.Data}
		}
		if rr != nil {
			reply.Answer = append(reply.Answer, rr)
		}
	}
	_ = w.WriteMsg(reply)
}

func stopDNSProxy() {
	done := make(chan struct{})
	go func() {
		if dnsUDPServer != nil {
			dnsUDPServer.Shutdown()
		}
		if dnsTCPServer != nil {
			dnsTCPServer.Shutdown()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		logVerbose("DNS server shutdown timed out, continuing")
	}
	removeDNSRedirectRule()
}

func startSocksProxy(agentID string, port int, username, password string) string {
	connLock.Lock()
	_, ok := connections[agentID]
	connLock.Unlock()
	if !ok {
		return "[-] Agent not found\n"
	}

	listenerID := "socks-" + uuid.New().String()[:8]

	pf := &PortForward{
		AgentListenPort:    port,
		ListenerID:         listenerID,
		DestinationAgentID: agentID,
		DestinationHost:    "",
		DestinationPort:    0,
	}
	connLock.Lock()
	portForwards[listenerID] = pf
	portForwardLookup[fmt.Sprintf("%s:%d", agentID, port)] = listenerID
	connLock.Unlock()

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		connLock.Lock()
		delete(portForwards, listenerID)
		delete(portForwardLookup, fmt.Sprintf("%s:%d", agentID, port))
		connLock.Unlock()
		return fmt.Sprintf("[-] Failed to bind :%d: %v\n", port, err)
	}

	socksMu.Lock()
	socksProxies[listenerID] = &SocksProxy{
		ListenerID:  listenerID,
		LocalPort:   port,
		AgentID:     agentID,
		Connections: 0,
		StartTime:   time.Now(),
		Username:    username,
		Password:    password,
	}
	socksListeners[listenerID] = ln
	socksMu.Unlock()

	go socks5Listener(ln, agentID, listenerID)

	if username != "" {
		return fmt.Sprintf("[+] SOCKS5 started on 127.0.0.1:%d → agent %s (id: %s, auth: %s)\n", port, agentID, listenerID, username)
	}
	return fmt.Sprintf("[+] SOCKS5 started on 127.0.0.1:%d → agent %s (id: %s, no auth)\n", port, agentID, listenerID)
}

func socks5Listener(ln net.Listener, agentID, listenerID string) {
	defer ln.Close()
	for {
		client, err := ln.Accept()
		if err != nil {
			continue
		}

		socksMu.Lock()
		sp := socksProxies[listenerID]
		sp.Connections++
		socksProxies[listenerID] = sp
		user := sp.Username
		pass := sp.Password
		socksMu.Unlock()

		go func(c net.Conn) {
			defer func() {
				socksMu.Lock()
				sp := socksProxies[listenerID]
				sp.Connections--
				socksProxies[listenerID] = sp
				socksMu.Unlock()
			}()
			handleSocks5Request(c, agentID, user, pass)
		}(client)
	}
}

func socks5Authenticate(client net.Conn, buf []byte, n int, username, password string) bool {
	if username == "" {
		client.Write([]byte{5, 0})
		return true
	}
	offersUserPass := false
	nMethods := int(buf[1])
	for i := 0; i < nMethods && 2+i < n; i++ {
		if buf[2+i] == 0x02 {
			offersUserPass = true
			break
		}
	}
	if !offersUserPass {
		client.Write([]byte{5, 0xFF})
		return false
	}
	client.Write([]byte{5, 0x02})
	n2, err := client.Read(buf)
	if err != nil || n2 < 3 || buf[0] != 0x01 {
		return false
	}
	uLen := int(buf[1])
	if n2 < 2+uLen+1 {
		return false
	}
	gotUser := string(buf[2 : 2+uLen])
	pLen := int(buf[2+uLen])
	if n2 < 3+uLen+pLen {
		return false
	}
	gotPass := string(buf[3+uLen : 3+uLen+pLen])
	if gotUser != username || gotPass != password {
		client.Write([]byte{0x01, 0x01})
		return false
	}
	client.Write([]byte{0x01, 0x00})
	return true
}

func socks5ParseAddress(client net.Conn, buf []byte, n int) (host string, port uint16, ok bool) {
	switch buf[3] {
	case 1:
		host = net.IP(buf[4:8]).String()
		port = binary.BigEndian.Uint16(buf[8:10])
		ok = true
	case 4:
		host = net.IP(buf[4:20]).String()
		port = binary.BigEndian.Uint16(buf[20:22])
		ok = true
	case 3:
		hostLen := int(buf[4])
		if n < 7+hostLen {
			return
		}
		host = string(buf[5 : 5+hostLen])
		port = binary.BigEndian.Uint16(buf[5+hostLen : 7+hostLen])
		ok = true
	default:
		client.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
	}
	return
}

func socks5DirectTunnel(client net.Conn, agentID, targetHost string, targetPort uint16, resolvedIP net.IP) bool {
	if resolvedIP != nil && routingTable.IsIPBlocked(resolvedIP) {
		logVerbose("SOCKS5: blocking connection to %s — subnet is disabled", targetHost)
		client.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
		return true
	}
	targetConn, err := net.DialTimeout("tcp", net.JoinHostPort(targetHost, fmt.Sprintf("%d", targetPort)), 10*time.Second)
	if err != nil {
		logVerbose("SOCKS5: direct dial to self‑target %s:%d failed: %v", targetHost, targetPort, err)
		client.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
		return true
	}
	defer targetConn.Close()
	reply := []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(reply[8:10], targetPort)
	client.Write(reply)
	go func() { io.Copy(targetConn, client); targetConn.Close() }()
	io.Copy(client, targetConn)
	logVerbose("SOCKS5 direct tunnel %s:%d → %s (self‑connection, via server routing)", targetHost, targetPort, agentID)
	return true
}

func socks5AgentTunnel(client net.Conn, agentID, routeAgentID, targetHost string, targetPort uint16) {
	connID := uuid.New().String()
	req := ConnectRequest{TargetHost: targetHost, TargetPort: int(targetPort), ConnID: connID, Protocol: "tcp"}
	payload, _ := json.Marshal(req)
	msg := Message{Type: "connect", Payload: payload, TargetAgentID: routeAgentID}
	if err := sendControlMessageToAgent(routeAgentID, msg); err != nil {
		logVerbose("Failed to send connect request to agent %s: %v", routeAgentID, err)
		client.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	responseChan := make(chan ConnectResponse, 1)
	respChanMap.Store(connID, responseChan)
	defer respChanMap.Delete(connID)
	select {
	case resp := <-responseChan:
		if !resp.Success {
			client.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
			logVerbose("Agent %s failed to connect to %s:%d: %s", routeAgentID, targetHost, targetPort, resp.Error)
			return
		}
	case <-time.After(10 * time.Second):
		client.Write([]byte{5, 6, 0, 1, 0, 0, 0, 0, 0, 0})
		logVerbose("Timeout waiting for agent %s to connect to %s:%d", routeAgentID, targetHost, targetPort)
		return
	}
	reply := []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(reply[8:10], targetPort)
	client.Write(reply)
	pendingConns.Store(connID, &pendingConn{conn: client, agentID: agentID})
	go func() {
		defer client.Close()
		buf := make([]byte, 8192)
		for {
			n, err := client.Read(buf)
			if err != nil {
				dataMsg := DataMessage{ConnID: connID, Close: true}
				payload, _ := json.Marshal(dataMsg)
				sendControlMessageToAgent(routeAgentID, Message{Type: "data", Payload: payload, TargetAgentID: routeAgentID})
				pendingConns.Delete(connID)
				return
			}
			dataMsg := DataMessage{ConnID: connID, Data: buf[:n]}
			payload, _ := json.Marshal(dataMsg)
			sendControlMessageToAgent(routeAgentID, Message{Type: "data", Payload: payload, TargetAgentID: routeAgentID})
		}
	}()
	logVerbose("SOCKS5 %s:%d → %s (via %s, conn %s)", targetHost, targetPort, routeAgentID, agentID, connID)
}

func handleSocks5Request(client net.Conn, agentID, username, password string) {
	defer client.Close()
	client.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer client.SetReadDeadline(time.Time{})

	buf := make([]byte, 258)
	n, err := client.Read(buf)
	if err != nil || n < 3 || buf[0] != 5 {
		return
	}
	if !socks5Authenticate(client, buf, n, username, password) {
		return
	}

	n, err = client.Read(buf)
	if err != nil || n < 10 || buf[0] != 5 || buf[1] != 1 {
		client.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}

	targetHost, targetPort, ok := socks5ParseAddress(client, buf, n)
	if !ok {
		return
	}

	routeAgentID := agentID
	resolvedIP := net.ParseIP(targetHost)
	if resolvedIP == nil {
		if addrs, err := net.LookupHost(targetHost); err == nil && len(addrs) > 0 {
			resolvedIP = net.ParseIP(addrs[0])
		}
	}
	if resolvedIP != nil {
		if ownerAgentID, found := routingTable.FindAgentForIP(resolvedIP); found {
			if ownerAgentID != agentID {
				routeAgentID = ownerAgentID
				logVerbose("SOCKS5: target %s owned by agent %s, routing directly instead of via egress %s", targetHost, ownerAgentID, agentID)
			} else {
				logVerbose("SOCKS5: target %s is on egress agent %s's own subnet — will connect directly from server", targetHost, agentID)
			}
		}
	}

	if routeAgentID == agentID {
		socks5DirectTunnel(client, agentID, targetHost, targetPort, resolvedIP)
		return
	}
	socks5AgentTunnel(client, agentID, routeAgentID, targetHost, targetPort)
}

func listSocksProxies(out *strings.Builder) {
	socksMu.Lock()
	defer socksMu.Unlock()

	fmt.Fprintln(out, "\nSOCKS5 Servers (Proxy Pivots):")
	fmt.Fprintln(out, "ID              Port  Agent        Conns  Uptime")
	fmt.Fprintln(out, strings.Repeat("-", 60))

	for id, proxy := range socksProxies {
		uptime := time.Since(proxy.StartTime).Truncate(time.Second).String()
		fmt.Fprintf(out, "%-14s %s  %-12s %d    %s\n",
			id,
			fmt.Sprintf(":%d", proxy.LocalPort),
			proxy.AgentID,
			proxy.Connections,
			uptime,
		)
	}
}

func stopSocksProxy(id string, out *strings.Builder) {
	connLock.Lock()
	pf, ok := portForwards[id]
	if !ok {
		connLock.Unlock()
		fmt.Fprintln(out, "SOCKS5 not found")
		return
	}
	agentID := pf.DestinationAgentID
	connLock.Unlock()

	socksMu.Lock()
	if ln, ok := socksListeners[id]; ok {
		ln.Close()
		delete(socksListeners, id)
	}
	delete(socksProxies, id)
	socksMu.Unlock()

	connLock.Lock()
	delete(portForwards, id)
	delete(portForwardLookup, fmt.Sprintf("%s:%d", agentID, pf.AgentListenPort))
	connLock.Unlock()

	stopMsg := StopAgentListenerMessage{ListenerID: id}
	payload, _ := json.Marshal(stopMsg)
	msg := Message{Type: "stop-agent-listener", Payload: payload, TargetAgentID: agentID}
	sendControlMessageToAgent(agentID, msg)

	fmt.Fprintf(out, " [+] SOCKS5 %s stopped\n", id)
}
func notifyShutdownSignals(c chan<- os.Signal) {
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
}

func addIcmpIptablesRule(subnet string) error {
	if isIPv6Subnet(subnet) {
		return nil
	}
	cmd := iptCmd("iptables", "-t", "mangle", "-A", "OUTPUT",
		"-d", subnet, "-p", "icmp", "--icmp-type", "echo-request",
		"-j", "MARK", "--set-mark", "1")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables ICMP MARK add failed: %v - %s", err, output)
	}
	logVerbose("iptables: added ICMP MARK for %s", subnet)
	return nil
}

func removeIcmpIptablesRule(subnet string) error {
	if isIPv6Subnet(subnet) {
		return nil
	}
	cmd := iptCmd("iptables", "-t", "mangle", "-D", "OUTPUT",
		"-d", subnet, "-p", "icmp", "--icmp-type", "echo-request",
		"-j", "MARK", "--set-mark", "1")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables ICMP MARK remove failed: %v - %s", err, output)
	}
	logVerbose("iptables: removed ICMP MARK for %s", subnet)
	return nil
}

func icmpChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func sendICMPReply(srcIP, dstIP net.IP, echoID, echoSeq uint16, payload []byte) {
	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	if src4 == nil || dst4 == nil {
		return
	}

	icmpMsg := make([]byte, 8+len(payload))
	icmpMsg[0] = 0
	icmpMsg[1] = 0
	binary.BigEndian.PutUint16(icmpMsg[4:6], echoID)
	binary.BigEndian.PutUint16(icmpMsg[6:8], echoSeq)
	copy(icmpMsg[8:], payload)
	cs := icmpChecksum(icmpMsg)
	binary.BigEndian.PutUint16(icmpMsg[2:4], cs)

	totalLen := 20 + len(icmpMsg)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[6] = 0x40
	pkt[8] = 64
	pkt[9] = 1
	copy(pkt[12:16], src4)
	copy(pkt[16:20], dst4)
	copy(pkt[20:], icmpMsg)
	cs16 := icmpChecksum(pkt[:20])
	binary.BigEndian.PutUint16(pkt[10:12], cs16)

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		logVerbose("sendICMPReply: create socket: %v", err)
		return
	}
	defer syscall.Close(fd)

	dst := &syscall.SockaddrInet4{}
	copy(dst.Addr[:], dst4)
	if err := syscall.Sendto(fd, pkt, 0, dst); err != nil {
		logVerbose("sendICMPReply: sendto: %v", err)
	}
}

func startICMPInterceptor() {
	c, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Printf("ICMP interceptor: failed to listen: %v", err)
		return
	}

	pc := ipv4.NewPacketConn(c)
	if err := pc.SetControlMessage(ipv4.FlagDst, true); err != nil {
		log.Printf("ICMP interceptor: SetControlMessage failed: %v", err)
		c.Close()
		return
	}

	stop := make(chan struct{})
	icmpInterceptStop = stop
	go func() {
		<-stop
		c.Close()
	}()

	logVerbose("ICMP interceptor started")
	buf := make([]byte, 1500)
	for {
		n, cm, srcAddr, err := pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-stop:
				return
			default:
				continue
			}
		}

		if n < 8 || buf[0] != 8 {
			continue
		}

		if cm == nil || cm.Dst == nil {
			continue
		}
		dstIP := cm.Dst
		agentID, ok := routingTable.FindAgentForIP(dstIP)
		if !ok {
			continue
		}

		srcIP := srcAddr.(*net.IPAddr).IP

		echoID := binary.BigEndian.Uint16(buf[4:6])
		echoSeq := binary.BigEndian.Uint16(buf[6:8])
		echoData := make([]byte, n-8)
		copy(echoData, buf[8:n])

		targetIP := dstIP.String()
		localSrc := srcIP
		localDst := net.IP(append([]byte{}, dstIP...))
		id, seq, data := echoID, echoSeq, echoData

		go func() {
			connID := fmt.Sprintf("icmp-%s-%d-%d", targetIP, id, seq)
			ch := make(chan ICMPProxyResponse, 1)
			pendingICMPProxy.Store(connID, ch)
			defer pendingICMPProxy.Delete(connID)

			req := ICMPProxyRequest{
				ConnID:    connID,
				Target:    targetIP,
				TimeoutMs: 2000,
			}
			payload, _ := json.Marshal(req)
			msg := Message{
				Type:          "icmp_proxy",
				Payload:       payload,
				TargetAgentID: agentID,
			}
			if err := sendControlMessageToAgent(agentID, msg); err != nil {
				return
			}

			select {
			case resp := <-ch:
				if resp.Success {
					sendICMPReply(localDst, localSrc, id, seq, data)
				}
			case <-time.After(3 * time.Second):
			}
		}()
	}
}

func setBSDLoopbackRouting()         {}
func getFreeBSDEpairGateway() string { return "" }

func stopProxies() {
	if tcpStopChan != nil {
		close(tcpStopChan)
		tcpStopChan = nil
	}
	if udpStopChan != nil {
		close(udpStopChan)
		udpStopChan = nil
	}
	if udpV6StopChan != nil {
		close(udpV6StopChan)
		udpV6StopChan = nil
	}
	if icmpInterceptStop != nil {
		close(icmpInterceptStop)
		icmpInterceptStop = nil
	}
}
