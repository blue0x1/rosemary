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

//go:build windows
// +build windows

package main

import (
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"github.com/miekg/dns"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// WinDivert.dll and WinDivert64.sys must be present at build time.
// Download from https://reqrypt.org/windivert.html (v2.x, 64-bit).
//
//go:embed WinDivert.dll
var winDivertDLLBytes []byte

//go:embed WinDivert64.sys
var winDivertSYSBytes []byte

const (
	WINDIVERT_LAYER_NETWORK = 0

	wdFlagOutbound = uint32(1 << 17)
	wdFlagLoopback = uint32(1 << 18)
)

var (
	proxyPort    = currentTCPPort
	udpProxyPort = currentUDPPort
	dnsLocalPort = currentDNSPort
)

var (
	tcpStopChan chan struct{}
	udpStopChan chan struct{}
	dnsStopChan chan struct{}
)

type WinDivertAddress struct {
	Timestamp int64
	Flags0    uint32
	Reserved2 uint32
	IfIdx     uint32
	SubIfIdx  uint32
	_         [56]byte
}

type origDstEntry struct {
	IP       net.IP
	Port     int
	SrcIP    net.IP
	IfIdx    uint32
	SubIfIdx uint32
}

type dnsQueryKey struct {
	ClientIP   uint32
	ClientPort uint16
	DNSID      uint16
}

type dnsQueryEntry struct {
	ClientIP net.IP
	DNSIP    net.IP
	DNSPort  int
	IfIdx    uint32
	SubIfIdx uint32
}

var winCurrentGateway string
var (
	_ = startTransparentProxy
	_ = startUDPProxy
	_ = addIptablesRule
	_ = removeIptablesRule
	_ = addUdpIptablesRule
	_ = removeUdpIptablesRule
	_ = sendUDPResponse

	winDivertLib                     *windows.LazyDLL
	procWinDivertOpen                *windows.LazyProc
	procWinDivertClose               *windows.LazyProc
	procWinDivertRecv                *windows.LazyProc
	procWinDivertSend                *windows.LazyProc
	procWinDivertHelperCalcChecksums *windows.LazyProc

	winDivertDir  string
	winDivertOnce sync.Once
	winDivertErr  error

	tcpOutHandle windows.Handle = windows.InvalidHandle
	tcpRetHandle windows.Handle = windows.InvalidHandle
	udpOutHandle windows.Handle = windows.InvalidHandle

	tcpOrigDstMap sync.Map

	tcpSubnetsMu  sync.RWMutex
	tcpSubnetList []*net.IPNet

	udpSubnetsMu  sync.RWMutex
	udpSubnetList []*net.IPNet

	tcpProxyOnce sync.Once
	udpProxyOnce sync.Once

	dnsUDPServer *dns.Server
	dnsTCPServer *dns.Server

	pendingDNSNAT      sync.Map
	dnsInterceptHandle windows.Handle = windows.InvalidHandle
)

func initWinDivert() error {
	winDivertOnce.Do(func() {
		dir, err := os.MkdirTemp("", "wd-*")
		if err != nil {
			winDivertErr = fmt.Errorf("WinDivert temp dir: %w", err)
			return
		}
		winDivertDir = dir

		if err := os.WriteFile(filepath.Join(dir, "WinDivert.dll"), winDivertDLLBytes, 0644); err != nil {
			winDivertErr = fmt.Errorf("extract WinDivert.dll: %w", err)
			return
		}
		if err := os.WriteFile(filepath.Join(dir, "WinDivert64.sys"), winDivertSYSBytes, 0644); err != nil {
			winDivertErr = fmt.Errorf("extract WinDivert64.sys: %w", err)
			return
		}

		if err := loadWinDivertDriver(filepath.Join(dir, "WinDivert64.sys")); err != nil {
			logVerbose("WinDivert driver note: %v", err)
		}

		dllPath := filepath.Join(dir, "WinDivert.dll")
		winDivertLib = windows.NewLazyDLL(dllPath)
		procWinDivertOpen = winDivertLib.NewProc("WinDivertOpen")
		procWinDivertClose = winDivertLib.NewProc("WinDivertClose")
		procWinDivertRecv = winDivertLib.NewProc("WinDivertRecv")
		procWinDivertSend = winDivertLib.NewProc("WinDivertSend")
		procWinDivertHelperCalcChecksums = winDivertLib.NewProc("WinDivertHelperCalcChecksums")
	})
	return winDivertErr
}

func loadWinDivertDriver(sysPath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.CreateService("WinDivert", sysPath, mgr.Config{
		ServiceType:  windows.SERVICE_KERNEL_DRIVER,
		StartType:    mgr.StartManual,
		ErrorControl: mgr.ErrorNormal,
	})
	if err != nil {

		s, err = m.OpenService("WinDivert")
		if err != nil {
			return fmt.Errorf("open existing WinDivert service: %w", err)
		}
		defer s.Close()
		if cfg, err := s.Config(); err == nil {
			cfg.BinaryPathName = sysPath
			_ = s.UpdateConfig(cfg)
		}
	} else {
		defer s.Close()
	}

	if err := s.Start(); err != nil {

		if errno, ok := err.(windows.Errno); ok && errno == 1056 {
			return nil
		}
		return err
	}
	return nil
}

func wdOpen(filter string, layer int, priority int16, flags uint64) (windows.Handle, error) {
	fp, err := windows.BytePtrFromString(filter)
	if err != nil {
		return windows.InvalidHandle, err
	}
	r, _, e := procWinDivertOpen.Call(
		uintptr(unsafe.Pointer(fp)),
		uintptr(layer),
		uintptr(priority),
		uintptr(flags),
	)
	if windows.Handle(r) == windows.InvalidHandle {
		return windows.InvalidHandle, fmt.Errorf("WinDivertOpen(%q): %w", filter, e)
	}
	return windows.Handle(r), nil
}

func wdClose(h windows.Handle) {
	if h != windows.InvalidHandle {
		procWinDivertClose.Call(uintptr(h))
	}
}

func wdRecv(h windows.Handle, buf []byte, addr *WinDivertAddress) (int, error) {
	var recvLen uint32
	r, _, e := procWinDivertRecv.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&recvLen)),
		uintptr(unsafe.Pointer(addr)),
	)
	if r == 0 {
		return 0, fmt.Errorf("WinDivertRecv: %w", e)
	}
	return int(recvLen), nil
}

func wdSend(h windows.Handle, pkt []byte, addr *WinDivertAddress) error {
	var sendLen uint32
	r, _, e := procWinDivertSend.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&pkt[0])),
		uintptr(len(pkt)),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(addr)),
	)
	if r == 0 {
		return fmt.Errorf("WinDivertSend: %w", e)
	}
	return nil
}

func wdCalcChecksums(pkt []byte, addr *WinDivertAddress) {
	procWinDivertHelperCalcChecksums.Call(
		uintptr(unsafe.Pointer(&pkt[0])),
		uintptr(len(pkt)),
		uintptr(unsafe.Pointer(addr)),
		0,
	)
}

func parseIPv4(pkt []byte) (src, dst net.IP, proto uint8, ihl int, ok bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return
	}
	ihl = int(pkt[0]&0x0F) * 4
	if len(pkt) < ihl {
		return
	}
	return net.IP(pkt[12:16]), net.IP(pkt[16:20]), pkt[9], ihl, true
}

func setIPv4Src(pkt []byte, ip net.IP) { copy(pkt[12:16], ip.To4()) }
func setIPv4Dst(pkt []byte, ip net.IP) { copy(pkt[16:20], ip.To4()) }

func getTCPPorts(pkt []byte, ihl int) (srcPort, dstPort uint16) {
	if len(pkt) < ihl+4 {
		return
	}
	return binary.BigEndian.Uint16(pkt[ihl:]), binary.BigEndian.Uint16(pkt[ihl+2:])
}

func setTCPSrcPort(pkt []byte, ihl int, port uint16) {
	binary.BigEndian.PutUint16(pkt[ihl:], port)
}

func setTCPDstPort(pkt []byte, ihl int, port uint16) {
	binary.BigEndian.PutUint16(pkt[ihl+2:], port)
}

func getUDPPorts(pkt []byte, ihl int) (srcPort, dstPort uint16) {
	if len(pkt) < ihl+4 {
		return
	}
	return binary.BigEndian.Uint16(pkt[ihl:]), binary.BigEndian.Uint16(pkt[ihl+2:])
}

func setUDPDstPort(pkt []byte, ihl int, port uint16) {
	binary.BigEndian.PutUint16(pkt[ihl+2:], port)
}

func ipInSubnets(ip net.IP, subnets []*net.IPNet) bool {
	for _, s := range subnets {
		if s.Contains(ip) {
			return true
		}
	}
	return false
}

func copyIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}

func startTransparentProxy() {
	if tcpStopChan != nil {
		close(tcpStopChan)
		tcpStopChan = nil
	}
	if tcpOutHandle != windows.InvalidHandle {
		wdClose(tcpOutHandle)
		tcpOutHandle = windows.InvalidHandle
	}
	if tcpRetHandle != windows.InvalidHandle {
		wdClose(tcpRetHandle)
		tcpRetHandle = windows.InvalidHandle
	}
	if proxyListener != nil {
		proxyListener.Close()
		proxyListener = nil
	}

	if err := initWinDivert(); err != nil {
		log.Printf(colorBoldRed+"[-]"+colorReset+" WinDivert init failed (TCP proxy): %v — run as Administrator", err)
		return
	}

	outH, err := wdOpen("outbound and not loopback and tcp", WINDIVERT_LAYER_NETWORK, 0, 0)
	if err != nil {
		logVerbose("WinDivert TCP outbound handle: %v", err)
		return
	}
	tcpOutHandle = outH

	retFilter := fmt.Sprintf("outbound and loopback and tcp and tcp.SrcPort == %d", proxyPort)
	retH, err := wdOpen(retFilter, WINDIVERT_LAYER_NETWORK, 1, 0)
	if err != nil {
		logVerbose("WinDivert TCP return handle: %v", err)
		wdClose(outH)
		tcpOutHandle = windows.InvalidHandle
		return
	}
	tcpRetHandle = retH

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", proxyPort))
	if err != nil {
		logVerbose("TCP proxy listener :%d: %v", proxyPort, err)
		wdClose(outH)
		wdClose(retH)
		tcpOutHandle = windows.InvalidHandle
		tcpRetHandle = windows.InvalidHandle
		return
	}
	proxyListener = ln
	logVerbose("Transparent TCP proxy listening on :%d", proxyPort)

	stop := make(chan struct{})
	tcpStopChan = stop

	go tcpOutboundLoop(outH, stop)
	go tcpReturnLoop(retH, stop)

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-stop:
				return
			default:
				logVerbose("TCP proxy accept: %v", err)
				continue
			}
		}
		go handleProxyConnection(conn)
	}
}

func tcpOutboundLoop(h windows.Handle, stop <-chan struct{}) {
	buf := make([]byte, 65536)
	loopback4 := net.ParseIP("127.0.0.1").To4()

	for {
		select {
		case <-stop:
			return
		default:
		}

		var addr WinDivertAddress
		n, err := wdRecv(h, buf, &addr)
		if err != nil {
			logVerbose("tcpOutboundLoop recv: %v", err)
			continue
		}

		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		src, dst, proto, ihl, ok := parseIPv4(pkt)
		if !ok || proto != 6 {
			wdSend(h, pkt, &addr)
			continue
		}

		tcpSubnetsMu.RLock()
		match := ipInSubnets(dst, tcpSubnetList)
		tcpSubnetsMu.RUnlock()

		srcPort, dstPort := getTCPPorts(pkt, ihl)

		if !match {
			// Allow catch-all egress: if a default egress agent is set and
			// the destination is not the server's own subnet or the control
			// port, route it through the proxy so handleProxyConnection can
			// forward it via the egress agent.
			if getDefaultEgressAgent() == "" || isServerLocalIP(dst) || int(dstPort) == currentHTTPPort {
				wdSend(h, pkt, &addr)
				continue
			}
		}

		tcpFlags := pkt[ihl+13]
		if tcpFlags&0x02 != 0 {
			tcpOrigDstMap.Store(srcPort, &origDstEntry{
				IP:       copyIP(dst),
				Port:     int(dstPort),
				SrcIP:    copyIP(src),
				IfIdx:    addr.IfIdx,
				SubIfIdx: addr.SubIfIdx,
			})
		}

		setIPv4Src(pkt, loopback4)
		setIPv4Dst(pkt, loopback4)
		setTCPDstPort(pkt, ihl, uint16(proxyPort))

		addr.Flags0 |= wdFlagLoopback
		wdCalcChecksums(pkt, &addr)

		if err := wdSend(h, pkt, &addr); err != nil {
			logVerbose("tcpOutboundLoop send: %v", err)
		}
	}
}

func tcpReturnLoop(h windows.Handle, stop <-chan struct{}) {
	buf := make([]byte, 65536)

	for {
		select {
		case <-stop:
			return
		default:
		}

		var addr WinDivertAddress
		n, err := wdRecv(h, buf, &addr)
		if err != nil {
			logVerbose("tcpReturnLoop recv: %v", err)
			continue
		}

		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		_, _, proto, ihl, ok := parseIPv4(pkt)
		if !ok || proto != 6 {
			wdSend(h, pkt, &addr)
			continue
		}

		_, dstPort := getTCPPorts(pkt, ihl)

		val, found := tcpOrigDstMap.Load(dstPort)
		if !found {
			wdSend(h, pkt, &addr)
			continue
		}
		entry := val.(*origDstEntry)

		setIPv4Src(pkt, entry.IP)
		setTCPSrcPort(pkt, ihl, uint16(entry.Port))
		setIPv4Dst(pkt, entry.SrcIP)

		addr.IfIdx = entry.IfIdx
		addr.SubIfIdx = entry.SubIfIdx
		addr.Flags0 &^= (wdFlagOutbound | wdFlagLoopback)
		wdCalcChecksums(pkt, &addr)

		if err := wdSend(h, pkt, &addr); err != nil {
			logVerbose("tcpReturnLoop send: %v", err)
		}
	}
}

func getOriginalDest(conn net.Conn) (net.IP, int, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, 0, fmt.Errorf("not a *net.TCPConn")
	}
	remote, ok := tcpConn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return nil, 0, fmt.Errorf("unexpected remote addr type")
	}
	srcPort := uint16(remote.Port)
	val, found := tcpOrigDstMap.Load(srcPort)
	if !found {
		return nil, 0, fmt.Errorf("no original destination for port %d", srcPort)
	}
	e := val.(*origDstEntry)
	return e.IP, e.Port, nil
}

func handleProxyConnection(localConn net.Conn) {
	dstIP, dstPort, err := getOriginalDest(localConn)
	if err != nil {
		localConn.Close()
		logVerbose("handleProxyConnection: %v", err)
		return
	}

	clientPort := uint16(localConn.RemoteAddr().(*net.TCPAddr).Port)

	// Declare map cleanup BEFORE Close (LIFO: runs AFTER Close).
	// tcpReturnLoop must be able to rewrite the final RST/FIN back to the
	// original client IP; deleting the NAT entry too early means the RST
	// goes out as loopback and the caller never sees it — causing timeouts.
	// A short-lived timer gives WinDivert time to process the closing packet.
	defer time.AfterFunc(3*time.Second, func() { tcpOrigDstMap.Delete(clientPort) })
	defer localConn.Close() // runs first (LIFO: declared last)

	agentID, ok := routingTable.FindAgentForIP(dstIP)
	if !ok {
		egress := getDefaultEgressAgent()
		if egress == "" || isServerLocalIP(dstIP) {
			logVerbose("No agent for IP %s", dstIP)
			return
		}
		agentID = egress
	}

	connID := uuid.New().String()

	// Register response channel before sending connect so we don't miss the reply.
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
		logVerbose("connect request to agent %s: %v", agentID, err)
		return
	}

	// Wait for agent to confirm the target connection.
	resetConn := func() {
		if tc, ok := localConn.(*net.TCPConn); ok {
			tc.SetLinger(0)
		}
	}
	select {
	case resp := <-responseChan:
		if !resp.Success {
			logVerbose("agent %s: connect to %s:%d failed: %s", agentID, dstIP, dstPort, resp.Error)
			resetConn()
			return
		}
	case <-time.After(10 * time.Second):
		logVerbose("timeout waiting for connect_response for %s:%d", dstIP, dstPort)
		resetConn()
		return
	}

	pendingConns.Store(connID, &pendingConn{conn: localConn, agentID: agentID})
	defer pendingConns.Delete(connID)

	buf := make([]byte, 32*1024)
	for {
		localConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, err := localConn.Read(buf)
		if err != nil {
			closeMsg := DataMessage{ConnID: connID, Close: true}
			p, _ := json.Marshal(closeMsg)
			sendControlMessageToAgent(agentID, Message{
				Type:          "data",
				Payload:       p,
				TargetAgentID: agentID,
			})
			return
		}
		dataMsg := DataMessage{ConnID: connID, Data: buf[:n]}
		p, _ := json.Marshal(dataMsg)
		if err := sendControlMessageToAgent(agentID, Message{
			Type:          "data",
			Payload:       p,
			TargetAgentID: agentID,
		}); err != nil {
			logVerbose("relay data to agent: %v", err)
			return
		}
	}
}

func startUDPProxy() {
	if udpStopChan != nil {
		close(udpStopChan)
		udpStopChan = nil
	}
	if udpOutHandle != windows.InvalidHandle {
		wdClose(udpOutHandle)
		udpOutHandle = windows.InvalidHandle
	}

	if err := initWinDivert(); err != nil {
		log.Printf(colorBoldRed+"[-]"+colorReset+" WinDivert init failed (UDP proxy): %v — run as Administrator", err)
		return
	}

	h, err := wdOpen("outbound and not loopback and udp", WINDIVERT_LAYER_NETWORK, 0, 0)
	if err != nil {
		logVerbose("WinDivert UDP handle: %v", err)
		return
	}
	udpOutHandle = h
	logVerbose("Transparent UDP proxy running on port %d via WinDivert", udpProxyPort)

	stop := make(chan struct{})
	udpStopChan = stop

	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Second):
				cleanupUDP()
			}
		}
	}()

	buf := make([]byte, 65536)
	for {
		select {
		case <-stop:
			return
		default:
		}

		var addr WinDivertAddress
		n, err := wdRecv(h, buf, &addr)
		if err != nil {
			select {
			case <-stop:
				return
			default:
				logVerbose("UDP recv: %v", err)
				continue
			}
		}

		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		_, dst, proto, ihl, ok := parseIPv4(pkt)
		if !ok || proto != 17 {
			wdSend(h, pkt, &addr)
			continue
		}

		udpSubnetsMu.RLock()
		match := ipInSubnets(dst, udpSubnetList)
		udpSubnetsMu.RUnlock()

		srcPort, dstPort := getUDPPorts(pkt, ihl)

		if !match {
			// Allow catch-all egress for UDP (exclude port 53 — DNS is
			// handled by the dedicated DNS intercept handle).
			if getDefaultEgressAgent() == "" || isServerLocalIP(dst) || dstPort == 53 {
				wdSend(h, pkt, &addr)
				continue
			}
		}

		srcIP := copyIP(net.IP(pkt[12:16]))
		dstIPCopy := copyIP(dst)

		clientAddr := &net.UDPAddr{IP: srcIP, Port: int(srcPort)}
		origDstAddr := &net.UDPAddr{IP: dstIPCopy, Port: int(dstPort)}

		payload := make([]byte, n-ihl-8)
		copy(payload, pkt[ihl+8:])

		go handleUDPPacket(nil, clientAddr, origDstAddr, payload)
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

func handleUDPPacket(_ *net.UDPConn, clientAddr *net.UDPAddr, origDst *net.UDPAddr, data []byte) {
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
		pendingUDPConns.Store(sessionKey, session)
		pendingUDPConns.Store(connID, session)

		req := ConnectRequest{
			TargetHost: origDst.IP.String(),
			TargetPort: origDst.Port,
			ConnID:     connID,
			Protocol:   "udp",
		}
		p, _ := json.Marshal(req)
		if err := sendControlMessageToAgent(agentID, Message{
			Type:          "connect",
			Payload:       p,
			TargetAgentID: agentID,
		}); err != nil {
			logVerbose("UDP connect to agent %s: %v", agentID, err)
			pendingUDPConns.Delete(sessionKey)
			pendingUDPConns.Delete(connID)
			return
		}
	}

	p, _ := json.Marshal(DataMessage{ConnID: session.connID, Data: data})
	if err := sendControlMessageToAgent(agentID, Message{
		Type:          "data",
		Payload:       p,
		TargetAgentID: agentID,
	}); err != nil {
		logVerbose("UDP data to agent: %v", err)
	}
	session.expire = time.Now().Add(udpTimeout)
}

func sendUDPResponse(clientAddr *net.UDPAddr, sourceIP net.IP, sourcePort int, data []byte) {
	h := udpOutHandle
	if h == windows.InvalidHandle {
		h = tcpOutHandle
	}
	if h == windows.InvalidHandle {
		logVerbose("sendUDPResponse: no WinDivert handle available")
		return
	}

	src4 := sourceIP.To4()
	dst4 := clientAddr.IP.To4()
	if src4 == nil || dst4 == nil {
		sendUDPResponse6(clientAddr, sourceIP, sourcePort, data)
		return
	}

	udpLen := 8 + len(data)
	ipLen := 20 + udpLen
	pkt := make([]byte, ipLen)

	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(ipLen))
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], src4)
	copy(pkt[16:20], dst4)

	binary.BigEndian.PutUint16(pkt[20:], uint16(sourcePort))
	binary.BigEndian.PutUint16(pkt[22:], uint16(clientAddr.Port))
	binary.BigEndian.PutUint16(pkt[24:], uint16(udpLen))
	copy(pkt[28:], data)

	var addr WinDivertAddress
	addr.Flags0 = 0
	wdCalcChecksums(pkt, &addr)

	if err := wdSend(h, pkt, &addr); err != nil {
		logVerbose("sendUDPResponse inject: %v", err)
	}
}

func sendUDPResponse6(clientAddr *net.UDPAddr, sourceIP net.IP, sourcePort int, data []byte) {
	h := udpOutHandle
	if h == windows.InvalidHandle {
		h = tcpOutHandle
	}
	if h == windows.InvalidHandle {
		logVerbose("sendUDPResponse6: no WinDivert handle available")
		return
	}

	src16 := sourceIP.To16()
	dst16 := clientAddr.IP.To16()
	if src16 == nil || dst16 == nil {
		logVerbose("sendUDPResponse6: invalid IPv6 address")
		return
	}

	udpPayloadLen := 8 + len(data)
	pkt := make([]byte, 40+udpPayloadLen)

	pkt[0] = 0x60
	pkt[1] = 0x00
	pkt[2] = 0x00
	pkt[3] = 0x00
	binary.BigEndian.PutUint16(pkt[4:6], uint16(udpPayloadLen))
	pkt[6] = 17
	pkt[7] = 64
	copy(pkt[8:24], src16)
	copy(pkt[24:40], dst16)

	binary.BigEndian.PutUint16(pkt[40:42], uint16(sourcePort))
	binary.BigEndian.PutUint16(pkt[42:44], uint16(clientAddr.Port))
	binary.BigEndian.PutUint16(pkt[44:46], uint16(udpPayloadLen))

	copy(pkt[48:], data)

	var addr WinDivertAddress
	addr.Flags0 = 0
	wdCalcChecksums(pkt, &addr)

	if err := wdSend(h, pkt, &addr); err != nil {
		logVerbose("sendUDPResponse6 inject: %v", err)
	}
}

// ── Windows route management ──────────────────────────────────────────────────
//
// Without explicit routes, Windows never generates IP packets for subnets that
// are not in its routing table.  WinDivert only intercepts packets that the
// kernel has already decided to send; if there's no route (e.g. no default
// gateway), the connect() call fails before any packet is produced.
//
// We work around this by adding on-link routes for every registered agent
// subnet via the primary non-loopback interface.  WinDivert then intercepts
// the outbound packet before it hits the wire and redirects it to the proxy.

var (
	winRoutesMu     sync.Mutex
	winSubnetRoutes = map[string]struct{}{} // CIDRs we own
	winEgressRouted bool
)

// winPrimaryIface returns the name of the first non-loopback, non-link-local
// interface that has an IPv4 address.
func winPrimaryIface() string {
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				ip4 := ipnet.IP.To4()
				if ip4 != nil && !ip4.IsLoopback() && !ip4.IsLinkLocalUnicast() {
					return iface.Name
				}
			}
		}
	}
	return ""
}

func addWinRoute(cidr string, gw string) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return
	}
	mask := net.IP(ipNet.Mask).String()
	if gw == "" {
		logVerbose("addWinRoute: no gateway for %s, skipping", cidr)
		return
	}
	cmd := exec.Command("route", "ADD", ipNet.IP.String(), "MASK", mask, gw, "METRIC", "500")
	out, err := cmd.CombinedOutput()
	if err != nil {
		logVerbose("addWinRoute failed: %v - %s", err, strings.TrimSpace(string(out)))
		return
	}
	logVerbose("WinDivert: TCP intercept added for %s → :%d via %s", cidr, proxyPort, gw)
}

func winDetectGateway() string {
	out, err := exec.Command("route", "print", "-4").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			// Look for default route 0.0.0.0
			if len(fields) >= 3 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
				if ip := net.ParseIP(fields[2]); ip != nil && !ip.IsLoopback() {
					return fields[2]
				}
			}
		}
		// No default route — pick the first real gateway from any route
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				gw := net.ParseIP(fields[2])
				if gw != nil && !gw.IsLoopback() && fields[2] != "On-link" {
					return fields[2]
				}
			}
		}
	}
	return ""
}

func delWinRoute(cidr string) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return
	}
	mask := net.IP(ipNet.Mask).String()
	exec.Command("route", "DELETE", ipNet.IP.String(), "MASK", mask).Run()
}

func addIptablesRule(subnet string, gw string) error {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return fmt.Errorf("addIptablesRule: invalid CIDR %q: %w", subnet, err)
	}
	tcpSubnetsMu.Lock()
	tcpSubnetList = append(tcpSubnetList, ipNet)
	tcpSubnetsMu.Unlock()
	winRoutesMu.Lock()
	if _, exists := winSubnetRoutes[subnet]; !exists {
		addWinRoute(ipNet.String(), gw)
		winSubnetRoutes[subnet] = struct{}{}
	}
	winRoutesMu.Unlock()
	logVerbose("WinDivert: TCP intercept added for %s → :%d", subnet, proxyPort)
	return nil
}

func removeIptablesRule(subnet string) error {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return fmt.Errorf("removeIptablesRule: invalid CIDR %q: %w", subnet, err)
	}
	tcpSubnetsMu.Lock()
	defer tcpSubnetsMu.Unlock()
	for i, s := range tcpSubnetList {
		if s.String() == ipNet.String() {
			tcpSubnetList = append(tcpSubnetList[:i], tcpSubnetList[i+1:]...)
			break
		}
	}

	winRoutesMu.Lock()
	if _, exists := winSubnetRoutes[subnet]; exists {
		delWinRoute(ipNet.String())
		delete(winSubnetRoutes, subnet)
	}
	winRoutesMu.Unlock()

	logVerbose("WinDivert: TCP intercept removed for %s", subnet)
	return nil
}

func addUdpIptablesRule(subnet string) error {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return fmt.Errorf("addUdpIptablesRule: invalid CIDR %q: %w", subnet, err)
	}
	udpSubnetsMu.Lock()
	udpSubnetList = append(udpSubnetList, ipNet)
	udpSubnetsMu.Unlock()
	// Route is managed by addIptablesRule (same subnet, no duplicate needed).
	logVerbose("WinDivert: UDP intercept added for %s → :%d", subnet, udpProxyPort)
	return nil
}

func removeUdpIptablesRule(subnet string) error {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return fmt.Errorf("removeUdpIptablesRule: invalid CIDR %q: %w", subnet, err)
	}
	udpSubnetsMu.Lock()
	defer udpSubnetsMu.Unlock()
	for i, s := range udpSubnetList {
		if s.String() == ipNet.String() {
			udpSubnetList = append(udpSubnetList[:i], udpSubnetList[i+1:]...)
			logVerbose("WinDivert: UDP intercept removed for %s", subnet)
			return nil
		}
	}
	return fmt.Errorf("removeUdpIptablesRule: subnet %s not found", subnet)
}

func startDNSProxy() {
	if dnsStopChan != nil {
		close(dnsStopChan)
		dnsStopChan = nil
	}
	if dnsUDPServer != nil {
		dnsUDPServer.Shutdown()
		dnsUDPServer = nil
	}
	if dnsTCPServer != nil {
		dnsTCPServer.Shutdown()
		dnsTCPServer = nil
	}
	if dnsInterceptHandle != windows.InvalidHandle {
		wdClose(dnsInterceptHandle)
		dnsInterceptHandle = windows.InvalidHandle
	}

	if err := initWinDivert(); err != nil {
		log.Printf(colorBoldRed+"[-]"+colorReset+" WinDivert init failed (DNS proxy): %v — run as Administrator", err)
		return
	}

	stop := make(chan struct{})
	dnsStopChan = stop

	go func() {
		filter := "outbound and not loopback and udp and udp.DstPort == 53"
		h, err := wdOpen(filter, WINDIVERT_LAYER_NETWORK, 2, 0)
		if err != nil {
			logVerbose("WinDivert DNS intercept handle: %v", err)
			return
		}
		dnsInterceptHandle = h
		defer wdClose(h)

		loopback4 := net.ParseIP("127.0.0.1").To4()
		buf := make([]byte, 65536)
		logVerbose("DNS intercept: UDP :53 → :%d", dnsLocalPort)

		for {
			select {
			case <-stop:
				return
			default:
			}

			var addr WinDivertAddress
			n, err := wdRecv(h, buf, &addr)
			if err != nil {
				logVerbose("DNS intercept recv: %v", err)
				continue
			}

			pkt := make([]byte, n)
			copy(pkt, buf[:n])

			src, dst, proto, ihl, ok := parseIPv4(pkt)
			if !ok || proto != 17 {
				wdSend(h, pkt, &addr)
				continue
			}

			srcPort, dstPort := getUDPPorts(pkt, ihl)
			if dstPort != 53 {
				wdSend(h, pkt, &addr)
				continue
			}

			if len(pkt) < ihl+8+2 {
				wdSend(h, pkt, &addr)
				continue
			}
			dnsID := binary.BigEndian.Uint16(pkt[ihl+8 : ihl+10])

			// Key must use 127.0.0.1 as ClientIP because we rewrite the
			// source address to loopback before injecting; handleDNSRequest
			// will see w.RemoteAddr() == 127.0.0.1 and look up the same key.
			key := dnsQueryKey{
				ClientIP:   binary.BigEndian.Uint32(loopback4),
				ClientPort: srcPort,
				DNSID:      dnsID,
			}
			pendingDNSNAT.Store(key, &dnsQueryEntry{
				ClientIP: copyIP(src), // original client — used for the reply
				DNSIP:    copyIP(dst), // original DNS server — used as reply source
				DNSPort:  int(dstPort),
				IfIdx:    addr.IfIdx,
				SubIfIdx: addr.SubIfIdx,
			})

			setIPv4Src(pkt, loopback4)
			setIPv4Dst(pkt, loopback4)
			setUDPDstPort(pkt, ihl, uint16(dnsLocalPort))

			addr.Flags0 |= wdFlagLoopback
			wdCalcChecksums(pkt, &addr)
			wdSend(h, pkt, &addr)
		}
	}()

	addr := fmt.Sprintf(":%d", dnsLocalPort)

	udpSrv := &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: dns.HandlerFunc(handleDNSRequest),
	}
	dnsUDPServer = udpSrv
	go func() {
		logVerbose("DNS proxy UDP listening on %s", addr)
		if err := udpSrv.ListenAndServe(); err != nil {
			logVerbose("DNS UDP server: %v", err)
		}
	}()

	tcpSrv := &dns.Server{
		Addr:    addr,
		Net:     "tcp",
		Handler: dns.HandlerFunc(handleDNSRequest),
	}
	dnsTCPServer = tcpSrv
	go func() {
		logVerbose("DNS proxy TCP listening on %s", addr)
		if err := tcpSrv.ListenAndServe(); err != nil {
			logVerbose("DNS TCP server: %v", err)
		}
	}()
}

func stopDNSProxy() {
	if dnsStopChan != nil {
		close(dnsStopChan)
		dnsStopChan = nil
	}
	if dnsUDPServer != nil {
		dnsUDPServer.Shutdown()
		dnsUDPServer = nil
	}
	if dnsTCPServer != nil {
		dnsTCPServer.Shutdown()
		dnsTCPServer = nil
	}
	if dnsInterceptHandle != windows.InvalidHandle {
		wdClose(dnsInterceptHandle)
		dnsInterceptHandle = windows.InvalidHandle
	}
}

func sendDNSResponseWithIf(clientAddr *net.UDPAddr, sourceIP net.IP, sourcePort int, ifIdx, subIfIdx uint32, data []byte) {
	h := dnsInterceptHandle
	if h == windows.InvalidHandle {
		h = udpOutHandle
	}
	if h == windows.InvalidHandle {
		h = tcpOutHandle
	}
	if h == windows.InvalidHandle {
		logVerbose("sendDNSResponseWithIf: no WinDivert handle available")
		return
	}

	src4 := sourceIP.To4()
	dst4 := clientAddr.IP.To4()
	if src4 == nil || dst4 == nil {
		return
	}

	udpLen := 8 + len(data)
	ipLen := 20 + udpLen
	pkt := make([]byte, ipLen)

	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(ipLen))
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], src4)
	copy(pkt[16:20], dst4)

	binary.BigEndian.PutUint16(pkt[20:], uint16(sourcePort))
	binary.BigEndian.PutUint16(pkt[22:], uint16(clientAddr.Port))
	binary.BigEndian.PutUint16(pkt[24:], uint16(udpLen))
	copy(pkt[28:], data)

	var addr WinDivertAddress
	addr.Flags0 = 0
	addr.IfIdx = ifIdx
	addr.SubIfIdx = subIfIdx
	wdCalcChecksums(pkt, &addr)

	if err := wdSend(h, pkt, &addr); err != nil {
		logVerbose("sendDNSResponseWithIf inject: %v", err)
	}
}

func handleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		return
	}
	q := req.Question[0]

	connLock.Lock()
	agents := make([]string, 0, len(connections))
	for id := range connections {
		agents = append(agents, id)
	}
	connLock.Unlock()

	servfail := func() {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		w.WriteMsg(m)
	}

	if len(agents) == 0 {
		servfail()
		return
	}

	reqID := uint16(atomic.AddUint32(&nextDNSRequestID, 1) % 65536)
	respChan := make(chan *DNSResponseMessage, len(agents))
	pendingDNSRequests.Store(reqID, respChan)
	defer pendingDNSRequests.Delete(reqID)

	dnsReq := DNSRequestMessage{RequestID: reqID, Domain: q.Name, QType: q.Qtype}
	p, _ := json.Marshal(dnsReq)

	sent := 0
	for _, id := range agents {
		if err := sendControlMessageToAgent(id, Message{
			Type:          "dns_request",
			Payload:       p,
			TargetAgentID: id,
		}); err == nil {
			sent++
		}
	}
	if sent == 0 {
		servfail()
		return
	}

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	var resp *DNSResponseMessage
	received := 0
	for received < sent {
		select {
		case r := <-respChan:
			received++
			if r.RCode == dns.RcodeSuccess && len(r.Answers) > 0 {
				resp = r
				goto got
			}
			if resp == nil {
				resp = r
			}
		case <-timer.C:
			goto got
		}
	}
got:
	if resp == nil {
		servfail()
		return
	}

	reply := new(dns.Msg)
	reply.SetReply(req)
	reply.Rcode = resp.RCode
	for _, ans := range resp.Answers {
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

	if udpAddr, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		loopback4 := net.IPv4(127, 0, 0, 1)
		key := dnsQueryKey{
			ClientIP:   binary.BigEndian.Uint32(loopback4.To4()),
			ClientPort: uint16(udpAddr.Port),
			DNSID:      req.Id,
		}
		val, found := pendingDNSNAT.Load(key)
		if !found {
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeServerFailure)
			w.WriteMsg(m)
			return
		}
		pendingDNSNAT.Delete(key)

		entry := val.(*dnsQueryEntry)
		raw, err := reply.Pack()
		if err != nil {
			logVerbose("DNS: pack error: %v", err)
			return
		}
		sendDNSResponseWithIf(&net.UDPAddr{IP: entry.ClientIP, Port: int(key.ClientPort)},
			entry.DNSIP, entry.DNSPort, entry.IfIdx, entry.SubIfIdx, raw)
	} else {
		w.WriteMsg(reply)
	}
}

// ── DNS redirect stubs (WinDivert intercept handles this) ─

func addDNSRedirectRule() error    { return nil }
func removeDNSRedirectRule() error { return nil }

func unloadWinDivertDriver() {
	wdClose(tcpOutHandle)
	wdClose(tcpRetHandle)
	wdClose(udpOutHandle)
	wdClose(dnsInterceptHandle)
	tcpOutHandle = windows.InvalidHandle
	tcpRetHandle = windows.InvalidHandle
	udpOutHandle = windows.InvalidHandle
	dnsInterceptHandle = windows.InvalidHandle

	m, err := mgr.Connect()
	if err != nil {
		return
	}
	defer m.Disconnect()
	s, err := m.OpenService("WinDivert")
	if err != nil {
		return
	}
	defer s.Close()
	s.Control(svc.Stop)
	s.Delete()

	if winDivertDir != "" {
		os.RemoveAll(winDivertDir)
		winDivertDir = ""
	}
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
	if err := sendControlMessageToAgent(routeAgentID, Message{Type: "connect", Payload: payload, TargetAgentID: routeAgentID}); err != nil {
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
	done := make(chan struct{})
	defer close(done)
	go func() {
		buf := make([]byte, 8192)
		for {
			select {
			case <-done:
				return
			default:
				client.SetReadDeadline(time.Now().Add(30 * time.Second))
				n, err := client.Read(buf)
				if err != nil {
					if err != io.EOF {
						logVerbose("Client read error: %v", err)
					}
					dataMsg := DataMessage{ConnID: connID, Close: true}
					payload, _ := json.Marshal(dataMsg)
					sendControlMessageToAgent(routeAgentID, Message{Type: "data", Payload: payload, TargetAgentID: routeAgentID})
					pendingConns.Delete(connID)
					return
				}
				if n > 0 {
					dataMsg := DataMessage{ConnID: connID, Data: buf[:n]}
					payload, _ := json.Marshal(dataMsg)
					if err := sendControlMessageToAgent(routeAgentID, Message{Type: "data", Payload: payload, TargetAgentID: routeAgentID}); err != nil {
						logVerbose("Failed to send data to agent: %v", err)
						return
					}
				}
			}
		}
	}()
	logVerbose("SOCKS5 %s:%d → %s (via %s, conn %s)", targetHost, targetPort, routeAgentID, agentID, connID)
	<-done
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
	socksMu.Lock()
	if ln, ok := socksListeners[id]; ok {
		ln.Close()
		delete(socksListeners, id)
	}
	socksMu.Unlock()

	connLock.Lock()
	pf, ok := portForwards[id]
	if !ok {
		connLock.Unlock()
		fmt.Fprintln(out, "SOCKS5 not found")
		return
	}
	agentID := pf.DestinationAgentID

	delete(portForwards, id)
	delete(portForwardLookup, fmt.Sprintf("%s:%d", agentID, pf.AgentListenPort))

	socksMu.Lock()
	delete(socksProxies, id)
	socksMu.Unlock()

	connLock.Unlock()

	stopMsg := StopAgentListenerMessage{ListenerID: id}
	payload, _ := json.Marshal(stopMsg)
	msg := Message{Type: "stop-agent-listener", Payload: payload, TargetAgentID: agentID}
	sendControlMessageToAgent(agentID, msg)

	fmt.Fprintf(out, " [+] SOCKS5 %s stopped\n", id)
}

func notifyShutdownSignals(c chan<- os.Signal) {
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	setConsoleCtrlHandler := kernel32.NewProc("SetConsoleCtrlHandler")

	cb := windows.NewCallback(func(ctrlType uint32) uintptr {
		if ctrlType == 0 || ctrlType == 1 || ctrlType == 2 {
			log.Println("Console control event received, exiting...")
			select {
			case c <- os.Interrupt:
			default:
			}
			go func() {
				time.Sleep(3 * time.Second)
				os.Exit(1)
			}()
			return 1
		}
		return 0
	})
	setConsoleCtrlHandler.Call(cb, 1)
}

func setBSDLoopbackRouting()                                      {}            // no-op on Windows
func getFreeBSDEpairGateway() string                              { return "" } // no-op on Windows
func sendUDPPortUnreachable(clientIP net.IP, target *net.UDPAddr) {}            // no-op on Windows

func addIcmpIptablesRule(subnet string) error    { return nil }
func removeIcmpIptablesRule(subnet string) error { return nil }
func startICMPInterceptor()                      {}
func stopProxies() {
	// Remove all Windows routes we added so the routing table is clean on exit.
	winRoutesMu.Lock()
	defer winRoutesMu.Unlock()
	for cidr := range winSubnetRoutes {
		_, ipNet, _ := net.ParseCIDR(cidr)
		if ipNet != nil {
			delWinRoute(ipNet.String())
		}
		delete(winSubnetRoutes, cidr)
	}
	if winEgressRouted {
		delWinRoute("0.0.0.0/0")
		winEgressRouted = false
	}
}

func reloadDefaultEgressRules() error {

	winRoutesMu.Lock()
	had := winEgressRouted
	winRoutesMu.Unlock()
	if had {
		delWinRoute("0.0.0.0/0")
		winRoutesMu.Lock()
		winEgressRouted = false
		winRoutesMu.Unlock()
	}
	if getDefaultEgressAgent() == "" {
		return nil
	}
	gw := winCurrentGateway
	if gw == "" {

		out, err := exec.Command("route", "print", "-4").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					if ip := net.ParseIP(fields[2]); ip != nil && !ip.IsLoopback() && fields[2] != "On-link" {
						gw = fields[2]
						break
					}
				}
			}
		}
	}
	if gw == "" {
		logVerbose("reloadDefaultEgressRules: no gateway available, skipping default route")
		return nil
	}
	addWinRoute("0.0.0.0/0", gw)
	winRoutesMu.Lock()
	winEgressRouted = true
	winRoutesMu.Unlock()
	return nil
}
