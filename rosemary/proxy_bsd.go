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

//go:build darwin || freebsd || openbsd

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
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
)

const (
	connIdleTimeout = 5 * time.Minute

	DIOCNATLOOK = 0xC04C4417

	PF_IN  = 1
	PF_OUT = 2
)

type pfAddr struct {
	addr [16]byte
}

type pfNatLook struct {
	saddr    pfAddr
	daddr    pfAddr
	rsaddr   pfAddr
	rdaddr   pfAddr
	sport    uint16
	dport    uint16
	rsport   uint16
	rdport   uint16
	af       uint8
	proto    uint8
	protoVar uint8
	dir      uint8
}

func htons(n uint16) uint16 { return n>>8 | n<<8 }

func diocNatLookDir(pf *os.File, srcIP net.IP, srcPort int, dstIP net.IP, dstPort int, proto uint8, dir uint8) (net.IP, int, error) {
	nl := pfNatLook{
		af:    syscall.AF_INET,
		proto: proto,
		dir:   dir,
	}

	nl.sport = htons(uint16(srcPort))
	nl.dport = htons(uint16(dstPort))

	if v4 := srcIP.To4(); v4 != nil {
		copy(nl.saddr.addr[:4], v4)
	} else {
		copy(nl.saddr.addr[:], srcIP.To16())
		nl.af = syscall.AF_INET6
	}

	if v4 := dstIP.To4(); v4 != nil {
		copy(nl.daddr.addr[:4], v4)
	} else {
		copy(nl.daddr.addr[:], dstIP.To16())
	}

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, pf.Fd(), DIOCNATLOOK, uintptr(unsafe.Pointer(&nl)))
	if errno != 0 {
		return nil, 0, fmt.Errorf("DIOCNATLOOK dir=%d: %v", dir, errno)
	}

	origPort := int(htons(nl.rdport))
	if nl.af == syscall.AF_INET6 {
		ip := make(net.IP, 16)
		copy(ip, nl.rdaddr.addr[:])
		return ip, origPort, nil
	}
	return net.IPv4(nl.rdaddr.addr[0], nl.rdaddr.addr[1], nl.rdaddr.addr[2], nl.rdaddr.addr[3]), origPort, nil
}

func diocNatLook(srcIP net.IP, srcPort int, dstIP net.IP, dstPort int, proto uint8) (net.IP, int, error) {

	pf, err := os.OpenFile("/dev/pf", os.O_RDWR, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("open /dev/pf: %v", err)
	}
	defer pf.Close()

	if ip, port, err := diocNatLookDir(pf, srcIP, srcPort, dstIP, dstPort, proto, PF_OUT); err == nil {
		return ip, port, nil
	}

	return diocNatLookDir(pf, srcIP, srcPort, dstIP, dstPort, proto, PF_IN)
}

var tcpBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 64*1024)
		return &b
	},
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
	icmpDivertStop    chan struct{}
	darwinBPFStop     chan struct{}
)

var (
	darwinSynMapMu sync.Mutex
	darwinSynMap   = map[int]darwinSynEntry{}
)

type darwinSynEntry struct {
	dstIP   net.IP
	dstPort int
	ts      time.Time
}

const icmpDivertPort = 12853

var (
	dnsUDPServer *dns.Server
	dnsTCPServer *dns.Server

	freebsdDNS53UDP *dns.Server
	freebsdDNS53TCP *dns.Server

	darwinExtDNS53UDP *dns.Server
	darwinExtDNS53TCP *dns.Server

	darwinDNSServicesMu      sync.Mutex
	darwinDNSServices        []string
	darwinDNSOriginalServers map[string]string

	darwinDNSListenIP string
)

func pfEnabled() bool {
	out, err := exec.Command("pfctl", "-si").CombinedOutput()
	if err != nil {
		log.Printf("Warning: pfctl not available: %v", err)
		return false
	}

	return strings.Contains(string(out), "Enabled")
}

func enablePF() error {
	if pfEnabled() {
		logVerbose("Packet Filter (pf) is already enabled")
		return nil
	}

	log.Printf("")
	log.Printf("Packet Filter (pf) is NOT enabled on this system")
	log.Printf("")
	log.Printf("To enable pf, run the following command(s):")
	if runtime.GOOS != "darwin" {

		log.Printf("    sudo kldload pf")
	}
	log.Printf("    sudo pfctl -e")
	log.Printf("")
	log.Printf("Then restart the server.")
	log.Printf("")

	if runtime.GOOS != "darwin" {
		return fmt.Errorf("packet filter not enabled - please load and enable with: sudo kldload pf && sudo pfctl -e")
	}
	return fmt.Errorf("packet filter not enabled - please enable with: sudo pfctl -e")
}

func pfctlCmd(args ...string) *exec.Cmd {
	return exec.Command("pfctl", args...)
}

func runPfctl(args ...string) error {
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			time.Sleep(200 * time.Millisecond)
		}
		out, err := exec.Command("pfctl", args...).CombinedOutput()
		if err == nil {
			return nil
		}
		lastErr = fmt.Errorf("pfctl %s: %v - %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		if !strings.Contains(string(out), "busy") && !strings.Contains(string(out), "Busy") {
			break
		}
	}
	return lastErr
}

func addPFRule(ruleFile string) error {

	content, err := os.ReadFile(ruleFile)
	if err != nil {
		return fmt.Errorf("failed to read rule file: %v", err)
	}

	cmd := exec.Command("pfctl", "-a", "tunnel", "-f", "-")
	cmd.Stdin = strings.NewReader(string(content))
	out, err := cmd.Output()
	if err != nil {

		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("failed to load pf rules: %v - %s", err, exitErr.Stderr)
		}
		return fmt.Errorf("failed to load pf rules: %v", err)
	}
	if len(out) > 0 {
		log.Printf("pfctl output: %s", string(out))
	}
	return nil
}

func removePFRule() error {

	cmd := pfctlCmd("-a", "tunnel", "-F", "rules")
	out, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "not found") {
		return fmt.Errorf("failed to clear pf rules: %v - %s", err, out)
	}
	return nil
}

func initTransparentMode() error {

	if err := enablePF(); err != nil {
		return fmt.Errorf("failed to initialize packet filter: %v", err)
	}

	if out, err := exec.Command("sysctl", "-w", "net.inet.ip.forwarding=1").CombinedOutput(); err != nil {
		log.Printf("Warning: sysctl net.inet.ip.forwarding: %v %s", err, out)
	}

	if out, err := exec.Command("sysctl", "-n", "net.inet6.ip6.forwarding").CombinedOutput(); err == nil {
		if strings.TrimSpace(string(out)) != "1" {
			if out, err := exec.Command("sysctl", "-w", "net.inet6.ip6.forwarding=1").CombinedOutput(); err != nil {
				log.Printf("Warning: sysctl net.inet6.ip6.forwarding: %v %s", err, out)
			}
		}
	}

	if runtime.GOOS == "freebsd" {
		if err := setupFreeBSDEpair(); err != nil {
			return fmt.Errorf("FreeBSD epair setup: %v", err)
		}
	}

	if runtime.GOOS == "darwin" {
		go startDarwinTCPSynTracker()
	}

	return nil
}

func startTransparentProxy() {
	if proxyStarted {
		return
	}

	if err := initTransparentMode(); err != nil {
		log.Printf("Failed to initialize transparent mode: %v", err)
		return
	}

	go startICMPInterceptor()

	if err := ensurePFConf(); err != nil {
		log.Printf("Warning: pf.conf anchor setup: %v — multi-hop for locally-generated traffic may not work", err)
	}

	if err := reloadPFSubnetRules(); err != nil {
		log.Printf("Warning: initial pf anchor load: %v", err)
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
				log.Printf("Proxy accept error: %v", err)
				continue
			}
		}
		go handleProxyConnection(conn)
	}
}

func startUDPProxy() {

	addr := net.UDPAddr{
		Port: udpProxyPort,
		IP:   net.ParseIP("0.0.0.0"),
	}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Printf("Failed to bind UDP socket: %v", err)
		return
	}
	udpListener = conn
	logVerbose("UDP proxy listening on 0.0.0.0:%d", udpProxyPort)

	stop := make(chan struct{})
	udpStopChan = stop

	go func() {
		<-stop
		conn.Close()
	}()

	go startUDPProxyV6()

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
	for {
		select {
		case <-stop:
			return
		default:
		}

		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-stop:
				return
			default:
				log.Printf("UDP read error: %v", err)
				continue
			}
		}

		origDst, err := getOriginalDestUDP(conn, remoteAddr)
		if err != nil {
			logVerbose("Failed to get original UDP destination: %v", err)
			continue
		}

		go handleUDPPacket(conn, remoteAddr, origDst, buf[:n])
	}
}

func startUDPProxyV6() {
	addr := net.UDPAddr{
		Port: udpProxyPort,
		IP:   net.ParseIP("::"),
	}
	conn, err := net.ListenUDP("udp6", &addr)
	if err != nil {
		logVerbose("Failed to bind IPv6 UDP socket: %v", err)
		return
	}
	log.Printf("IPv6 UDP proxy listening on [::]:6%d", udpProxyPort)

	stop := make(chan struct{})
	udpV6StopChan = stop

	go func() {
		<-stop
		conn.Close()
	}()

	buf := make([]byte, 65535)
	for {
		select {
		case <-stop:
			return
		default:
		}

		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-stop:
				return
			default:
				log.Printf("IPv6 UDP read error: %v", err)
				continue
			}
		}

		origDst, err := getOriginalDestUDP(conn, remoteAddr)
		if err != nil {
			logVerbose("Failed to get original IPv6 UDP destination: %v", err)
			continue
		}

		go handleUDPPacket(conn, remoteAddr, origDst, buf[:n])
	}
}

var (
	pfStateCacheMu  sync.Mutex
	pfStateCache    map[string]string
	pfStateCacheAge time.Time
)

const pfStateCacheTTL = 150 * time.Millisecond

func runPfctlSS() []byte {

	anchorOut, _ := exec.Command("pfctl", "-a", pfAnchorName, "-ss").CombinedOutput()

	globalOut, _ := exec.Command("pfctl", "-ss").CombinedOutput()
	combined := append(anchorOut, '\n')
	combined = append(combined, globalOut...)
	return combined
}

func getOriginalDestFromPFState(srcIP net.IP, srcPort int) (net.IP, int, error) {
	needle := fmt.Sprintf("%s:%d", srcIP.String(), srcPort)

	pfStateCacheMu.Lock()
	if time.Since(pfStateCacheAge) < pfStateCacheTTL {
		dst := pfStateCache[needle]
		pfStateCacheMu.Unlock()
		if dst != "" {
			return parsePFDst(dst)
		}

	} else {
		pfStateCacheMu.Unlock()
	}

	out := runPfctlSS()
	logVerbose("Darwin pfctl -ss output (looking for %s):\n%s", needle, string(out))

	cache := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		src, dst, ok := parsePFStateLine(line)
		if ok {
			cache[src] = dst
		}
	}

	pfStateCacheMu.Lock()
	pfStateCache = cache
	pfStateCacheAge = time.Now()
	dst := cache[needle]
	pfStateCacheMu.Unlock()

	if dst == "" {
		return nil, 0, fmt.Errorf("pf state not found for %s", needle)
	}
	return parsePFDst(dst)
}

func parsePFStateLine(line string) (src, dst string, ok bool) {
	line = strings.TrimSpace(line)
	if !strings.Contains(line, " tcp ") {
		return
	}

	if strings.Contains(line, " <- ") {
		parts := strings.SplitN(line, " <- ", 2)
		if len(parts) < 2 {
			return
		}
		leftPart := strings.TrimSpace(parts[0])
		rightPart := strings.TrimSpace(parts[1])

		srcFields := strings.Fields(rightPart)
		if len(srcFields) == 0 || !strings.Contains(srcFields[0], ":") {
			return
		}
		srcCandidate := srcFields[0]

		if parenStart := strings.Index(leftPart, "("); parenStart >= 0 {
			parenEnd := strings.Index(leftPart, ")")
			if parenEnd > parenStart {
				inner := leftPart[parenStart+1 : parenEnd]
				if strings.Contains(inner, ":") {
					h, _, e := net.SplitHostPort(inner)
					if e == nil && net.ParseIP(h) != nil && !strings.HasPrefix(h, "127.") {
						src = srcCandidate
						dst = inner
						ok = true
						return
					}
				}
			}
		}

		leftFields := strings.Fields(leftPart)
		if len(leftFields) >= 3 {
			origDst := leftFields[len(leftFields)-1]
			if strings.Contains(origDst, ":") {
				h, _, e := net.SplitHostPort(origDst)
				if e == nil && net.ParseIP(h) != nil && !strings.HasPrefix(h, "127.") {
					src = srcCandidate
					dst = origDst
					ok = true
					return
				}
			}
		}
		return
	}

	arrowIdx := strings.Index(line, " -> ")
	if arrowIdx < 0 {
		return
	}
	before := strings.TrimSpace(line[:arrowIdx])
	fields := strings.Fields(before)
	if len(fields) < 3 {
		return
	}
	src = fields[2]
	if !strings.Contains(src, ":") {
		return
	}
	after := strings.TrimSpace(line[arrowIdx+4:])
	dstFields := strings.Fields(after)
	if len(dstFields) == 0 {
		return
	}
	first := strings.TrimLeft(dstFields[0], "(")
	first = strings.TrimRight(first, ")")
	if !strings.Contains(first, ":") {
		return
	}
	host, _, err := net.SplitHostPort(first)
	if err != nil {
		return
	}
	if !strings.HasPrefix(host, "127.") {
		dst = first
		ok = true
		return
	}
	for _, f := range dstFields[1:] {
		candidate := strings.TrimLeft(f, "(")
		candidate = strings.TrimRight(candidate, ")")
		if !strings.Contains(candidate, ":") {
			continue
		}
		h, _, e := net.SplitHostPort(candidate)
		if e != nil || strings.HasPrefix(h, "127.") || net.ParseIP(h) == nil {
			continue
		}
		dst = candidate
		ok = true
		return
	}
	return
}

func parsePFDst(dst string) (net.IP, int, error) {
	host, portStr, err := net.SplitHostPort(dst)
	if err != nil {
		return nil, 0, fmt.Errorf("parse pf dst %q: %v", dst, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, fmt.Errorf("invalid IP in pf state: %q", host)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid port in pf state: %q", portStr)
	}
	return ip, port, nil
}

func getOriginalDestTCP(conn net.Conn) (net.IP, int, error) {
	srcAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return nil, 0, fmt.Errorf("not a TCP connection")
	}
	dstAddr, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return nil, 0, fmt.Errorf("cannot get local address")
	}

	ip, port, err := diocNatLook(srcAddr.IP, srcAddr.Port, dstAddr.IP, dstAddr.Port, syscall.IPPROTO_TCP)
	if err == nil {
		return ip, port, nil
	}
	logDebug("DIOCNATLOOK failed (src=%s dst=%s): %v — falling back to BPF/pfctl-ss",
		srcAddr, dstAddr, err)

	if runtime.GOOS == "darwin" {
		if bfpIP, bpfPort, ok := darwinLookupSynMap(srcAddr.Port); ok {
			return bfpIP, bpfPort, nil
		}
	}

	retryDelays := []time.Duration{0, 15 * time.Millisecond, 30 * time.Millisecond, 60 * time.Millisecond, 100 * time.Millisecond}
	var lastErr error
	for _, d := range retryDelays {
		if d > 0 {
			time.Sleep(d)
		}
		ip, port, lastErr = getOriginalDestFromPFState(srcAddr.IP, srcAddr.Port)
		if lastErr == nil {
			return ip, port, nil
		}
	}

	if runtime.GOOS == "freebsd" && freebsdEpairA != "" {
		pf, pfErr := os.OpenFile("/dev/pf", os.O_RDWR, 0)
		if pfErr == nil {
			defer pf.Close()

			if ip2, port2, err2 := diocNatLookDir(pf, dstAddr.IP, dstAddr.Port, srcAddr.IP, srcAddr.Port, syscall.IPPROTO_TCP, PF_IN); err2 == nil {
				return ip2, port2, nil
			}
		}
	}

	return nil, 0, lastErr
}

func getOriginalDest(conn net.Conn) (net.IP, int, error) {
	return getOriginalDestTCP(conn)
}

func getOriginalDestUDP(conn *net.UDPConn, remoteAddr *net.UDPAddr) (*net.UDPAddr, error) {
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	dstIP := localAddr.IP
	if dstIP == nil || dstIP.IsUnspecified() {
		dstIP = net.IPv4(127, 0, 0, 1)
	}
	ip, port, err := diocNatLook(remoteAddr.IP, remoteAddr.Port, dstIP, localAddr.Port, syscall.IPPROTO_UDP)
	if err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: ip, Port: port}, nil
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
			log.Printf("No agent found for IP %s", dstIP.String())
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
		log.Printf("Failed to send connect request to agent %s: %v", agentID, err)
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
			log.Printf("Failed to send UDP connect to agent %s: %v", agentID, err)
			respChanMap.Delete(connID)
			pendingUDPConns.Delete(sessionKey)
			pendingUDPConns.Delete(connID)
			return
		}

		select {
		case resp := <-responseChan:
			respChanMap.Delete(connID)
			if !resp.Success {
				log.Printf("Agent failed to open UDP to %s:%d: %s", origDst.IP, origDst.Port, resp.Error)
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
		log.Printf("Failed to send UDP data to agent: %v", err)
	}
	session.expire = time.Now().Add(udpTimeout)
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

func sendUDPResponse(clientAddr *net.UDPAddr, sourceIP net.IP, sourcePort int, data []byte) {
	src4 := sourceIP.To4()
	if src4 == nil {
		sendUDPResponse6(clientAddr, sourceIP, sourcePort, data)
		return
	}
	dst4 := clientAddr.IP.To4()
	if dst4 == nil {
		sendUDPResponse6(clientAddr, sourceIP, sourcePort, data)
		return
	}

	udpLen := 8 + len(data)
	ipLen := 20 + udpLen
	pkt := make([]byte, ipLen)

	pkt[0] = 0x45

	if runtime.GOOS == "darwin" {
		binary.LittleEndian.PutUint16(pkt[2:4], uint16(ipLen))
	} else {
		binary.BigEndian.PutUint16(pkt[2:4], uint16(ipLen))
	}
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], src4)
	copy(pkt[16:20], dst4)
	ipCS := icmpChecksum(pkt[:20])
	binary.BigEndian.PutUint16(pkt[10:12], ipCS)

	binary.BigEndian.PutUint16(pkt[20:22], uint16(sourcePort))
	binary.BigEndian.PutUint16(pkt[22:24], uint16(clientAddr.Port))
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpLen))

	copy(pkt[28:], data)

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Printf("sendUDPResponse: socket: %v", err)
		return
	}
	defer syscall.Close(fd)
	syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)

	addr := syscall.SockaddrInet4{Port: 0}
	copy(addr.Addr[:], dst4)
	if err := syscall.Sendto(fd, pkt, 0, &addr); err != nil {
		log.Printf("sendUDPResponse: sendto: %v", err)
	}
}

const ipv6BindAny = 64

func sendUDPResponse6(clientAddr *net.UDPAddr, sourceIP net.IP, sourcePort int, data []byte) {
	src16 := sourceIP.To16()
	dst16 := clientAddr.IP.To16()
	if src16 == nil || dst16 == nil {
		logVerbose("sendUDPResponse6: invalid address")
		return
	}

	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, 0)
	if err != nil {
		log.Printf("sendUDPResponse6: socket: %v", err)
		return
	}
	defer syscall.Close(fd)

	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)

	if runtime.GOOS == "freebsd" {
		syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, ipv6BindAny, 1)
	}

	spoofAddr := &syscall.SockaddrInet6{Port: sourcePort}
	copy(spoofAddr.Addr[:], src16)
	if err := syscall.Bind(fd, spoofAddr); err != nil {
		logVerbose("sendUDPResponse6: bind %s:%d: %v", sourceIP, sourcePort, err)
		return
	}

	dstAddr := &syscall.SockaddrInet6{Port: clientAddr.Port}
	copy(dstAddr.Addr[:], dst16)
	if err := syscall.Sendto(fd, data, 0, dstAddr); err != nil {
		log.Printf("sendUDPResponse6: sendto: %v", err)
	}
}

var pfSubnetRules = make(map[string]bool)
var pfSubnetMu sync.Mutex

var bsdLoopbackRouting int32

func setBSDLoopbackRouting() { atomic.StoreInt32(&bsdLoopbackRouting, 1) }

var (
	freebsdEpairA   string
	freebsdEpairB   string
	freebsdEpairBIP string
)

const (
	epairLinkNet = "100.64.254.0/30"
	epairAIP     = "100.64.254.1"
	epairBIP     = "100.64.254.2"

	epairMask = "30"
)

func getFreeBSDEpairGateway() string { return freebsdEpairBIP }

func cleanupStaleEpairs() {
	out, err := exec.Command("ifconfig", "-g", "epair").CombinedOutput()
	if err != nil || len(out) == 0 {
		return
	}
	for _, iface := range strings.Fields(string(out)) {

		if strings.HasSuffix(iface, "a") {
			exec.Command("ifconfig", iface, "destroy").CombinedOutput()
		}
	}
}

func setupFreeBSDEpair() error {

	cleanupStaleEpairs()

	exec.Command("kldload", "if_epair").CombinedOutput()

	out, err := exec.Command("ifconfig", "epair", "create").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig epair create: %v — %s", err, out)
	}
	epairA := strings.TrimSpace(string(out))
	if epairA == "" {
		return fmt.Errorf("ifconfig epair create returned empty name")
	}
	epairB := epairA[:len(epairA)-1] + "b"

	if out, err := exec.Command("ifconfig", epairA, "inet", epairAIP+"/"+epairMask, "up").CombinedOutput(); err != nil {
		exec.Command("ifconfig", epairA, "destroy").CombinedOutput()
		return fmt.Errorf("ifconfig %s: %v — %s", epairA, err, out)
	}
	if out, err := exec.Command("ifconfig", epairB, "inet", epairBIP+"/"+epairMask, "up").CombinedOutput(); err != nil {
		exec.Command("ifconfig", epairA, "destroy").CombinedOutput()
		return fmt.Errorf("ifconfig %s: %v — %s", epairB, err, out)
	}

	exec.Command("route", "delete", "-host", epairAIP).CombinedOutput()
	if out, err := exec.Command("route", "add", "-host", epairAIP, "-iface", epairB).CombinedOutput(); err != nil {
		exec.Command("ifconfig", epairA, "destroy").CombinedOutput()
		return fmt.Errorf("route add -host %s -iface %s: %v — %s", epairAIP, epairB, err, out)
	}

	freebsdEpairA = epairA
	freebsdEpairB = epairB
	freebsdEpairBIP = epairBIP
	logVerbose("FreeBSD: created epair %s/%s (gateway %s) for transparent proxy", epairA, epairB, epairBIP)
	return nil
}

func teardownFreeBSDEpair() {
	if freebsdEpairA == "" {
		return
	}
	exec.Command("route", "delete", "-host", epairAIP).CombinedOutput()
	exec.Command("ifconfig", freebsdEpairA, "destroy").CombinedOutput()
	log.Printf("FreeBSD: destroyed epair %s/%s", freebsdEpairA, freebsdEpairB)
	freebsdEpairA = ""
	freebsdEpairB = ""
	freebsdEpairBIP = ""
}

var pfConfMu sync.Mutex

func ensurePFConf() error {
	pfConfMu.Lock()
	defer pfConfMu.Unlock()

	os.MkdirAll("/etc/pf.anchors", 0755)
	os.WriteFile(pfAnchorFile, []byte(""), 0644)
	runPfctl("-a", pfAnchorName, "-F", "all")
	if _, err := os.Stat(pfAnchorFile); os.IsNotExist(err) {
		os.WriteFile(pfAnchorFile, []byte(""), 0644)
	}

	if runtime.GOOS != "darwin" {
		return ensurePFConfBSD()
	}
	return ensurePFConfDarwin()
}

func ensurePFConfBSD() error {
	rdrLine := fmt.Sprintf(`rdr-anchor "%s"`, pfAnchorName)
	filtLine := fmt.Sprintf(`anchor "%s"`, pfAnchorName)
	markerBeg := "# tunnel-pass-begin"
	markerEnd := "# tunnel-pass-end"

	icmpBlockLine := ""
	if freebsdEpairB != "" {
		icmpBlockLine = fmt.Sprintf("\nblock in quick on %s proto icmp", freebsdEpairB)
	}
	passBlock := fmt.Sprintf(
		"%s\npass in quick proto tcp to port { %d, %d, %d }\npass in quick proto udp to port { %d, %d }%s\n%s",
		markerBeg,
		currentHTTPPort, proxyPort, dnsLocalPort,
		udpProxyPort, dnsLocalPort,
		icmpBlockLine,
		markerEnd,
	)

	if _, err := os.Stat("/etc/pf.conf"); os.IsNotExist(err) {
		content := fmt.Sprintf(
			"# Created by tunnel server\n%s\n%s\n%s\npass all\n",
			rdrLine, passBlock, filtLine,
		)
		if err := os.WriteFile("/etc/pf.conf", []byte(content), 0644); err != nil {
			return fmt.Errorf("create /etc/pf.conf: %v", err)
		}
		if err := runPfctl("-f", "/etc/pf.conf"); err != nil {
			return fmt.Errorf("pfctl -f /etc/pf.conf: %v", err)
		}
		logVerbose("pf: created and loaded /etc/pf.conf with anchor %q", pfAnchorName)
		return nil
	}

	pfConf, err := os.ReadFile("/etc/pf.conf")
	if err != nil {
		return fmt.Errorf("read /etc/pf.conf: %v", err)
	}
	text := string(pfConf)

	changed := false

	if strings.Contains(text, "set skip on lo0") {
		var kept []string
		for _, l := range strings.Split(text, "\n") {
			if strings.TrimSpace(l) != "set skip on lo0" {
				kept = append(kept, l)
			}
		}
		text = strings.Join(kept, "\n")
		changed = true
	}

	if strings.Contains(text, markerBeg) {
		startIdx := strings.Index(text, markerBeg)
		endIdx := strings.Index(text, markerEnd)
		if endIdx > startIdx {
			text = text[:startIdx] + passBlock + text[endIdx+len(markerEnd):]
			changed = true
		}
	} else {
		text = passBlock + "\n" + text
		changed = true
	}

	if !strings.Contains(text, filtLine) {
		text = filtLine + "\n" + text
		changed = true
	}

	if !strings.Contains(text, rdrLine) {
		text = rdrLine + "\n" + text
		changed = true
	}

	if changed {
		if err := os.WriteFile("/etc/pf.conf", []byte(text), 0644); err != nil {
			return fmt.Errorf("write /etc/pf.conf: %v", err)
		}
		if err := runPfctl("-f", "/etc/pf.conf"); err != nil {
			return fmt.Errorf("pfctl -f /etc/pf.conf (may need rdr-anchor support): %v", err)
		}
		logVerbose("pf: rdr-anchor + anchor %q registered in /etc/pf.conf", pfAnchorName)
		return nil
	}

	return runPfctl("-f", "/etc/pf.conf")
}

func ensurePFConfDarwin() error {
	pfConf, err := os.ReadFile("/etc/pf.conf")
	if err != nil {
		return fmt.Errorf("read /etc/pf.conf: %v", err)
	}
	text := string(pfConf)

	rdrLine := fmt.Sprintf(`rdr-anchor "%s"`, pfAnchorName)
	filtLine := fmt.Sprintf(`anchor "%s"`, pfAnchorName)
	loadLine := fmt.Sprintf(`load anchor "%s" from "%s"`, pfAnchorName, pfAnchorFile)

	if strings.Contains(text, rdrLine) &&
		strings.Contains(text, filtLine) &&
		strings.Contains(text, loadLine) {
		return nil
	}

	lines := strings.Split(text, "\n")
	lastRdrIdx, lastFiltIdx, lastLoadIdx := -1, -1, -1
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "rdr-anchor") {
			lastRdrIdx = i
		} else if strings.HasPrefix(t, "anchor ") {
			lastFiltIdx = i
		}
		if strings.HasPrefix(t, "load anchor") {
			lastLoadIdx = i
		}
	}

	ins := func(sl []string, idx int, val string) []string {
		out := make([]string, 0, len(sl)+1)
		out = append(out, sl[:idx+1]...)
		out = append(out, val)
		out = append(out, sl[idx+1:]...)
		return out
	}

	if !strings.Contains(text, loadLine) {
		if lastLoadIdx >= 0 {
			lines = ins(lines, lastLoadIdx, loadLine)
		} else {
			lines = append(lines, loadLine)
		}
	}
	if !strings.Contains(text, filtLine) {
		if lastFiltIdx >= 0 {
			lines = ins(lines, lastFiltIdx, filtLine)
		} else if lastRdrIdx >= 0 {
			lines = ins(lines, lastRdrIdx+1, filtLine)
		} else {
			lines = append([]string{filtLine}, lines...)
		}
	}
	if !strings.Contains(text, rdrLine) {
		if lastRdrIdx >= 0 {
			lines = ins(lines, lastRdrIdx, rdrLine)
		} else {
			lines = append([]string{rdrLine}, lines...)
		}
	}

	if err := os.WriteFile("/etc/pf.conf", []byte(strings.Join(lines, "\n")), 0644); err != nil {
		return fmt.Errorf("write /etc/pf.conf: %v", err)
	}

	if loadErr := runPfctl("-f", "/etc/pf.conf"); loadErr != nil {
		return loadErr
	}
	logVerbose("pf: anchor %q registered in /etc/pf.conf (rdr-anchor + anchor + load)", pfAnchorName)
	return nil
}

func restorePFConf() {
	pfConf, err := os.ReadFile("/etc/pf.conf")
	if err != nil {
		logVerbose("restorePFConf: read /etc/pf.conf: %v", err)
		return
	}
	text := string(pfConf)
	orig := text

	rdrLine := fmt.Sprintf(`rdr-anchor "%s"`, pfAnchorName)
	filtLine := fmt.Sprintf(`anchor "%s"`, pfAnchorName)
	loadLine := fmt.Sprintf(`load anchor "%s" from "%s"`, pfAnchorName, pfAnchorFile)
	markerBeg := "# tunnel-pass-begin"
	markerEnd := "# tunnel-pass-end"
	egressBeg := "# tunnel-egress-begin"
	egressEnd := "# tunnel-egress-end"
	createdLine := "# Created by tunnel server"

	if strings.HasPrefix(strings.TrimSpace(text), createdLine) {
		os.Remove("/etc/pf.conf")
		runPfctl("-d")
		logVerbose("pf: removed /etc/pf.conf (was created by tunnel server)")
		return
	}

	if beg := strings.Index(text, markerBeg); beg >= 0 {
		if end := strings.Index(text, markerEnd); end > beg {
			text = text[:beg] + text[end+len(markerEnd):]
		}
	}

	if beg := strings.Index(text, egressBeg); beg >= 0 {
		if end := strings.Index(text, egressEnd); end > beg {
			text = text[:beg] + text[end+len(egressEnd):]
		}
	}

	var kept []string
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		if t == rdrLine || t == filtLine || t == loadLine {
			continue
		}
		kept = append(kept, line)
	}
	text = strings.Join(kept, "\n")

	for strings.Contains(text, "\n\n\n") {
		text = strings.ReplaceAll(text, "\n\n\n", "\n\n")
	}
	text = strings.TrimLeft(text, "\n")

	if text == orig {
		return
	}

	if err := os.WriteFile("/etc/pf.conf", []byte(text), 0644); err != nil {
		log.Printf("restorePFConf: write /etc/pf.conf: %v", err)
		return
	}

	runPfctl("-a", pfAnchorName, "-F", "all")
	os.WriteFile(pfAnchorFile, []byte(""), 0644)
	if err := runPfctl("-f", "/etc/pf.conf"); err != nil {
		log.Printf("restorePFConf: pfctl -f /etc/pf.conf: %v", err)
	} else {
		logVerbose("pf: /etc/pf.conf restored, tunnel anchor removed")
	}
}

func getServerDirectSubnets() []string {
	seen := make(map[string]bool)
	result := []string{"127.0.0.0/8", epairLinkNet}
	seen["127.0.0.0/8"] = true
	seen[epairLinkNet] = true
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

func serverDirectIPNets() []*net.IPNet {
	var nets []*net.IPNet
	for _, s := range getServerDirectSubnets() {
		_, n, err := net.ParseCIDR(s)
		if err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}

func ipNetOverlapsAny(n *net.IPNet, list []*net.IPNet) bool {
	for _, d := range list {
		if n.Contains(d.IP) || d.Contains(n.IP) {
			return true
		}
	}
	return false
}

func reloadPFSubnetRules() error {
	pfSubnetMu.Lock()
	defer pfSubnetMu.Unlock()

	var rdrLines []string
	var passLines []string

	isFreeBSD := runtime.GOOS == "freebsd"
	needsRouteTo := !isFreeBSD && (runtime.GOOS == "darwin" || atomic.LoadInt32(&bsdLoopbackRouting) == 0)

	rdrIface := "lo0"
	if isFreeBSD && freebsdEpairB != "" {
		rdrIface = freebsdEpairB
	}

	directNets := serverDirectIPNets()

	for subnet := range pfSubnetRules {
		rdrLines = append(rdrLines,
			fmt.Sprintf("rdr pass on %s proto tcp from any to %s -> 127.0.0.1 port %d", rdrIface, subnet, proxyPort),
			fmt.Sprintf("rdr pass on %s proto udp from any to %s -> 127.0.0.1 port %d", rdrIface, subnet, udpProxyPort),
		)
		_, snet, err := net.ParseCIDR(subnet)
		localSub := err == nil && ipNetOverlapsAny(snet, directNets)
		if needsRouteTo && !localSub {
			passLines = append(passLines,
				fmt.Sprintf("pass out quick route-to (lo0 127.0.0.1) proto tcp from any to %s keep state", subnet),
				fmt.Sprintf("pass out quick route-to (lo0 127.0.0.1) proto udp from any to %s keep state", subnet),
			)
		}
		if !isFreeBSD && !localSub {
			passLines = append(passLines,
				fmt.Sprintf("pass out quick route-to (lo0 127.0.0.1) proto icmp from any to %s no state", subnet),
			)
		}
	}

	if runtime.GOOS != "darwin" {
		rdrLines = append(rdrLines,
			fmt.Sprintf("rdr pass on %s proto udp from any to any port 53 -> 127.0.0.1 port %d", rdrIface, dnsLocalPort),
			fmt.Sprintf("rdr pass on %s proto tcp from any to any port 53 -> 127.0.0.1 port %d", rdrIface, dnsLocalPort),
		)
	}

	if !isFreeBSD {
		passLines = append(
			[]string{
				"pass out quick proto udp from 127.0.0.2 to any port 53",
				"pass out quick proto tcp from 127.0.0.2 to any port 53",
			},
			passLines...,
		)
	}

	if needsRouteTo {
		if runtime.GOOS == "darwin" {

			passLines = append(passLines,
				"pass out quick proto udp to 127.0.0.0/8 port 53",
				"pass out quick proto tcp to 127.0.0.0/8 port 53",
			)
		}

		if darwinDNSListenIP != "" {
			passLines = append(passLines,
				fmt.Sprintf("pass out quick proto udp to %s port 53", darwinDNSListenIP),
				fmt.Sprintf("pass out quick proto tcp to %s port 53", darwinDNSListenIP),
			)
		}

		if runtime.GOOS != "darwin" {
			passLines = append(passLines,
				"pass out quick route-to (lo0 127.0.0.1) proto udp from any to any port 53 keep state",
				"pass out quick route-to (lo0 127.0.0.1) proto tcp from any to any port 53 keep state",
			)
		}
	}

	if getDefaultEgressAgent() != "" {
		const egressPortList = "{ 1:52, 54:65535 }"

		localSubs := getServerDirectSubnets()
		rdrLines = append(rdrLines,
			fmt.Sprintf("table <noproxy_egress> { %s }", strings.Join(localSubs, ", ")),
		)
		if runtime.GOOS == "darwin" {

			rdrLines = append(rdrLines,
				fmt.Sprintf("rdr pass on lo0 proto tcp from any to !127.0.0.0/8 -> 127.0.0.1 port %d", proxyPort),
				fmt.Sprintf("rdr pass on lo0 proto udp from any to !127.0.0.0/8 -> 127.0.0.1 port %d", udpProxyPort),
			)

			if needsRouteTo {
				for _, s := range localSubs {
					passLines = append(passLines,
						fmt.Sprintf("pass out quick proto tcp to %s", s),
						fmt.Sprintf("pass out quick proto udp to %s", s),
					)
				}
				passLines = append(passLines,
					"pass out quick route-to (lo0 127.0.0.1) proto tcp from any to any keep state",
					"pass out quick route-to (lo0 127.0.0.1) proto udp from any to any port != 53 keep state",
				)
			}
		} else {

			rdrLines = append(rdrLines,
				fmt.Sprintf("rdr pass on %s proto tcp from any to !<noproxy_egress> port %s -> 127.0.0.1 port %d", rdrIface, egressPortList, proxyPort),
				fmt.Sprintf("rdr pass on %s proto udp from any to !<noproxy_egress> port %s -> 127.0.0.1 port %d", rdrIface, egressPortList, udpProxyPort),
			)
			if !isFreeBSD && needsRouteTo {
				passLines = append(passLines,
					"pass out quick route-to (lo0 127.0.0.1) proto tcp from any to !<noproxy_egress> keep state",
					"pass out quick route-to (lo0 127.0.0.1) proto udp from any to !<noproxy_egress> port != 53 keep state",
				)
			}
		}
	}

	if runtime.GOOS == "darwin" {
		passLines = append(passLines,
			fmt.Sprintf("pass in quick proto tcp to port %d keep state", currentHTTPPort),
			fmt.Sprintf("pass in quick proto tcp to port %d keep state", proxyPort),
			fmt.Sprintf("pass in quick proto udp to port %d keep state", udpProxyPort),
			fmt.Sprintf("pass in quick proto tcp to port %d keep state", dnsLocalPort),
			fmt.Sprintf("pass in quick proto udp to port %d keep state", dnsLocalPort),

			"pass in quick proto tcp to port 53 keep state",
			"pass in quick proto udp to port 53 keep state",
		)
	} else {
		passLines = append(passLines,
			fmt.Sprintf("pass in quick proto tcp to port %d", currentHTTPPort),
			fmt.Sprintf("pass in quick proto tcp to port %d", proxyPort),
			fmt.Sprintf("pass in quick proto udp to port %d", udpProxyPort),
			fmt.Sprintf("pass in quick proto tcp to port %d", dnsLocalPort),
			fmt.Sprintf("pass in quick proto udp to port %d", dnsLocalPort),
		)
	}

	all := append(rdrLines, passLines...)
	content := strings.Join(all, "\n") + "\n"
	if err := os.WriteFile(pfAnchorFile, []byte(content), 0644); err != nil {
		return fmt.Errorf("write pf anchor file: %v", err)
	}
	return runPfctl("-a", pfAnchorName, "-f", pfAnchorFile)
}

func addIptablesRule(subnet string, gw string) error {
	pfSubnetMu.Lock()
	pfSubnetRules[subnet] = true
	pfSubnetMu.Unlock()
	if err := reloadPFSubnetRules(); err != nil {
		return fmt.Errorf("failed to add pf rule for %s: %v", subnet, err)
	}
	logVerbose("pfctl: added TCP redirect for %s -> %d", subnet, proxyPort)
	return nil
}

func removeIptablesRule(subnet string) error {
	pfSubnetMu.Lock()
	delete(pfSubnetRules, subnet)
	pfSubnetMu.Unlock()
	if err := reloadPFSubnetRules(); err != nil {
		return fmt.Errorf("failed to remove pf rule for %s: %v", subnet, err)
	}
	logVerbose("pfctl: removed TCP redirect for %s", subnet)
	return nil
}

func addUdpIptablesRule(subnet string) error {

	return nil
}

func removeUdpIptablesRule(subnet string) error {

	return nil
}

func addIcmpIptablesRule(subnet string) error {
	return nil
}

func removeIcmpIptablesRule(subnet string) error {
	return nil
}

func icmpChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 != 0 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func sendICMPReply(srcIP, dstIP net.IP, echoID, echoSeq uint16, payload []byte) {
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

	if runtime.GOOS == "darwin" {
		binary.LittleEndian.PutUint16(pkt[2:4], uint16(totalLen))
	} else {
		binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	}
	pkt[8] = 64
	pkt[9] = 1
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())
	copy(pkt[20:], icmpMsg)
	cs16 := icmpChecksum(pkt[:20])
	binary.BigEndian.PutUint16(pkt[10:12], cs16)

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		logVerbose("sendICMPReply: create socket: %v", err)
		return
	}
	defer syscall.Close(fd)
	syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	addr := syscall.SockaddrInet4{Port: 0}
	copy(addr.Addr[:], dstIP.To4())
	if err := syscall.Sendto(fd, pkt, 0, &addr); err != nil {
		logVerbose("sendICMPReply: sendto: %v", err)
	}
}

func startICMPInterceptor() {
	if runtime.GOOS == "freebsd" {
		go startICMPDivertInterceptor()
	} else if runtime.GOOS == "darwin" {
		go startICMPBPFOnLoopback()
	} else {
		go startICMPRawInterceptor()
	}
}

func startICMPBPFOnLoopback() {

	var bpfFd int = -1
	for i := 0; i < 16; i++ {
		fd, err := syscall.Open(fmt.Sprintf("/dev/bpf%d", i), syscall.O_RDWR, 0)
		if err == nil {
			bpfFd = fd
			break
		}
	}
	if bpfFd < 0 {
		log.Printf("ICMP BPF (lo0): no free /dev/bpf* device")
		return
	}

	if err := syscall.SetBpfInterface(bpfFd, "lo0"); err != nil {
		log.Printf("ICMP BPF (lo0): SetBpfInterface: %v", err)
		syscall.Close(bpfFd)
		return
	}
	if err := syscall.SetBpfImmediate(bpfFd, 1); err != nil {
		log.Printf("ICMP BPF (lo0): SetBpfImmediate: %v", err)
		syscall.Close(bpfFd)
		return
	}

	bufLen, err := syscall.BpfBuflen(bpfFd)
	if err != nil {
		bufLen = 65536
	}

	filter := []syscall.BpfInsn{
		{Code: 0x30, K: 4},
		{Code: 0x54, K: 0xf0},
		{Code: 0x15, Jf: 4, K: 0x40},
		{Code: 0x30, K: 13},
		{Code: 0x15, Jf: 2, K: 1},
		{Code: 0x30, K: 24},
		{Code: 0x15, Jf: 1, K: 8},
		{Code: 0x06, K: 65535},
		{Code: 0x06, K: 0},
	}
	if err := syscall.SetBpf(bpfFd, filter); err != nil {
		log.Printf("ICMP BPF (lo0): SetBpf: %v", err)
		syscall.Close(bpfFd)
		return
	}

	logVerbose("ICMP interceptor: BPF capture on lo0 (bufLen=%d)", bufLen)

	stop := make(chan struct{})
	icmpInterceptStop = stop
	go func() {
		<-stop
		syscall.Close(bpfFd)
	}()

	var firstRead sync.Once
	buf := make([]byte, bufLen)
	const bpfAlign = syscall.BPF_ALIGNMENT
	for {
		n, err := syscall.Read(bpfFd, buf)
		if err != nil {
			return
		}
		firstRead.Do(func() {
			logVerbose("ICMP BPF (lo0): first read %d bytes — BPF is capturing", n)
		})
		offset := 0
		for offset+syscall.SizeofBpfHdr <= n {
			hdr := (*syscall.BpfHdr)(unsafe.Pointer(&buf[offset]))
			capLen := int(hdr.Caplen)
			hdrLen := int(hdr.Hdrlen)
			frameStart := offset + hdrLen
			frameEnd := frameStart + capLen
			if frameEnd > n {
				break
			}
			processBPFNullFrame(buf[frameStart:frameEnd])
			recLen := hdrLen + capLen
			offset += (recLen + bpfAlign - 1) &^ (bpfAlign - 1)
		}
	}
}

func processBPFNullFrame(frame []byte) {

	if len(frame) < 32 {
		return
	}
	ip := frame[4:]
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl+8 {
		return
	}
	icmpPkt := ip[ihl:]
	if icmpPkt[0] != 8 {
		return
	}
	srcIP := net.IP(append([]byte{}, ip[12:16]...))
	dstIP := net.IP(append([]byte{}, ip[16:20]...))
	logVerbose("ICMP BPF (lo0): echo request src=%s dst=%s", srcIP, dstIP)
	agentID, ok := routingTable.FindAgentForIP(dstIP)
	if !ok {
		logVerbose("ICMP BPF (lo0): no agent found for %s", dstIP)
		return
	}
	proxyICMPEchoRequest(srcIP, dstIP, icmpPkt[4:6], icmpPkt[6:8], icmpPkt[8:], agentID)
}

func startICMPRawInterceptor() {
	c, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		logVerbose("ICMP interceptor: failed to listen: %v", err)
		return
	}

	pc := ipv4.NewPacketConn(c)
	if err := pc.SetControlMessage(ipv4.FlagDst, true); err != nil {
		logVerbose("ICMP interceptor: SetControlMessage failed: %v", err)
		c.Close()
		return
	}

	stop := make(chan struct{})
	icmpInterceptStop = stop
	go func() {
		<-stop
		c.Close()
	}()

	logVerbose("ICMP interceptor (raw) started")
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
		proxyICMPEchoRequest(srcIP, dstIP, buf[4:6], buf[6:8], buf[8:n], agentID)
	}
}

func startICMPDivertInterceptor() {
	const IPPROTO_DIVERT = 258

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, IPPROTO_DIVERT)
	if err != nil {

		logVerbose("ICMP: divert socket unavailable (%v), falling back to BPF capture", err)
		startICMPBPFInterceptor()
		return
	}

	sa := &syscall.SockaddrInet4{Port: icmpDivertPort}
	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		logVerbose("ICMP: divert bind port %d failed (%v), falling back to BPF", icmpDivertPort, err)
		startICMPBPFInterceptor()
		return
	}

	stop := make(chan struct{})
	icmpDivertStop = stop
	go func() {
		<-stop
		syscall.Close(fd)
	}()

	logVerbose("ICMP interceptor: divert socket ready on port %d", icmpDivertPort)
	buf := make([]byte, 65536)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			select {
			case <-stop:
				return
			default:
				logVerbose("ICMP divert: recvfrom: %v", err)
				continue
			}
		}

		if n < 28 {
			continue
		}

		ihl := int(buf[0]&0x0f) * 4
		if ihl < 20 || n < ihl+8 {
			continue
		}

		srcIP := net.IP(append([]byte{}, buf[12:16]...))
		dstIP := net.IP(append([]byte{}, buf[16:20]...))
		icmp := buf[ihl:n]

		if icmp[0] != 8 {
			continue
		}

		agentID, ok := routingTable.FindAgentForIP(dstIP)
		if !ok {
			continue
		}

		proxyICMPEchoRequest(srcIP, dstIP, icmp[4:6], icmp[6:8], icmp[8:], agentID)
	}
}

func startICMPBPFInterceptor() {
	epairB := freebsdEpairB
	if epairB == "" {
		log.Printf("ICMP BPF: epairB not set, ICMP interception disabled")
		return
	}

	fd, err := syscall.Open("/dev/bpf", syscall.O_RDONLY, 0)
	if err != nil {

		for i := 0; i < 20 && fd < 0; i++ {
			fd, err = syscall.Open(fmt.Sprintf("/dev/bpf%d", i), syscall.O_RDONLY, 0)
		}
	}
	if err != nil {
		log.Printf("ICMP BPF: cannot open BPF device: %v", err)
		return
	}

	if err := syscall.SetBpfInterface(fd, epairB); err != nil {
		syscall.Close(fd)
		log.Printf("ICMP BPF: SetBpfInterface(%s): %v", epairB, err)
		return
	}
	if err := syscall.SetBpfImmediate(fd, 1); err != nil {
		logVerbose("ICMP BPF: SetBpfImmediate: %v", err)
	}

	filter := []syscall.BpfInsn{
		{Code: 0x28, K: 12},
		{Code: 0x15, Jf: 5, K: 0x0800},
		{Code: 0x30, K: 23},
		{Code: 0x15, Jf: 3, K: 1},
		{Code: 0x30, K: 34},
		{Code: 0x15, Jf: 1, K: 8},
		{Code: 0x06, K: 65535},
		{Code: 0x06, K: 0},
	}
	if err := syscall.SetBpf(fd, filter); err != nil {
		syscall.Close(fd)
		log.Printf("ICMP BPF: SetBpf: %v", err)
		return
	}

	bufLen, _ := syscall.BpfBuflen(fd)
	if bufLen < 4096 {
		bufLen = 65536
	}

	stop := make(chan struct{})
	icmpDivertStop = stop
	go func() {
		<-stop
		syscall.Close(fd)
	}()

	logVerbose("ICMP interceptor: BPF capture on %s", epairB)
	buf := make([]byte, bufLen)

	const bpfAlign = 8
	for {
		n, err := syscall.Read(fd, buf)
		if err != nil {
			select {
			case <-stop:
				return
			default:
				if err == syscall.ENXIO || err == syscall.EBADF {
					time.Sleep(500 * time.Millisecond)
				} else {
					logVerbose("ICMP BPF: read: %v", err)
					time.Sleep(5 * time.Millisecond)
				}
				continue
			}
		}

		offset := 0
		for offset+syscall.SizeofBpfHdr <= n {
			hdr := (*syscall.BpfHdr)(unsafe.Pointer(&buf[offset]))
			capLen := int(hdr.Caplen)
			hdrLen := int(hdr.Hdrlen)
			frameStart := offset + hdrLen
			frameEnd := frameStart + capLen
			if frameEnd > n {
				break
			}

			processBPFFrame(buf[frameStart:frameEnd])

			recLen := hdrLen + capLen
			offset += (recLen + bpfAlign - 1) &^ (bpfAlign - 1)
		}
	}
}

func processBPFFrame(frame []byte) {

	if len(frame) < 42 {
		return
	}

	if frame[12] != 0x08 || frame[13] != 0x00 {
		return
	}
	ip := frame[14:]
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl+8 {
		return
	}
	icmpPkt := ip[ihl:]
	if icmpPkt[0] != 8 {
		return
	}
	srcIP := net.IP(append([]byte{}, ip[12:16]...))
	dstIP := net.IP(append([]byte{}, ip[16:20]...))
	agentID, ok := routingTable.FindAgentForIP(dstIP)
	if !ok {
		return
	}
	proxyICMPEchoRequest(srcIP, dstIP, icmpPkt[4:6], icmpPkt[6:8], icmpPkt[8:], agentID)
}

func startDarwinTCPSynTracker() {
	fd, err := syscall.Open("/dev/bpf", syscall.O_RDONLY, 0)
	if err != nil {
		for i := 0; i < 20; i++ {
			fd, err = syscall.Open(fmt.Sprintf("/dev/bpf%d", i), syscall.O_RDONLY, 0)
			if err == nil {
				break
			}
		}
	}
	if err != nil {
		logVerbose("Darwin TCP tracker: cannot open BPF device: %v", err)
		return
	}

	if err := syscall.SetBpfInterface(fd, "lo0"); err != nil {
		syscall.Close(fd)
		logVerbose("Darwin TCP tracker: SetBpfInterface(lo0): %v", err)
		return
	}
	if err := syscall.SetBpfImmediate(fd, 1); err != nil {
		logVerbose("Darwin TCP tracker: SetBpfImmediate: %v", err)
	}

	if err := syscall.SetBpf(fd, []syscall.BpfInsn{{Code: 0x06, K: 65535}}); err != nil {
		syscall.Close(fd)
		logVerbose("Darwin TCP tracker: SetBpf: %v", err)
		return
	}

	bufLen, _ := syscall.BpfBuflen(fd)
	if bufLen < 4096 {
		bufLen = 65536
	}

	stop := make(chan struct{})
	darwinBPFStop = stop
	go func() { <-stop; syscall.Close(fd) }()

	go func() {
		buf := make([]byte, bufLen)
		const bpfAlign = 8
		for {
			n, err := syscall.Read(fd, buf)
			if err != nil {
				select {
				case <-stop:
					return
				default:
					time.Sleep(5 * time.Millisecond)
					continue
				}
			}
			offset := 0
			for offset+syscall.SizeofBpfHdr <= n {
				hdr := (*syscall.BpfHdr)(unsafe.Pointer(&buf[offset]))
				capLen := int(hdr.Caplen)
				hdrLen := int(hdr.Hdrlen)
				frameStart := offset + hdrLen
				frameEnd := frameStart + capLen
				if frameEnd > n {
					break
				}
				processDarwinLoopbackSyn(buf[frameStart:frameEnd])
				recLen := hdrLen + capLen
				offset += (recLen + bpfAlign - 1) &^ (bpfAlign - 1)
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				now := time.Now()
				darwinSynMapMu.Lock()
				for port, e := range darwinSynMap {
					if now.Sub(e.ts) > 120*time.Second {
						delete(darwinSynMap, port)
					}
				}
				darwinSynMapMu.Unlock()
			case <-stop:
				return
			}
		}
	}()

	logVerbose("Darwin: TCP SYN BPF tracker active on lo0")
}

func processDarwinLoopbackSyn(frame []byte) {

	if len(frame) < 44 {
		return
	}
	family := binary.LittleEndian.Uint32(frame[0:4])
	if family != syscall.AF_INET {
		return
	}
	ip := frame[4:]
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl+20 {
		return
	}
	if ip[9] != 6 {
		return
	}
	tcp := ip[ihl:]
	flags := tcp[13]
	if flags&0x02 == 0 || flags&0x10 != 0 {
		return
	}
	srcPort := int(binary.BigEndian.Uint16(tcp[0:2]))
	dstPort := int(binary.BigEndian.Uint16(tcp[2:4]))
	dstIP := net.IP(append([]byte{}, ip[16:20]...))
	srcIP := net.IP(append([]byte{}, ip[12:16]...))
	logVerbose("Darwin BPF SYN: src=%s:%d dst=%s:%d", srcIP, srcPort, dstIP, dstPort)
	if dstIP[0] == 127 {
		return
	}
	darwinSynMapMu.Lock()
	darwinSynMap[srcPort] = darwinSynEntry{dstIP: dstIP, dstPort: dstPort, ts: time.Now()}
	darwinSynMapMu.Unlock()
}

func darwinLookupSynMap(srcPort int) (net.IP, int, bool) {
	darwinSynMapMu.Lock()
	e, ok := darwinSynMap[srcPort]
	if ok {
		delete(darwinSynMap, srcPort)
	}
	darwinSynMapMu.Unlock()
	if !ok {
		return nil, 0, false
	}
	return e.dstIP, e.dstPort, true
}

var icmpInFlight sync.Map

type icmpFlight struct {
	done chan struct{}
	ok   bool
}

func proxyICMPEchoRequest(srcIP, dstIP net.IP, idBytes, seqBytes, payload []byte, agentID string) {
	echoID := binary.BigEndian.Uint16(idBytes)
	echoSeq := binary.BigEndian.Uint16(seqBytes)
	echoData := make([]byte, len(payload))
	copy(echoData, payload)

	targetIP := dstIP.String()
	localSrc := net.IP(append([]byte{}, srcIP...))
	localDst := net.IP(append([]byte{}, dstIP...))
	id, seq, data := echoID, echoSeq, echoData

	flightKey := fmt.Sprintf("%s-%d-%d", targetIP, id, seq)

	go func() {

		flight := &icmpFlight{done: make(chan struct{})}
		actual, loaded := icmpInFlight.LoadOrStore(flightKey, flight)
		if loaded {

			existing := actual.(*icmpFlight)
			select {
			case <-existing.done:
			case <-time.After(3 * time.Second):
			}
			return
		}

		defer func() {
			icmpInFlight.Delete(flightKey)
			close(flight.done)
		}()

		connID := fmt.Sprintf("icmp-%s-%d-%d", targetIP, id, seq)
		ch := make(chan ICMPProxyResponse, 1)
		pendingICMPProxy.Store(connID, ch)
		defer pendingICMPProxy.Delete(connID)

		req := ICMPProxyRequest{
			ConnID:    connID,
			Target:    targetIP,
			TimeoutMs: 2000,
		}
		reqPayload, _ := json.Marshal(req)
		msg := Message{
			Type:          "icmp_proxy",
			Payload:       reqPayload,
			TargetAgentID: agentID,
		}
		if err := sendControlMessageToAgent(agentID, msg); err != nil {
			log.Printf("ICMP proxy: sendControlMessage to agent %s failed: %v", agentID, err)
			return
		}

		select {
		case resp := <-ch:
			if resp.Success {
				flight.ok = true
				sendICMPReply(localDst, localSrc, id, seq, data)
			}
		case <-time.After(3 * time.Second):
		}
	}()
}

func startDNSProxy() {
	dnsUDPServer = &dns.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%d", dnsLocalPort),
		Net:     "udp",
		Handler: dns.HandlerFunc(handleDNSRequest),
	}
	dnsTCPServer = &dns.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%d", dnsLocalPort),
		Net:     "tcp",
		Handler: dns.HandlerFunc(handleDNSRequest),
	}

	go func() {
		logVerbose("Starting DNS UDP proxy on 0.0.0.0:%d", dnsLocalPort)
		if err := dnsUDPServer.ListenAndServe(); err != nil && err.Error() != "dns: server closed" {
			log.Printf("DNS UDP server error: %v", err)
		}
	}()
	go func() {
		logVerbose("Starting DNS TCP proxy on 0.0.0.0:%d", dnsLocalPort)
		if err := dnsTCPServer.ListenAndServe(); err != nil && err.Error() != "dns: server closed" {
			log.Printf("DNS TCP server error: %v", err)
		}
	}()

	if err := addDNSRedirectRule(); err != nil {
		log.Printf("Failed to configure DNS interception: %v", err)
	} else {
		logVerbose("DNS interception configured (port 53 -> %d)", dnsLocalPort)
	}
}

func stopDNSProxy() {
	if dnsUDPServer != nil {
		dnsUDPServer.Shutdown()
	}
	if dnsTCPServer != nil {
		dnsTCPServer.Shutdown()
	}
	removeDNSRedirectRule()
}

const pfAnchorName = "com.tunnel"
const pfAnchorFile = "/etc/pf.anchors/tunnel"

func addDNSRedirectRule() error {
	switch runtime.GOOS {
	case "freebsd":
		return addFreeBSDUnboundForward()
	case "darwin":
		return addDarwinDNSForward()
	}
	if err := ensurePFConf(); err != nil {
		return err
	}
	return reloadPFSubnetRules()
}

var darwinOrigResolvConf []byte

func darwinWriteResolvConf() {
	orig, err := os.ReadFile("/etc/resolv.conf")
	if err == nil {
		darwinOrigResolvConf = orig
	} else {
		darwinOrigResolvConf = nil
	}
	content := "nameserver 127.0.0.1\n"
	if orig != nil {

		for _, line := range strings.Split(string(orig), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" && !strings.HasPrefix(trimmed, "nameserver") {
				content += line + "\n"
			}
		}
	}
	if err := os.WriteFile("/etc/resolv.conf", []byte(content), 0644); err != nil {
		logVerbose("Darwin DNS: write /etc/resolv.conf: %v", err)
	} else {
		logVerbose("Darwin DNS: wrote /etc/resolv.conf with nameserver 127.0.0.1")
	}
}

func darwinRestoreResolvConf() {
	if darwinOrigResolvConf != nil {
		if err := os.WriteFile("/etc/resolv.conf", darwinOrigResolvConf, 0644); err != nil {
			logVerbose("Darwin DNS: restore /etc/resolv.conf: %v", err)
		}
		darwinOrigResolvConf = nil
	}
}

var darwinOrigScutilDNSSaved bool
var darwinAddedDefaultRoute string

func darwinEnsureDefaultRoute() {

	out, err := exec.Command("route", "-n", "get", "default").CombinedOutput()
	if err == nil && strings.Contains(string(out), "gateway:") {
		return
	}

	gw := ""
	for _, ip := range serverIPs {
		if ip.To4() == nil || ip.IsLoopback() {
			continue
		}
		ip4 := ip.To4()
		candidate := fmt.Sprintf("%d.%d.%d.1", ip4[0], ip4[1], ip4[2])
		if candidate != ip.String() {
			gw = candidate
			break
		}
		gw = fmt.Sprintf("%d.%d.%d.2", ip4[0], ip4[1], ip4[2])
		break
	}
	if gw == "" {
		return
	}

	if out, err := exec.Command("route", "add", "default", gw).CombinedOutput(); err != nil {
		log.Printf("Darwin DNS: route add default %s: %v — %s", gw, err, out)
	} else {
		darwinAddedDefaultRoute = gw
		log.Printf("Darwin DNS: added temporary default route via %s (for mDNSResponder reachability)", gw)
	}
}

func darwinRemoveDefaultRoute() {
	if darwinAddedDefaultRoute == "" {
		return
	}
	exec.Command("route", "delete", "default", darwinAddedDefaultRoute).Run()
	log.Printf("Darwin DNS: removed temporary default route via %s", darwinAddedDefaultRoute)
	darwinAddedDefaultRoute = ""
}

func darwinScutilSetDNS(ip string) error {
	input := fmt.Sprintf("d.init\nd.add ServerAddresses * %s\nset State:/Network/Global/DNS\n", ip)
	cmd := exec.Command("scutil")
	cmd.Stdin = strings.NewReader(input)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("scutil set State:/Network/Global/DNS %s: %v — %s", ip, err, out)
	}
	darwinOrigScutilDNSSaved = true
	log.Printf("Darwin DNS: scutil State:/Network/Global/DNS -> %s", ip)
	return nil
}

func darwinScutilRestoreDNS() {
	if !darwinOrigScutilDNSSaved {
		return
	}
	cmd := exec.Command("scutil")
	cmd.Stdin = strings.NewReader("remove State:/Network/Global/DNS\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		logVerbose("Darwin DNS: scutil remove State:/Network/Global/DNS: %v — %s", err, out)
	}
	darwinOrigScutilDNSSaved = false
}

func darwinGetActiveNetworkServices() []string {
	out, err := exec.Command("networksetup", "-listallnetworkservices").CombinedOutput()
	if err != nil {
		return nil
	}
	var services []string
	for i, l := range strings.Split(string(out), "\n") {
		if i == 0 {
			continue
		}
		l = strings.TrimSpace(l)

		if l != "" && !strings.HasPrefix(l, "*") {
			services = append(services, l)
		}
	}
	return services
}

func darwinPickDNSListenIP() string {
	for _, ip := range serverIPs {
		if ip.To4() != nil && !ip.IsLoopback() {
			return ip.String()
		}
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip != nil && ip.To4() != nil && !ip.IsLoopback() {
			return ip.String()
		}
	}
	return ""
}

var darwinResolverTLDs = []string{

	"com", "net", "org", "info", "biz", "edu", "gov", "mil", "int",

	"io", "dev", "app", "ai", "tech", "online", "site", "web",
	"cloud", "digital", "store", "shop", "media", "news", "blog",
	"co", "me", "us", "tv", "cc",

	"uk", "de", "fr", "it", "es", "nl", "be", "ch", "at",
	"au", "nz", "ca", "jp", "cn", "kr", "in", "ru", "br",

	"htb", "box", "lab", "ctf", "local", "internal", "corp",
	"lan", "intranet", "hack", "pwn", "red", "blue",
}

func darwinWriteResolverFiles() {
	os.MkdirAll("/etc/resolver", 0755)
	content := fmt.Sprintf("nameserver 127.0.0.1\nport %d\n", dnsLocalPort)
	for _, tld := range darwinResolverTLDs {
		path := "/etc/resolver/" + tld
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			logVerbose("Darwin DNS: write /etc/resolver/%s: %v", tld, err)
		}
	}
	log.Printf("Darwin DNS: wrote /etc/resolver/ for %d TLDs -> 127.0.0.1:%d", len(darwinResolverTLDs), dnsLocalPort)
}

func darwinRemoveResolverFiles() {
	for _, tld := range darwinResolverTLDs {
		os.Remove("/etc/resolver/" + tld)
	}
}

func addDarwinDNSForward() error {

	darwinWriteResolverFiles()

	if out, err := exec.Command("ifconfig", "lo0", "alias", "127.0.0.2").CombinedOutput(); err != nil {
		logVerbose("Darwin DNS: ifconfig lo0 alias 127.0.0.2: %v — %s", err, out)
	}
	errCh := make(chan error, 2)
	freebsdDNS53UDP = &dns.Server{Addr: "127.0.0.2:53", Net: "udp", Handler: dns.HandlerFunc(handleDNSRequest)}
	freebsdDNS53TCP = &dns.Server{Addr: "127.0.0.2:53", Net: "tcp", Handler: dns.HandlerFunc(handleDNSRequest)}
	go func() {
		if err := freebsdDNS53UDP.ListenAndServe(); err != nil && err.Error() != "dns: server closed" {
			errCh <- err
		}
	}()
	go func() {
		if err := freebsdDNS53TCP.ListenAndServe(); err != nil && err.Error() != "dns: server closed" {
			errCh <- err
		}
	}()
	time.Sleep(150 * time.Millisecond)
	select {
	case err := <-errCh:
		logVerbose("Darwin DNS: 127.0.0.2:53 bind failed: %v", err)
		exec.Command("ifconfig", "lo0", "-alias", "127.0.0.2").Run()
	default:
		darwinWriteResolvConf()
	}

	exec.Command("dscacheutil", "-flushcache").Run()
	exec.Command("killall", "-HUP", "mDNSResponder").Run()

	darwinDNSListenIP = ""
	if err := reloadPFSubnetRules(); err != nil {
		logVerbose("Darwin DNS: pf reload: %v", err)
	}
	log.Printf("Darwin: DNS via /etc/resolver/ -> 127.0.0.1:%d + 127.0.0.2:53 fallback", dnsLocalPort)
	return nil
}

func removeDarwinDNSForward() error {
	darwinRemoveResolverFiles()

	if freebsdDNS53UDP != nil {
		freebsdDNS53UDP.Shutdown()
		freebsdDNS53UDP = nil
	}
	if freebsdDNS53TCP != nil {
		freebsdDNS53TCP.Shutdown()
		freebsdDNS53TCP = nil
	}

	darwinRestoreResolvConf()
	darwinScutilRestoreDNS()
	darwinRemoveDefaultRoute()

	exec.Command("ifconfig", "lo0", "-alias", "127.0.0.2").Run()
	exec.Command("dscacheutil", "-flushcache").Run()
	exec.Command("killall", "-HUP", "mDNSResponder").Run()

	darwinDNSListenIP = ""
	logVerbose("Darwin: DNS restored")
	return nil
}

func removeDNSRedirectRule() error {
	if runtime.GOOS == "freebsd" {
		return removeFreeBSDUnboundForward()
	}
	if runtime.GOOS == "darwin" {
		return removeDarwinDNSForward()
	}

	os.Remove(pfAnchorFile)

	pfConf, err := os.ReadFile("/etc/pf.conf")
	if err != nil {
		return nil
	}
	var kept []string
	for _, line := range strings.Split(string(pfConf), "\n") {
		if !strings.Contains(line, pfAnchorName) && !strings.Contains(line, pfAnchorFile) {
			kept = append(kept, line)
		}
	}
	cleaned := strings.TrimRight(strings.Join(kept, "\n"), "\n") + "\n"
	os.WriteFile("/etc/pf.conf", []byte(cleaned), 0644)
	exec.Command("pfctl", "-f", "/etc/pf.conf").Run()
	return nil
}

var freebsdResolvConfBackup []byte

func addFreeBSDUnboundForward() error {

	if out, err := exec.Command("service", "local_unbound", "stop").CombinedOutput(); err != nil {
		log.Printf("FreeBSD DNS: local_unbound stop: %v — %s", err, out)

	}

	errCh := make(chan error, 2)

	freebsdDNS53UDP = &dns.Server{
		Addr:    "127.0.0.1:53",
		Net:     "udp",
		Handler: dns.HandlerFunc(handleDNSRequest),
	}
	freebsdDNS53TCP = &dns.Server{
		Addr:    "127.0.0.1:53",
		Net:     "tcp",
		Handler: dns.HandlerFunc(handleDNSRequest),
	}

	go func() {
		if err := freebsdDNS53UDP.ListenAndServe(); err != nil && err.Error() != "dns: server closed" {
			log.Printf("FreeBSD DNS53 UDP error: %v", err)
			errCh <- err
		}
	}()
	go func() {
		if err := freebsdDNS53TCP.ListenAndServe(); err != nil && err.Error() != "dns: server closed" {
			log.Printf("FreeBSD DNS53 TCP error: %v", err)
			errCh <- err
		}
	}()

	time.Sleep(150 * time.Millisecond)
	select {
	case err := <-errCh:

		exec.Command("service", "local_unbound", "start").CombinedOutput()
		return fmt.Errorf("bind 127.0.0.1:53: %v", err)
	default:
	}

	if err := freebsdForceResolvConf(); err != nil {
		log.Printf("FreeBSD DNS: resolv.conf: %v", err)
	}

	logVerbose("FreeBSD: DNS proxy listening on 127.0.0.1:53 (local_unbound stopped)")
	return nil
}

func freebsdForceResolvConf() error {
	const resolvConf = "/etc/resolv.conf"
	orig, err := os.ReadFile(resolvConf)
	if err != nil {
		orig = nil
	}
	freebsdResolvConfBackup = orig

	lines := strings.Split(string(orig), "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "nameserver") {
			if strings.Contains(l, "127.0.0.1") {
				return nil
			}
			break
		}
	}

	var kept []string
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			kept = append(kept, l)
		}
	}
	newConf := "nameserver 127.0.0.1\n" + strings.Join(kept, "\n") + "\n"
	if err := os.WriteFile(resolvConf, []byte(newConf), 0644); err != nil {
		return fmt.Errorf("write resolv.conf: %v", err)
	}
	logVerbose("FreeBSD: /etc/resolv.conf updated — nameserver 127.0.0.1 prepended")
	return nil
}

func removeFreeBSDUnboundForward() error {
	if freebsdDNS53UDP != nil {
		freebsdDNS53UDP.Shutdown()
		freebsdDNS53UDP = nil
	}
	if freebsdDNS53TCP != nil {
		freebsdDNS53TCP.Shutdown()
		freebsdDNS53TCP = nil
	}

	if freebsdResolvConfBackup != nil {
		os.WriteFile("/etc/resolv.conf", freebsdResolvConfBackup, 0644)
		freebsdResolvConfBackup = nil
	}

	if out, err := exec.Command("service", "local_unbound", "start").CombinedOutput(); err != nil {
		log.Printf("FreeBSD DNS cleanup: local_unbound start: %v — %s", err, out)
	}
	log.Printf("FreeBSD: restored local_unbound on port 53")
	return nil
}

var savedDefaultEgressGW string

func freebsdGetDefaultGW() string {
	out, err := exec.Command("route", "-n", "get", "default").CombinedOutput()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			gw := strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
			if ip := net.ParseIP(gw); ip != nil && ip.To4() != nil {
				return gw
			}
		}
	}
	return ""
}

func bsdSetDefaultRoute(gw string) {
	out, err := exec.Command("route", "change", "default", gw).CombinedOutput()
	if err != nil {
		out, err = exec.Command("route", "add", "default", gw).CombinedOutput()
		if err != nil {
			log.Printf("egress: failed to set default route -> %s: %v - %s", gw, err, out)
		}
	}
}

func reloadDefaultEgressRules() error {
	if getDefaultEgressAgent() == "" {
		if runtime.GOOS == "freebsd" {
			if savedDefaultEgressGW != "" {
				exec.Command("route", "change", "default", savedDefaultEgressGW).CombinedOutput()
				savedDefaultEgressGW = ""
			} else {
				exec.Command("route", "delete", "default").CombinedOutput()
			}
		} else if runtime.GOOS == "darwin" {

			exec.Command("route", "delete", "-net", "0.0.0.0/1").CombinedOutput()
			exec.Command("route", "delete", "-net", "128.0.0.0/1").CombinedOutput()
			savedDefaultEgressGW = ""
		}
		updatePFConfEgressBlock(false)
		return reloadPFSubnetRules()
	}

	switch runtime.GOOS {
	case "freebsd":
		if freebsdEpairA != "" {
			if savedDefaultEgressGW == "" {
				savedDefaultEgressGW = freebsdGetDefaultGW()
			}
			bsdSetDefaultRoute(epairBIP)
		}
	case "darwin":

		if savedDefaultEgressGW == "" {
			savedDefaultEgressGW = freebsdGetDefaultGW()
		}
		exec.Command("route", "add", "-net", "0.0.0.0/1", "127.0.0.1").CombinedOutput()
		exec.Command("route", "add", "-net", "128.0.0.0/1", "127.0.0.1").CombinedOutput()
		logVerbose("Darwin: added 0/1+128/1 routes via 127.0.0.1 (lo0) for egress interception")
	}

	if err := updatePFConfEgressBlock(true); err != nil {
		return err
	}
	return reloadPFSubnetRules()
}

func updatePFConfEgressBlock(enable bool) error {
	pfConfMu.Lock()
	defer pfConfMu.Unlock()

	const egressBeg = "# tunnel-egress-begin"
	const egressEnd = "# tunnel-egress-end"

	data, err := os.ReadFile("/etc/pf.conf")
	if err != nil {
		return fmt.Errorf("read /etc/pf.conf: %v", err)
	}
	text := string(data)

	var block string
	if enable && freebsdEpairA != "" {

		localSubs := getServerDirectSubnets()

		var lines []string
		lines = append(lines, egressBeg)
		lines = append(lines, fmt.Sprintf("table <noproxy_egress> { %s }", strings.Join(localSubs, ", ")))
		lines = append(lines, "pass out quick proto udp from 127.0.0.2 to any port 53")
		lines = append(lines, "pass out quick proto tcp from 127.0.0.2 to any port 53")
		lines = append(lines,
			fmt.Sprintf("pass out quick route-to (%s %s) proto tcp from any to !<noproxy_egress> no state", freebsdEpairA, freebsdEpairBIP),
			fmt.Sprintf("pass out quick route-to (%s %s) proto udp from any to !<noproxy_egress> port != 53 no state", freebsdEpairA, freebsdEpairBIP),
		)
		lines = append(lines, egressEnd)
		block = strings.Join(lines, "\n")
	} else if enable && runtime.GOOS == "darwin" {

		block = egressBeg + "\n" + egressEnd
	} else {
		block = egressBeg + "\n" + egressEnd
	}

	if strings.Contains(text, egressBeg) {
		startIdx := strings.Index(text, egressBeg)
		endIdx := strings.Index(text, egressEnd)
		if endIdx > startIdx {
			text = text[:startIdx] + block + text[endIdx+len(egressEnd):]
		}
	} else {
		anchorLine := fmt.Sprintf(`anchor "%s"`, pfAnchorName)
		pfLines := strings.Split(text, "\n")
		insertIdx := -1
		for i, l := range pfLines {
			if strings.TrimSpace(l) == anchorLine {
				insertIdx = i
				break
			}
		}
		if insertIdx >= 0 {
			blockLines := strings.Split(block, "\n")
			merged := make([]string, 0, len(pfLines)+len(blockLines)+1)
			merged = append(merged, pfLines[:insertIdx]...)
			merged = append(merged, blockLines...)
			merged = append(merged, "")
			merged = append(merged, pfLines[insertIdx:]...)
			text = strings.Join(merged, "\n")
		} else {
			text = text + "\n" + block + "\n"
		}
	}

	if err := os.WriteFile("/etc/pf.conf", []byte(text), 0644); err != nil {
		return fmt.Errorf("write /etc/pf.conf: %v", err)
	}
	return runPfctl("-f", "/etc/pf.conf")
}

func queryFallbackDNS(domain string, qtype uint16) *DNSResponseMessage {
	servers := getSavedSystemDNSServers()
	if len(servers) == 0 {
		return nil
	}
	for _, server := range servers {
		c := &dns.Client{
			Net:     "udp",
			Timeout: 2 * time.Second,
			Dialer: &net.Dialer{
				Timeout:   2 * time.Second,
				LocalAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.2")},
			},
		}
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

const (
	dnsCacheTTL    = 60 * time.Second
	dnsCacheMinTTL = uint32(60)
)

type dnsRespCacheEntry struct {
	response *DNSResponseMessage
	expires  time.Time
}

var (
	dnsRespCacheMu sync.RWMutex
	dnsRespCache   = make(map[string]*dnsRespCacheEntry)
)

func dnsCacheKey(name string, qtype uint16) string {
	return name + "/" + strconv.Itoa(int(qtype))
}

func dnsRespCacheGet(name string, qtype uint16) *DNSResponseMessage {
	dnsRespCacheMu.RLock()
	e := dnsRespCache[dnsCacheKey(name, qtype)]
	dnsRespCacheMu.RUnlock()
	if e == nil || time.Now().After(e.expires) {
		return nil
	}
	return e.response
}

func dnsRespCachePut(name string, qtype uint16, resp *DNSResponseMessage) {
	dnsRespCacheMu.Lock()
	dnsRespCache[dnsCacheKey(name, qtype)] = &dnsRespCacheEntry{
		response: resp,
		expires:  time.Now().Add(dnsCacheTTL),
	}
	dnsRespCacheMu.Unlock()
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

	if cached := dnsRespCacheGet(q.Name, q.Qtype); cached != nil {
		buildAndSendDNSReply(w, req, cached)
		return
	}

	connLock.Lock()
	agents := make([]string, 0, len(connections))
	for id := range connections {
		agents = append(agents, id)
	}
	connLock.Unlock()

	if len(agents) == 0 {

		if fb := queryFallbackDNS(q.Name, q.Qtype); fb != nil {
			if fb.RCode == dns.RcodeSuccess && len(fb.Answers) > 0 {
				dnsRespCachePut(q.Name, q.Qtype, fb)
			}
			buildAndSendDNSReply(w, req, fb)
			return
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
		}
	}
	if bestResponse == nil {
		servfail()
		return
	}

	if bestResponse.RCode == dns.RcodeSuccess && len(bestResponse.Answers) > 0 {
		dnsRespCachePut(q.Name, q.Qtype, bestResponse)
	}

	buildAndSendDNSReply(w, req, bestResponse)
}

func buildAndSendDNSReply(w dns.ResponseWriter, req *dns.Msg, resp *DNSResponseMessage) {
	reply := new(dns.Msg)
	reply.SetReply(req)
	reply.Rcode = resp.RCode
	for _, ans := range resp.Answers {
		ttl := ans.TTL
		if ttl < dnsCacheMinTTL {
			ttl = dnsCacheMinTTL
		}
		hdr := dns.RR_Header{
			Name:   ans.Name,
			Rrtype: ans.Type,
			Class:  dns.ClassINET,
			Ttl:    ttl,
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
		log.Printf("SOCKS5: blocking connection to %s — subnet is disabled", targetHost)
		client.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
		return true
	}
	targetConn, err := net.DialTimeout("tcp", net.JoinHostPort(targetHost, fmt.Sprintf("%d", targetPort)), 10*time.Second)
	if err != nil {
		log.Printf("SOCKS5: direct dial to self-target %s:%d failed: %v", targetHost, targetPort, err)
		client.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
		return true
	}
	defer targetConn.Close()
	reply := []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(reply[8:10], targetPort)
	client.Write(reply)
	go func() { io.Copy(targetConn, client); targetConn.Close() }()
	io.Copy(client, targetConn)
	log.Printf("SOCKS5 direct tunnel %s:%d → %s (self-connection, via server routing)", targetHost, targetPort, agentID)
	return true
}

func socks5AgentTunnel(client net.Conn, agentID, routeAgentID, targetHost string, targetPort uint16) {
	connID := uuid.New().String()
	req := ConnectRequest{TargetHost: targetHost, TargetPort: int(targetPort), ConnID: connID, Protocol: "tcp"}
	payload, _ := json.Marshal(req)
	if err := sendControlMessageToAgent(routeAgentID, Message{Type: "connect", Payload: payload, TargetAgentID: routeAgentID}); err != nil {
		log.Printf("Failed to send connect request to agent %s: %v", routeAgentID, err)
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
			log.Printf("Agent %s failed to connect to %s:%d: %s", routeAgentID, targetHost, targetPort, resp.Error)
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
	log.Printf("SOCKS5 %s:%d → %s (via %s, conn %s)", targetHost, targetPort, routeAgentID, agentID, connID)
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

	client.SetReadDeadline(time.Time{})

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
				log.Printf("SOCKS5: target %s owned by agent %s, routing directly instead of via egress %s", targetHost, ownerAgentID, agentID)
			} else {
				log.Printf("SOCKS5: target %s is on egress agent %s's own subnet — will connect directly from server", targetHost, agentID)
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
	if icmpDivertStop != nil {
		close(icmpDivertStop)
		icmpDivertStop = nil
	}
	stopDNSProxy()

	restorePFConf()

	if runtime.GOOS == "freebsd" {
		teardownFreeBSDEpair()
	}

	socksMu.Lock()
	for _, ln := range socksListeners {
		ln.Close()
	}
	socksListeners = make(map[string]net.Listener)
	socksProxies = make(map[string]*SocksProxy)
	socksMu.Unlock()
}

func sendUDPPortUnreachable(clientIP net.IP, target *net.UDPAddr) {

	icmpMsg := make([]byte, 8)
	icmpMsg[0] = 3
	icmpMsg[1] = 3
	cs := icmpChecksum(icmpMsg)
	binary.BigEndian.PutUint16(icmpMsg[2:4], cs)

	totalLen := 20 + len(icmpMsg)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64
	pkt[9] = 1
	if target != nil {
		copy(pkt[12:16], target.IP.To4())
	}
	copy(pkt[16:20], clientIP.To4())
	copy(pkt[20:], icmpMsg)
	cs16 := icmpChecksum(pkt[:20])
	binary.BigEndian.PutUint16(pkt[10:12], cs16)

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return
	}
	defer syscall.Close(fd)
	syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	addr := syscall.SockaddrInet4{Port: 0}
	copy(addr.Addr[:], clientIP.To4())
	syscall.Sendto(fd, pkt, 0, &addr)
}
