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
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

"github.com/gorilla/websocket"
	"github.com/xtaci/smux"
	"github.com/miekg/dns"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// ── Verbose logging ───────────────────────────────────────────────────────────

var verboseMode int32  

func logVerbose(format string, args ...interface{}) {
	if atomic.LoadInt32(&verboseMode) != 0 {
		log.Printf(format, args...)
	}
}

// ── Shared message types ──────────────────────────────────────────────────────

type Message struct {
	Type            string          `json:"type"`
	Payload         json.RawMessage `json:"payload"`
	OriginalAgentID string          `json:"original_agent_id,omitempty"`
	TargetAgentID   string          `json:"target_agent_id,omitempty"`
}

type RegisterMessage struct {
	Subnets     []string `json:"subnets"`
	OS          string   `json:"os"`
	Hostname    string   `json:"hostname"`
	Username    string   `json:"username"`
	HasInternet bool     `json:"has_internet"`
	PrevID      string   `json:"prev_id,omitempty"`
}

type ForwardMessage struct {
	DestinationAgentID string `json:"destination_agent_id"`
	Payload            []byte `json:"payload"`
}

type StartAgentListenerMessage struct {
	ListenerID      string `json:"listener_id"`
	AgentListenPort int    `json:"agent_listen_port"`
	DestinationHost string `json:"destination_host"`
	DestinationPort int    `json:"destination_port"`
	Protocol        string `json:"protocol"`
}

type StopAgentListenerMessage struct {
	ListenerID string `json:"listener_id"`
}

type ConnectRequest struct {
	TargetHost string `json:"target_host"`
	TargetPort int    `json:"target_port"`
	ConnID     string `json:"conn_id"`
	Protocol   string `json:"protocol"`
}

type ConnectResponse struct {
	ConnID  string `json:"conn_id"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

type DataMessage struct {
	ConnID     string `json:"conn_id"`
	Data       []byte `json:"data,omitempty"`
	Close      bool   `json:"close,omitempty"`
	Compressed bool   `json:"z,omitempty"`
}

type ICMPRequest struct {
	Target    string `json:"target"`
	Count     int    `json:"count"`
	TimeoutMs int    `json:"timeout_ms"`
}

type ICMPResponse struct {
	Target  string  `json:"target"`
	Seq     int     `json:"seq"`
	RttMs   float64 `json:"rtt_ms"`
	Success bool    `json:"success"`
	Error   string  `json:"error,omitempty"`
}

type ICMPProxyRequest struct {
	ConnID    string `json:"conn_id"`
	Target    string `json:"target"`
	TimeoutMs int    `json:"timeout_ms"`
}

type ICMPProxyResponse struct {
	ConnID  string  `json:"conn_id"`
	Success bool    `json:"success"`
	RttMs   float64 `json:"rtt_ms"`
	Error   string  `json:"error,omitempty"`
}

 
type AgentFwdOpen struct {
	ConnID     string `json:"conn_id"`
	TargetHost string `json:"target_host"`
	TargetPort int    `json:"target_port"`
}

type AgentFwdAck struct {
	ConnID  string `json:"conn_id"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

var agentFwdConns  sync.Map // stores *agentFwdConn
var agentFwdAckMap sync.Map

// agentFwdConn serializes writes to clientConn so that a concurrent close
// message cannot race past an in-flight data message (yamux delivers each
// message on a separate goroutine, so ordering is not guaranteed at dispatch).
type agentFwdConn struct {
	conn      net.Conn
	writeCh   chan []byte
	closeOnce sync.Once
}

func newAgentFwdConn(conn net.Conn) *agentFwdConn {
	afc := &agentFwdConn{
		conn:    conn,
		writeCh: make(chan []byte, 1024),
	}
	go func() {
		for data := range afc.writeCh {
			conn.Write(data) //nolint:errcheck
		}
		conn.Close()
	}()
	return afc
}

func (a *agentFwdConn) send(data []byte) {
	defer func() { recover() }()
	cp := make([]byte, len(data))
	copy(cp, data)
	select {
	case a.writeCh <- cp:
	default:
		go func() {
			defer func() { recover() }()
			a.writeCh <- cp
		}()
	}
}

func (a *agentFwdConn) close() {
	a.closeOnce.Do(func() { close(a.writeCh) })
}

type PortScanRequest struct {
	Target string `json:"target"`
	Ports  string `json:"ports"`
	Proto  string `json:"proto"`
}

type PortScanResult struct {
	Port  int    `json:"port"`
	Open  bool   `json:"open"`
	Error string `json:"error,omitempty"`
}

type PortScanResponse struct {
	Target  string           `json:"target"`
	Proto   string           `json:"proto"`
	Results []PortScanResult `json:"results"`
	Done    bool             `json:"done"`
}

type PingSweepRequest struct {
	Subnet    string `json:"subnet"`
	TimeoutMs int    `json:"timeout_ms"`
	Workers   int    `json:"workers"`
}

type PingSweepResult struct {
	IP  string `json:"ip"`
	RTT int64  `json:"rtt"`
}

type PingSweepResponse struct {
	Subnet  string            `json:"subnet"`
	Results []PingSweepResult `json:"results"`
}

type DNSRequestMessage struct {
	RequestID uint16 `json:"request_id"`
	Domain    string `json:"domain"`
	QType     uint16 `json:"qtype"`
}

type DNSAnswer struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
	TTL  uint32 `json:"ttl"`
	Data string `json:"data"`
}

type DNSResponseMessage struct {
	RequestID uint16      `json:"request_id"`
	Answers   []DNSAnswer `json:"answers"`
	RCode     int         `json:"rcode"`
}

// ── Encryption ────────────────────────────────────────────────────────────────

var encryptionKeyAtomic atomic.Value  

func getEncryptionKey() []byte {
	if v := encryptionKeyAtomic.Load(); v != nil {
		return v.([]byte)
	}
	return nil
}

func setEncryptionKey(key []byte) {
	cp := make([]byte, len(key))
	copy(cp, key)
	encryptionKeyAtomic.Store(cp)
}

var encryptionKey []byte  

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func generateRandomKey(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// ── Config ────────────────────────────────────────────────────────────────────

type ConfigFile struct {
	Key        string `json:"key"`
	ServerAddr string `json:"server_addr"`
	Mode       string `json:"mode"`
}

var (
	configServerAddr string
	configMode       string
	serverAccessKey  string
)

func loadConfigFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read config: %v", err)
	}
	var cfg ConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("invalid config JSON: %v", err)
	}
	if cfg.Key != "" {
		keyBytes, err := base64.URLEncoding.DecodeString(cfg.Key)
		if err != nil || len(keyBytes) != 32 {
			return fmt.Errorf("config key is invalid (must be base64url-encoded 32 bytes)")
		}
		setEncryptionKey(keyBytes)
		encryptionKey = keyBytes
		serverAccessKey = cfg.Key
	}
	if cfg.ServerAddr != "" {
		configServerAddr = cfg.ServerAddr
	}
	if cfg.Mode != "" {
		configMode = cfg.Mode
	}
	return nil
}

// ── Agent-side globals ────────────────────────────────────────────────────────

var respChanMap sync.Map

var (
	agentSideListeners       = make(map[string]net.Listener)
	agentSideListenersLock   = sync.Mutex{}
	agentSideListenerCancels = make(map[string]context.CancelFunc)

	agentSideUDPListeners     = make(map[string]*net.UDPConn)
	agentSideUDPListenersLock = sync.Mutex{}
)

// ── Subnet discovery ──────────────────────────────────────────────────────────

func probeInternet() bool {
	conn, err := net.DialTimeout("tcp", "8.8.8.8:53", 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func getSubnets() ([]string, error) {
	var subnets []string
	seen := make(map[string]bool)

	addNet := func(ns string) {
		if !seen[ns] {
			seen[ns] = true
			subnets = append(subnets, ns)
		}
	}

	isUseless := func(ip net.IP, mask net.IPMask) bool {
		if ip == nil || ip.IsLoopback() || ip.IsMulticast() {
			return true
		}
		if ip.Equal(net.IPv4zero) {
			return true
		}
		if ip.Equal(net.IPv4bcast) {
			return true
		}
		ones, bits := mask.Size()
		if bits == 32 && ones == 32 {
			return true
		}
		return false
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, i := range interfaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if v, ok := addr.(*net.IPNet); ok {
				if v.IP.To4() != nil && !v.IP.IsLoopback() {
					_, network, _ := net.ParseCIDR(v.String())
					if network != nil && !isUseless(network.IP, network.Mask) {
						addNet(network.String())
					}
				}
			}
		}
	}

	if runtime.GOOS == "linux" {
		out, err := exec.Command("ip", "route", "show").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				fields := strings.Fields(line)
				if len(fields) == 0 || fields[0] == "default" {
					continue
				}
				_, network, err := net.ParseCIDR(fields[0])
				if err != nil || network == nil {
					continue
				}
				if isUseless(network.IP, network.Mask) {
					continue
				}
				addNet(network.String())
			}
		}
	} else if runtime.GOOS == "windows" {
		out, err := exec.Command("route", "print", "-4").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				fields := strings.Fields(line)
				if len(fields) < 3 {
					continue
				}
				if strings.EqualFold(fields[2], "On-link") {
					continue
				}
				ip := net.ParseIP(fields[0])
				mask := net.ParseIP(fields[1])
				if ip == nil || mask == nil {
					continue
				}
				ip4 := ip.To4()
				mask4 := mask.To4()
				if ip4 == nil || mask4 == nil {
					continue
				}
				network := &net.IPNet{
					IP:   ip4.Mask(net.IPMask(mask4)),
					Mask: net.IPMask(mask4),
				}
				if isUseless(network.IP, network.Mask) {
					continue
				}
				addNet(network.String())
			}
		}
	}

	return subnets, nil
}

// ── Ping validation ───────────────────────────────────────────────────────────

var validPingTarget = regexp.MustCompile(
	`^([a-zA-Z0-9\-\.]+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-fA-F0-9:]+)$`,
)

func validatePingTarget(target string) error {
	if len(target) == 0 || len(target) > 253 {
		return fmt.Errorf("invalid target length")
	}
	if !validPingTarget.MatchString(target) {
		return fmt.Errorf("invalid target: illegal characters")
	}
	return nil
}

// ── ICMP ping ─────────────────────────────────────────────────────────────────

func pingIPv4(ip net.IP, req ICMPRequest, send func(ICMPResponse)) {
	conn, err := icmp.ListenPacket("ip4:icmp", "")
	if err != nil {
		execPing(req, send)
		return
	}
	defer conn.Close()
	id := os.Getpid() & 0xffff
	for i := 0; i < req.Count; i++ {
		m := icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 0,
			Body: &icmp.Echo{ID: id, Seq: i + 1, Data: []byte("rosemary-icmp")},
		}
		b, err := m.Marshal(nil)
		if err != nil {
			send(ICMPResponse{Target: req.Target, Seq: i + 1, Success: false, Error: fmt.Sprintf("marshal error: %v", err)})
			continue
		}
		start := time.Now()
		if _, err := conn.WriteTo(b, &net.IPAddr{IP: ip}); err != nil {
			send(ICMPResponse{Target: req.Target, Seq: i + 1, Success: false, Error: fmt.Sprintf("send error: %v", err)})
			continue
		}
		conn.SetReadDeadline(time.Now().Add(time.Duration(req.TimeoutMs) * time.Millisecond))
		buf := make([]byte, 1500)
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			send(ICMPResponse{Target: req.Target, Seq: i + 1, Success: false, Error: fmt.Sprintf("timeout or read error: %v", err)})
			continue
		}
		rm, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			send(ICMPResponse{Target: req.Target, Seq: i + 1, Success: false, Error: fmt.Sprintf("parse error: %v", err)})
			continue
		}
		if rm.Type == ipv4.ICMPTypeEchoReply {
			send(ICMPResponse{Target: req.Target, Seq: i + 1, Success: true, RttMs: float64(time.Since(start).Milliseconds())})
		} else {
			send(ICMPResponse{Target: req.Target, Seq: i + 1, Success: false, Error: fmt.Sprintf("unexpected ICMP type: %v", rm.Type)})
		}
	}
}

func pingIPv6(ip net.IP, req ICMPRequest, send func(ICMPResponse)) {
	conn, err := icmp.ListenPacket("ip6:ipv6-icmp", "")
	if err != nil {
		execPing(req, send)
		return
	}
	defer conn.Close()
	id := os.Getpid() & 0xffff
	for i := 0; i < req.Count; i++ {
		m := icmp.Message{
			Type: ipv6.ICMPTypeEchoRequest, Code: 0,
			Body: &icmp.Echo{ID: id, Seq: i + 1, Data: []byte("rosemary-icmp6")},
		}
		b, err := m.Marshal(nil)
		if err != nil {
			send(ICMPResponse{Target: req.Target, Seq: i + 1, Success: false, Error: fmt.Sprintf("marshal error: %v", err)})
			continue
		}
		start := time.Now()
		if _, err := conn.WriteTo(b, &net.IPAddr{IP: ip}); err != nil {
			send(ICMPResponse{Target: req.Target, Seq: i + 1, Success: false, Error: fmt.Sprintf("send error: %v", err)})
			continue
		}
		conn.SetReadDeadline(time.Now().Add(time.Duration(req.TimeoutMs) * time.Millisecond))
		buf := make([]byte, 1500)
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			send(ICMPResponse{Target: req.Target, Seq: i + 1, Success: false, Error: fmt.Sprintf("timeout or read error: %v", err)})
			continue
		}
		rm, err := icmp.ParseMessage(58, buf[:n])
		if err != nil {
			send(ICMPResponse{Target: req.Target, Seq: i + 1, Success: false, Error: fmt.Sprintf("parse error: %v", err)})
			continue
		}
		if rm.Type == ipv6.ICMPTypeEchoReply {
			send(ICMPResponse{Target: req.Target, Seq: i + 1, Success: true, RttMs: float64(time.Since(start).Milliseconds())})
		} else {
			send(ICMPResponse{Target: req.Target, Seq: i + 1, Success: false, Error: fmt.Sprintf("unexpected ICMPv6 type: %v", rm.Type)})
		}
	}
}

func execPing(req ICMPRequest, send func(ICMPResponse)) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", fmt.Sprintf("%d", req.Count), "-w", fmt.Sprintf("%d", req.TimeoutMs), req.Target)
	} else {
		timeoutSec := req.TimeoutMs / 1000
		if timeoutSec < 1 {
			timeoutSec = 1
		}
		cmd = exec.Command("ping", "-c", fmt.Sprintf("%d", req.Count), "-W", fmt.Sprintf("%d", timeoutSec), req.Target)
	}
	output, err := cmd.Output()
	if err != nil {
		for i := 1; i <= req.Count; i++ {
			send(ICMPResponse{Target: req.Target, Seq: i, Success: false, Error: "host unreachable"})
		}
		return
	}
	parsePingOutput(req, string(output), send)
}

func parsePingOutput(req ICMPRequest, output string, send func(ICMPResponse)) {
	lines := strings.Split(output, "\n")
	seq := 1
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if runtime.GOOS == "windows" {
			if strings.HasPrefix(line, "Reply from") {
				send(ICMPResponse{Target: req.Target, Seq: seq, Success: true, RttMs: parseWindowsRTT(line)})
				seq++
			} else if strings.Contains(line, "timed out") || strings.Contains(line, "unreachable") {
				send(ICMPResponse{Target: req.Target, Seq: seq, Success: false, Error: line})
				seq++
			}
		} else {
			if strings.Contains(line, "bytes from") && strings.Contains(line, "time=") {
				send(ICMPResponse{Target: req.Target, Seq: seq, Success: true, RttMs: parseLinuxRTT(line)})
				seq++
			} else if strings.Contains(line, "no answer") || strings.Contains(line, "100% packet loss") {
				send(ICMPResponse{Target: req.Target, Seq: seq, Success: false, Error: "host unreachable"})
				seq++
			}
		}
	}
}

func parseWindowsRTT(line string) float64 {
	for _, prefix := range []string{"time=", "time<"} {
		idx := strings.Index(line, prefix)
		if idx == -1 {
			continue
		}
		part := line[idx+5:]
		part = strings.Fields(part)[0]
		part = strings.TrimSuffix(part, "ms")
		v, _ := strconv.ParseFloat(part, 64)
		return v
	}
	return 0
}

func parseLinuxRTT(line string) float64 {
	idx := strings.Index(line, "time=")
	if idx == -1 {
		return 0
	}
	fields := strings.Fields(line[idx+5:])
	if len(fields) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(fields[0], 64)
	return v
}

func pingOnce(ipStr string, timeout time.Duration) (bool, float64) {
	network := "ip4:icmp"
	if runtime.GOOS == "windows" {
		network = "udp4"
	}
	c, err := icmp.ListenPacket(network, "0.0.0.0")
	if err != nil {
		return false, 0
	}
	defer c.Close()
	dst := net.ParseIP(ipStr)
	if dst == nil {
		return false, 0
	}
	echo := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: 1, Data: []byte("rosemary-ping-sweep")},
	}
	b, err := echo.Marshal(nil)
	if err != nil {
		return false, 0
	}
	start := time.Now()
	var dstAddr net.Addr
	if network == "udp4" {
		dstAddr = &net.UDPAddr{IP: dst, Zone: ""}
	} else {
		dstAddr = &net.IPAddr{IP: dst}
	}
	if _, err := c.WriteTo(b, dstAddr); err != nil {
		return false, 0
	}
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	reply := make([]byte, 1500)
	n, _, err := c.ReadFrom(reply)
	if err != nil || n == 0 {
		return false, 0
	}
	rm, err := icmp.ParseMessage(1, reply[:n])
	if err != nil {
		return false, 0
	}
	switch rm.Body.(type) {
	case *icmp.Echo:
		return true, time.Since(start).Seconds() * 1000.0
	default:
		return false, 0
	}
}

// ── Ping sweep ────────────────────────────────────────────────────────────────

func doPingSweep(req PingSweepRequest) []PingSweepResult {
	var results []PingSweepResult
	_, ipnet, err := net.ParseCIDR(req.Subnet)
	if err != nil {
		return results
	}
	baseIP := ipnet.IP.To4()
	if baseIP == nil {
		return results
	}
	mask := ipnet.Mask
	startIP := binary.BigEndian.Uint32(baseIP)
	ones, bits := mask.Size()
	hostBits := uint(bits - ones)
	count := uint32(1 << hostBits)

	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 300 * time.Millisecond
	}
	workers := int(req.Workers)
	if workers <= 0 || int(count) < workers {
		workers = int(count)
	}
	if workers < 1 {
		workers = 1
	}

	type job struct{ ipStr string }
	jobs := make(chan job, count)
	resCh := make(chan PingSweepResult, count)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for j := range jobs {
			alive, rtt := tcpPing(j.ipStr, timeout)
			if alive {
				resCh <- PingSweepResult{IP: j.ipStr, RTT: int64(rtt.Milliseconds())}
			}
		}
	}
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go worker()
	}
	for i := uint32(1); i < count-1; i++ {
		ipVal := startIP + i
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, ipVal)
		jobs <- job{ipStr: ip.String()}
	}
	close(jobs)
	go func() { wg.Wait(); close(resCh) }()
	for r := range resCh {
		results = append(results, r)
	}
	sort.Slice(results, func(i, j int) bool {
		return bytes.Compare(net.ParseIP(results[i].IP).To4(), net.ParseIP(results[j].IP).To4()) < 0
	})
	return results
}

func tcpPing(ipStr string, timeout time.Duration) (bool, time.Duration) {
	start := time.Now()
	rawPorts := []string{
		":80", ":443", ":8080", ":8443", ":8000", ":8888",
		":445", ":139", ":2049", ":548",
		":22", ":3389", ":5900", ":5901", ":23",
		":3306", ":5432", ":27017", ":6379",
		":25", ":110", ":143",
		":53", ":67", ":68",
		":161", ":162",
		":1883", ":5683",
		":25565", ":27015",
		":3000", ":5000", ":9000",
		":123", ":5001", ":5002", ":5003", ":5004", ":5005", ":5006", ":5007", ":5008", ":5009",
		":49152", ":49153", ":49154", ":49155", ":49156", ":49157", ":49158", ":49159", ":49160",
		":62078", ":62079", ":62080", ":62081", ":62082",
		":8086", ":8087", ":8088", ":8089", ":8090",
		":8883", ":8884", ":8885", ":8886", ":8887", ":8889",
		":9999", ":10000", ":10001", ":10002", ":10003", ":10004", ":10005",
		":50000", ":50001", ":50002", ":50003", ":50004", ":50005",
	}
	seen := make(map[string]bool, len(rawPorts))
	ports := rawPorts[:0]
	for _, p := range rawPorts {
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	type portResult struct {
		ok  bool
		rtt time.Duration
	}
	ch := make(chan portResult, len(ports))
	const maxConcurrent = 10
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()
			conn, err := net.DialTimeout("tcp", ipStr+target, timeout)
			rtt := time.Since(start)
			if err == nil {
				conn.Close()
				ch <- portResult{ok: true, rtt: rtt}
				return
			}
			ch <- portResult{ok: false}
		}(port)
	}
	go func() { wg.Wait(); close(ch) }()
	for res := range ch {
		if res.ok {
			return true, res.rtt
		}
	}
	return false, 0
}

// ── DNS handler ───────────────────────────────────────────────────────────────

// publicDNSServers is a list of well-known public resolvers used as fallback
// when the system resolver cannot resolve internet-facing domains.
var publicDNSServers = []string{"8.8.8.8:53", "1.1.1.1:53", "8.8.4.4:53"}

// queryPublicDNS sends a DNS query directly to public resolvers (UDP first,
// then TCP) without going through the agent's system resolver.
func queryPublicDNS(domain string, qtype uint16) []DNSAnswer {
	msg := new(dns.Msg)
	msg.SetQuestion(domain, qtype)
	msg.RecursionDesired = true

	for _, server := range publicDNSServers {
		for _, net := range []string{"tcp", "udp"} {
			c := &dns.Client{Net: net, Timeout: 3 * time.Second}
			resp, _, err := c.Exchange(msg, server)
			if err != nil || resp == nil || resp.Rcode != dns.RcodeSuccess {
				continue
			}
			var answers []DNSAnswer
			for _, rr := range resp.Answer {
				hdr := rr.Header()
				ans := DNSAnswer{Name: hdr.Name, Type: hdr.Rrtype, TTL: hdr.Ttl}
				switch v := rr.(type) {
				case *dns.A:
					if qtype == dns.TypeA || qtype == dns.TypeANY {
						ans.Data = v.A.String()
					}
				case *dns.AAAA:
					if qtype == dns.TypeAAAA || qtype == dns.TypeANY {
						ans.Data = v.AAAA.String()
					}
				case *dns.CNAME:
					ans.Data = v.Target
				default:
					continue
				}
				if ans.Data != "" {
					answers = append(answers, ans)
				}
			}
			if len(answers) > 0 {
				return answers
			}
		}
	}
	return nil
}

func handleAgentDNSRequest(agentID string, msg DNSRequestMessage, writeMu *sync.Mutex, wsConn *websocket.Conn, yamuxClient *smux.Session) {
	var answers []DNSAnswer
	domain := strings.TrimSuffix(msg.Domain, ".")
	switch msg.QType {
	case dns.TypeA:
		ips, err := net.LookupIP(domain)
		if err == nil {
			for _, ip := range ips {
				if v4 := ip.To4(); v4 != nil {
					answers = append(answers, DNSAnswer{Name: msg.Domain, Type: dns.TypeA, TTL: 300, Data: v4.String()})
				}
			}
		}
	case dns.TypeAAAA:
		ips, err := net.LookupIP(domain)
		if err == nil {
			for _, ip := range ips {
				if ip.To4() == nil {
					answers = append(answers, DNSAnswer{Name: msg.Domain, Type: dns.TypeAAAA, TTL: 300, Data: ip.String()})
				}
			}
		}
	case dns.TypeCNAME:
		cname, err := net.LookupCNAME(domain)
		if err == nil {
			answers = append(answers, DNSAnswer{Name: msg.Domain, Type: dns.TypeCNAME, TTL: 300, Data: cname})
		}
	}

	// If the system resolver returned nothing, try public DNS directly.
	// This helps when the agent's resolver only covers private/VPN domains.
	if len(answers) == 0 {
		logVerbose("Agent: system resolver failed for %s, trying public DNS", domain)
		if pub := queryPublicDNS(msg.Domain, msg.QType); len(pub) > 0 {
			logVerbose("Agent: public DNS resolved %s (%d answers)", domain, len(pub))
			answers = pub
		} else {
			logVerbose("Agent: public DNS also failed for %s", domain)
		}
	}

	rcode := 0
	if len(answers) == 0 {
		rcode = 3
	}
	resp := DNSResponseMessage{RequestID: msg.RequestID, Answers: answers, RCode: rcode}
	payload, _ := json.Marshal(resp)
	outMsg := Message{Type: "dns_response", Payload: payload, OriginalAgentID: agentID}
	outPayload, _ := json.Marshal(outMsg)
	encrypted, err := encrypt(outPayload, getEncryptionKey())
	if err != nil {
		logVerbose("Agent: encryption error: %v", err)
		return
	}
	agentSend(yamuxClient, wsConn, writeMu, encrypted)
}

// ── Port-forward connection handler ───────────────────────────────────────────

 
func agentFwdGenID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func handleAgentClientConnection(clientConn net.Conn, destinationHost string, destinationPort int, agentAssignedID string, sendEnc func([]byte) error) {
	// Close clientConn on early return (before afc takes ownership).
	// Once afc is created it drains the write channel and closes the conn itself.
	afcOwned := false
	defer func() {
		if !afcOwned {
			clientConn.Close()
		}
	}()

	connID := agentFwdGenID()
	ackCh := make(chan AgentFwdAck, 1)
	agentFwdAckMap.Store(connID, ackCh)
	defer agentFwdAckMap.Delete(connID)

	openMsg := AgentFwdOpen{ConnID: connID, TargetHost: destinationHost, TargetPort: destinationPort}
	openPayload, _ := json.Marshal(openMsg)
	m := Message{Type: "agent_fwd_open", Payload: openPayload, OriginalAgentID: agentAssignedID}
	mp, _ := json.Marshal(m)
	enc, err := encrypt(mp, getEncryptionKey())
	if err != nil {
		logVerbose("Agent %s: fwd encrypt error: %v", agentAssignedID, err)
		return
	}
	if err := sendEnc(enc); err != nil {
		logVerbose("Agent %s: fwd send agent_fwd_open error: %v", agentAssignedID, err)
		return
	}

	var ack AgentFwdAck
	select {
	case ack = <-ackCh:
	case <-time.After(10 * time.Second):
		logVerbose("Agent %s: fwd ack timeout (conn %s)", agentAssignedID, connID)
		return
	}
	if !ack.Success {
		logVerbose("Agent %s: fwd server dial failed: %s", agentAssignedID, ack.Error)
		return
	}

	afc := newAgentFwdConn(clientConn)
	afcOwned = true
	agentFwdConns.Store(connID, afc)
	defer func() {
		agentFwdConns.Delete(connID)
		afc.close()
	}()

	logVerbose("Agent %s: fwd tunnel open %s:%d (conn %s)", agentAssignedID, destinationHost, destinationPort, connID)

	sendFwdData := func(data []byte, closeConn bool) error {
		dm := DataMessage{ConnID: connID, Data: data, Close: closeConn}
		if !closeConn && len(data) > 256 {
			if compressed, ok := compressData(data); ok {
				dm.Data = compressed
				dm.Compressed = true
			}
		}
		p, _ := json.Marshal(dm)
		fwdMsg := Message{Type: "agent_fwd_data", Payload: p, OriginalAgentID: agentAssignedID}
		fmp, _ := json.Marshal(fwdMsg)
		enc, err := encrypt(fmp, getEncryptionKey())
		if err != nil {
			return err
		}
		return sendEnc(enc)
	}

	buf := make([]byte, 32*1024)
	for {
		n, readErr := clientConn.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			if sendErr := sendFwdData(chunk, false); sendErr != nil {
				logVerbose("Agent %s: fwd data send error: %v", agentAssignedID, sendErr)
				return
			}
		}
		if readErr != nil {
			break
		}
	}

	sendFwdData(nil, true) //nolint:errcheck
}

 
func handleAgentUDPListener(pc *net.UDPConn, destHost string, destPort int, agentID string, ctx context.Context) {
	defer pc.Close()

	const udpSessionTimeout = 30 * time.Second
	const bufSize = 65535

	type session struct {
		conn     *net.UDPConn
		lastSeen time.Time
	}

	sessions := make(map[string]*session)
	var mu sync.Mutex

	destAddrStr := net.JoinHostPort(destHost, strconv.Itoa(destPort))
	destUDPAddr, err := net.ResolveUDPAddr("udp", destAddrStr)
	if err != nil {
		logVerbose("Agent %s: UDP fwd bad dest %s: %v", agentID, destAddrStr, err)
		return
	}

	 
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				mu.Lock()
				for key, s := range sessions {
					if time.Since(s.lastSeen) > udpSessionTimeout {
						s.conn.Close()
						delete(sessions, key)
					}
				}
				mu.Unlock()
			}
		}
	}()

	buf := make([]byte, bufSize)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		pc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, clientAddr, err := pc.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		data := make([]byte, n)
		copy(data, buf[:n])
		key := clientAddr.String()

		mu.Lock()
		sess, exists := sessions[key]
		if !exists {
			outConn, err := net.DialUDP("udp", nil, destUDPAddr)
			if err != nil {
				mu.Unlock()
				logVerbose("Agent %s: UDP fwd dial %s failed: %v", agentID, destAddrStr, err)
				continue
			}
			sess = &session{conn: outConn, lastSeen: time.Now()}
			sessions[key] = sess
			logVerbose("Agent %s: UDP fwd new session %s -> %s", agentID, key, destAddrStr)

			 
			go func(outConn *net.UDPConn, clientAddr *net.UDPAddr) {
				rbuf := make([]byte, bufSize)
				for {
					outConn.SetReadDeadline(time.Now().Add(udpSessionTimeout))
					rn, err := outConn.Read(rbuf)
					if err != nil {
						return
					}
					pc.WriteToUDP(rbuf[:rn], clientAddr)
					mu.Lock()
					if s, ok := sessions[key]; ok {
						s.lastSeen = time.Now()
					}
					mu.Unlock()
				}
			}(outConn, clientAddr)
		}
		sess.lastSeen = time.Now()
		mu.Unlock()

		sess.conn.Write(data)
	}
}

// ── Port scan ─────────────────────────────────────────────────────────────────

func doLocalPortScan(req PortScanRequest) []PortScanResult {
	var results []PortScanResult
	parseToken := func(token string) []int {
		token = strings.TrimSpace(token)
		if token == "" {
			return nil
		}
		if strings.Contains(token, "-") {
			parts := strings.SplitN(token, "-", 2)
			s, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			e, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 != nil || err2 != nil || s <= 0 || e < s {
				return nil
			}
			ports := make([]int, 0, e-s+1)
			for p := s; p <= e; p++ {
				ports = append(ports, p)
			}
			return ports
		}
		p, err := strconv.Atoi(token)
		if err != nil || p <= 0 {
			return nil
		}
		return []int{p}
	}
	var allPorts []int
	for _, tok := range strings.Split(req.Ports, ",") {
		if ps := parseToken(tok); ps != nil {
			allPorts = append(allPorts, ps...)
		}
	}
	if len(allPorts) == 0 {
		return results
	}
	numPorts := len(allPorts)
	maxWorkers := 50
	switch {
	case numPorts > 1000:
		maxWorkers = 300
	case numPorts > 100:
		maxWorkers = 150
	}
	timeout := 800 * time.Millisecond
	type job struct{ port int }
	jobs := make(chan job, numPorts)
	resultsCh := make(chan PortScanResult, numPorts)
	var wg sync.WaitGroup

	tcpWorker := func() {
		defer wg.Done()
		for j := range jobs {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(req.Target, fmt.Sprintf("%d", j.port)), timeout)
			if err != nil {
				continue
			}
			conn.Close()
			resultsCh <- PortScanResult{Port: j.port, Open: true}
		}
	}
	udpWorker := func() {
		defer wg.Done()
		for j := range jobs {
			addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(req.Target, fmt.Sprintf("%d", j.port)))
			if err != nil {
				continue
			}
			conn, err := net.DialUDP("udp", nil, addr)
			if err != nil {
				continue
			}
			_, err = conn.Write([]byte("rosemary-udp-scan"))
			if err != nil {
				conn.Close()
				continue
			}
			buf := make([]byte, 1)
			_ = conn.SetReadDeadline(time.Now().Add(timeout))
			_, _, err = conn.ReadFrom(buf)
			conn.Close()
			if err == nil {
				resultsCh <- PortScanResult{Port: j.port, Open: true}
			}
		}
	}

	var workerFunc func()
	if strings.ToLower(req.Proto) == "udp" {
		workerFunc = udpWorker
	} else {
		workerFunc = tcpWorker
	}

	workers := maxWorkers
	if numPorts < workers {
		workers = numPorts
	}
	if workers < 1 {
		workers = 1
	}
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go workerFunc()
	}
	for _, p := range allPorts {
		jobs <- job{port: p}
	}
	close(jobs)
	go func() { wg.Wait(); close(resultsCh) }()
	for r := range resultsCh {
		results = append(results, r)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })
	return results
}


// ── Signal / cleanup ──────────────────────────────────────────────────────────

func notifyShutdownSignals(c chan<- os.Signal) {
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
}

func cleanupAll() {
	// Agent does not manage routes or iptables; nothing to clean up.
}

// ── Entry point ───────────────────────────────────────────────────────────────

func main() {
	modeFlag   := flag.String("m", "agent", "Mode: agent | agent-bind")
	serverAddr := flag.String("s", "localhost:8080", "Server address (agent mode)")
	agentKey   := flag.String("k", "", "Encryption key (base64, must match server)")
	bindAddr   := flag.String("l", "0.0.0.0:9001", "Listen address (agent-bind mode)")
	configFlag := flag.String("c", "", "Path to JSON config file")
	wsPathFlag := flag.String("w", "/ws", "WebSocket path (must match server)")
	background := flag.Bool("b", false, "Run agent in background (detach from terminal)")
	verbose    := flag.Bool("v", false, "Verbose logging")
	flag.Parse()
	if *verbose {
		atomic.StoreInt32(&verboseMode, 1)
	}

	if len(os.Args) == 1 {
		flag.Usage()
		os.Exit(0)
	}

	if *background {
		var args []string
		for _, a := range os.Args[1:] {
			if a == "-b" || a == "--b" {
				continue
			}
			args = append(args, a)
		}
		runBackground(args)
	}

	if *configFlag != "" {
		if err := loadConfigFile(*configFlag); err != nil {
			log.Fatalf("Failed to load config file: %v", err)
		}
		logVerbose("[Config] Loaded from %s", *configFlag)
	}

	resolvedMode := *modeFlag
	if resolvedMode == "agent" && configMode != "" {
		resolvedMode = configMode
	}

	agentStop := make(chan struct{})
	var agentStopOnce sync.Once
	sigChan := make(chan os.Signal, 1)
	notifyShutdownSignals(sigChan)
	go func() {
		<-sigChan
		log.Println("Interrupt received, shutting down...")
		agentStopOnce.Do(func() { close(agentStop) })
		cleanupAll()
		os.Exit(0)
	}()

	switch resolvedMode {
	case "agent":
		resolvedKey := *agentKey
		if resolvedKey == "" {
			resolvedKey = serverAccessKey
		}
		if resolvedKey == "" {
			log.Fatal("Agent requires -k (or 'key' in config.json)")
		}
		resolvedAddr := *serverAddr
		if resolvedAddr == "localhost:8080" && configServerAddr != "" {
			resolvedAddr = configServerAddr
		}
		fmt.Println("Running in agent mode")
		agent(resolvedAddr, resolvedKey, *wsPathFlag, agentStop)

	case "agent-bind":
		resolvedKey := *agentKey
		if resolvedKey == "" {
			resolvedKey = serverAccessKey
		}
		if resolvedKey == "" {
			log.Fatal("agent-bind requires -k (or 'key' in config.json)")
		}
		fmt.Println("Running in agent-bind mode")
		runAgentBind(*bindAddr, resolvedKey, agentStop)

	default:
		fmt.Println("Invalid mode. Use 'agent' or 'agent-bind'")
	}
}
