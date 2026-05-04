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
	"compress/flate"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chzyer/readline"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/xtaci/smux"
	"golang.org/x/time/rate"
)

var serverAccessKey string

const (
	logLevelError int32 = iota
	logLevelWarn
	logLevelInfo
	logLevelDebug
)

var (
	colorReset      = "\033[0m"
	colorBold       = "\033[1m"
	colorDim        = "\033[2m"
	colorRed        = "\033[38;2;220;20;60m"
	colorGreen      = "\033[38;2;46;204;113m"
	colorYellow     = "\033[38;2;255;192;203m"
	colorCyan       = "\033[38;2;95;158;160m"
	colorBoldRed    = "\033[1;38;2;220;20;60m"
	colorBoldGreen  = "\033[1;38;2;46;204;113m"
	colorBoldYellow = "\033[1;38;2;219;112;147m"
	colorBoldCyan   = "\033[1;38;2;95;158;160m"
	colorBoldWhite  = "\033[1;38;2;245;245;220m"
)

var currentLogLevel int32 = logLevelInfo

func logDebug(format string, args ...interface{}) {
	if atomic.LoadInt32(&currentLogLevel) >= logLevelDebug {
		log.Printf("[DEBUG] "+format, args...)
	}
}
func logInfo(format string, args ...interface{}) {
	if atomic.LoadInt32(&currentLogLevel) >= logLevelInfo {
		log.Printf("[INFO]  "+format, args...)
	}
}
func logWarn(format string, args ...interface{}) {
	if atomic.LoadInt32(&currentLogLevel) >= logLevelWarn {
		log.Printf("[WARN]  "+format, args...)
	}
}
func logError(format string, args ...interface{}) {
	log.Printf("[ERROR] "+format, args...)
}

func logVerbose(format string, args ...interface{}) {
	if atomic.LoadInt32(&currentLogLevel) >= logLevelDebug {
		log.Printf(format, args...)
		return
	}

	now := time.Now().Format("2006/01/02 15:04:05")
	appendServerLog(fmt.Sprintf(now+" "+format, args...))
}

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

var socksMu sync.Mutex
var respChanMap sync.Map
var socksListeners = make(map[string]net.Listener)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

var dashboardUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {

			return true
		}
		host := r.Host
		for _, scheme := range []string{"https://", "http://"} {
			if strings.HasPrefix(origin, scheme) && origin[len(scheme):] == host {
				return true
			}
		}
		logWarn("Dashboard WS rejected cross-origin connection: origin=%s host=%s", origin, host)
		return false
	},
}

func isValidHostChar(c rune) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'
}

func validateHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if net.ParseIP(h) != nil {
		return true
	}
	for _, label := range strings.Split(h, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !isValidHostChar(c) {
				return false
			}
		}
	}
	return true
}

func validatePortsString(ports string) bool {
	if len(ports) == 0 || len(ports) > 256 {
		return false
	}
	for _, c := range ports {
		if !((c >= '0' && c <= '9') || c == ',' || c == '-') {
			return false
		}
	}
	return true
}

//go:embed webroot/*
var staticContent embed.FS

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

type StartAgentListenerResponse struct {
	ListenerID string `json:"listener_id"`
	Success    bool   `json:"success"`
	Error      string `json:"error,omitempty"`
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

var pendingICMPProxy sync.Map

type AgentFwdOpen struct {
	ConnID     string `json:"conn_id"`
	TargetHost string `json:"target_host"`
	TargetPort int    `json:"target_port"`
	ClientAddr string `json:"client_addr,omitempty"`
}

type AgentFwdAck struct {
	ConnID  string `json:"conn_id"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

type serverFwdConn struct {
	conn    net.Conn
	agentID string
}

var serverFwdConns sync.Map

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

var socksProxies = make(map[string]*SocksProxy)

type SocksProxy struct {
	ListenerID  string
	LocalPort   int
	AgentID     string
	Connections int
	StartTime   time.Time
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
}

type AgentInfo struct {
	ID             string    `json:"id"`
	Subnets        []string  `json:"subnets"`
	DirectWSConnID string    `json:"direct_ws_conn_id,omitempty"`
	OS             string    `json:"os"`
	Hostname       string    `json:"hostname"`
	Username       string    `json:"username"`
	LastSeen       time.Time `json:"last_seen"`
	ConnectedAt    time.Time `json:"connected_at"`
	Tag            string    `json:"tag,omitempty"`
	HasInternet    bool      `json:"has_internet"`
}

type RoutingTable struct {
	sync.RWMutex
	routes map[string]string
}

type PortForward struct {
	AgentListenPort    int    `json:"agent_listen_port"`
	ListenerID         string `json:"listener_id"`
	DestinationAgentID string `json:"destination_agent_id"`
	DestinationHost    string `json:"destination_host"`
	DestinationPort    int    `json:"destination_port"`
	Protocol           string `json:"protocol"`
}

type PingRecord struct {
	Time    time.Time `json:"time"`
	AgentID string    `json:"agent_id"`
	Target  string    `json:"target"`
	Seq     int       `json:"seq"`
	Success bool      `json:"success"`
	RttMs   float64   `json:"rtt_ms"`
	Error   string    `json:"error,omitempty"`
}

var (
	settingsMu      sync.Mutex
	httpServerMu    sync.Mutex
	currentHTTPPort = 1024
	currentTCPPort  = 1080
	currentUDPPort  = 1081
	currentDNSPort  = 5300
	currentWSPath   = "/ws"
	httpServer      *http.Server
	httpServeMux    *http.ServeMux
)

type ServerSettings struct {
	HTTPPort           int    `json:"http_port"`
	TCPPort            int    `json:"tcp_port"`
	UDPPort            int    `json:"udp_port"`
	DNSPort            int    `json:"dns_port"`
	CurrentKey         string `json:"current_key,omitempty"`
	NewKey             string `json:"new_key,omitempty"`
	Action             string `json:"action,omitempty"`
	SessionIdleMinutes int    `json:"session_idle_minutes,omitempty"`
}

type ConfigFile struct {
	HTTPPort           int    `json:"http_port"`
	TCPPort            int    `json:"tcp_port"`
	UDPPort            int    `json:"udp_port"`
	DNSPort            int    `json:"dns_port"`
	Key                string `json:"key"`
	SessionIdleMinutes int    `json:"session_idle_minutes,omitempty"`
	WSPath             string `json:"ws_path,omitempty"`
}

func applyConfigFilePorts2(cfg ConfigFile) {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	if cfg.HTTPPort > 0 && cfg.HTTPPort <= 65535 {
		currentHTTPPort = cfg.HTTPPort
	}
	if cfg.TCPPort > 0 && cfg.TCPPort <= 65535 {
		currentTCPPort = cfg.TCPPort
	}
	if cfg.UDPPort > 0 && cfg.UDPPort <= 65535 {
		currentUDPPort = cfg.UDPPort
	}
	if cfg.DNSPort > 0 && cfg.DNSPort <= 65535 {
		currentDNSPort = cfg.DNSPort
	}
}

func loadConfigFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read config: %v", err)
	}
	var cfg ConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("invalid config JSON: %v", err)
	}
	applyConfigFilePorts2(cfg)
	if cfg.Key != "" {
		keyBytes, err := base64.URLEncoding.DecodeString(cfg.Key)
		if err != nil || len(keyBytes) != 32 {
			return fmt.Errorf("config key is invalid (must be base64url-encoded 32 bytes)")
		}
		setEncryptionKey(keyBytes)
		encryptionKey = keyBytes
		serverAccessKey = cfg.Key
	}
	if cfg.SessionIdleMinutes >= 0 {
		sessionIdleTimeout = time.Duration(cfg.SessionIdleMinutes) * time.Minute
	}
	if cfg.WSPath != "" {
		settingsMu.Lock()
		currentWSPath = cfg.WSPath
		settingsMu.Unlock()
	}
	return nil
}

func currentConfigFile() ConfigFile {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	idleMin := int(sessionIdleTimeout.Minutes())
	return ConfigFile{
		HTTPPort:           currentHTTPPort,
		TCPPort:            currentTCPPort,
		UDPPort:            currentUDPPort,
		DNSPort:            currentDNSPort,
		Key:                base64.URLEncoding.EncodeToString(encryptionKey),
		SessionIdleMinutes: idleMin,
		WSPath:             currentWSPath,
	}
}

func saveConfigFile(path string) error {
	cfg := currentConfigFile()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

var recentForwardsByAgent sync.Map
var pendingSubnetCleanups sync.Map
var activeSubnetRules sync.Map

func restoreAgentForwards(agentID string) {
	val, ok := recentForwardsByAgent.LoadAndDelete(agentID)
	if !ok {
		return
	}
	forwards := val.([]*PortForward)
	time.Sleep(200 * time.Millisecond)

	connLock.Lock()
	for _, pf := range forwards {
		portForwards[pf.ListenerID] = pf
		portForwardLookup[fmt.Sprintf("%s:%d", pf.DestinationAgentID, pf.AgentListenPort)] = pf.ListenerID
	}
	connLock.Unlock()

	for _, pf := range forwards {
		p, _ := json.Marshal(StartAgentListenerMessage{
			ListenerID:      pf.ListenerID,
			AgentListenPort: pf.AgentListenPort,
			DestinationHost: pf.DestinationHost,
			DestinationPort: pf.DestinationPort,
			Protocol:        pf.Protocol,
		})
		sendControlMessageToAgent(agentID, Message{ //nolint:errcheck
			Type:    "start-agent-listener",
			Payload: p,
		})
		log.Printf(colorBoldGreen+"[+]"+colorReset+" Auto-restored forward :%d → %s:%d for agent "+colorYellow+"%s"+colorReset,
			pf.AgentListenPort, pf.DestinationHost, pf.DestinationPort, agentID)
	}
}

var (
	connections       = make(map[string]*AgentInfo)
	directConnections = make(map[string]*websocket.Conn)

	wsWriteMus        = make(map[string]*sync.Mutex)
	yamuxSessions     = make(map[string]*smux.Session)
	connLock          = sync.Mutex{}
	nextAgentID       = 1
	routingTable      = &RoutingTable{routes: make(map[string]string)}
	portForwards      = make(map[string]*PortForward)
	portForwardLookup = make(map[string]string)

	activeSessions = make(map[string]sessionEntry)
	csrfTokens     = make(map[string]string)
	sessionsMu     sync.RWMutex

	sessionIdleTimeout = 30 * time.Minute

	loginFailures  = make(map[string]*loginFailEntry)
	loginFailureMu sync.Mutex

	disabledSubnets   = make(map[string]bool)
	disabledSubnetsMu sync.Mutex

	subnetOwners      = make(map[string][]string)
	subnetOwnersMu    sync.Mutex
	pendingConns      sync.Map
	pendingUDPConns   sync.Map
	proxyListener     net.Listener
	udpListener       *net.UDPConn
	proxyStarted      bool
	serverIPs         []net.IP
	addedRoutes       []string
	addedIptables     []string
	addedUdpIptables  []string
	addedIcmpIptables []string
	cleanupMu         sync.Mutex

	ipLimiters               = make(map[string]*rate.Limiter)
	ipLimitersMu             sync.Mutex
	agentConnectionsPerIP    = make(map[string]int)
	agentConnectionsPerIPMu  sync.Mutex
	maxAgentConnectionsPerIP = 20
	maxTotalAgents           = 100

	pingHistory   []PingRecord
	pingHistoryMu sync.Mutex

	cliLogMu sync.Mutex
	cliLog   []string

	loginCsrfTokens = make(map[string]loginCsrfEntry)
	loginCsrfMu     sync.Mutex

	agentLastSeen      = make(map[string]time.Time)
	agentLastSeenMu    sync.Mutex
	pendingDNSRequests sync.Map
	listenerStartAcks  sync.Map
	recentAgentIDs     sync.Map
	nextDNSRequestID   uint32
	dnsProxyStarted    bool

	savedSystemDNSServers   []string
	savedSystemDNSServersMu sync.RWMutex

	defaultEgressAgentID string
	defaultEgressMu      sync.RWMutex

	bindConnects   = make(map[string]*bindConnectState)
	bindConnectsMu sync.Mutex
)

type bindConnectState struct {
	cancel   context.CancelFunc
	connID   string
	connIDMu sync.Mutex
}

type loginCsrfEntry struct {
	token  string
	expiry time.Time
}

type sessionEntry struct {
	expiresAt    time.Time
	lastActivity time.Time
}

type loginFailEntry struct {
	count       int
	lockedUntil time.Time
}

func startLoginCsrfCleaner() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			loginCsrfMu.Lock()
			for id, entry := range loginCsrfTokens {
				if now.After(entry.expiry) {
					delete(loginCsrfTokens, id)
				}
			}
			loginCsrfMu.Unlock()
		}
	}()
}

var (
	cliListenersMu sync.Mutex
	cliListeners   = make(map[uint64]chan string)
	cliListenerSeq uint64
)

func appendCliLine(line string) {
	cliLogMu.Lock()
	cliLog = append(cliLog, stripANSI(line))
	cliLogMu.Unlock()

	cliListenersMu.Lock()
	for _, ch := range cliListeners {
		select {
		case ch <- line:
		default:
		}
	}
	cliListenersMu.Unlock()
	triggerDashboardBroadcast()
}

func broadcastToListeners(line string) {
	cliListenersMu.Lock()
	for _, ch := range cliListeners {
		select {
		case ch <- line:
		default:
		}
	}
	cliListenersMu.Unlock()
}

func isNormalCloseError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "websocket: close 1006") ||
		strings.Contains(s, "websocket: close 1000") ||
		strings.Contains(s, "websocket: close 1001") ||
		strings.Contains(s, "EOF") ||
		strings.Contains(s, "connection reset by peer") ||
		strings.Contains(s, "broken pipe")
}

func registerCLIListener(bufSize int) (uint64, chan string) {
	ch := make(chan string, bufSize)
	cliListenersMu.Lock()
	cliListenerSeq++
	id := cliListenerSeq
	cliListeners[id] = ch
	cliListenersMu.Unlock()
	return id, ch
}

func unregisterCLIListener(id uint64) {
	cliListenersMu.Lock()
	delete(cliListeners, id)
	cliListenersMu.Unlock()
}

var (
	dashboardClients   = make(map[*websocket.Conn]bool)
	dashboardClientsMu sync.Mutex
	dashboardDirtyCh   = make(chan struct{}, 1)
)

func triggerDashboardBroadcast() {
	select {
	case dashboardDirtyCh <- struct{}{}:
	default:
	}
}

func buildDashboardPayload() ([]byte, error) {
	connLock.Lock()
	var agentsList []AgentInfo
	for _, agentInfo := range connections {
		copied := *agentInfo
		agentLastSeenMu.Lock()
		if t, ok := agentLastSeen[copied.ID]; ok {
			copied.LastSeen = t
		}
		agentLastSeenMu.Unlock()
		agentTagsMu.Lock()
		copied.Tag = agentTags[copied.ID]
		agentTagsMu.Unlock()
		agentsList = append(agentsList, copied)
	}
	portForwardsList := make([]PortForward, 0, len(portForwards))
	for _, pf := range portForwards {
		portForwardsList = append(portForwardsList, *pf)
	}
	routesCopy := make(map[string]string, len(routingTable.routes))
	for k, v := range routingTable.routes {
		routesCopy[k] = v
	}
	connLock.Unlock()

	pingHistoryMu.Lock()
	historyCopy := make([]PingRecord, len(pingHistory))
	copy(historyCopy, pingHistory)
	pingHistoryMu.Unlock()

	cliLogMu.Lock()
	cliLogCopy := make([]string, len(cliLog))
	copy(cliLogCopy, cliLog)
	cliLogMu.Unlock()

	serverLogMu.Lock()
	serverLogCopy := make([]string, len(serverLog))
	copy(serverLogCopy, serverLog)
	serverLogMu.Unlock()

	disabledSubnetsMu.Lock()
	disabledCopy := make(map[string]bool, len(disabledSubnets))
	for k, v := range disabledSubnets {
		disabledCopy[k] = v
	}
	disabledSubnetsMu.Unlock()

	subnetOwnersMu.Lock()
	ownersCopy := make(map[string][]string, len(subnetOwners))
	for k, v := range subnetOwners {
		ownersCopy[k] = append([]string{}, v...)
	}
	subnetOwnersMu.Unlock()

	reverseForwardsLock.Lock()
	rfList := make([]ReverseForward, 0, len(reverseForwards))
	for _, rf := range reverseForwards {
		rfList = append(rfList, ReverseForward{
			ListenerID: rf.ListenerID,
			ListenPort: rf.ListenPort,
			AgentID:    rf.AgentID,
			TargetHost: rf.TargetHost,
			TargetPort: rf.TargetPort,
		})
	}
	reverseForwardsLock.Unlock()

	type DashboardData struct {
		Agents          []AgentInfo         `json:"agents"`
		RoutingTable    map[string]string   `json:"routing_table"`
		PortForwards    []PortForward       `json:"port_forwards"`
		PingHistory     []PingRecord        `json:"ping_history"`
		CliLog          []string            `json:"cli_log"`
		ServerLog       []string            `json:"server_log"`
		DisabledSubnets map[string]bool     `json:"disabled_subnets"`
		SubnetOwners    map[string][]string `json:"subnet_owners"`
		ReverseForwards []ReverseForward    `json:"reverse_forwards"`
	}
	data := DashboardData{
		Agents:          agentsList,
		RoutingTable:    routesCopy,
		PortForwards:    portForwardsList,
		PingHistory:     historyCopy,
		CliLog:          cliLogCopy,
		ServerLog:       serverLogCopy,
		DisabledSubnets: disabledCopy,
		SubnetOwners:    ownersCopy,
		ReverseForwards: rfList,
	}
	return json.Marshal(data)
}

func broadcastDashboard() {
	payload, err := buildDashboardPayload()
	if err != nil {
		return
	}
	dashboardClientsMu.Lock()
	for ws := range dashboardClients {
		ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := ws.WriteMessage(websocket.TextMessage, payload); err != nil {
			ws.Close()
			delete(dashboardClients, ws)
		}
	}
	dashboardClientsMu.Unlock()
}

func notifyDashboardShutdown() {
	payload := []byte(`{"type":"shutdown"}`)
	dashboardClientsMu.Lock()
	for ws := range dashboardClients {
		ws.SetWriteDeadline(time.Now().Add(2 * time.Second))
		ws.WriteMessage(websocket.TextMessage, payload)
		ws.Close()
		delete(dashboardClients, ws)
	}
	dashboardClientsMu.Unlock()
}

func startDashboardBroadcastLoop() {
	ticker := time.NewTicker(200 * time.Millisecond)
	dirty := false
	for {
		select {
		case <-dashboardDirtyCh:
			dirty = true
		case <-ticker.C:
			if dirty {
				broadcastDashboard()
				dirty = false
			}
		}
	}
}

func handleDashboardWS(w http.ResponseWriter, r *http.Request) {
	ws, err := dashboardUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	dashboardClientsMu.Lock()
	dashboardClients[ws] = true
	dashboardClientsMu.Unlock()

	triggerDashboardBroadcast()

	defer func() {
		dashboardClientsMu.Lock()
		delete(dashboardClients, ws)
		dashboardClientsMu.Unlock()
		ws.Close()
	}()
	for {
		if _, _, err := ws.ReadMessage(); err != nil {
			return
		}
	}
}

var (
	agentTags   = make(map[string]string)
	agentTagsMu sync.Mutex
)

var (
	serverLogMu  sync.Mutex
	serverLog    []string
	serverLogMax = 2000
)

func appendServerLog(line string) {
	serverLogMu.Lock()
	serverLog = append(serverLog, line)
	if len(serverLog) > serverLogMax {
		serverLog = serverLog[len(serverLog)-serverLogMax:]
	}
	serverLogMu.Unlock()
	triggerDashboardBroadcast()
}

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

const asciiArtString = `::::;;:;::::;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;:::::;;:::::::::::::::::::::::::::::::::::,,,,,,,,,,,,,,,,
:::::::::::::::::;;;;;;;;;;;;;;;;;;;;;;::::::;::::::::::::::::::::::::::::::::::,::,,,,,,,,,,,,,,,,,
:::::::::::::::::::::;:::::::::;:::::::::::::::::::::::::::::::::::::::::::::,,,,,,,,,,,,,,,,,,,,,,,
:::::::::::::::::::::;:::::::;::;;;:::::::::::::::::::::::::::::::::::::::::,,,,,,,,,,,,,,,,,,,,,,,,
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::,,:,,,,,,,,,,,,,,,,,,,,,,
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::,:,:,,,,,,,,,,,,,,,,,,,,,
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::,::::,,,::,,,,,,,,,,,,,,,,,
::::::::::::::::::::::::::::;:::::::::::::::::::::::::::::::::::::::::::::::::::::,,,,,,,,,,,,,,,,,,
:::::::::::::::::::::::::::::::::::::::::::::::::::::;;;;:::::::::::::::::::,:::,,,,,,,,,,,,,,,,,,,,
::::::hMMMMMWMf:::vMWMoMWaT::ikWMooMWI:TvvczXYUF:nWoIiIIII:nnF:::::kWMj::::lMMMMMMMb:,xxi;Ii:aMt,,,,
::::::uvI:::;oWI:bWc::::;kMJ:YWQ::::;::fcr:::::::uWMuiIft:nnnF::::dWThMl,:,lWo,,,,FWa,,nxI,,oMi,,,,,
::::::aWf:::lMWiFWk::::::iMM:lhWMoQc:::zWoaaaaw::uWLrnl;;nrInF:::LWu,iMo:::lWo,,,,XWh,,,jxrMa;,,,,,,
::::::aWWWWWWh;:IMo::::::jWh::::::uMWm:zWL:::::::uWL,fnTur:Inf:,rMp,xIuMd,,IWWWWWWMJ,,,,,xMo:,,,,,,,
,:::::aWT,:jWa;::vMov::iQWMl:rmT::,JWb:cWL,::,:::uWL,,Tnj::lnF,IMo:l!!:CWC,lWo,,,mMC,,,,,cWm,,,,,,,,
,:::::bht:::;hhI:::cboMadt:::;JkoMobf::vhhhkkhkJ,xhU:::::::Irf,khi::,,,,whuIhb,,,,vhb,,,,vhL,,,,,,,,
,,,,::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::,,,,,:,,,,,,,,,,,,,,,,,,,,,,,,,,,
,,,,::::::::::::::::::::::::::::::::::::::::::::::::::::::::,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
,,,,,,:::::::::::::::::::::::::::::::::::::,:,,,,,,,:,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
,,,,,,,,,,,,,,,,,,,:,::,,:,,,,,,,,:,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,..,,,,,,
,,,,,,,,,,,,,,,,,,,,,,,,,,,,,:,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,.,,.,,`

func stripANSI(s string) string { return ansiRe.ReplaceAllString(s, "") }

type teeWriter struct{ w io.Writer }

func (t teeWriter) Write(p []byte) (int, error) {
	n, err := t.w.Write(p)
	if n > 0 {
		line := strings.TrimRight(string(p[:n]), "\n")
		if line != "" {
			appendServerLog(stripANSI(line))
		}
	}
	return n, err
}

const (
	authCookieName = "tunnel_auth"
	csrfCookieName = "tunnel_csrf"
	rateLimit      = 5
	rateBurst      = 10
	udpTimeout     = 60 * time.Second

	agentConnectResponseTimeout = 8 * time.Second
)

type pendingConn struct {
	conn      net.Conn
	agentID   string
	writeCh   chan []byte
	closeOnce sync.Once
}

func newPendingConn(conn net.Conn, agentID string) *pendingConn {
	pc := &pendingConn{
		conn:    conn,
		agentID: agentID,
		writeCh: make(chan []byte, 1024),
	}
	go func() {
		for data := range pc.writeCh {
			if _, err := conn.Write(data); err != nil {
				return
			}
		}
	}()
	return pc
}

func (p *pendingConn) send(data []byte) {
	defer func() { recover() }()
	dataCopy := append([]byte(nil), data...)
	select {
	case p.writeCh <- dataCopy:
	default:
		go func() {
			defer func() { recover() }()
			select {
			case p.writeCh <- dataCopy:
			case <-time.After(5 * time.Second):
				p.closeConn()
			}
		}()
	}
}

func (p *pendingConn) closeConn() {
	p.closeOnce.Do(func() {
		p.conn.Close()
		close(p.writeCh)
	})
}

type udpSession struct {
	clientAddr *net.UDPAddr
	remoteAddr *net.UDPAddr
	agentID    string
	connID     string
	expire     time.Time
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

func isPrivileged() bool {
	if runtime.GOOS == "windows" {
		return true
	}
	return os.Geteuid() == 0
}

func disconnectAllAgents() {

	connLock.Lock()
	agentIDs := make([]string, 0, len(connections))
	for id := range connections {
		agentIDs = append(agentIDs, id)
	}
	connLock.Unlock()

	for _, id := range agentIDs {
		disconnectMsg := Message{
			Type:          "disconnect",
			Payload:       []byte(`{}`),
			TargetAgentID: id,
		}
		sendControlMessageToAgent(id, disconnectMsg) //nolint:errcheck
	}

	if len(agentIDs) > 0 {
		time.Sleep(300 * time.Millisecond)
	}

	connLock.Lock()
	defer connLock.Unlock()
	for id, conn := range directConnections {
		conn.Close()
		delete(directConnections, id)
	}
	for id, sess := range yamuxSessions {
		sess.Close()
		delete(yamuxSessions, id)
	}
	for id := range connections {
		delete(connections, id)
	}
	log.Printf(colorBoldYellow + "[!]" + colorReset + " " + colorDim + "[Settings]" + colorReset + " All agents disconnected")
}

func restartHTTPOnPort(newPort int) {
	httpServerMu.Lock()
	defer httpServerMu.Unlock()
	if httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		httpServer.Shutdown(ctx)
	}
	newServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", newPort),
		Handler: httpServeMux,
	}
	httpServer = newServer
	go func() {
		log.Printf(colorBoldGreen+"[+]"+colorReset+" "+colorDim+"[Settings]"+colorReset+" HTTP server listening on port "+colorCyan+"%d"+colorReset, newPort)
		if err := newServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Printf("[Settings] HTTP server error: %v", err)
		}
	}()
}

func restartTCPProxy() {
	if tcpStopChan != nil {
		close(tcpStopChan)
		tcpStopChan = nil
	}
	if proxyListener != nil {
		proxyListener.Close()
		proxyListener = nil
	}
	proxyStarted = false
	time.Sleep(200 * time.Millisecond)
	go startTransparentProxy()
	log.Printf(colorBoldGreen+"[+]"+colorReset+" "+colorDim+"[Settings]"+colorReset+" TCP proxy restarted on port "+colorCyan+"%d"+colorReset, currentTCPPort)
}

func restartUDPProxy() {
	if udpStopChan != nil {
		close(udpStopChan)
		udpStopChan = nil
	}
	if udpListener != nil {
		udpListener.Close()
		udpListener = nil
	}
	time.Sleep(200 * time.Millisecond)
	go startUDPProxy()
	log.Printf(colorBoldGreen+"[+]"+colorReset+" "+colorDim+"[Settings]"+colorReset+" UDP proxy restarted on port "+colorCyan+"%d"+colorReset, currentUDPPort)
}

func restartDNSProxy() {
	stopDNSProxy()
	time.Sleep(200 * time.Millisecond)
	go startDNSProxy()
	log.Printf(colorBoldGreen+"[+]"+colorReset+" "+colorDim+"[Settings]"+colorReset+" DNS proxy restarted on port "+colorCyan+"%d"+colorReset, currentDNSPort)
}

type APIToken struct {
	ID          string     `json:"id"`
	Token       string     `json:"token,omitempty"`
	Name        string     `json:"name"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  time.Time  `json:"last_used_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Permissions []string   `json:"permissions"`
}

var (
	apiTokensMu sync.RWMutex
	apiTokens   = make(map[string]*APIToken)
)

func generateAPIToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "tun_" + base64.URLEncoding.EncodeToString(b), nil
}

func apiTokenMiddleware(perms ...string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				tokenVal := strings.TrimPrefix(authHeader, "Bearer ")
				apiTokensMu.Lock()
				tok, ok := apiTokens[tokenVal]
				if ok {
					if tok.ExpiresAt != nil && time.Now().After(*tok.ExpiresAt) {
						delete(apiTokens, tokenVal)
						ok = false
					} else {
						tok.LastUsedAt = time.Now()
					}
				}
				apiTokensMu.Unlock()
				if !ok {
					w.Header().Set("WWW-Authenticate", `Bearer realm="tunnel-api"`)
					w.Header().Set("Content-Type", "application/json")
					http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
					return
				}
				if len(perms) > 0 {
					allowed := false
					for _, need := range perms {
						for _, have := range tok.Permissions {
							if have == "admin" || have == need {
								allowed = true
								break
							}
						}
						if allowed {
							break
						}
					}
					if !allowed {
						w.Header().Set("Content-Type", "application/json")
						http.Error(w, `{"error":"insufficient_permissions"}`, http.StatusForbidden)
						return
					}
				}
				next.ServeHTTP(w, r)
				return
			}
			if isAuthenticated(r) {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="tunnel-api"`)
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		}
	}
}

func handleAPITokensList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	apiTokensMu.RLock()
	list := make([]*APIToken, 0, len(apiTokens))
	for _, tok := range apiTokens {
		safe := *tok
		safe.Token = ""
		list = append(list, &safe)
	}
	apiTokensMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

func handleAPITokenCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Name        string   `json:"name"`
		Permissions []string `json:"permissions"`
		TTLHours    int      `json:"ttl_hours"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		http.Error(w, `{"error":"name_required"}`, http.StatusBadRequest)
		return
	}
	if len(name) > 64 {
		http.Error(w, `{"error":"name_too_long"}`, http.StatusBadRequest)
		return
	}
	validPerms := map[string]bool{"read": true, "write": true, "admin": true}
	var perms []string
	seen := map[string]bool{}
	for _, p := range req.Permissions {
		if validPerms[p] && !seen[p] {
			perms = append(perms, p)
			seen[p] = true
		}
	}
	if len(perms) == 0 {
		perms = []string{"read"}
	}
	rawToken, err := generateAPIToken()
	if err != nil {
		http.Error(w, `{"error":"generation_failed"}`, http.StatusInternalServerError)
		return
	}
	id, _ := generateSessionToken(8)
	tok := &APIToken{
		ID:          id,
		Token:       rawToken,
		Name:        name,
		CreatedAt:   time.Now(),
		Permissions: perms,
	}
	if req.TTLHours > 0 {
		exp := time.Now().Add(time.Duration(req.TTLHours) * time.Hour)
		tok.ExpiresAt = &exp
	}
	apiTokensMu.Lock()
	apiTokens[rawToken] = tok
	apiTokensMu.Unlock()
	log.Printf("[API] Token created: name=%q id=%s perms=%v ttl_hours=%d", name, id, perms, req.TTLHours)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(tok)
}

func handleAPITokenRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, `{"error":"id_required"}`, http.StatusBadRequest)
		return
	}
	apiTokensMu.Lock()
	var found bool
	for rawToken, tok := range apiTokens {
		if tok.ID == id {
			delete(apiTokens, rawToken)
			found = true
			log.Printf("[API] Token revoked: name=%q id=%s", tok.Name, id)
			break
		}
	}
	apiTokensMu.Unlock()
	if !found {
		http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"revoked": true})
}

func handleAPITokenView(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, `{"error":"id_required"}`, http.StatusBadRequest)
		return
	}
	apiTokensMu.RLock()
	var found *APIToken
	for _, tok := range apiTokens {
		if tok.ID == id {
			cp := *tok
			found = &cp
			break
		}
	}
	apiTokensMu.RUnlock()
	if found == nil {
		http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": found.Token})
}

func handleAPIKeyAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	var req struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Key == "" {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"key_required"}`, http.StatusBadRequest)
		return
	}
	settingsMu.Lock()
	expected := serverAccessKey
	settingsMu.Unlock()
	if subtle.ConstantTimeCompare([]byte(req.Key), []byte(expected)) != 1 {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"invalid_key"}`, http.StatusUnauthorized)
		return
	}
	rawToken, err := generateAPIToken()
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	id, _ := generateSessionToken(8)
	expires := time.Now().Add(24 * time.Hour)
	tok := &APIToken{
		ID:          id,
		Token:       rawToken,
		Name:        "extension-auto",
		CreatedAt:   time.Now(),
		Permissions: []string{"admin"},
		ExpiresAt:   &expires,
	}
	apiTokensMu.Lock()
	apiTokens[rawToken] = tok
	apiTokensMu.Unlock()
	logVerbose("[API] Key-auth token issued: id=%s", id)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":      rawToken,
		"expires_in": int((24 * time.Hour).Seconds()),
	})
}

func resolveAgentIDAndAction(r *http.Request, prefix string) (string, string) {
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	parts := strings.SplitN(rest, "/", 2)
	id := parts[0]
	action := ""
	if len(parts) == 2 {
		action = strings.TrimSuffix(parts[1], "/")
	}
	return id, action
}

func apiAgentMustExist(w http.ResponseWriter, agentID string) bool {
	connLock.Lock()
	_, ok := connections[agentID]
	connLock.Unlock()
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"agent_not_found"}`, http.StatusNotFound)
		return false
	}
	return true
}

func handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	connLock.Lock()
	agentCount := len(connections)
	connLock.Unlock()
	settingsMu.Lock()
	httpPort := currentHTTPPort
	tcpPort := currentTCPPort
	udpPort := currentUDPPort
	dnsPort := currentDNSPort
	settingsMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":        true,
		"agents":    agentCount,
		"http_port": httpPort,
		"tcp_port":  tcpPort,
		"udp_port":  udpPort,
		"dns_port":  dnsPort,
	})
}

func handleAPIAgents(w http.ResponseWriter, r *http.Request) {
	connLock.Lock()
	list := make([]AgentInfo, 0, len(connections))
	for _, info := range connections {
		copied := *info
		agentLastSeenMu.Lock()
		if t, ok := agentLastSeen[copied.ID]; ok {
			copied.LastSeen = t
		}
		agentLastSeenMu.Unlock()
		agentTagsMu.Lock()
		copied.Tag = agentTags[copied.ID]
		agentTagsMu.Unlock()
		list = append(list, copied)
	}
	connLock.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

type RouteEntry struct {
	Subnet   string `json:"subnet"`
	AgentID  string `json:"agent_id"`
	Disabled bool   `json:"disabled"`
}

func handleAPIRoutes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		routingTable.RLock()
		routes := make([]RouteEntry, 0, len(routingTable.routes))
		for subnet, agentID := range routingTable.routes {
			disabledSubnetsMu.Lock()
			disabled := disabledSubnets[subnet]
			disabledSubnetsMu.Unlock()
			routes = append(routes, RouteEntry{Subnet: subnet, AgentID: agentID, Disabled: disabled})
		}
		routingTable.RUnlock()
		json.NewEncoder(w).Encode(routes)

	case http.MethodPatch:
		var req struct {
			Subnet   string `json:"subnet"`
			Disabled bool   `json:"disabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
			return
		}
		if req.Subnet == "" {
			http.Error(w, `{"error":"subnet_required"}`, http.StatusBadRequest)
			return
		}
		routingTable.RLock()
		_, exists := routingTable.routes[req.Subnet]
		routingTable.RUnlock()
		if !exists {
			http.Error(w, `{"error":"subnet_not_found"}`, http.StatusNotFound)
			return
		}
		disabledSubnetsMu.Lock()
		disabledSubnets[req.Subnet] = req.Disabled
		disabledSubnetsMu.Unlock()
		state := "enabled"
		if req.Disabled {
			state = "disabled"
		}
		triggerDashboardBroadcast()
		log.Printf(colorBoldCyan+"[*]"+colorReset+" "+colorDim+"[API]"+colorReset+" Route "+colorYellow+"%s"+colorReset+" %s", req.Subnet, state)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"subnet":   req.Subnet,
			"disabled": req.Disabled,
		})

	default:
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
	}
}

func handleAPIForwardsList(w http.ResponseWriter, r *http.Request) {
	connLock.Lock()
	list := make([]*PortForward, 0, len(portForwards))
	for _, pf := range portForwards {
		list = append(list, pf)
	}
	connLock.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

func handleAPIForwardsCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AgentID    string `json:"agent_id"`
		ListenPort int    `json:"listen_port"`
		TargetHost string `json:"target_host"`
		TargetPort int    `json:"target_port"`
		Protocol   string `json:"protocol"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}
	if req.AgentID == "" || req.ListenPort == 0 || req.TargetHost == "" || req.TargetPort == 0 {
		http.Error(w, `{"error":"agent_id, listen_port, target_host, target_port required"}`, http.StatusBadRequest)
		return
	}
	if req.ListenPort < 1 || req.ListenPort > 65535 {
		http.Error(w, `{"error":"listen_port_out_of_range"}`, http.StatusBadRequest)
		return
	}
	if req.TargetPort < 1 || req.TargetPort > 65535 {
		http.Error(w, `{"error":"target_port_out_of_range"}`, http.StatusBadRequest)
		return
	}
	if !validateHost(req.TargetHost) {
		http.Error(w, `{"error":"invalid_target_host"}`, http.StatusBadRequest)
		return
	}
	if req.Protocol == "" {
		req.Protocol = "tcp"
	}
	connLock.Lock()
	_, ok := connections[req.AgentID]
	connLock.Unlock()
	if !ok {
		http.Error(w, `{"error":"agent_not_found"}`, http.StatusNotFound)
		return
	}
	listenerKey := fmt.Sprintf("%s:%d", req.AgentID, req.ListenPort)
	connLock.Lock()
	_, exists := portForwardLookup[listenerKey]
	connLock.Unlock()
	if exists {
		http.Error(w, `{"error":"port_already_in_use"}`, http.StatusConflict)
		return
	}
	listenerID := uuid.New().String()
	pf := &PortForward{
		AgentListenPort:    req.ListenPort,
		DestinationAgentID: req.AgentID,
		DestinationHost:    req.TargetHost,
		DestinationPort:    req.TargetPort,
		ListenerID:         listenerID,
		Protocol:           req.Protocol,
	}
	connLock.Lock()
	portForwards[listenerID] = pf
	portForwardLookup[listenerKey] = listenerID
	connLock.Unlock()
	startPayload, _ := json.Marshal(StartAgentListenerMessage{
		ListenerID:      listenerID,
		AgentListenPort: req.ListenPort,
		DestinationHost: req.TargetHost,
		DestinationPort: req.TargetPort,
		Protocol:        req.Protocol,
	})
	msg := Message{
		Type:            "start-agent-listener",
		Payload:         startPayload,
		OriginalAgentID: "server",
		TargetAgentID:   req.AgentID,
	}
	if err := startAgentListenerAndWait(req.AgentID, listenerID, msg); err != nil {
		connLock.Lock()
		delete(portForwards, listenerID)
		delete(portForwardLookup, listenerKey)
		connLock.Unlock()
		http.Error(w, fmt.Sprintf(`{"error":"listener_start_failed","detail":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	log.Printf(colorBoldGreen+"[+]"+colorReset+" "+colorDim+"[API]"+colorReset+" Port forward created: agent "+colorYellow+"%s"+colorReset+" :"+colorCyan+"%d"+colorReset+" -> "+colorCyan+"%s:%d"+colorReset, req.AgentID, req.ListenPort, req.TargetHost, req.TargetPort)
	triggerDashboardBroadcast()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(pf)
}

func handleAPIForwardsDelete(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, `{"error":"id_required"}`, http.StatusBadRequest)
		return
	}
	connLock.Lock()
	pf, ok := portForwards[id]
	if !ok {
		connLock.Unlock()
		http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
		return
	}
	delete(portForwards, id)
	delete(portForwardLookup, fmt.Sprintf("%s:%d", pf.DestinationAgentID, pf.AgentListenPort))
	connLock.Unlock()
	stopPayload, _ := json.Marshal(StopAgentListenerMessage{ListenerID: id})
	msg := Message{
		Type:            "stop-agent-listener",
		Payload:         stopPayload,
		OriginalAgentID: "server",
		TargetAgentID:   pf.DestinationAgentID,
	}
	sendControlMessageToAgent(pf.DestinationAgentID, msg)
	log.Printf(colorBoldRed+"[-]"+colorReset+" "+colorDim+"[API]"+colorReset+" Port forward deleted: "+colorDim+"%s"+colorReset, id)
	triggerDashboardBroadcast()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "id": id})
}

func handleAPIForwards(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleAPIForwardsList(w, r)
	case http.MethodPost:
		handleAPIForwardsCreate(w, r)
	case http.MethodDelete:
		handleAPIForwardsDelete(w, r)
	default:
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
	}
}

func handleAPIRForwardsPOST(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AgentID    string `json:"agent_id"`
		ListenPort int    `json:"listen_port"`
		TargetHost string `json:"target_host"`
		TargetPort int    `json:"target_port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}
	if req.AgentID == "" || req.ListenPort == 0 || req.TargetHost == "" || req.TargetPort == 0 {
		http.Error(w, `{"error":"agent_id, listen_port, target_host, target_port required"}`, http.StatusBadRequest)
		return
	}
	if req.ListenPort < 1 || req.ListenPort > 65535 {
		http.Error(w, `{"error":"listen_port_out_of_range"}`, http.StatusBadRequest)
		return
	}
	if req.TargetPort < 1 || req.TargetPort > 65535 {
		http.Error(w, `{"error":"target_port_out_of_range"}`, http.StatusBadRequest)
		return
	}
	if !validateHost(req.TargetHost) {
		http.Error(w, `{"error":"invalid_target_host"}`, http.StatusBadRequest)
		return
	}
	id, err := startReverseForward(req.AgentID, req.ListenPort, req.TargetHost, req.TargetPort)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	log.Printf(colorBoldGreen+"[+]"+colorReset+" "+colorDim+"[API]"+colorReset+" Reverse forward created: :"+colorCyan+"%d"+colorReset+" -> agent "+colorYellow+"%s"+colorReset+" -> "+colorCyan+"%s:%d"+colorReset+" (id:"+colorDim+"%s"+colorReset+")", req.ListenPort, req.AgentID, req.TargetHost, req.TargetPort, id)
	triggerDashboardBroadcast()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "id": id,
		"listen_port": req.ListenPort, "agent_id": req.AgentID,
		"target_host": req.TargetHost, "target_port": req.TargetPort})
}

func handleAPIRForwards(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		reverseForwardsLock.Lock()
		list := make([]ReverseForward, 0, len(reverseForwards))
		for _, rf := range reverseForwards {
			list = append(list, ReverseForward{
				ListenerID: rf.ListenerID,
				ListenPort: rf.ListenPort,
				AgentID:    rf.AgentID,
				TargetHost: rf.TargetHost,
				TargetPort: rf.TargetPort,
			})
		}
		reverseForwardsLock.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)
	case http.MethodPost:
		handleAPIRForwardsPOST(w, r)
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, `{"error":"id_required"}`, http.StatusBadRequest)
			return
		}
		if err := stopReverseForward(id); err != nil {
			http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
			return
		}
		log.Printf(colorBoldRed+"[-]"+colorReset+" "+colorDim+"[API]"+colorReset+" Reverse forward deleted: "+colorDim+"%s"+colorReset, id)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "id": id})
	default:
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
	}
}

func handleAPISocks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		socksMu.Lock()
		list := make([]*SocksProxy, 0, len(socksProxies))
		for _, p := range socksProxies {
			list = append(list, p)
		}
		socksMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)

	case http.MethodPost:
		var req struct {
			AgentID  string `json:"agent_id"`
			Port     int    `json:"port"`
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
			return
		}
		if req.AgentID == "" || req.Port == 0 {
			http.Error(w, `{"error":"agent_id and port required"}`, http.StatusBadRequest)
			return
		}
		if req.Port < 1 || req.Port > 65535 {
			http.Error(w, `{"error":"invalid_port"}`, http.StatusBadRequest)
			return
		}
		connLock.Lock()
		_, ok := connections[req.AgentID]
		connLock.Unlock()
		if !ok {
			http.Error(w, `{"error":"agent_not_found"}`, http.StatusNotFound)
			return
		}
		result := startSocksProxy(req.AgentID, req.Port, req.Username, req.Password)
		log.Printf(colorBoldGreen+"[+]"+colorReset+" "+colorDim+"[API]"+colorReset+" SOCKS proxy started: agent "+colorYellow+"%s"+colorReset+" port "+colorCyan+"%d"+colorReset+" user=%q", req.AgentID, req.Port, req.Username)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "message": strings.TrimSpace(result)})

	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, `{"error":"id_required"}`, http.StatusBadRequest)
			return
		}
		var out strings.Builder
		stopSocksProxy(id, &out)
		msg := strings.TrimSpace(out.String())
		if strings.Contains(strings.ToLower(msg), "not found") {
			http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
			return
		}
		log.Printf(colorBoldRed+"[-]"+colorReset+" "+colorDim+"[API]"+colorReset+" SOCKS proxy stopped: "+colorDim+"%s"+colorReset, id)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "id": id})

	default:
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
	}
}

func handleAPICLI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Cmd string `json:"cmd"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Cmd) == "" {
		http.Error(w, `{"error":"cmd_required"}`, http.StatusBadRequest)
		return
	}
	if isHTTPBlockedCommand(req.Cmd) {
		http.Error(w, `{"error":"command_not_available_over_http"}`, http.StatusForbidden)
		return
	}
	output := handleConsoleCommand(req.Cmd)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"output": output})
}

func applyAPIKeyChangeHelper(req ServerSettings, response map[string]interface{}, w http.ResponseWriter, remoteAddr string) bool {
	if req.Action == "regenerate" {
		newKey := make([]byte, 32)
		rand.Read(newKey)
		setEncryptionKey(newKey)
		encryptionKey = newKey
		newKeyB64 := base64.URLEncoding.EncodeToString(newKey)
		serverAccessKey = newKeyB64
		response["new_key"] = newKeyB64
		response["message"] = "Key regenerated. All agents disconnected."
		log.Printf("[!] Access key regenerated via API (from %s) — all agents disconnected.", remoteAddr)
		go disconnectAllAgents()
	} else if req.NewKey != "" {
		keyBytes, err := base64.URLEncoding.DecodeString(req.NewKey)
		if err != nil || len(keyBytes) != 32 {
			http.Error(w, `{"error":"invalid_key"}`, http.StatusBadRequest)
			return false
		}
		setEncryptionKey(keyBytes)
		encryptionKey = keyBytes
		serverAccessKey = req.NewKey
		response["message"] = "Key updated. All agents disconnected."
		go disconnectAllAgents()
	}
	return true
}

func applyAPIPortUpdate(req ServerSettings) (oldHTTP, oldTCP, oldUDP, oldDNS int) {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	oldHTTP, oldTCP, oldUDP, oldDNS = currentHTTPPort, currentTCPPort, currentUDPPort, currentDNSPort
	if req.HTTPPort > 0 && req.HTTPPort <= 65535 && req.HTTPPort != currentHTTPPort {
		currentHTTPPort = req.HTTPPort
	}
	if req.TCPPort > 0 && req.TCPPort <= 65535 && req.TCPPort != currentTCPPort {
		currentTCPPort = req.TCPPort
		proxyPort = currentTCPPort
	}
	if req.UDPPort > 0 && req.UDPPort <= 65535 && req.UDPPort != currentUDPPort && runtime.GOOS != "windows" {
		currentUDPPort = req.UDPPort
		udpProxyPort = currentUDPPort
	}
	if req.DNSPort > 0 && req.DNSPort <= 65535 && req.DNSPort != currentDNSPort {
		currentDNSPort = req.DNSPort
		dnsLocalPort = currentDNSPort
	}
	return
}

func triggerAPIRestarts(response map[string]interface{}, oldHTTP, oldTCP, oldUDP, oldDNS int) {
	if currentHTTPPort != oldHTTP {
		response["http_restart"] = true
		go func() { time.Sleep(600 * time.Millisecond); restartHTTPOnPort(currentHTTPPort) }()
	}
	if currentTCPPort != oldTCP && isPrivileged() {
		go restartTCPProxy()
		response["tcp_restart"] = true
	}
	if currentUDPPort != oldUDP && isPrivileged() && runtime.GOOS != "windows" {
		go restartUDPProxy()
		response["udp_restart"] = true
	}
	if currentDNSPort != oldDNS && isPrivileged() {
		go restartDNSProxy()
		response["dns_restart"] = true
	}
}

func handleAPISettingsPATCH(w http.ResponseWriter, r *http.Request) {
	var req ServerSettings
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}
	response := map[string]interface{}{"ok": true}
	if !applyAPIKeyChangeHelper(req, response, w, r.RemoteAddr) {
		return
	}
	oldHTTP, oldTCP, oldUDP, oldDNS := applyAPIPortUpdate(req)
	triggerAPIRestarts(response, oldHTTP, oldTCP, oldUDP, oldDNS)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleAPISettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		settingsMu.Lock()
		httpPort := currentHTTPPort
		tcpPort := currentTCPPort
		udpPort := currentUDPPort
		dnsPort := currentDNSPort
		settingsMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"http_port": httpPort,
			"tcp_port":  tcpPort,
			"udp_port":  udpPort,
			"dns_port":  dnsPort,
		})
	case http.MethodPatch:
		handleAPISettingsPATCH(w, r)
	default:
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
	}
}

func handleAPIAgentGet(w http.ResponseWriter, agentID string) {
	connLock.Lock()
	info, ok := connections[agentID]
	if !ok {
		connLock.Unlock()
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"agent_not_found"}`, http.StatusNotFound)
		return
	}
	copied := *info
	connLock.Unlock()
	agentLastSeenMu.Lock()
	if t, ok2 := agentLastSeen[copied.ID]; ok2 {
		copied.LastSeen = t
	}
	agentLastSeenMu.Unlock()
	agentTagsMu.Lock()
	copied.Tag = agentTags[copied.ID]
	agentTagsMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(copied)
}

func handleAPIAgentDisconnect(w http.ResponseWriter, agentID string) {
	connLock.Lock()
	agentInfo, ok := connections[agentID]
	connLock.Unlock()
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"agent_not_found"}`, http.StatusNotFound)
		return
	}
	sendControlMessageToAgent(agentID, Message{Type: "disconnect", Payload: []byte(`{}`), TargetAgentID: agentID})
	connLock.Lock()
	if ws, wsOk := directConnections[agentInfo.DirectWSConnID]; wsOk {
		ws.Close()
	}
	connLock.Unlock()
	log.Printf(colorBoldRed+"[-]"+colorReset+" "+colorDim+"[API]"+colorReset+" Agent "+colorYellow+"%s"+colorReset+" disconnected", agentID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "agent_id": agentID})
}

func handleAPIAgentReconnect(w http.ResponseWriter, agentID string) {
	if !apiAgentMustExist(w, agentID) {
		return
	}
	if err := sendControlMessageToAgent(agentID, Message{Type: "reconnect", Payload: []byte(`{}`), TargetAgentID: agentID}); err != nil {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"send_failed"}`, http.StatusInternalServerError)
		return
	}
	log.Printf(colorBoldCyan+"[*]"+colorReset+" "+colorDim+"[API]"+colorReset+" Agent "+colorYellow+"%s"+colorReset+" reconnect requested", agentID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "agent_id": agentID})
}

func handleAPIAgentTag(w http.ResponseWriter, r *http.Request, agentID string) {
	if !apiAgentMustExist(w, agentID) {
		return
	}
	var req struct {
		Tag string `json:"tag"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}
	tag := strings.TrimSpace(req.Tag)
	if len(tag) > 64 {
		http.Error(w, `{"error":"tag_too_long"}`, http.StatusBadRequest)
		return
	}
	for _, ch := range tag {
		if ch < 0x20 || ch == '<' || ch == '>' || ch == '&' || ch == '"' || ch == '\'' {
			http.Error(w, `{"error":"tag_invalid_characters"}`, http.StatusBadRequest)
			return
		}
	}
	agentTagsMu.Lock()
	if tag == "" {
		delete(agentTags, agentID)
	} else {
		agentTags[agentID] = tag
	}
	agentTagsMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "agent_id": agentID, "tag": tag})
}

func handleAPIAgentPing(w http.ResponseWriter, r *http.Request, agentID string) {
	if !apiAgentMustExist(w, agentID) {
		return
	}
	var req struct {
		Target string `json:"target"`
		Count  int    `json:"count"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}
	if req.Target == "" {
		http.Error(w, `{"error":"target_required"}`, http.StatusBadRequest)
		return
	}
	if req.Count <= 0 || req.Count > 20 {
		req.Count = 4
	}
	payload, _ := json.Marshal(ICMPRequest{Target: req.Target, Count: req.Count, TimeoutMs: 1000})

	listenerID, resultCh := registerCLIListener(req.Count + 4)
	defer unregisterCLIListener(listenerID)

	if err := sendControlMessageToAgent(agentID, Message{
		Type: "icmp-request", Payload: payload,
		OriginalAgentID: "server", TargetAgentID: agentID,
	}); err != nil {
		http.Error(w, `{"error":"send_failed"}`, http.StatusInternalServerError)
		return
	}
	maxWait := time.Duration(req.Count)*(1100*time.Millisecond) + 2*time.Second
	deadline := time.NewTimer(maxWait)
	defer deadline.Stop()
	received := 0
waitPing:
	for received < req.Count {
		select {
		case _, ok := <-resultCh:
			if !ok {
				break waitPing
			}
			received++
		case <-deadline.C:
			break waitPing
		}
	}
	pingHistoryMu.Lock()
	var results []PingRecord
	for _, rec := range pingHistory {
		if rec.AgentID == agentID && rec.Target == req.Target {
			results = append(results, rec)
		}
	}
	pingHistoryMu.Unlock()
	if len(results) > req.Count {
		results = results[len(results)-req.Count:]
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"agent_id": agentID, "target": req.Target,
		"count": req.Count, "results": results,
	})
}

func handleAPIAgentPingSweep(w http.ResponseWriter, r *http.Request, agentID string) {
	if !apiAgentMustExist(w, agentID) {
		return
	}
	var req struct {
		Subnet    string `json:"subnet"`
		TimeoutMs int    `json:"timeout_ms"`
		Workers   int    `json:"workers"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}
	if req.Subnet == "" {
		http.Error(w, `{"error":"subnet_required"}`, http.StatusBadRequest)
		return
	}
	if !isValidCIDR(req.Subnet) {
		http.Error(w, `{"error":"invalid_subnet"}`, http.StatusBadRequest)
		return
	}
	if req.TimeoutMs <= 0 {
		req.TimeoutMs = 300
	}
	if req.Workers <= 0 {
		req.Workers = 100
	}
	payload, _ := json.Marshal(PingSweepRequest{Subnet: req.Subnet, TimeoutMs: req.TimeoutMs, Workers: req.Workers})

	listenerID, resultCh := registerCLIListener(256)
	defer unregisterCLIListener(listenerID)

	if err := sendControlMessageToAgent(agentID, Message{
		Type: "ping-sweep-request", Payload: payload,
		OriginalAgentID: "server", TargetAgentID: agentID,
	}); err != nil {
		http.Error(w, `{"error":"send_failed"}`, http.StatusInternalServerError)
		return
	}
	var lines []string
	sweepTimer := time.NewTimer(30 * time.Second)
	defer sweepTimer.Stop()
sweepWait:
	for {
		select {
		case line, ok := <-resultCh:
			if !ok {
				break sweepWait
			}
			lines = append(lines, line)

			break sweepWait
		case <-sweepTimer.C:
			break sweepWait
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"agent_id": agentID, "subnet": req.Subnet, "output": strings.Join(lines, ""),
	})
}

func handleAPIAgentPortScan(w http.ResponseWriter, r *http.Request, agentID string) {
	if !apiAgentMustExist(w, agentID) {
		return
	}
	var req struct {
		Target string `json:"target"`
		Ports  string `json:"ports"`
		Proto  string `json:"proto"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}
	if req.Target == "" {
		http.Error(w, `{"error":"target_required"}`, http.StatusBadRequest)
		return
	}
	if req.Ports == "" {
		req.Ports = "1-1024"
	}
	req.Proto = strings.ToLower(req.Proto)
	if req.Proto != "tcp" && req.Proto != "udp" {
		req.Proto = "tcp"
	}
	payload, _ := json.Marshal(PortScanRequest{Target: req.Target, Ports: req.Ports, Proto: req.Proto})

	listenerID, resultCh := registerCLIListener(512)
	defer unregisterCLIListener(listenerID)

	if err := sendControlMessageToAgent(agentID, Message{
		Type: "port-scan-request", Payload: payload,
		OriginalAgentID: "server", TargetAgentID: agentID,
	}); err != nil {
		http.Error(w, `{"error":"send_failed"}`, http.StatusInternalServerError)
		return
	}
	lines := collectScanResults(resultCh, 60*time.Second)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"agent_id": agentID, "target": req.Target,
		"ports": req.Ports, "proto": req.Proto,
		"output": strings.Join(lines, ""),
	})
}

func collectScanResults(resultCh <-chan string, timeout time.Duration) []string {
	var lines []string
	scanTimer := time.NewTimer(timeout)
	defer scanTimer.Stop()
scanWait:
	for {
		select {
		case line, ok := <-resultCh:
			if !ok {
				break scanWait
			}
			lines = append(lines, line)
			drainT := time.NewTimer(2 * time.Second)
		drainScan:
			for {
				select {
				case l2, ok2 := <-resultCh:
					if !ok2 {
						drainT.Stop()
						break scanWait
					}
					lines = append(lines, l2)
					drainT.Reset(2 * time.Second)
				case <-drainT.C:
					drainT.Stop()
					break drainScan
				}
			}
			break scanWait
		case <-scanTimer.C:
			break scanWait
		}
	}
	return lines
}

func handleAPIAgentControl(w http.ResponseWriter, r *http.Request) {
	agentID, action := resolveAgentIDAndAction(r, "/api/v1/agents/")
	if agentID == "" {
		http.Error(w, `{"error":"agent_id_required"}`, http.StatusBadRequest)
		return
	}
	if action == "" {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		handleAPIAgentGet(w, agentID)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	switch action {
	case "disconnect":
		handleAPIAgentDisconnect(w, agentID)
	case "reconnect":
		handleAPIAgentReconnect(w, agentID)
	case "tag":
		handleAPIAgentTag(w, r, agentID)
	case "ping":
		handleAPIAgentPing(w, r, agentID)
	case "discover":
		handleAPIAgentPingSweep(w, r, agentID)
	case "portscan":
		handleAPIAgentPortScan(w, r, agentID)
	default:
		http.Error(w, `{"error":"unknown_action"}`, http.StatusNotFound)
	}
}

func handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	settingsMu.Lock()
	defer settingsMu.Unlock()
	currentKeyB64 := base64.URLEncoding.EncodeToString(encryptionKey)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ServerSettings{
		HTTPPort:           currentHTTPPort,
		TCPPort:            currentTCPPort,
		UDPPort:            currentUDPPort,
		DNSPort:            currentDNSPort,
		CurrentKey:         currentKeyB64,
		SessionIdleMinutes: int(sessionIdleTimeout.Minutes()),
	})
}

func applyKeyChange(req ServerSettings, response map[string]interface{}, w http.ResponseWriter) bool {
	if req.Action == "regenerate" {
		newKey := make([]byte, 32)
		rand.Read(newKey)
		setEncryptionKey(newKey)
		encryptionKey = newKey
		response["new_key"] = base64.URLEncoding.EncodeToString(newKey)
		response["message"] = "Key regenerated. All agents disconnected."
		go disconnectAllAgents()
	} else if req.NewKey != "" {
		keyBytes, err := base64.URLEncoding.DecodeString(req.NewKey)
		if err != nil || len(keyBytes) != 32 {
			http.Error(w, "Invalid key: must be base64-encoded 32-byte key", 400)
			return false
		}
		setEncryptionKey(keyBytes)
		encryptionKey = keyBytes
		response["message"] = "Key updated. All agents disconnected."
		response["new_key"] = req.NewKey
		go disconnectAllAgents()
	}
	return true
}

func applyPortSettings(req ServerSettings, response map[string]interface{}) (oldHTTPPort, oldTCPPort, oldUDPPort, oldDNSPort int, needHTTPRestart bool) {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	oldHTTPPort, oldTCPPort, oldUDPPort, oldDNSPort = currentHTTPPort, currentTCPPort, currentUDPPort, currentDNSPort
	if req.HTTPPort > 0 && req.HTTPPort <= 65535 && req.HTTPPort != currentHTTPPort {
		currentHTTPPort = req.HTTPPort
		needHTTPRestart = true
	}
	if req.TCPPort > 0 && req.TCPPort <= 65535 && req.TCPPort != currentTCPPort {
		currentTCPPort = req.TCPPort
		proxyPort = currentTCPPort
	}
	if req.UDPPort > 0 && req.UDPPort <= 65535 && req.UDPPort != currentUDPPort {
		if runtime.GOOS == "windows" {
			response["udp_restart_warning"] = "UDP port change ignored on Windows (proxy uses WinDivert)"
		} else {
			currentUDPPort = req.UDPPort
			udpProxyPort = currentUDPPort
		}
	}
	if req.DNSPort > 0 && req.DNSPort <= 65535 && req.DNSPort != currentDNSPort {
		currentDNSPort = req.DNSPort
		dnsLocalPort = currentDNSPort
	}
	return
}

func applyTCPRestart(req ServerSettings, response map[string]interface{}, oldTCPPort int) {
	if req.TCPPort <= 0 || req.TCPPort > 65535 || req.TCPPort == oldTCPPort {
		return
	}
	if isPrivileged() {
		go restartTCPProxy()
		response["tcp_restart"] = true
		response["new_tcp_port"] = currentTCPPort
		response["old_tcp_port"] = oldTCPPort
	} else {
		response["tcp_restart_warning"] = "TCP port changed but requires root/admin to restart proxy"
	}
}

func applyUDPRestart(req ServerSettings, response map[string]interface{}, oldUDPPort int) {
	if req.UDPPort <= 0 || req.UDPPort > 65535 || req.UDPPort == oldUDPPort || runtime.GOOS == "windows" {
		return
	}
	if isPrivileged() {
		go restartUDPProxy()
		response["udp_restart"] = true
		response["new_udp_port"] = currentUDPPort
		response["old_udp_port"] = oldUDPPort
	} else {
		response["udp_restart_warning"] = "UDP port changed but requires root/admin to restart proxy"
	}
}

func applyDNSRestart(req ServerSettings, response map[string]interface{}, oldDNSPort int) {
	if req.DNSPort <= 0 || req.DNSPort > 65535 || req.DNSPort == oldDNSPort {
		return
	}
	if isPrivileged() {
		go restartDNSProxy()
		response["dns_restart"] = true
		response["new_dns_port"] = currentDNSPort
		response["old_dns_port"] = oldDNSPort
	} else {
		response["dns_restart_warning"] = "DNS port changed but requires root/admin to restart proxy"
	}
}

func applyPortRestarts(req ServerSettings, response map[string]interface{}, needHTTPRestart bool, oldHTTPPort, oldTCPPort, oldUDPPort, oldDNSPort int) {
	if needHTTPRestart {
		response["http_restart"] = true
		response["new_port"] = currentHTTPPort
		response["old_port"] = oldHTTPPort
		go func() {
			time.Sleep(600 * time.Millisecond)
			restartHTTPOnPort(currentHTTPPort)
		}()
	}
	applyTCPRestart(req, response, oldTCPPort)
	applyUDPRestart(req, response, oldUDPPort)
	applyDNSRestart(req, response, oldDNSPort)
}

func handlePostSettings(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	sessionCookie, err := r.Cookie(authCookieName)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	sessionsMu.RLock()
	expectedCSRF, ok := csrfTokens[sessionCookie.Value]
	sessionsMu.RUnlock()
	csrfToken := r.Header.Get("X-CSRF-Token")
	if !ok || csrfToken == "" || csrfToken != expectedCSRF {
		http.Error(w, "Invalid CSRF token", 403)
		return
	}
	var req ServerSettings
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", 400)
		return
	}
	response := map[string]interface{}{"success": true}
	if !applyKeyChange(req, response, w) {
		return
	}
	oldHTTPPort, oldTCPPort, oldUDPPort, oldDNSPort, needHTTPRestart := applyPortSettings(req, response)
	applyPortRestarts(req, response, needHTTPRestart, oldHTTPPort, oldTCPPort, oldUDPPort, oldDNSPort)
	if req.SessionIdleMinutes >= 0 && req.SessionIdleMinutes != int(sessionIdleTimeout.Minutes()) {
		sessionIdleTimeout = time.Duration(req.SessionIdleMinutes) * time.Minute
		response["session_idle_minutes"] = req.SessionIdleMinutes
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

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
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
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
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func compressData(b []byte) ([]byte, bool) {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestSpeed)
	w.Write(b)
	w.Close()
	if buf.Len() >= len(b) {
		return b, false
	}
	return buf.Bytes(), true
}

func decompressData(b []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(b))
	defer r.Close()
	return io.ReadAll(r)
}

func isIPv6Subnet(subnet string) bool {
	return strings.Contains(subnet, ":")
}

func isValidCIDR(subnet string) bool {
	_, _, err := net.ParseCIDR(subnet)
	return err == nil
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := strings.Split(r.RemoteAddr, ":")[0]
		ipLimitersMu.Lock()
		limiter, exists := ipLimiters[ip]
		if !exists {
			limiter = rate.NewLimiter(rate.Limit(rateLimit), rateBurst)
			ipLimiters[ip] = limiter
		}
		ipLimitersMu.Unlock()
		if !limiter.Allow() {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func canAcceptAgentConnection(ip string) bool {

	connLock.Lock()
	totalAgents := len(connections)
	connLock.Unlock()

	agentConnectionsPerIPMu.Lock()
	defer agentConnectionsPerIPMu.Unlock()
	count := agentConnectionsPerIP[ip]
	if count >= maxAgentConnectionsPerIP {
		return false
	}
	if totalAgents >= maxTotalAgents {
		return false
	}
	agentConnectionsPerIP[ip] = count + 1
	return true
}

func releaseAgentConnection(ip string) {
	agentConnectionsPerIPMu.Lock()
	defer agentConnectionsPerIPMu.Unlock()
	if count, ok := agentConnectionsPerIP[ip]; ok && count > 0 {
		agentConnectionsPerIP[ip] = count - 1
	}
}

func generateRandomKey(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func generateSessionToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (rt *RoutingTable) AddRoute(subnet, agentID string) {
	rt.Lock()
	defer rt.Unlock()
	rt.routes[subnet] = agentID

	subnetOwnersMu.Lock()
	owners := subnetOwners[subnet]
	found := false
	for _, id := range owners {
		if id == agentID {
			found = true
			break
		}
	}
	if !found {
		subnetOwners[subnet] = append(owners, agentID)
		if len(subnetOwners[subnet]) > 1 {
			logVerbose(colorBoldYellow+"[!]"+colorReset+" Routing conflict: subnet "+colorCyan+"%s"+colorReset+" claimed by agents: %s",
				subnet, strings.Join(subnetOwners[subnet], ", "))
		}
	}
	subnetOwnersMu.Unlock()
}

func (rt *RoutingTable) RemoveRoute(subnet string) {
	rt.Lock()
	defer rt.Unlock()
	delete(rt.routes, subnet)

	subnetOwnersMu.Lock()
	delete(subnetOwners, subnet)
	subnetOwnersMu.Unlock()
}

func (rt *RoutingTable) FindAgentForIP(ip net.IP) (string, bool) {

	disabledSubnetsMu.Lock()
	disabledSnapshot := make(map[string]bool, len(disabledSubnets))
	for k, v := range disabledSubnets {
		disabledSnapshot[k] = v
	}
	disabledSubnetsMu.Unlock()

	rt.RLock()
	defer rt.RUnlock()
	for subnetStr, agentID := range rt.routes {
		if disabledSnapshot[subnetStr] {
			continue
		}
		_, subnet, err := net.ParseCIDR(subnetStr)
		if err != nil {
			continue
		}
		if subnet.Contains(ip) {
			return agentID, true
		}
	}
	return "", false
}

func captureScutilDNS() []string {
	var result []string
	out, err := exec.Command("scutil", "--dns").CombinedOutput()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "nameserver[") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		ip := strings.TrimSpace(parts[1])
		if net.ParseIP(ip) != nil && !strings.HasPrefix(ip, "127.") && ip != "::1" && !seen[ip] {
			seen[ip] = true
			result = append(result, ip)
		}
	}
	return result
}

func captureResolvConfDNS() []string {
	var result []string
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	allowLoopback := runtime.GOOS == "linux" || runtime.GOOS == "freebsd"
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 && fields[0] == "nameserver" {
			ip := fields[1]
			if net.ParseIP(ip) != nil && ip != "::1" && (allowLoopback || !strings.HasPrefix(ip, "127.")) {
				result = append(result, ip)
			}
		}
	}
	return result
}

func captureSystemDNSServers() {
	var result []string
	if runtime.GOOS == "darwin" {
		result = captureScutilDNS()
	}
	if len(result) == 0 {
		result = captureResolvConfDNS()
	}
	savedSystemDNSServersMu.Lock()
	savedSystemDNSServers = result
	savedSystemDNSServersMu.Unlock()
	if len(result) > 0 {
		logVerbose("Captured system DNS servers for fallback: %v", result)
	}
}

func getSavedSystemDNSServers() []string {
	savedSystemDNSServersMu.RLock()
	defer savedSystemDNSServersMu.RUnlock()
	cp := make([]string, len(savedSystemDNSServers))
	copy(cp, savedSystemDNSServers)
	return cp
}

func getDefaultEgressAgent() string {
	defaultEgressMu.RLock()
	defer defaultEgressMu.RUnlock()
	return defaultEgressAgentID
}

func setDefaultEgressAgent(id string) {
	defaultEgressMu.Lock()
	defer defaultEgressMu.Unlock()
	defaultEgressAgentID = id
}

func autoAssignDefaultEgress(newAgentID string, hasInternet bool) {
	if !hasInternet {
		return
	}
	current := getDefaultEgressAgent()
	if current != "" {
		connLock.Lock()
		_, ok := connections[current]
		connLock.Unlock()
		if ok {
			return
		}
	}
	setDefaultEgressAgent(newAgentID)
	if isPrivileged() {
		if err := reloadDefaultEgressRules(); err != nil {
			log.Printf(colorBoldRed+"[-]"+colorReset+" Failed to install default egress rules: %v", err)
		}
	}
	log.Printf(colorBoldGreen+"[+]"+colorReset+" Default egress agent set to "+colorYellow+"%s"+colorReset, newAgentID)
}

func autoReassignDefaultEgress(removedIDs map[string]bool) {
	current := getDefaultEgressAgent()
	if current == "" || !removedIDs[current] {
		return
	}
	connLock.Lock()
	var next, nextWithInternet string
	for id, info := range connections {
		if nextWithInternet == "" && info.HasInternet {
			nextWithInternet = id
		}
		if next == "" {
			next = id
		}
	}
	connLock.Unlock()
	chosen := nextWithInternet
	if chosen == "" {
		chosen = next
	}
	setDefaultEgressAgent(chosen)
	if isPrivileged() {
		if err := reloadDefaultEgressRules(); err != nil {
			log.Printf(colorBoldRed+"[-]"+colorReset+" Failed to update egress rules: %v", err)
		}
	}
	if chosen != "" {
		log.Printf(colorBoldGreen+"[+]"+colorReset+" Default egress agent reassigned to "+colorYellow+"%s"+colorReset, chosen)
	} else {
		log.Print(colorBoldRed + "[-]" + colorReset + " Default egress agent cleared (no agents remaining)")
	}
}

func (rt *RoutingTable) IsIPBlocked(ip net.IP) bool {
	disabledSubnetsMu.Lock()
	disabledSnapshot := make(map[string]bool, len(disabledSubnets))
	for k, v := range disabledSubnets {
		disabledSnapshot[k] = v
	}
	disabledSubnetsMu.Unlock()

	rt.RLock()
	defer rt.RUnlock()
	for subnetStr := range rt.routes {
		if !disabledSnapshot[subnetStr] {
			continue
		}
		_, subnet, err := net.ParseCIDR(subnetStr)
		if err != nil {
			continue
		}
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

func sendControlMessageToAgent(agentID string, msg Message) error {
	connLock.Lock()
	targetAgentInfo, ok := connections[agentID]
	if !ok {
		connLock.Unlock()
		return fmt.Errorf("target agent %s not found", agentID)
	}
	session, hasYamux := yamuxSessions[targetAgentInfo.DirectWSConnID]
	directWSConn, wsOk := directConnections[targetAgentInfo.DirectWSConnID]
	wsmu, _ := wsWriteMus[targetAgentInfo.DirectWSConnID]
	connLock.Unlock()

	payload, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %v", err)
	}
	encrypted, err := encrypt(payload, getEncryptionKey())
	if err != nil {
		return fmt.Errorf("failed to encrypt message: %v", err)
	}

	if hasYamux && session != nil {
		stream, err := session.OpenStream()
		if err != nil {
			return fmt.Errorf("yamux open stream: %v", err)
		}
		defer stream.Close()
		_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
		l := len(encrypted)
		buf := []byte{byte(l >> 24), byte(l >> 16), byte(l >> 8), byte(l)}
		buf = append(buf, encrypted...)
		_, err = stream.Write(buf)
		_ = stream.SetDeadline(time.Time{})
		return err
	}

	if !wsOk {
		return fmt.Errorf("no connection for agent %s", agentID)
	}

	if wsmu != nil {
		wsmu.Lock()
		defer wsmu.Unlock()
	}
	directWSConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	err = directWSConn.WriteMessage(websocket.BinaryMessage, encrypted)
	directWSConn.SetWriteDeadline(time.Time{})
	return err
}

func startAgentListenerAndWait(agentID, listenerID string, msg Message) error {
	ackCh := make(chan StartAgentListenerResponse, 1)
	listenerStartAcks.Store(listenerID, ackCh)
	defer listenerStartAcks.Delete(listenerID)

	if err := sendControlMessageToAgent(agentID, msg); err != nil {
		return err
	}

	select {
	case ack := <-ackCh:
		if !ack.Success {
			if ack.Error == "" {
				ack.Error = "agent failed to start listener"
			}
			return fmt.Errorf("%s", ack.Error)
		}
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timeout waiting for agent listener confirmation")
	}
}

func subnetContainsServerIP(subnet string) bool {
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return false
	}
	for _, ip := range serverIPs {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

func routeExistsForSubnet(networkStr string) bool {
	switch runtime.GOOS {
	case "linux":
		args := []string{"ip", "route", "show", networkStr}
		if isIPv6Subnet(networkStr) {
			args = []string{"ip", "-6", "route", "show", networkStr}
		}
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			return false
		}
		return strings.TrimSpace(string(out)) != ""
	case "darwin", "freebsd", "openbsd":

		out, err := exec.Command("netstat", "-rn").CombinedOutput()
		if err != nil {
			return false
		}
		ip, ipnet, err := net.ParseCIDR(networkStr)
		if err != nil {
			return false
		}
		_ = ip
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			_, lineNet, err := net.ParseCIDR(fields[0])
			if err != nil {
				continue
			}
			if lineNet.String() == ipnet.String() {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func getDefaultGateway() (string, error) {
	if runtime.GOOS == "freebsd" || runtime.GOOS == "openbsd" {
		return getDefaultGatewayBSD()
	}
	out, err := exec.Command("route", "-n", "get", "default").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("route -n get default: %v - %s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			gw := strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
			if ip := net.ParseIP(gw); ip != nil && ip.To4() != nil {
				return gw, nil
			}
		}
	}
	return "", fmt.Errorf("no IPv4 default gateway found in route output")
}

func parseBSDGatewayLine(out []byte) string {
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

func parseBSDNetstatGW(out []byte) string {
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 &&
			(fields[0] == "default" || fields[0] == "0.0.0.0" || fields[0] == "0.0.0.0/0") {
			if ip := net.ParseIP(fields[1]); ip != nil && ip.To4() != nil {
				return fields[1]
			}
		}
	}
	return ""
}

func parseBSDIfconfigGW(out []byte) string {
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "inet ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		ip := net.ParseIP(fields[1])
		if ip == nil || ip.To4() == nil || ip.IsLoopback() {
			continue
		}
		ip4 := ip.To4()
		var mask net.IPMask
		maskStr := fields[3]
		if strings.HasPrefix(maskStr, "0x") {
			if n, err := strconv.ParseUint(strings.TrimPrefix(maskStr, "0x"), 16, 32); err == nil {
				mask = net.IPMask{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
			}
		} else if m := net.ParseIP(maskStr); m != nil {
			if m4 := m.To4(); m4 != nil {
				mask = net.IPMask(m4)
			}
		}
		if mask == nil {
			continue
		}
		netIP := ip4.Mask(mask)
		ipNet := &net.IPNet{IP: netIP, Mask: mask}
		for _, last := range []byte{1, 2, 254, 253} {
			gw := make(net.IP, 4)
			copy(gw, netIP)
			gw[3] = last
			if !gw.Equal(ip4) && ipNet.Contains(gw) {
				return gw.String()
			}
		}
	}
	return ""
}

func getDefaultGatewayBSD() (string, error) {
	if out, err := exec.Command("route", "get", "default").CombinedOutput(); err == nil {
		if gw := parseBSDGatewayLine(out); gw != "" {
			return gw, nil
		}
	}
	if out, err := exec.Command("route", "get", "0.0.0.0").CombinedOutput(); err == nil {
		if gw := parseBSDGatewayLine(out); gw != "" {
			return gw, nil
		}
	}
	for _, args := range [][]string{{"netstat", "-rn", "-f", "inet"}, {"netstat", "-rn"}} {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			continue
		}
		if gw := parseBSDNetstatGW(out); gw != "" {
			return gw, nil
		}
	}
	if out, err := exec.Command("ifconfig").CombinedOutput(); err == nil {
		if gw := parseBSDIfconfigGW(out); gw != "" {
			return gw, nil
		}
	}
	return "", fmt.Errorf("no IPv4 default gateway found")
}

func addRouteWindows(networkStr string, ipnet *net.IPNet, agentIP string) error {
	mask := net.IP(ipnet.Mask).String()
	cmd := exec.Command("route", "ADD", ipnet.IP.String(), "MASK", mask, agentIP)
	logVerbose("Executing: route ADD %s MASK %s %s", ipnet.IP.String(), mask, agentIP)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add Windows route: %v - %s", err, output)
	}
	logVerbose("Added Windows route: %s via %s", networkStr, agentIP)
	cleanupMu.Lock()
	addedRoutes = append(addedRoutes, networkStr)
	cleanupMu.Unlock()
	return nil
}

func getBSDGateway() string {
	switch runtime.GOOS {
	case "freebsd":
		gw := getFreeBSDEpairGateway()
		if gw == "" {
			logWarn("FreeBSD epair not ready, falling back to lo0 routing")
			setBSDLoopbackRouting()
			return "127.0.0.1"
		}
		return gw
	case "darwin":
		setBSDLoopbackRouting()
		return "127.0.0.1"
	default:
		gw, err := getDefaultGateway()
		if err != nil {
			logWarn("no outbound gateway detected (%v) — routing via lo0", err)
			setBSDLoopbackRouting()
			return "127.0.0.1"
		}
		return gw
	}
}

func addRouteBSD(networkStr string) error {
	if routeExistsForSubnet(networkStr) {
		logVerbose("Route for %s already exists (system-managed), skipping", networkStr)
		cleanupMu.Lock()
		addedRoutes = append(addedRoutes, "skip:"+networkStr)
		cleanupMu.Unlock()
		return nil
	}
	var cmd *exec.Cmd
	if isIPv6Subnet(networkStr) {
		cmd = exec.Command("route", "add", "-inet6", networkStr, "::1")
	} else {
		cmd = exec.Command("route", "add", "-net", networkStr, getBSDGateway())
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add route: %v - %s", err, output)
	}
	logVerbose("Added route: %s via default gateway for pf interception", networkStr)
	cleanupMu.Lock()
	addedRoutes = append(addedRoutes, networkStr)
	cleanupMu.Unlock()
	return nil
}

func addRouteLinux(networkStr, agentIP string) error {
	if routeExistsForSubnet(networkStr) {
		logVerbose("Route for %s already exists in kernel (system-managed), skipping ip route add", networkStr)
		cleanupMu.Lock()
		addedRoutes = append(addedRoutes, "skip:"+networkStr)
		cleanupMu.Unlock()
		return nil
	}
	isV6 := isIPv6Subnet(networkStr)
	ipArgs := []string{"ip"}
	if isV6 {
		ipArgs = []string{"ip", "-6"}
	}
	cmd := exec.Command(ipArgs[0], append(ipArgs[1:], "route", "add", networkStr, "via", agentIP)...)
	output, err := cmd.CombinedOutput()
	if err == nil {
		logVerbose("Added route: %s via %s", networkStr, agentIP)
		cleanupMu.Lock()
		addedRoutes = append(addedRoutes, networkStr)
		cleanupMu.Unlock()
		return nil
	}
	isGWErr := strings.Contains(string(output), "invalid gateway") || strings.Contains(string(output), "Nexthop") ||
		strings.Contains(string(output), "Network unreachable") || strings.Contains(string(output), "no route")
	if !isGWErr {
		return fmt.Errorf("failed to add route: %v - %s", err, output)
	}
	cmd2 := exec.Command(ipArgs[0], append(ipArgs[1:], "route", "add", networkStr, "dev", "lo")...)
	out2, err2 := cmd2.CombinedOutput()
	if err2 != nil {
		if isV6 && (strings.Contains(string(out2), "disabled") || strings.Contains(string(out2), "disable_ipv6")) {
			log.Printf("Warning: skipping IPv6 route %s — IPv6 is disabled on this system", networkStr)
		} else {
			return fmt.Errorf("failed to add route (via agentIP and dev lo both failed): %v - %s", err2, out2)
		}
	} else {
		logVerbose("Added route: %s dev lo (agentIP %s not a direct nexthop)", networkStr, agentIP)
	}
	cleanupMu.Lock()
	addedRoutes = append(addedRoutes, networkStr)
	cleanupMu.Unlock()
	return nil
}

func addRoute(subnet string, agentIP string) error {
	if !isValidCIDR(subnet) {
		return fmt.Errorf("invalid subnet format: %s", subnet)
	}
	if !isValidIP(agentIP) {
		return fmt.Errorf("invalid agent IP: %s", agentIP)
	}
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return fmt.Errorf("invalid subnet: %v", err)
	}
	networkStr := ipnet.String()
	switch runtime.GOOS {
	case "windows":
		return addRouteWindows(networkStr, ipnet, agentIP)
	case "darwin", "freebsd", "openbsd":
		return addRouteBSD(networkStr)
	default:
		return addRouteLinux(networkStr, agentIP)
	}
}

func removeRouteFromSlice(key string) {
	cleanupMu.Lock()
	defer cleanupMu.Unlock()
	for i, r := range addedRoutes {
		if r == key {
			addedRoutes = append(addedRoutes[:i], addedRoutes[i+1:]...)
			return
		}
	}
}

func checkSkipRoute(networkStr string) bool {
	skipKey := "skip:" + networkStr
	cleanupMu.Lock()
	defer cleanupMu.Unlock()
	for i, r := range addedRoutes {
		if r == skipKey {
			addedRoutes = append(addedRoutes[:i], addedRoutes[i+1:]...)
			return true
		}
	}
	return false
}

func removeRoute(subnet string) error {
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		if strings.HasPrefix(subnet, "skip:") {
			actual := strings.TrimPrefix(subnet, "skip:")
			removeRouteFromSlice(subnet)
			removeRouteFromSlice(actual)
			return nil
		}
		return fmt.Errorf("invalid subnet: %v", err)
	}
	networkStr := ipnet.String()

	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("route", "DELETE", ipnet.IP.String())
		output, err := cmd.CombinedOutput()
		if err != nil {
			if !strings.Contains(string(output), "The route was not found") {
				log.Printf("Failed to remove Windows route %s: %v", networkStr, err)
			}
		} else {
			log.Printf("Removed Windows route: %s", networkStr)
		}
		removeRouteFromSlice(networkStr)
		return nil

	case "darwin", "freebsd", "openbsd":
		if checkSkipRoute(networkStr) {
			logVerbose("Skipping kernel route removal for %s (system-managed)", networkStr)
			return nil
		}
		var cmd *exec.Cmd
		if isIPv6Subnet(networkStr) {
			cmd = exec.Command("route", "delete", "-inet6", networkStr)
		} else {
			cmd = exec.Command("route", "delete", "-net", networkStr)
		}
		output, err := cmd.CombinedOutput()
		if err != nil {
			if !strings.Contains(string(output), "not in table") {
				log.Printf("Failed to remove route %s: %v", networkStr, err)
			}
		} else {
			logVerbose("Removed route: %s", networkStr)
		}
		removeRouteFromSlice(networkStr)
		return nil

	default:
		if checkSkipRoute(networkStr) {
			log.Printf("Skipping kernel route removal for %s (system-managed)", networkStr)
			return nil
		}
		cmd := exec.Command("ip", "route", "del", networkStr)
		output, err := cmd.CombinedOutput()
		if err != nil {
			if !strings.Contains(string(output), "No such process") {
				log.Printf("Failed to remove route %s: %v", networkStr, err)
			}
		} else {
			logVerbose("Removed route: %s", networkStr)
		}
		removeRouteFromSlice(networkStr)
		return nil
	}
}

func cleanupAll() {
	log.Println("Cleaning up...")
	var routesToRemove []string
	var iptablesToRemove []string
	var udpIptablesToRemove []string
	var icmpIptablesToRemove []string

	cleanupMu.Lock()
	routesToRemove = append([]string{}, addedRoutes...)
	iptablesToRemove = append([]string{}, addedIptables...)
	udpIptablesToRemove = append([]string{}, addedUdpIptables...)
	icmpIptablesToRemove = append([]string{}, addedIcmpIptables...)
	cleanupMu.Unlock()

	for _, subnet := range routesToRemove {
		if strings.HasPrefix(subnet, "skip:") {
			logVerbose("cleanupAll: skipping kernel route removal for %s (system-managed)", strings.TrimPrefix(subnet, "skip:"))
			continue
		}
		removeRoute(subnet)
	}
	for _, rule := range iptablesToRemove {
		removeIptablesRule(rule)
	}
	for _, rule := range udpIptablesToRemove {
		removeUdpIptablesRule(rule)
	}
	for _, rule := range icmpIptablesToRemove {
		removeIcmpIptablesRule(rule)
	}

	cleanupMu.Lock()
	addedRoutes = nil
	addedIptables = nil
	addedUdpIptables = nil
	addedIcmpIptables = nil
	cleanupMu.Unlock()

	if getDefaultEgressAgent() != "" {
		setDefaultEgressAgent("")
		if err := reloadDefaultEgressRules(); err != nil {
			log.Printf("Warning: failed to remove egress rules on shutdown: %v", err)
		}
	}

	stopDNSProxy()
	stopProxies()
}

func handleConnectBind(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	host := r.FormValue("host")
	port := r.FormValue("port")
	if host == "" || port == "" {
		http.Error(w, "host and port required", http.StatusBadRequest)
		return
	}
	if _, err := strconv.Atoi(port); err != nil {
		http.Error(w, "Invalid port", http.StatusBadRequest)
		return
	}
	addr := fmt.Sprintf("%s:%s", host, port)
	bindConnectsMu.Lock()
	if _, exists := bindConnects[addr]; exists {
		bindConnectsMu.Unlock()
		http.Error(w, fmt.Sprintf("Already connecting/connected to %s", addr), http.StatusConflict)
		return
	}
	bindConnectsMu.Unlock()
	go connectCliToBindAgent(addr)
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "Connecting to bind agent at %s...\n", addr)
}

type BindConnectEntry struct {
	Addr   string `json:"addr"`
	Active bool   `json:"active"`
}

func handleAPIConnectBindPOST(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}
	if req.Host == "" || req.Port == 0 {
		http.Error(w, `{"error":"host and port required"}`, http.StatusBadRequest)
		return
	}
	if req.Port < 1 || req.Port > 65535 {
		http.Error(w, `{"error":"invalid_port"}`, http.StatusBadRequest)
		return
	}
	addr := net.JoinHostPort(req.Host, fmt.Sprintf("%d", req.Port))
	bindConnectsMu.Lock()
	if _, exists := bindConnects[addr]; exists {
		bindConnectsMu.Unlock()
		http.Error(w, `{"error":"already_connecting"}`, http.StatusConflict)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	st := &bindConnectState{cancel: cancel}
	bindConnects[addr] = st
	bindConnectsMu.Unlock()
	go connectCliToBindAgentCtx(ctx, addr, st)
	logVerbose("[API] Bind connect started: %s", addr)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "addr": addr})
}

func handleAPIConnectBindDELETE(w http.ResponseWriter, r *http.Request, addr string) {
	bindConnectsMu.Lock()
	state, ok := bindConnects[addr]
	if ok {
		state.cancel()
		delete(bindConnects, addr)
	}
	bindConnectsMu.Unlock()
	if !ok {
		http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
		return
	}
	if state != nil {
		state.connIDMu.Lock()
		connID := state.connID
		state.connIDMu.Unlock()
		if connID != "" {
			connLock.Lock()
			var agentID string
			for id, info := range connections {
				if info.DirectWSConnID == connID {
					agentID = id
					break
				}
			}
			if sess, ok2 := yamuxSessions[connID]; ok2 {
				sess.Close()
			}
			connLock.Unlock()
			if agentID != "" {
				log.Printf("[API] Bind connect DELETE: disconnecting agent %s (connID %s)", agentID, connID)
			}
		}
	}
	log.Printf("[API] Bind connect stopped: %s", addr)
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "addr": addr})
}

func handleAPIConnectBind(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		bindConnectsMu.Lock()
		list := make([]BindConnectEntry, 0, len(bindConnects))
		for addr := range bindConnects {
			list = append(list, BindConnectEntry{Addr: addr, Active: true})
		}
		bindConnectsMu.Unlock()
		json.NewEncoder(w).Encode(list)
	case http.MethodPost:
		handleAPIConnectBindPOST(w, r)
	case http.MethodDelete:
		addr := r.URL.Query().Get("addr")
		if addr == "" {
			http.Error(w, `{"error":"addr_required"}`, http.StatusBadRequest)
			return
		}
		handleAPIConnectBindDELETE(w, r, addr)
	default:
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
	}
}

func isServerLocalIP(ip net.IP) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

func getServerIPs() []net.IP {
	var ips []net.IP
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Printf("Failed to get server IPs: %v", err)
		return ips
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
				ips = append(ips, ipnet.IP)
			}
		}
	}
	return ips
}

func connectCliToBindAgent(addr string) {
	bindConnectsMu.Lock()
	if _, exists := bindConnects[addr]; exists {
		bindConnectsMu.Unlock()
		appendCliLine(fmt.Sprintf("[!] Already connecting/connected to %s\n", addr))
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	state := &bindConnectState{cancel: cancel}
	bindConnects[addr] = state
	bindConnectsMu.Unlock()
	connectCliToBindAgentCtx(ctx, addr, state)
}

func connectCliToBindAgentCtx(ctx context.Context, addr string, state *bindConnectState) {
	defer func() {
		bindConnectsMu.Lock()
		delete(bindConnects, addr)
		bindConnectsMu.Unlock()
	}()
	for {
		select {
		case <-ctx.Done():
			appendCliLine(fmt.Sprintf("[-] Bind connect to %s cancelled.\n", addr))
			return
		default:
		}

		state.connIDMu.Lock()
		state.connID = ""
		state.connIDMu.Unlock()

		dialer := &net.Dialer{Timeout: 10 * time.Second}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			appendCliLine(fmt.Sprintf("[-] Bind agent %s unreachable: %v, retrying in 5s...\n", addr, err))
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		appendCliLine(fmt.Sprintf("[+] Connected to bind agent at %s\n", addr))
		handleBindAgentConn(conn, state)
		appendCliLine(fmt.Sprintf("[-] Bind agent %s disconnected, retrying in 5s...\n", addr))
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func handleConsoleCommand(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	parts := strings.Fields(line)
	cmd := parts[0]
	var out strings.Builder
	if fn, ok := consoleCmds[cmd]; ok {
		fn(parts, &out)
	} else {
		out.WriteString("Unknown command. Type 'help' for commands.\n")
	}
	return out.String()
}

type ghostTextPainter struct {
	bestMatch func(string) string
}

func (p *ghostTextPainter) Paint(line []rune, pos int) []rune {
	if pos == 0 || pos != len(line) {
		return line
	}
	suggestion := p.bestMatch(string(line))
	if suggestion == "" || len(suggestion) <= len(line) {
		return line
	}
	suffix := suggestion[len(line):]
	n := len([]rune(suffix))
	ghost := "\x1b[2m" + suffix + "\x1b[0m\x1b[" + strconv.Itoa(n) + "D"
	return append(line, []rune(ghost)...)
}

func startREPL() {
	useANSI := runtime.GOOS != "windows"

	prompt := "rosemary> "
	asciiArt := `
    ██████   ██████  ███████ ███████ ███    ███  █████  ██████  ██    ██ 
    ██   ██ ██    ██ ██      ██      ████  ████ ██   ██ ██   ██  ██  ██  
    ██████  ██    ██ ███████ █████   ██ ████ ██ ███████ ██████    ████   
    ██   ██ ██    ██      ██ ██      ██  ██  ██ ██   ██ ██   ██    ██    
    ██   ██  ██████  ███████ ███████ ██      ██ ██   ██ ██   ██    ██    

                                                                    Coded by blue0x1
                                                                    Version: 1.0.4
`

	if useANSI {
		prompt = colorYellow + "rosemary> " + colorReset
		asciiArt = colorYellow + `
    ██████   ██████  ███████ ███████ ███    ███  █████  ██████  ██    ██
    ██   ██ ██    ██ ██      ██      ████  ████ ██   ██ ██   ██  ██  ██
    ██████  ██    ██ ███████ █████   ██ ████ ██ ███████ ██████    ████
    ██   ██ ██    ██      ██ ██      ██  ██  ██ ██   ██ ██   ██    ██
    ██   ██  ██████  ███████ ███████ ██      ██ ██   ██ ██   ██    ██
` + colorDim + `
                                                                    Coded by blue0x1
                                                                    Version: 1.0.4
` + colorReset
	}

	topLevelCmds := []string{
		"help", "agents", "egress", "routes", "forwards", "forward", "rforward",
		"socks", "ping", "discover", "portscan", "reconnect", "disconnect",
		"connect", "tag", "port", "tcp-port", "udp-port", "dns-port",
		"settings", "rotate-key", "load-config", "save-config", "clear",
		"verbose", "token", "exit",
	}

	getAgentIDs := func() []string {
		connLock.Lock()
		defer connLock.Unlock()
		ids := make([]string, 0, len(connections))
		for id := range connections {
			ids = append(ids, id)
		}
		return ids
	}

	agentIDs := func(string) []string { return getAgentIDs() }

	var replHistory []string

	ghostBestMatch := func(input string) string {
		if input == "" {
			return ""
		}
		for _, h := range replHistory {
			if strings.HasPrefix(h, input) {
				return h
			}
		}
		var best string
		for _, cmd := range topLevelCmds {
			if strings.HasPrefix(cmd, input) {
				if best == "" || len(cmd) < len(best) {
					best = cmd
				}
			}
		}
		if best != "" {
			return best
		}
		parts := strings.SplitN(input, " ", 2)
		if len(parts) == 2 {
			for _, id := range getAgentIDs() {
				candidate := parts[0] + " " + id
				if strings.HasPrefix(candidate, input) {
					if best == "" || len(candidate) < len(best) {
						best = candidate
					}
				}
			}
		}
		return best
	}

	completer := readline.NewPrefixCompleter(
		readline.PcItem("help"),
		readline.PcItem("agents", readline.PcItemDynamic(agentIDs)),
		readline.PcItem("egress", readline.PcItemDynamic(agentIDs), readline.PcItem("none")),
		readline.PcItem("routes", readline.PcItem("enable"), readline.PcItem("disable")),
		readline.PcItem("forwards"),
		readline.PcItem("forward", readline.PcItem("add"), readline.PcItem("del")),
		readline.PcItem("rforward", readline.PcItem("add"), readline.PcItem("del"), readline.PcItem("list")),
		readline.PcItem("socks", readline.PcItemDynamic(agentIDs)),
		readline.PcItem("ping", readline.PcItemDynamic(agentIDs)),
		readline.PcItem("discover", readline.PcItemDynamic(agentIDs)),
		readline.PcItem("portscan", readline.PcItemDynamic(agentIDs)),
		readline.PcItem("reconnect", readline.PcItemDynamic(agentIDs)),
		readline.PcItem("disconnect", readline.PcItemDynamic(agentIDs), readline.PcItem("all")),
		readline.PcItem("connect"),
		readline.PcItem("tag", readline.PcItemDynamic(agentIDs)),
		readline.PcItem("port"),
		readline.PcItem("tcp-port"),
		readline.PcItem("udp-port"),
		readline.PcItem("dns-port"),
		readline.PcItem("settings"),
		readline.PcItem("rotate-key"),
		readline.PcItem("load-config"),
		readline.PcItem("save-config"),
		readline.PcItem("verbose"),
		readline.PcItem("token", readline.PcItem("list"), readline.PcItem("create"), readline.PcItem("revoke")),
		readline.PcItem("exit"),
		readline.PcItem("clear"),
	)

	ghostPainter := &ghostTextPainter{bestMatch: ghostBestMatch}

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          prompt,
		AutoComplete:    completer,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		HistoryLimit:    500,
		HistoryFile:     os.ExpandEnv("$HOME/.rosemary_history"),
		Painter:         ghostPainter,
	})
	if err != nil {
		log.Printf("REPL init error: %v", err)
		return
	}

	rl.Config.SetListener(func(line []rune, pos int, key rune) ([]rune, int, bool) {
		const charForward = 6
		if key == charForward && pos == len(line) {
			suggestion := ghostBestMatch(string(line))
			if suggestion != "" && len(suggestion) > len(line) {
				newLine := []rune(suggestion)
				return newLine, len(newLine), true
			}
		}
		return nil, 0, false
	})
	defer rl.Close()

	fmt.Println(asciiArt)
	fmt.Println("Type 'help' for commands.")

	for {
		line, err := rl.Readline()
		if err == readline.ErrInterrupt {
			log.Println("Interrupt received, shutting down...")
			notifyDashboardShutdown()
			time.Sleep(3 * time.Second)
			done := make(chan struct{})
			go func() { cleanupAll(); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				log.Println("Cleanup timed out, forcing exit")
			}
			os.Exit(0)
		}
		if err != nil {
			break
		}
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			replHistory = append([]string{trimmed}, replHistory...)
			if len(replHistory) > 500 {
				replHistory = replHistory[:500]
			}
		}
		out := handleConsoleCommand(line)
		if out != "" {
			if !useANSI {
				out = stripANSI(out)
			}
			fmt.Fprint(os.Stdout, out)
		}
	}
}

var httpBlockedCommands = map[string]bool{
	"load-config": true,
	"save-config": true,
}

func isHTTPBlockedCommand(cmd string) bool {
	verb := strings.ToLower(strings.Fields(strings.TrimSpace(cmd))[0])
	return httpBlockedCommands[verb]
}

func handleCLI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad form", http.StatusBadRequest)
		return
	}
	cmd := strings.TrimSpace(r.FormValue("cmd"))
	if cmd == "" {
		http.Error(w, "cmd required", http.StatusBadRequest)
		return
	}
	if isHTTPBlockedCommand(cmd) {
		http.Error(w, "command not available over HTTP", http.StatusForbidden)
		return
	}
	output := handleConsoleCommand(cmd)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(output))
}

func handlePortScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	agentID := r.FormValue("agentID")
	target := r.FormValue("target")
	ports := r.FormValue("ports")
	proto := r.FormValue("proto")
	if proto == "" {
		proto = "tcp"
	}

	if agentID == "" || target == "" || ports == "" {
		http.Error(w, "agentID, target, and ports required", http.StatusBadRequest)
		return
	}
	if !validateHost(target) {
		http.Error(w, "invalid target", http.StatusBadRequest)
		return
	}
	if !validatePortsString(ports) {
		http.Error(w, "invalid ports format (digits, commas, hyphens only; max 256 chars)", http.StatusBadRequest)
		return
	}
	if proto != "tcp" && proto != "udp" {
		http.Error(w, "proto must be tcp or udp", http.StatusBadRequest)
		return
	}

	connLock.Lock()
	_, ok := connections[agentID]
	connLock.Unlock()
	if !ok {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}

	req := PortScanRequest{
		Target: target,
		Ports:  ports,
		Proto:  proto,
	}
	payload, _ := json.Marshal(req)
	msg := Message{
		Type:            "port-scan-request",
		Payload:         payload,
		OriginalAgentID: "server",
		TargetAgentID:   agentID,
	}

	if err := sendControlMessageToAgent(agentID, msg); err != nil {
		http.Error(w, "Failed to send port-scan-request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("Port scan started"))
}

func handleConfigExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := currentConfigFile()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		http.Error(w, "Failed to encode config", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\"config.json\"")
	w.Write(data)
}

func applyConfigFilePorts(cfg ConfigFile) (needHTTPRestart bool, oldHTTPPort int) {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	oldHTTPPort = currentHTTPPort
	if cfg.HTTPPort > 0 && cfg.HTTPPort <= 65535 && cfg.HTTPPort != currentHTTPPort {
		currentHTTPPort = cfg.HTTPPort
		needHTTPRestart = true
	}
	if cfg.TCPPort > 0 && cfg.TCPPort <= 65535 && cfg.TCPPort != currentTCPPort {
		currentTCPPort = cfg.TCPPort
		proxyPort = currentTCPPort
	}
	if cfg.UDPPort > 0 && cfg.UDPPort <= 65535 && cfg.UDPPort != currentUDPPort && runtime.GOOS != "windows" {
		currentUDPPort = cfg.UDPPort
		udpProxyPort = currentUDPPort
	}
	if cfg.DNSPort > 0 && cfg.DNSPort <= 65535 && cfg.DNSPort != currentDNSPort {
		currentDNSPort = cfg.DNSPort
		dnsLocalPort = currentDNSPort
	}
	return
}

func handleConfigImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	var cfg ConfigFile
	if err := json.Unmarshal(body, &cfg); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if cfg.Key != "" {
		keyBytes, err := base64.URLEncoding.DecodeString(cfg.Key)
		if err != nil || len(keyBytes) != 32 {
			http.Error(w, "Invalid key (must be base64url 32 bytes)", http.StatusBadRequest)
			return
		}
	}
	response := map[string]interface{}{"success": true}
	needHTTPRestart, oldHTTPPort := applyConfigFilePorts(cfg)
	if cfg.Key != "" {
		keyBytes, _ := base64.URLEncoding.DecodeString(cfg.Key)
		setEncryptionKey(keyBytes)
		encryptionKey = keyBytes
		serverAccessKey = cfg.Key
		response["key_updated"] = true
		go disconnectAllAgents()
	}
	if needHTTPRestart {
		response["http_restart"] = true
		response["new_port"] = currentHTTPPort
		response["old_port"] = oldHTTPPort
		go func() {
			time.Sleep(600 * time.Millisecond)
			restartHTTPOnPort(currentHTTPPort)
		}()
	}
	if isPrivileged() {
		go restartTCPProxy()
		go restartUDPProxy()
		go restartDNSProxy()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func initServerKey(agentKey string) {
	if agentKey != "" {
		serverAccessKey = agentKey
		log.Printf("Using provided login key")
	} else if serverAccessKey != "" {
		log.Printf("Using key from config file")
	} else {
		key, _ := generateRandomKey(32)
		serverAccessKey = key
	}
	log.Printf(colorBoldYellow+"Server login key: "+colorReset+colorBoldWhite+"%s"+colorReset, serverAccessKey)
	var err error
	encryptionKey, err = base64.URLEncoding.DecodeString(serverAccessKey)
	if err != nil || len(encryptionKey) != 32 {
		log.Fatalf("Failed to decode encryption key")
	}
	setEncryptionKey(encryptionKey)
}

func startShutdownHandler(sigChan <-chan os.Signal) {
	go func() {
		<-sigChan
		log.Println("Interrupt received, shutting down...")
		notifyDashboardShutdown()
		time.Sleep(3 * time.Second)
		done := make(chan struct{})
		go func() { cleanupAll(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			log.Println("Cleanup timed out, forcing exit")
		}
		os.Exit(0)
	}()
}

func initProxyServices() {
	if isPrivileged() {
		switch runtime.GOOS {
		case "windows":
			logVerbose("Transparent proxy enabled (WinDivert)")
		case "darwin", "freebsd", "openbsd":
			logVerbose("Transparent proxy enabled (pfctl)")
		default:
			logVerbose("Transparent proxy enabled (iptables)")
		}
		go startTransparentProxy()
		go startUDPProxy()
		captureSystemDNSServers()
		go startDNSProxy()
		switch runtime.GOOS {
		case "darwin", "freebsd", "openbsd":
		default:
			go startICMPInterceptor()
		}
	} else {
		logVerbose("Note: Run as Administrator/root for transparent proxy")
	}
}

func startTokenExpiry() {
	go func() {
		for range time.Tick(10 * time.Minute) {
			now := time.Now()
			apiTokensMu.Lock()
			for k, tok := range apiTokens {
				if tok.ExpiresAt != nil && now.After(*tok.ExpiresAt) {
					delete(apiTokens, k)
				}
			}
			apiTokensMu.Unlock()
		}
	}()
}

func detectWSEndpointPath(wsPathFlag string) string {
	wsExplicit := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "ws-path" {
			wsExplicit = true
		}
	})
	wsEndpointPath := wsPathFlag
	if !wsExplicit {
		settingsMu.Lock()
		if currentWSPath != "" {
			wsEndpointPath = currentWSPath
		}
		settingsMu.Unlock()
	}
	if wsEndpointPath == "" {
		wsEndpointPath = "/ws"
	}
	settingsMu.Lock()
	currentWSPath = wsEndpointPath
	settingsMu.Unlock()
	return wsEndpointPath
}

func registerRoutes(wsEndpointPath string, readOnly, writeOp, adminOp func(http.HandlerFunc) http.HandlerFunc) {
	httpServeMux.HandleFunc("/login", rateLimitMiddleware(handleLogin))
	httpServeMux.HandleFunc("/login-post", rateLimitMiddleware(handleLoginPost))
	httpServeMux.HandleFunc(wsEndpointPath, handleConnections)
	log.Printf("Agent WebSocket endpoint: %s", wsEndpointPath)

	subFS, _ := fs.Sub(staticContent, "webroot")
	staticFileServer := http.FileServer(http.FS(subFS))
	noCacheStatic := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		http.StripPrefix("/static/", staticFileServer).ServeHTTP(w, r)
	})
	httpServeMux.Handle("/static/", noCacheStatic)

	httpServeMux.HandleFunc("/port-forward", authMiddleware(csrfValidationMiddleware(rateLimitMiddleware(handlePortForward))))
	httpServeMux.HandleFunc("/stop-port-forward", authMiddleware(csrfValidationMiddleware(rateLimitMiddleware(handleStopPortForward))))
	httpServeMux.HandleFunc("/disconnect-agent", authMiddleware(csrfValidationMiddleware(rateLimitMiddleware(handleDisconnectAgent))))
	httpServeMux.HandleFunc("/api/set-tag", authMiddleware(csrfValidationMiddleware(rateLimitMiddleware(handleSetTag))))
	httpServeMux.HandleFunc("/api/connect-bind", authMiddleware(csrfValidationMiddleware(rateLimitMiddleware(handleConnectBind))))
	httpServeMux.HandleFunc("/api/toggle-subnet", authMiddleware(csrfValidationMiddleware(rateLimitMiddleware(handleToggleSubnet))))
	httpServeMux.HandleFunc("/api/subnet-status", authMiddleware(rateLimitMiddleware(handleSubnetStatus)))
	httpServeMux.HandleFunc("/api/reverse-forward", authMiddleware(csrfValidationMiddleware(rateLimitMiddleware(handleReverseForwardAPI))))
	httpServeMux.HandleFunc("/api/reverse-forwards", authMiddleware(rateLimitMiddleware(handleReverseForwardList)))
	httpServeMux.HandleFunc("/dashboard", authMiddleware(csrfGenerationMiddleware(rateLimitMiddleware(serveDashboard))))
	httpServeMux.HandleFunc("/docs", rateLimitMiddleware(serveDocs))
	httpServeMux.HandleFunc("/api/dashboard-data", apiTokenMiddleware("read")(rateLimitMiddleware(dashboardDataHandler)))
	httpServeMux.HandleFunc("/api/dashboard-ws", authMiddleware(handleDashboardWS))
	httpServeMux.HandleFunc("/api/icmp-ping", authMiddleware(csrfValidationMiddleware(rateLimitMiddleware(handleICMPPing))))
	httpServeMux.HandleFunc("/api/port-scan", authMiddleware(csrfValidationMiddleware(rateLimitMiddleware(handlePortScan))))
	httpServeMux.HandleFunc("/api/cli", authMiddleware(csrfValidationMiddleware(rateLimitMiddleware(handleCLI))))
	httpServeMux.HandleFunc("/logout", authMiddleware(handleLogout))
	httpServeMux.HandleFunc("/api/shutdown", authMiddleware(csrfValidationMiddleware(rateLimitMiddleware(handleShutdown))))

	httpServeMux.HandleFunc("/api/settings", authMiddleware(rateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetSettings(w, r)
		case http.MethodPost:
			handlePostSettings(w, r)
		default:
			http.Error(w, "Method not allowed", 405)
		}
	})))

	httpServeMux.HandleFunc("/api/config/export", authMiddleware(rateLimitMiddleware(handleConfigExport)))
	httpServeMux.HandleFunc("/api/config/import", authMiddleware(csrfValidationMiddleware(rateLimitMiddleware(handleConfigImport))))

	httpServeMux.HandleFunc("/api/tokens", authMiddleware(rateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleAPITokensList(w, r)
		case http.MethodPost:
			handleAPITokenCreate(w, r)
		default:
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		}
	})))
	httpServeMux.HandleFunc("/api/tokens/revoke", authMiddleware(rateLimitMiddleware(handleAPITokenRevoke)))
	httpServeMux.HandleFunc("/api/tokens/view", authMiddleware(rateLimitMiddleware(handleAPITokenView)))

	httpServeMux.HandleFunc("/api/v1/auth", rateLimitMiddleware(handleAPIKeyAuth))

	httpServeMux.HandleFunc("/api/v1/status", readOnly(rateLimitMiddleware(handleAPIStatus)))
	httpServeMux.HandleFunc("/api/v1/agents", readOnly(rateLimitMiddleware(handleAPIAgents)))
	httpServeMux.HandleFunc("/api/v1/routes", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			readOnly(rateLimitMiddleware(handleAPIRoutes))(w, r)
		} else {
			writeOp(rateLimitMiddleware(handleAPIRoutes))(w, r)
		}
	})
	httpServeMux.HandleFunc("/api/v1/forwards", writeOp(rateLimitMiddleware(handleAPIForwards)))
	httpServeMux.HandleFunc("/api/v1/rforwards", writeOp(rateLimitMiddleware(handleAPIRForwards)))
	httpServeMux.HandleFunc("/api/v1/socks", writeOp(rateLimitMiddleware(handleAPISocks)))
	httpServeMux.HandleFunc("/api/v1/connect-bind", adminOp(rateLimitMiddleware(handleAPIConnectBind)))
	httpServeMux.HandleFunc("/api/v1/cli", adminOp(rateLimitMiddleware(handleAPICLI)))
	httpServeMux.HandleFunc("/api/v1/settings", adminOp(rateLimitMiddleware(handleAPISettings)))
	httpServeMux.HandleFunc("/api/v1/tokens", adminOp(rateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleAPITokensList(w, r)
		case http.MethodPost:
			handleAPITokenCreate(w, r)
		default:
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		}
	})))
	httpServeMux.HandleFunc("/api/v1/tokens/revoke", adminOp(rateLimitMiddleware(handleAPITokenRevoke)))
	httpServeMux.HandleFunc("/api/v1/shutdown", adminOp(rateLimitMiddleware(handleShutdown)))

	httpServeMux.HandleFunc("/api/v1/agents/", func(w http.ResponseWriter, r *http.Request) {
		_, action := resolveAgentIDAndAction(r, "/api/v1/agents/")
		if r.Method == http.MethodGet || action == "" {
			readOnly(rateLimitMiddleware(handleAPIAgentControl))(w, r)
		} else {
			writeOp(rateLimitMiddleware(handleAPIAgentControl))(w, r)
		}
	})

	httpServeMux.HandleFunc("/api/socks-data", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		type SocksData struct {
			Proxies []*SocksProxy `json:"proxies"`
		}
		var proxies []*SocksProxy
		socksMu.Lock()
		for _, p := range socksProxies {
			proxies = append(proxies, p)
		}
		socksMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(SocksData{Proxies: proxies})
	}))

	httpServeMux.HandleFunc("/", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	}))
}

func main() {

	initConsole()

	log.SetOutput(teeWriter{w: os.Stderr})

	agentKey := flag.String("key", "", "Encryption key")
	httpPortFlag := flag.Int("port", 1024, "HTTP dashboard port")
	tcpPortFlag := flag.Int("tcp-port", 1080, "TCP proxy port")
	udpPortFlag := flag.Int("udp-port", 1081, "UDP proxy port")
	dnsPortFlag := flag.Int("dns-port", 5300, "DNS proxy port")
	configFlag := flag.String("config", "", "Path to JSON config file (loads ports and key)")
	verboseFlag := flag.Bool("verbose", false, "Enable debug logging")
	wsPathFlag := flag.String("ws-path", "/ws", "WebSocket endpoint path (obfuscation)")

	flag.Parse()

	if *verboseFlag {
		atomic.StoreInt32(&currentLogLevel, logLevelDebug)
	}

	currentHTTPPort = *httpPortFlag
	currentTCPPort = *tcpPortFlag
	currentUDPPort = *udpPortFlag
	currentDNSPort = *dnsPortFlag

	if *configFlag != "" {
		if err := loadConfigFile(*configFlag); err != nil {
			log.Fatalf("Failed to load config file: %v", err)
		}
		log.Printf("[Config] Loaded from %s", *configFlag)
	}

	sigChan := make(chan os.Signal, 1)
	notifyShutdownSignals(sigChan)
	startShutdownHandler(sigChan)

	initServerKey(*agentKey)

	startLoginCsrfCleaner()
	startPreConnSweeper()

	serverIPs = getServerIPs()
	log.Printf(colorBoldCyan+"Server IPs: "+colorReset+colorBoldWhite+"%v"+colorReset, serverIPs)
	log.Printf(colorBoldGreen+"Dashboard: "+colorReset+colorBoldWhite+"http://0.0.0.0:%d"+colorReset, currentHTTPPort)

	initProxyServices()
	go startDashboardBroadcastLoop()
	startTokenExpiry()

	httpServeMux = http.NewServeMux()
	loginCsrfTokens = make(map[string]loginCsrfEntry)

	wsEndpointPath := detectWSEndpointPath(*wsPathFlag)

	readOnly := apiTokenMiddleware("read")
	writeOp := apiTokenMiddleware("write")
	adminOp := apiTokenMiddleware("admin")
	registerRoutes(wsEndpointPath, readOnly, writeOp, adminOp)

	httpServerMu.Lock()
	httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", currentHTTPPort),
		Handler: httpServeMux,
	}
	httpServerMu.Unlock()

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	startREPL()
}

func handleLogout(w http.ResponseWriter, r *http.Request) {

	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
	})

	cookie, err := r.Cookie(authCookieName)
	if err == nil {
		sessionToken := cookie.Value
		connLock.Lock()
		delete(activeSessions, sessionToken)
		connLock.Unlock()
	}

	http.Redirect(w, r, "/login", http.StatusFound)
}

func serveDashboard(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFS(staticContent, "webroot/dashboard.html")
	if err != nil {
		http.Error(w, "Dashboard template error", http.StatusInternalServerError)
		return
	}

	csrfToken := r.Context().Value("csrfToken").(string)

	data := struct{ CSRFToken string }{
		CSRFToken: csrfToken,
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "Render error", http.StatusInternalServerError)
		return
	}
}

func serveDocs(w http.ResponseWriter, r *http.Request) {
	f, err := staticContent.Open("webroot/docs.html")
	if err != nil {
		http.Error(w, "Docs page not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.Copy(w, f)
}

func dashboardDataHandler(w http.ResponseWriter, r *http.Request) {
	connLock.Lock()
	defer connLock.Unlock()
	type DashboardData struct {
		Agents          []AgentInfo         `json:"agents"`
		RoutingTable    map[string]string   `json:"routing_table"`
		PortForwards    []PortForward       `json:"port_forwards"`
		PingHistory     []PingRecord        `json:"ping_history"`
		CliLog          []string            `json:"cli_log"`
		ServerLog       []string            `json:"server_log"`
		DisabledSubnets map[string]bool     `json:"disabled_subnets"`
		SubnetOwners    map[string][]string `json:"subnet_owners"`
		ReverseForwards []ReverseForward    `json:"reverse_forwards"`
	}

	var agentsList []AgentInfo
	for _, agentInfo := range connections {
		copied := *agentInfo
		agentLastSeenMu.Lock()
		if t, ok := agentLastSeen[copied.ID]; ok {
			copied.LastSeen = t
		}
		agentLastSeenMu.Unlock()
		agentTagsMu.Lock()
		copied.Tag = agentTags[copied.ID]
		agentTagsMu.Unlock()
		agentsList = append(agentsList, copied)
	}

	portForwardsList := make([]PortForward, 0, len(portForwards))
	for _, pf := range portForwards {
		portForwardsList = append(portForwardsList, *pf)
	}

	pingHistoryMu.Lock()
	historyCopy := make([]PingRecord, len(pingHistory))
	copy(historyCopy, pingHistory)
	pingHistoryMu.Unlock()

	cliLogMu.Lock()
	cliLogCopy := make([]string, len(cliLog))
	copy(cliLogCopy, cliLog)
	cliLogMu.Unlock()

	serverLogMu.Lock()
	serverLogCopy := make([]string, len(serverLog))
	copy(serverLogCopy, serverLog)
	serverLogMu.Unlock()

	disabledSubnetsMu.Lock()
	disabledCopy := make(map[string]bool, len(disabledSubnets))
	for k, v := range disabledSubnets {
		disabledCopy[k] = v
	}
	disabledSubnetsMu.Unlock()

	subnetOwnersMu.Lock()
	ownersCopy := make(map[string][]string, len(subnetOwners))
	for k, v := range subnetOwners {
		ownersCopy[k] = append([]string{}, v...)
	}
	subnetOwnersMu.Unlock()

	reverseForwardsLock.Lock()
	rfList := make([]ReverseForward, 0, len(reverseForwards))
	for _, rf := range reverseForwards {
		rfList = append(rfList, ReverseForward{
			ListenerID: rf.ListenerID,
			ListenPort: rf.ListenPort,
			AgentID:    rf.AgentID,
			TargetHost: rf.TargetHost,
			TargetPort: rf.TargetPort,
		})
	}
	reverseForwardsLock.Unlock()

	data := DashboardData{
		Agents:          agentsList,
		RoutingTable:    routingTable.routes,
		PortForwards:    portForwardsList,
		PingHistory:     historyCopy,
		CliLog:          cliLogCopy,
		ServerLog:       serverLogCopy,
		DisabledSubnets: disabledCopy,
		SubnetOwners:    ownersCopy,
		ReverseForwards: rfList,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func handleICMPPing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	agentID := r.FormValue("agentID")
	target := r.FormValue("target")
	countStr := r.FormValue("count")

	if agentID == "" || target == "" {
		http.Error(w, "agentID and target required", http.StatusBadRequest)
		return
	}

	count := 4
	if countStr != "" {
		if c, err := strconv.Atoi(countStr); err == nil && c > 0 && c <= 10 {
			count = c
		}
	}

	connLock.Lock()
	_, ok := connections[agentID]
	connLock.Unlock()
	if !ok {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}

	req := ICMPRequest{
		Target:    target,
		Count:     count,
		TimeoutMs: 1000,
	}

	payload, _ := json.Marshal(req)
	msg := Message{
		Type:            "icmp-request",
		Payload:         payload,
		OriginalAgentID: "server",
		TargetAgentID:   agentID,
	}

	if err := sendControlMessageToAgent(agentID, msg); err != nil {
		http.Error(w, "Failed to send icmp-request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("ICMP ping started"))
}

func handlePortForward(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	agentListenPortStr := r.FormValue("agentListenPort")
	destinationAgentID := r.FormValue("destinationAgentID")
	destinationHost := r.FormValue("destinationHost")
	destinationPortStr := r.FormValue("destinationPort")
	protocol := strings.ToLower(r.FormValue("protocol"))
	if protocol != "tcp" && protocol != "udp" {
		protocol = "tcp"
	}
	agentListenPort, err := strconv.Atoi(agentListenPortStr)
	if err != nil {
		http.Error(w, "Invalid agent listen port", http.StatusBadRequest)
		return
	}
	destinationPort, err := strconv.Atoi(destinationPortStr)
	if err != nil {
		http.Error(w, "Invalid destination port", http.StatusBadRequest)
		return
	}
	if agentListenPort < 1 || agentListenPort > 65535 {
		http.Error(w, "Agent listen port out of range (1-65535)", http.StatusBadRequest)
		return
	}
	if destinationPort < 1 || destinationPort > 65535 {
		http.Error(w, "Destination port out of range (1-65535)", http.StatusBadRequest)
		return
	}
	if !validateHost(destinationHost) {
		http.Error(w, "Invalid destination host", http.StatusBadRequest)
		return
	}
	connLock.Lock()
	_, ok := connections[destinationAgentID]
	connLock.Unlock()
	if !ok {
		http.Error(w, "Destination agent not found", http.StatusNotFound)
		return
	}
	listenerKey := fmt.Sprintf("%s:%d", destinationAgentID, agentListenPort)
	connLock.Lock()
	if _, exists := portForwardLookup[listenerKey]; exists {
		connLock.Unlock()
		http.Error(w, fmt.Sprintf("Agent %s already has a listener on port %d", destinationAgentID, agentListenPort), http.StatusConflict)
		return
	}
	listenerID := uuid.New().String()
	pf := &PortForward{
		AgentListenPort:    agentListenPort,
		DestinationAgentID: destinationAgentID,
		DestinationHost:    destinationHost,
		DestinationPort:    destinationPort,
		ListenerID:         listenerID,
		Protocol:           protocol,
	}
	portForwards[listenerID] = pf
	portForwardLookup[listenerKey] = listenerID
	connLock.Unlock()
	startMsgPayload, _ := json.Marshal(StartAgentListenerMessage{
		ListenerID:      listenerID,
		AgentListenPort: agentListenPort,
		DestinationHost: destinationHost,
		DestinationPort: destinationPort,
		Protocol:        protocol,
	})
	controlMessage := Message{
		Type:            "start-agent-listener",
		Payload:         startMsgPayload,
		OriginalAgentID: "server",
		TargetAgentID:   destinationAgentID,
	}
	if err := startAgentListenerAndWait(destinationAgentID, listenerID, controlMessage); err != nil {
		connLock.Lock()
		delete(portForwards, listenerID)
		delete(portForwardLookup, listenerKey)
		connLock.Unlock()
		log.Printf("Failed to start agent listener: %v", err)
		http.Error(w, "Failed to start agent listener: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf(colorBoldGreen+"[+]"+colorReset+" Port forward: agent "+colorYellow+"%s"+colorReset+" :"+colorCyan+"%d"+colorReset+" -> "+colorCyan+"%s:%d"+colorReset+" (%s)", destinationAgentID, agentListenPort, destinationHost, destinationPort, protocol)
	triggerDashboardBroadcast()
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Port forward added: agent %s port %d -> %s:%d (%s) (id: %s)\n",
		destinationAgentID, agentListenPort, destinationHost, destinationPort, protocol, listenerID)
}

func handleStopPortForward(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	listenerID := r.FormValue("listenerID")
	if listenerID == "" {
		http.Error(w, "Listener ID required", http.StatusBadRequest)
		return
	}
	connLock.Lock()
	pf, ok := portForwards[listenerID]
	if !ok {
		connLock.Unlock()
		http.Error(w, "Port forward not found", http.StatusNotFound)
		return
	}
	connLock.Unlock()
	stopMsgPayload, _ := json.Marshal(StopAgentListenerMessage{
		ListenerID: listenerID,
	})
	controlMessage := Message{
		Type:            "stop-agent-listener",
		Payload:         stopMsgPayload,
		OriginalAgentID: "server",
		TargetAgentID:   pf.DestinationAgentID,
	}
	err := sendControlMessageToAgent(pf.DestinationAgentID, controlMessage)
	if err != nil {
		log.Printf("Failed to send stop command to agent: %v", err)
		http.Error(w, "Failed to instruct agent: "+err.Error(), http.StatusInternalServerError)
		return
	}
	connLock.Lock()
	delete(portForwards, listenerID)
	delete(portForwardLookup, fmt.Sprintf("%s:%d", pf.DestinationAgentID, pf.AgentListenPort))
	connLock.Unlock()
	log.Printf(colorBoldRed+"[-]"+colorReset+" Port forward stopped: "+colorDim+"%s"+colorReset+" (agent "+colorYellow+"%s"+colorReset+", port "+colorCyan+"%d"+colorReset+")", listenerID, pf.DestinationAgentID, pf.AgentListenPort)
	triggerDashboardBroadcast()
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Port forward stopped successfully"))
}

func handleToggleSubnet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	subnet := strings.TrimSpace(r.FormValue("subnet"))
	if subnet == "" {
		http.Error(w, "subnet required", http.StatusBadRequest)
		return
	}

	routingTable.RLock()
	_, exists := routingTable.routes[subnet]
	routingTable.RUnlock()
	if !exists {
		http.Error(w, "subnet not in routing table", http.StatusNotFound)
		return
	}

	disabledSubnetsMu.Lock()
	wasDisabled := disabledSubnets[subnet]
	disabledSubnets[subnet] = !wasDisabled
	nowDisabled := disabledSubnets[subnet]
	disabledSubnetsMu.Unlock()

	state := "enabled"
	if nowDisabled {
		state = "disabled"
	}
	log.Printf("[+] Subnet %s routing %s", subnet, state)
	appendServerLog(fmt.Sprintf("[+] Subnet %s routing %s", subnet, state))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"subnet":   subnet,
		"disabled": nowDisabled,
	})
}

func handleSubnetStatus(w http.ResponseWriter, r *http.Request) {
	disabledSubnetsMu.Lock()
	copy := make(map[string]bool, len(disabledSubnets))
	for k, v := range disabledSubnets {
		copy[k] = v
	}
	disabledSubnetsMu.Unlock()

	subnetOwnersMu.Lock()
	ownersCopy := make(map[string][]string, len(subnetOwners))
	for k, v := range subnetOwners {
		ownersCopy[k] = append([]string{}, v...)
	}
	subnetOwnersMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"disabled": copy,
		"owners":   ownersCopy,
	})
}

var (
	reverseForwards     = make(map[string]*ReverseForward)
	reverseForwardsLock sync.Mutex
)

type ReverseForward struct {
	ListenerID string `json:"listener_id"`
	ListenPort int    `json:"listen_port"`
	AgentID    string `json:"agent_id"`
	TargetHost string `json:"target_host"`
	TargetPort int    `json:"target_port"`
	listener   net.Listener
	cancel     context.CancelFunc
}

func startReverseForward(agentID string, listenPort int, targetHost string, targetPort int) (string, error) {

	if agentID != "server" {
		connLock.Lock()
		agentInfo, ok := connections[agentID]
		connLock.Unlock()
		if !ok {
			return "", fmt.Errorf("agent %s not found", agentID)
		}
		_ = agentInfo
	}

	listenAddr := fmt.Sprintf("0.0.0.0:%d", listenPort)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return "", fmt.Errorf("failed to listen on %s: %v", listenAddr, err)
	}

	listenerID := uuid.New().String()
	ctx, cancel := context.WithCancel(context.Background())

	rf := &ReverseForward{
		ListenerID: listenerID,
		ListenPort: listenPort,
		AgentID:    agentID,
		TargetHost: targetHost,
		TargetPort: targetPort,
		listener:   ln,
		cancel:     cancel,
	}

	reverseForwardsLock.Lock()
	reverseForwards[listenerID] = rf
	reverseForwardsLock.Unlock()

	log.Printf(colorBoldGreen+"[+]"+colorReset+" Reverse forward listening on :"+colorCyan+"%d"+colorReset+" -> agent "+colorYellow+"%s"+colorReset+" -> "+colorCyan+"%s:%d"+colorReset+" (id: "+colorDim+"%s"+colorReset+")",
		listenPort, agentID, targetHost, targetPort, listenerID)
	appendServerLog(fmt.Sprintf("[+] Reverse forward :%d -> agent %s -> %s:%d",
		listenPort, agentID, targetHost, targetPort))

	go func() {
		defer func() {
			ln.Close()
			reverseForwardsLock.Lock()
			delete(reverseForwards, listenerID)
			reverseForwardsLock.Unlock()
			log.Printf(colorBoldRed+"[-]"+colorReset+" Reverse forward "+colorDim+"%s"+colorReset+" stopped", listenerID)
		}()

		go func() {
			<-ctx.Done()
			ln.Close()
		}()

		for {
			clientConn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					log.Printf("Reverse forward accept error: %v", err)
					return
				}
			}
			if agentID == "server" {
				go handleReverseForwardConnDirect(clientConn, targetHost, targetPort)
			} else {
				go handleReverseForwardConn(clientConn, agentID, targetHost, targetPort, listenerID)
			}
		}
	}()

	return listenerID, nil
}

func handleReverseForwardConnDirect(clientConn net.Conn, targetHost string, targetPort int) {
	defer clientConn.Close()
	targetAddr := net.JoinHostPort(targetHost, fmt.Sprintf("%d", targetPort))
	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Printf("rforward direct: dial %s failed: %v", targetAddr, err)
		return
	}
	defer targetConn.Close()
	go func() {
		io.Copy(targetConn, clientConn)
		targetConn.Close()
	}()
	io.Copy(clientConn, targetConn)
}

func handleReverseForwardConn(clientConn net.Conn, agentID, targetHost string, targetPort int, listenerID string) {
	defer clientConn.Close()

	releaseSlot, err := acquireConnectSlot(agentID, targetHost, targetPort)
	if err != nil {
		log.Printf("Reverse forward: connect throttled for %s:%d via %s: %v", targetHost, targetPort, agentID, err)
		return
	}
	defer releaseSlot()

	connID := uuid.New().String()

	respCh := make(chan ConnectResponse, 1)
	respChanMap.Store(connID, respCh)
	defer respChanMap.Delete(connID)

	payload, _ := json.Marshal(ConnectRequest{
		TargetHost: targetHost,
		TargetPort: targetPort,
		ConnID:     connID,
		Protocol:   "tcp",
	})
	msg := Message{
		Type:            "connect",
		Payload:         payload,
		OriginalAgentID: "server",
		TargetAgentID:   agentID,
	}
	if err := sendControlMessageToAgent(agentID, msg); err != nil {
		log.Printf("Reverse forward: failed to send connect to agent %s: %v", agentID, err)
		closePreConnAtAgent(agentID, connID)
		return
	}

	var resp ConnectResponse
	select {
	case resp = <-respCh:
	case <-time.After(agentConnectResponseTimeout):
		log.Printf("Reverse forward: timeout waiting for connect_response from agent %s connID %s", agentID, connID)
		closePreConnAtAgent(agentID, connID)
		return
	}
	if !resp.Success {
		log.Printf("Reverse forward: agent %s failed to dial %s:%d – %s", agentID, targetHost, targetPort, resp.Error)
		return
	}

	pc := newPendingConn(clientConn, agentID)
	pendingConns.Store(connID, pc)
	defer func() {
		pendingConns.Delete(connID)
		pc.closeConn()
	}()

	sendData := func(data []byte, close bool) {
		dm := DataMessage{ConnID: connID, Data: data, Close: close}
		if len(data) > 256 {
			if compressed, ok := compressData(data); ok {
				dm.Data = compressed
				dm.Compressed = true
			}
		}
		p, _ := json.Marshal(dm)
		m := Message{
			Type:            "data",
			Payload:         p,
			OriginalAgentID: "server",
			TargetAgentID:   agentID,
		}
		sendControlMessageToAgent(agentID, m) //nolint:errcheck
	}

	buf := make([]byte, 32*1024)
	for {
		n, err := clientConn.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			sendData(chunk, false)
		}
		if err != nil {
			sendData(nil, true)
			return
		}
	}
}

func handleAgentFwdOpen(req AgentFwdOpen, agentID string) {
	sendAck := func(success bool, errMsg string) {
		ack := AgentFwdAck{ConnID: req.ConnID, Success: success, Error: errMsg}
		p, _ := json.Marshal(ack)
		m := Message{
			Type:          "agent_fwd_ack",
			Payload:       p,
			TargetAgentID: agentID,
		}
		if err := sendControlMessageToAgent(agentID, m); err != nil {
			logVerbose("agent_fwd: failed to send ack to %s for conn %s: %v", agentID, req.ConnID, err)
		}
	}

	targetAddr := net.JoinHostPort(req.TargetHost, fmt.Sprintf("%d", req.TargetPort))
	if req.ClientAddr != "" {
		logVerbose("agent_fwd: accepted client %s on %s, dialing %s (conn %s)", req.ClientAddr, agentID, targetAddr, req.ConnID)
	} else {
		logVerbose("agent_fwd: accepted client on %s, dialing %s (conn %s)", agentID, targetAddr, req.ConnID)
	}
	conn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Printf("agent_fwd: failed to dial %s for agent %s: %v", targetAddr, agentID, err)
		sendAck(false, err.Error())
		return
	}

	fc := &serverFwdConn{conn: conn, agentID: agentID}
	serverFwdConns.Store(req.ConnID, fc)

	sendAck(true, "")
	logVerbose("agent_fwd: tunnel open %s for agent %s (conn %s)", targetAddr, agentID, req.ConnID)

	sendData := func(data []byte, close bool) {
		dm := DataMessage{ConnID: req.ConnID, Data: data, Close: close}
		if !close && len(data) > 256 {
			if compressed, ok := compressData(data); ok {
				dm.Data = compressed
				dm.Compressed = true
			}
		}
		p, _ := json.Marshal(dm)
		m := Message{
			Type:          "agent_fwd_data",
			Payload:       p,
			TargetAgentID: agentID,
		}
		sendControlMessageToAgent(agentID, m) //nolint:errcheck
	}

	buf := make([]byte, 32*1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			sendData(chunk, false)
		}
		if err != nil {
			serverFwdConns.Delete(req.ConnID)
			sendData(nil, true)
			return
		}
	}
}

func stopReverseForward(listenerID string) error {
	reverseForwardsLock.Lock()
	rf, ok := reverseForwards[listenerID]
	if ok {
		rf.cancel()
		rf.listener.Close()
		delete(reverseForwards, listenerID)
	}
	reverseForwardsLock.Unlock()
	if !ok {
		return fmt.Errorf("reverse forward %s not found", listenerID)
	}
	log.Printf(colorBoldRed+"[-]"+colorReset+" Reverse forward "+colorDim+"%s"+colorReset+" stopped", listenerID)
	appendServerLog(fmt.Sprintf("[+] Reverse forward %s stopped", listenerID))
	triggerDashboardBroadcast()
	return nil
}

func handleReverseForwardAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	action := r.FormValue("action")
	switch action {
	case "add":
		agentID := r.FormValue("agentID")
		listenPortStr := r.FormValue("listenPort")
		targetHost := r.FormValue("targetHost")
		targetPortStr := r.FormValue("targetPort")
		listenPort, err := strconv.Atoi(listenPortStr)
		if err != nil {
			http.Error(w, "invalid listen port", http.StatusBadRequest)
			return
		}
		targetPort, err := strconv.Atoi(targetPortStr)
		if err != nil {
			http.Error(w, "invalid target port", http.StatusBadRequest)
			return
		}
		if listenPort < 1 || listenPort > 65535 {
			http.Error(w, "listen port out of range (1-65535)", http.StatusBadRequest)
			return
		}
		if targetPort < 1 || targetPort > 65535 {
			http.Error(w, "target port out of range (1-65535)", http.StatusBadRequest)
			return
		}
		if !validateHost(targetHost) {
			http.Error(w, "invalid target host", http.StatusBadRequest)
			return
		}
		id, err := startReverseForward(agentID, listenPort, targetHost, targetPort)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "[+] Reverse forward added: :%d -> agent %s -> %s:%d (id: %s)\n",
			listenPort, agentID, targetHost, targetPort, id)
	case "del":
		id := r.FormValue("listenerID")
		if err := stopReverseForward(id); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "[+] Reverse forward %s stopped\n", id)
	default:
		http.Error(w, "action must be add or del", http.StatusBadRequest)
	}
}

func handleReverseForwardList(w http.ResponseWriter, r *http.Request) {
	reverseForwardsLock.Lock()
	list := make([]ReverseForward, 0, len(reverseForwards))
	for _, rf := range reverseForwards {
		list = append(list, ReverseForward{
			ListenerID: rf.ListenerID,
			ListenPort: rf.ListenPort,
			AgentID:    rf.AgentID,
			TargetHost: rf.TargetHost,
			TargetPort: rf.TargetPort,
		})
	}
	reverseForwardsLock.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

func handleDisconnectAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	agentID := r.FormValue("agentID")
	if agentID == "" {
		http.Error(w, "Agent ID required", http.StatusBadRequest)
		return
	}
	connLock.Lock()
	_, ok := connections[agentID]
	connLock.Unlock()
	if !ok {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}
	disconnectMsg := Message{
		Type:          "disconnect",
		Payload:       []byte(`{}`),
		TargetAgentID: agentID,
	}
	if err := sendControlMessageToAgent(agentID, disconnectMsg); err != nil {
		log.Printf("Failed to send disconnect message to agent %s: %v", agentID, err)
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Agent disconnection initiated"))
}

func handleSetTag(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	agentID := r.FormValue("agentID")
	tag := r.FormValue("tag")

	if agentID == "" {
		http.Error(w, "agentID required", http.StatusBadRequest)
		return
	}

	tag = strings.TrimSpace(tag)
	if len(tag) > 64 {
		http.Error(w, "tag too long (max 64 chars)", http.StatusBadRequest)
		return
	}
	for _, ch := range tag {
		if ch < 0x20 || ch == '<' || ch == '>' || ch == '&' || ch == '"' || ch == '\'' {
			http.Error(w, "tag contains invalid characters", http.StatusBadRequest)
			return
		}
	}

	connLock.Lock()
	_, ok := connections[agentID]
	connLock.Unlock()
	if !ok {
		http.Error(w, "agent not found", http.StatusNotFound)
		return
	}

	agentTagsMu.Lock()
	if tag == "" {
		delete(agentTags, agentID)
	} else {
		agentTags[agentID] = tag
	}
	agentTagsMu.Unlock()
	triggerDashboardBroadcast()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie(authCookieName)
	if err != nil {
		return false
	}
	sessionToken := cookie.Value
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	entry, ok := activeSessions[sessionToken]
	if !ok {
		return false
	}
	now := time.Now()

	if now.After(entry.expiresAt) {
		delete(activeSessions, sessionToken)
		return false
	}

	if sessionIdleTimeout > 0 && now.After(entry.lastActivity.Add(sessionIdleTimeout)) {
		delete(activeSessions, sessionToken)
		logInfo("Session expired due to inactivity")
		return false
	}
	entry.lastActivity = now
	activeSessions[sessionToken] = entry
	return true
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if isAuthenticated(r) {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	csrfToken, _ := generateSessionToken(32)
	tempID, _ := generateSessionToken(32)

	loginCsrfMu.Lock()
	loginCsrfTokens[tempID] = loginCsrfEntry{token: csrfToken, expiry: time.Now().Add(10 * time.Minute)}
	loginCsrfMu.Unlock()

	tmpl, err := template.ParseFS(staticContent, "webroot/login.html")
	if err != nil {
		http.Error(w, "Login template error", http.StatusInternalServerError)
		return
	}

	data := struct {
		Error     string
		CSRFToken string
		TempID    string
	}{
		Error:     r.URL.Query().Get("error"),
		CSRFToken: csrfToken,
		TempID:    tempID,
	}
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "Render error", http.StatusInternalServerError)
		return
	}
}

func handleLoginPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	loginCsrfID := r.FormValue("csrf_id")
	submittedCSRF := r.FormValue("csrf_token")

	if loginCsrfID == "" || submittedCSRF == "" {
		http.Redirect(w, r, "/login?error=CSRF+token+missing", http.StatusFound)
		return
	}

	loginCsrfMu.Lock()
	entry, ok := loginCsrfTokens[loginCsrfID]
	delete(loginCsrfTokens, loginCsrfID)
	loginCsrfMu.Unlock()

	expectedCSRF := ""
	if ok {
		if time.Now().After(entry.expiry) {
			ok = false
		} else {
			expectedCSRF = entry.token
		}
	}

	if !ok || submittedCSRF == "" || submittedCSRF != expectedCSRF {
		log.Printf("Login CSRF validation failed from %s", r.RemoteAddr)
		http.Redirect(w, r, "/login?error=Invalid+CSRF+token", http.StatusFound)
		return
	}

	clientIP := r.RemoteAddr
	if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
		clientIP = clientIP[:idx]
	}
	loginFailureMu.Lock()
	if entry, exists := loginFailures[clientIP]; exists && time.Now().Before(entry.lockedUntil) {
		loginFailureMu.Unlock()
		http.Redirect(w, r, "/login?error=Too+many+failed+attempts.+Try+again+later.", http.StatusFound)
		return
	}
	loginFailureMu.Unlock()

	submittedKey := r.FormValue("key")
	if submittedKey == serverAccessKey {

		loginFailureMu.Lock()
		delete(loginFailures, clientIP)
		loginFailureMu.Unlock()

		sessionToken, _ := generateSessionToken(32)
		now := time.Now()
		expiresAt := now.Add(24 * time.Hour)
		sessionsMu.Lock()
		activeSessions[sessionToken] = sessionEntry{expiresAt: expiresAt, lastActivity: now}
		csrfToken, _ := generateSessionToken(32)
		csrfTokens[sessionToken] = csrfToken
		sessionsMu.Unlock()

		http.SetCookie(w, &http.Cookie{
			Name:     authCookieName,
			Value:    sessionToken,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Expires:  expiresAt,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     csrfCookieName,
			Value:    csrfToken,
			Path:     "/",
			HttpOnly: false,
			SameSite: http.SameSiteLaxMode,
			Expires:  expiresAt,
		})
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	} else {

		loginFailureMu.Lock()
		entry := loginFailures[clientIP]
		if entry == nil {
			entry = &loginFailEntry{}
			loginFailures[clientIP] = entry
		}
		entry.count++
		if entry.count >= 5 {
			entry.lockedUntil = time.Now().Add(1 * time.Hour)
			log.Printf("Login: IP %s locked out after %d failed attempts", clientIP, entry.count)
		}
		loginFailureMu.Unlock()
		http.Redirect(w, r, "/login?error=Invalid+Key", http.StatusFound)
	}
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isAuthenticated(r) && !strings.HasPrefix(r.URL.Path, "/static/") {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func csrfGenerationMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionCookie, err := r.Cookie(authCookieName)
		if err != nil {
			log.Printf("Session cookie not found in csrfGenerationMiddleware: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		sessionToken := sessionCookie.Value

		sessionsMu.RLock()
		csrfToken, ok := csrfTokens[sessionToken]
		sessionsMu.RUnlock()

		if !ok || csrfToken == "" {
			log.Printf("CSRF token not found for session %s", sessionToken)
			http.Error(w, "CSRF token not found, please re-login", http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), "csrfToken", csrfToken)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func csrfValidationMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {

			submittedCSRF := r.Header.Get("X-CSRF-Token")
			if submittedCSRF == "" {
				submittedCSRF = r.FormValue("csrf_token")
			}
			sessionCookie, err := r.Cookie(authCookieName)
			if err != nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			sessionToken := sessionCookie.Value

			sessionsMu.RLock()
			expectedCSRF, ok := csrfTokens[sessionToken]
			sessionsMu.RUnlock()

			if !ok || submittedCSRF == "" || submittedCSRF != expectedCSRF {
				log.Printf("CSRF validation failed for %s from %s", r.URL.Path, r.RemoteAddr)
				http.Error(w, "CSRF token invalid or missing", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	}
}

func handleShutdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintln(w, "Shutdown triggered - cleaning up in 3s...")

	go func() {
		time.Sleep(3 * time.Second)
		cleanupAll()
		os.Exit(0)
	}()
}
