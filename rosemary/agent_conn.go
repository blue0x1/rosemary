package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
	"golang.org/x/time/rate"
)

// authenticateWSAgent performs the challenge-response authentication handshake.
func authenticateWSAgent(ws *websocket.Conn, agentIP string) bool {
	nonce := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		logError("Auth: nonce generation failed: %v", err)
		return false
	}
	challengePayload, _ := json.Marshal(map[string]string{
		"nonce": base64.URLEncoding.EncodeToString(nonce),
	})
	challengeMsg := Message{Type: "auth_challenge", Payload: json.RawMessage(challengePayload)}
	challengeJSON, _ := json.Marshal(challengeMsg)
	enc, err := encrypt(challengeJSON, getEncryptionKey())
	if err != nil {
		return false
	}
	ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := ws.WriteMessage(websocket.BinaryMessage, enc); err != nil {
		logWarn("Auth: challenge send failed to %s: %v", agentIP, err)
		return false
	}
	ws.SetWriteDeadline(time.Time{})

	ws.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, rawResp, err := ws.ReadMessage()
	ws.SetReadDeadline(time.Time{})
	if err != nil {
		if !isNormalCloseError(err) {
			logWarn("Auth: no response from %s: %v", agentIP, err)
		}
		return false
	}
	plain, err := decrypt(rawResp, getEncryptionKey())
	if err != nil {
		logWarn("Auth: wrong key from %s", agentIP)
		return false
	}
	var respMsg Message
	if err := json.Unmarshal(plain, &respMsg); err != nil || respMsg.Type != "auth_response" {
		logWarn("Auth: bad response from %s", agentIP)
		return false
	}
	var respPayload map[string]string
	if err := json.Unmarshal(respMsg.Payload, &respPayload); err != nil ||
		respPayload["nonce"] != base64.URLEncoding.EncodeToString(nonce) {
		logWarn("Auth: nonce mismatch from %s", agentIP)
		return false
	}
	logDebug("Auth: agent from %s authenticated", agentIP)
	return true
}

// cleanupAgentConn removes all state for a disconnected agent connection.
func cleanupAgentConn(connID string) {
	connLock.Lock()
	removedSet := make(map[string]bool)
	for id, agentInfo := range connections {
		if agentInfo.DirectWSConnID == connID {
			removedSet[id] = true
		}
	}
	for id := range removedSet {
		if agentInfo, ok := connections[id]; ok {
			for _, subnet := range agentInfo.Subnets {
				if !subnetContainsServerIP(subnet) {
					removeIptablesRule(subnet)
					removeUdpIptablesRule(subnet)
					removeIcmpIptablesRule(subnet)
					removeRoute(subnet)
				}
			}
			delete(connections, id)
			log.Printf(colorBoldRed+"[-]"+colorReset+" Agent "+colorYellow+"%s"+colorReset+" disconnected and removed.", id)
		}
	}
	var subnetsToRemove []string
	for subnet, agentRouteID := range routingTable.routes {
		if removedSet[agentRouteID] {
			subnetsToRemove = append(subnetsToRemove, subnet)
		}
	}
	for _, subnet := range subnetsToRemove {
		routingTable.RemoveRoute(subnet)
	}
	for listenerID, pf := range portForwards {
		if removedSet[pf.DestinationAgentID] {
			delete(portForwards, listenerID)
			delete(portForwardLookup, fmt.Sprintf("%s:%d", pf.DestinationAgentID, pf.AgentListenPort))
		}
	}
	delete(directConnections, connID)
	delete(wsWriteMus, connID)
	if sess, ok := yamuxSessions[connID]; ok {
		sess.Close()
		delete(yamuxSessions, connID)
	}
	connLock.Unlock()

	pendingConns.Range(func(key, value interface{}) bool {
		pc := value.(*pendingConn)
		if removedSet[pc.agentID] {
			pc.conn.Close()
			pendingConns.Delete(key)
		}
		return true
	})
	serverFwdConns.Range(func(key, value interface{}) bool {
		fc := value.(*serverFwdConn)
		if removedSet[fc.agentID] {
			fc.conn.Close()
			serverFwdConns.Delete(key)
		}
		return true
	})
	triggerDashboardBroadcast()
}

// relayConnMsg relays a message via WebSocket to another agent.
func relayConnMsg(msg Message, actualSourceAgentID string) {
	connLock.Lock()
	targetAgentInfo, ok := connections[msg.TargetAgentID]
	var relayWS *websocket.Conn
	var relayWsmu *sync.Mutex
	var wsOk bool
	if ok {
		relayWS, wsOk = directConnections[targetAgentInfo.DirectWSConnID]
		relayWsmu = wsWriteMus[targetAgentInfo.DirectWSConnID]
	}
	connLock.Unlock()

	if !ok {
		log.Printf("Target agent %s not found. Cannot relay.", msg.TargetAgentID)
		return
	}
	if !wsOk {
		log.Printf("Direct WebSocket connection for agent %s not found. Cannot relay.", targetAgentInfo.DirectWSConnID)
		return
	}
	payload, err := json.Marshal(msg)
	if err != nil {
		log.Printf("Error marshalling relay message: %v", err)
		return
	}
	encrypted, err := encrypt(payload, getEncryptionKey())
	if err != nil {
		log.Printf("Error encrypting relay message: %v", err)
		return
	}
	if relayWsmu != nil {
		relayWsmu.Lock()
	}
	writeErr := relayWS.WriteMessage(websocket.BinaryMessage, encrypted)
	if relayWsmu != nil {
		relayWsmu.Unlock()
	}
	if writeErr != nil {
		log.Printf("Error relaying message: %v", writeErr)
	}
}

// dispatchConnMsg handles a message from a WebSocket-connected agent.
func dispatchConnMsg(msg Message, sourceID string, agentIP string, connID *string, ws *websocket.Conn) {
	switch msg.Type {
	case "register":
		handleMsgRegisterWS(msg, sourceID, agentIP, connID, ws)
	case "connect_response":
		handleMsgConnectResp(msg)
	case "dns_response":
		handleMsgDNSResp(msg)
	case "heartbeat":
		handleMsgHeartbeat(sourceID)
	case "forward":
		handleMsgForward(msg, sourceID)
	case "icmp-response":
		handleMsgICMPResp(msg, sourceID)
	case "icmp_proxy_response":
		handleMsgICMPProxyResp(msg)
	case "port-scan-response":
		handleMsgPortScanRespWS(msg, sourceID)
	case "ping-sweep-response":
		handleMsgPingSweepRespWS(msg)
	case "data":
		handleMsgData(msg)
	case "agent_fwd_open":
		handleMsgAgentFwdOpen(msg, sourceID)
	case "agent_fwd_data":
		handleMsgAgentFwdData(msg)
	}
}

// dispatchBindMsg handles a message from a TCP bind-connected agent.
func dispatchBindMsg(msg Message, sourceID string, agentIP string, connID *string) {
	switch msg.Type {
	case "register":
		handleMsgRegisterBind(msg, sourceID, agentIP, connID)
	case "connect_response":
		handleMsgConnectResp(msg)
	case "dns_response":
		handleMsgDNSResp(msg)
	case "heartbeat":
		handleMsgHeartbeat(sourceID)
	case "forward":
		handleMsgForward(msg, sourceID)
	case "icmp-response":
		handleMsgICMPResp(msg, sourceID)
	case "icmp_proxy_response":
		handleMsgICMPProxyResp(msg)
	case "port-scan-response":
		handleMsgPortScanRespBind(msg, sourceID)
	case "ping-sweep-response":
		handleMsgPingSweepRespBind(msg)
	case "data":
		handleMsgData(msg)
	case "agent_fwd_open":
		handleMsgAgentFwdOpen(msg, sourceID)
	case "agent_fwd_data":
		handleMsgAgentFwdData(msg)
	}
}

func handleMsgRegisterWS(msg Message, sourceID string, agentIP string, connID *string, ws *websocket.Conn) {
	var registerMsg RegisterMessage
	if err := json.Unmarshal(msg.Payload, &registerMsg); err != nil {
		log.Printf("error unmarshalling register message: %v", err)
		return
	}
	registeringAgentID := sourceID
	if msg.OriginalAgentID != "" {
		registeringAgentID = msg.OriginalAgentID
	}
	connLock.Lock()
	if _, ok := connections[registeringAgentID]; !ok {
		if registeringAgentID == *connID {
			registeringAgentID = fmt.Sprintf("agent-%d", nextAgentID)
			nextAgentID++
			directConnections[registeringAgentID] = ws
			delete(directConnections, sourceID)
			if sess, ok := yamuxSessions[sourceID]; ok {
				yamuxSessions[registeringAgentID] = sess
				delete(yamuxSessions, sourceID)
			}
			*connID = registeringAgentID
		}
		agentInfo := AgentInfo{
			ID:             registeringAgentID,
			Subnets:        registerMsg.Subnets,
			DirectWSConnID: *connID,
			OS:             registerMsg.OS,
			Hostname:       registerMsg.Hostname,
			Username:       registerMsg.Username,
			LastSeen:       time.Now(),
			ConnectedAt:    time.Now(),
			HasInternet:    registerMsg.HasInternet,
		}
		connections[registeringAgentID] = &agentInfo
		agentLastSeenMu.Lock()
		agentLastSeen[registeringAgentID] = time.Now()
		agentLastSeenMu.Unlock()
	}
	connLock.Unlock()
	triggerDashboardBroadcast()
	registerAgentSubnets(registeringAgentID, registerMsg.Subnets, agentIP)
	log.Printf(colorBoldGreen+"[+]"+colorReset+" Agent "+colorYellow+"%s"+colorReset+" connected with subnets: "+colorCyan+"%v"+colorReset, registeringAgentID, registerMsg.Subnets)
	sendControlMessageToAgent(registeringAgentID, Message{
		Type:            "register_ok",
		Payload:         []byte(fmt.Sprintf(`{"id": "%s"}`, registeringAgentID)),
		OriginalAgentID: registeringAgentID,
	})
}

func handleMsgRegisterBind(msg Message, sourceID string, agentIP string, connID *string) {
	var registerMsg RegisterMessage
	if err := json.Unmarshal(msg.Payload, &registerMsg); err != nil {
		log.Printf("bind agent: bad register: %v", err)
		return
	}
	registeringAgentID := sourceID
	if msg.OriginalAgentID != "" {
		registeringAgentID = msg.OriginalAgentID
	}
	connLock.Lock()
	if _, ok := connections[registeringAgentID]; !ok {
		if registeringAgentID == *connID {
			registeringAgentID = fmt.Sprintf("agent-%d", nextAgentID)
			nextAgentID++
			if sess, ok := yamuxSessions[*connID]; ok {
				yamuxSessions[registeringAgentID] = sess
				delete(yamuxSessions, *connID)
			}
			*connID = registeringAgentID
		}
		agentInfo := AgentInfo{
			ID:             registeringAgentID,
			Subnets:        registerMsg.Subnets,
			DirectWSConnID: *connID,
			OS:             registerMsg.OS,
			Hostname:       registerMsg.Hostname,
			Username:       registerMsg.Username,
			LastSeen:       time.Now(),
			ConnectedAt:    time.Now(),
			HasInternet:    registerMsg.HasInternet,
		}
		connections[registeringAgentID] = &agentInfo
		agentLastSeenMu.Lock()
		agentLastSeen[registeringAgentID] = time.Now()
		agentLastSeenMu.Unlock()
	}
	connLock.Unlock()
	triggerDashboardBroadcast()
	registerAgentSubnets(registeringAgentID, registerMsg.Subnets, agentIP)
	log.Printf(colorBoldGreen+"[+]"+colorReset+" Bind agent "+colorYellow+"%s"+colorReset+" connected with subnets: "+colorCyan+"%v"+colorReset, registeringAgentID, registerMsg.Subnets)
	sendControlMessageToAgent(registeringAgentID, Message{
		Type:            "register_ok",
		Payload:         []byte(fmt.Sprintf(`{"id": "%s"}`, registeringAgentID)),
		OriginalAgentID: registeringAgentID,
	})
}

// registerAgentSubnets sets up routing/iptables for each subnet the agent owns.
func registerAgentSubnets(agentID string, subnets []string, agentIP string) {
	for _, subnet := range subnets {
		routingTable.AddRoute(subnet, agentID)
		if isPrivileged() {
			applySubnetRules(subnet, agentIP)
		} else {
			log.Printf("Not root, skipping iptables rule and route for %s", subnet)
		}
	}
}

func applySubnetRules(subnet, agentIP string) {
	if subnetContainsServerIP(subnet) {
		logVerbose("Skipping iptables rule and route for %s (server is on this subnet)", subnet)
		return
	}
	if !isValidCIDR(subnet) {
		log.Printf("Invalid subnet format '%s' received from agent. Skipping iptables rules.", subnet)
		return
	}
	if err := addIptablesRule(subnet, agentIP); err != nil {
		log.Printf("Failed to add iptables rule for %s: %v", subnet, err)
	} else {
		cleanupMu.Lock()
		addedIptables = append(addedIptables, subnet)
		cleanupMu.Unlock()
	}
	if err := addUdpIptablesRule(subnet); err != nil {
		log.Printf("Failed to add UDP iptables rule for %s: %v", subnet, err)
	} else {
		cleanupMu.Lock()
		addedUdpIptables = append(addedUdpIptables, subnet)
		cleanupMu.Unlock()
	}
	if err := addIcmpIptablesRule(subnet); err != nil {
		log.Printf("Failed to add ICMP iptables rule for %s: %v", subnet, err)
	} else {
		cleanupMu.Lock()
		addedIcmpIptables = append(addedIcmpIptables, subnet)
		cleanupMu.Unlock()
	}
	if runtime.GOOS != "windows" {
		if err := addRoute(subnet, agentIP); err != nil {
			log.Printf("Failed to add route for %s: %v", subnet, err)
		}
	}
}

func handleMsgConnectResp(msg Message) {
	var resp ConnectResponse
	if err := json.Unmarshal(msg.Payload, &resp); err != nil {
		log.Printf("error unmarshalling connect_response: %v", err)
		return
	}
	if ch, ok := respChanMap.Load(resp.ConnID); ok {
		select {
		case ch.(chan ConnectResponse) <- resp:
		default:
		}
	}
}

func handleMsgDNSResp(msg Message) {
	var respMsg DNSResponseMessage
	if err := json.Unmarshal(msg.Payload, &respMsg); err != nil {
		log.Printf("Invalid dns_response: %v", err)
		return
	}
	if ch, ok := pendingDNSRequests.Load(respMsg.RequestID); ok {
		select {
		case ch.(chan *DNSResponseMessage) <- &respMsg:
		default:
		}
	}
}

func handleMsgHeartbeat(agentID string) {
	agentLastSeenMu.Lock()
	agentLastSeen[agentID] = time.Now()
	agentLastSeenMu.Unlock()
	connLock.Lock()
	if info, ok := connections[agentID]; ok {
		info.LastSeen = time.Now()
	}
	connLock.Unlock()
	triggerDashboardBroadcast()
}

func handleMsgForward(msg Message, sourceID string) {
	var forwardMsg ForwardMessage
	if err := json.Unmarshal(msg.Payload, &forwardMsg); err != nil {
		log.Printf("error unmarshalling forward message: %v", err)
		return
	}
	sendControlMessageToAgent(forwardMsg.DestinationAgentID, Message{
		Type:            "forward",
		Payload:         msg.Payload,
		OriginalAgentID: sourceID,
		TargetAgentID:   forwardMsg.DestinationAgentID,
	})
}

func handleMsgICMPResp(msg Message, sourceID string) {
	var resp ICMPResponse
	if err := json.Unmarshal(msg.Payload, &resp); err != nil {
		log.Printf("error unmarshalling icmp-response: %v", err)
		return
	}
	prefix := colorBoldGreen + "[+]" + colorReset
	if !resp.Success {
		prefix = colorBoldRed + "[-]" + colorReset
	}
	line := fmt.Sprintf(
		"%s ICMP %s%s%s → %s%s%s seq=%d rtt=%s%.2fms%s err=%s",
		prefix,
		colorCyan, sourceID, colorReset,
		colorYellow, resp.Target, colorReset,
		resp.Seq,
		colorBoldGreen, resp.RttMs, colorReset,
		resp.Error,
	)
	broadcastToListeners(line)
	pingHistoryMu.Lock()
	pingHistory = append(pingHistory, PingRecord{
		Time:    time.Now(),
		AgentID: sourceID,
		Target:  resp.Target,
		Seq:     resp.Seq,
		Success: resp.Success,
		RttMs:   resp.RttMs,
		Error:   resp.Error,
	})
	if len(pingHistory) > 100 {
		pingHistory = pingHistory[len(pingHistory)-100:]
	}
	pingHistoryMu.Unlock()
}

func handleMsgICMPProxyResp(msg Message) {
	var resp ICMPProxyResponse
	if err := json.Unmarshal(msg.Payload, &resp); err != nil {
		log.Printf("error unmarshalling icmp_proxy_response: %v", err)
		return
	}
	if ch, ok := pendingICMPProxy.Load(resp.ConnID); ok {
		ch.(chan ICMPProxyResponse) <- resp
	}
}

func handleMsgPortScanRespWS(msg Message, sourceID string) {
	var resp PortScanResponse
	if err := json.Unmarshal(msg.Payload, &resp); err != nil {
		log.Printf("error unmarshalling port-scan-response: %v", err)
		return
	}
	header := fmt.Sprintf(
		colorBoldCyan+"[*]"+colorReset+" Port scan — agent %s%s%s on %s%s%s (%s)\n",
		colorCyan, sourceID, colorReset,
		colorYellow, resp.Target, colorReset,
		resp.Proto,
	)
	appendCliLine(header)
	isUDP := strings.ToLower(resp.Proto) == "udp"
	for _, r := range resp.Results {
		if r.Open {
			if isUDP {
				appendCliLine(fmt.Sprintf("  "+colorGreen+"open|filtered"+colorReset+" %5d\n", r.Port))
			} else {
				appendCliLine(fmt.Sprintf("  "+colorBoldGreen+"open"+colorReset+"          %5d\n", r.Port))
			}
		} else if r.Error != "" {
			appendCliLine(fmt.Sprintf("  "+colorRed+"err"+colorReset+"           %5d %s\n", r.Port, r.Error))
		}
	}
}

func handleMsgPortScanRespBind(msg Message, sourceID string) {
	var resp PortScanResponse
	if err := json.Unmarshal(msg.Payload, &resp); err != nil {
		return
	}
	appendCliLine(fmt.Sprintf("Port scan from agent %s on %s (%s)\n", sourceID, resp.Target, resp.Proto))
	isUDP := strings.ToLower(resp.Proto) == "udp"
	for _, r := range resp.Results {
		if r.Open {
			if isUDP {
				appendCliLine(fmt.Sprintf("  open|filtered %5d\n", r.Port))
			} else {
				appendCliLine(fmt.Sprintf("  open          %5d\n", r.Port))
			}
		} else if r.Error != "" {
			appendCliLine(fmt.Sprintf("  err           %5d %s\n", r.Port, r.Error))
		}
	}
}

func handleMsgPingSweepRespWS(msg Message) {
	var resp PingSweepResponse
	if err := json.Unmarshal(msg.Payload, &resp); err != nil {
		log.Printf("error unmarshalling ping-sweep-response: %v", err)
		return
	}
	var output strings.Builder
	fmt.Fprintf(&output, colorBoldCyan+"[*]"+colorReset+" Discover %s%s%s — "+colorBoldWhite+"%d hosts up"+colorReset+":\n",
		colorYellow, resp.Subnet, colorReset, len(resp.Results))
	for _, h := range resp.Results {
		fmt.Fprintf(&output, "  "+colorGreen+"%-18s"+colorReset+"  "+colorDim+"%.1f ms"+colorReset+"\n", h.IP, float64(h.RTT))
	}
	appendCliLine(output.String())
}

func handleMsgPingSweepRespBind(msg Message) {
	var resp PingSweepResponse
	if err := json.Unmarshal(msg.Payload, &resp); err != nil {
		return
	}
	var output strings.Builder
	fmt.Fprintf(&output, "Ping sweep on %s (%d hosts up):\n", resp.Subnet, len(resp.Results))
	for _, h := range resp.Results {
		fmt.Fprintf(&output, "  %s  (%.1f ms)\n", h.IP, float64(h.RTT))
	}
	appendCliLine(output.String())
}

func handleMsgData(msg Message) {
	var dataMsg DataMessage
	if err := json.Unmarshal(msg.Payload, &dataMsg); err != nil {
		log.Printf("error unmarshalling data message: %v", err)
		return
	}
	if dataMsg.Compressed && len(dataMsg.Data) > 0 {
		dec, err := decompressData(dataMsg.Data)
		if err != nil {
			log.Printf("data decompress error: %v", err)
			return
		}
		dataMsg.Data = dec
	}
	if value, ok := pendingConns.Load(dataMsg.ConnID); ok {
		p := value.(*pendingConn)
		if dataMsg.Close {
			p.conn.Close()
			pendingConns.Delete(dataMsg.ConnID)
		} else {
			if _, err := p.conn.Write(dataMsg.Data); err != nil {
				p.conn.Close()
				pendingConns.Delete(dataMsg.ConnID)
			}
		}
	} else if value, ok := pendingUDPConns.Load(dataMsg.ConnID); ok {
		s := value.(*udpSession)
		if dataMsg.Close {
			pendingUDPConns.Delete(dataMsg.ConnID)
		} else if udpListener != nil && s.clientAddr != nil {
			sendUDPResponse(s.clientAddr, s.remoteAddr.IP, s.remoteAddr.Port, dataMsg.Data)
			s.expire = time.Now().Add(udpTimeout)
		}
	}
}

func handleMsgAgentFwdOpen(msg Message, sourceID string) {
	var req AgentFwdOpen
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		log.Printf("agent_fwd_open unmarshal error: %v", err)
		return
	}
	go handleAgentFwdOpen(req, sourceID)
}

func handleMsgAgentFwdData(msg Message) {
	var dm DataMessage
	if err := json.Unmarshal(msg.Payload, &dm); err != nil {
		log.Printf("agent_fwd_data unmarshal error: %v", err)
		return
	}
	if dm.Compressed && len(dm.Data) > 0 {
		dec, err := decompressData(dm.Data)
		if err != nil {
			log.Printf("agent_fwd_data decompress error: %v", err)
			return
		}
		dm.Data = dec
	}
	if value, ok := serverFwdConns.Load(dm.ConnID); ok {
		fc := value.(*serverFwdConn)
		if dm.Close {
			fc.conn.Close()
			serverFwdConns.Delete(dm.ConnID)
		} else {
			if _, err := fc.conn.Write(dm.Data); err != nil {
				fc.conn.Close()
				serverFwdConns.Delete(dm.ConnID)
			}
		}
	}
}

// handleConnections handles an incoming WebSocket agent connection.
func readWSAgentMsg(ws *websocket.Conn, yamuxSession *yamux.Session, yamuxErr error) (Message, error) {
	var msg Message
	if yamuxErr == nil {
		stream, err := yamuxSession.Accept()
		if err != nil {
			return msg, err
		}
		defer stream.Close()
		lenBuf := make([]byte, 4)
		if _, err := io.ReadFull(stream, lenBuf); err != nil {
			return msg, err
		}
		msgLen := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])
		data := make([]byte, msgLen)
		if _, err := io.ReadFull(stream, data); err != nil {
			return msg, err
		}
		plaintext, err := decrypt(data, getEncryptionKey())
		if err != nil {
			return msg, err
		}
		return msg, json.Unmarshal(plaintext, &msg)
	}
	_, encrypted, err := ws.ReadMessage()
	if err != nil {
		return msg, err
	}
	plaintext, err := decrypt(encrypted, getEncryptionKey())
	if err != nil {
		return msg, err
	}
	return msg, json.Unmarshal(plaintext, &msg)
}

func processWSAgentMsg(msg Message, connID *string, agentIP string, ws *websocket.Conn, limiter *rate.Limiter) {
	if msg.Type != "data" && msg.Type != "udp_data" && !limiter.Allow() {
		logVerbose("Agent %s: message rate limit exceeded, dropping message type=%s", *connID, msg.Type)
		return
	}
	actualSourceAgentID := *connID
	if msg.OriginalAgentID != "" {
		actualSourceAgentID = msg.OriginalAgentID
	}
	if msg.TargetAgentID != "" && msg.TargetAgentID != "server" && msg.TargetAgentID != actualSourceAgentID {
		relayConnMsg(msg, actualSourceAgentID)
		return
	}
	dispatchConnMsg(msg, actualSourceAgentID, agentIP, connID, ws)
}

func handleConnections(w http.ResponseWriter, r *http.Request) {
	clientIP := strings.Split(r.RemoteAddr, ":")[0]
	if !canAcceptAgentConnection(clientIP) {
		log.Printf("Reject agent connection from %s (rate limit or max agents reached)", clientIP)
		http.Error(w, "Connection limit reached", http.StatusTooManyRequests)
		return
	}
	defer releaseAgentConnection(clientIP)

	agentIP := clientIP
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		http.Error(w, "WebSocket upgrade failed", http.StatusBadRequest)
		return
	}
	ws.SetReadLimit(1 << 20)
	defer ws.Close()

	if !authenticateWSAgent(ws, agentIP) {
		return
	}

	connLock.Lock()
	directConnectedAgentID := fmt.Sprintf("conn-%d", nextAgentID)
	nextAgentID++
	directConnections[directConnectedAgentID] = ws
	wsWriteMus[directConnectedAgentID] = &sync.Mutex{}
	connLock.Unlock()

	yamuxCfg := yamux.DefaultConfig()
	yamuxCfg.KeepAliveInterval = 90 * time.Second
	yamuxCfg.ConnectionWriteTimeout = 30 * time.Second
	yamuxCfg.LogOutput = io.Discard
	yamuxSession, yamuxErr := yamux.Server(newWSNetConn(ws), yamuxCfg)
	if yamuxErr == nil {
		connLock.Lock()
		yamuxSessions[directConnectedAgentID] = yamuxSession
		connLock.Unlock()
	}
	go startWSPingKeepalive(ws, directConnectedAgentID)
	defer func() { cleanupAgentConn(directConnectedAgentID) }()

	agentMsgLimiter := rate.NewLimiter(rate.Limit(1000), 2000)
	for {
		msg, err := readWSAgentMsg(ws, yamuxSession, yamuxErr)
		if err != nil {
			if !isNormalCloseError(err) {
				log.Printf("Direct connection %s read error: %v", directConnectedAgentID, err)
			}
			break
		}
		processWSAgentMsg(msg, &directConnectedAgentID, agentIP, ws, agentMsgLimiter)
	}
}

// handleBindAgentConn handles an incoming TCP bind agent connection.
func handleBindAgentConn(conn net.Conn, state *bindConnectState) {
	defer conn.Close()
	agentIP := strings.Split(conn.RemoteAddr().String(), ":")[0]

	yamuxSession, err := yamux.Server(conn, yamux.DefaultConfig())
	if err != nil {
		log.Printf("handleBindAgentConn: yamux server: %v", err)
		return
	}

	connLock.Lock()
	directConnectedAgentID := fmt.Sprintf("conn-%d", nextAgentID)
	nextAgentID++
	yamuxSessions[directConnectedAgentID] = yamuxSession
	connLock.Unlock()

	if state != nil {
		state.connIDMu.Lock()
		state.connID = directConnectedAgentID
		state.connIDMu.Unlock()
	}

	defer func() { cleanupAgentConn(directConnectedAgentID) }()

	readMsg := func() (Message, error) {
		var msg Message
		stream, err := yamuxSession.Accept()
		if err != nil {
			return msg, err
		}
		defer stream.Close()
		lenBuf := make([]byte, 4)
		if _, err := io.ReadFull(stream, lenBuf); err != nil {
			return msg, err
		}
		msgLen := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])
		data := make([]byte, msgLen)
		if _, err := io.ReadFull(stream, data); err != nil {
			return msg, err
		}
		plaintext, err := decrypt(data, getEncryptionKey())
		if err != nil {
			return msg, err
		}
		err = json.Unmarshal(plaintext, &msg)
		return msg, err
	}

	for {
		msg, err := readMsg()
		if err != nil {
			if !isNormalCloseError(err) {
				log.Printf("Bind agent %s read error: %v", directConnectedAgentID, err)
			}
			break
		}
		actualSourceAgentID := directConnectedAgentID
		if msg.OriginalAgentID != "" {
			actualSourceAgentID = msg.OriginalAgentID
		}
		if msg.TargetAgentID != "" && msg.TargetAgentID != "server" && msg.TargetAgentID != actualSourceAgentID {
			relayMsg := Message{
				Type:            msg.Type,
				Payload:         msg.Payload,
				OriginalAgentID: actualSourceAgentID,
				TargetAgentID:   msg.TargetAgentID,
			}
			if err := sendControlMessageToAgent(msg.TargetAgentID, relayMsg); err != nil {
				log.Printf("Bind relay to %s failed: %v", msg.TargetAgentID, err)
			}
			continue
		}
		dispatchBindMsg(msg, actualSourceAgentID, agentIP, &directConnectedAgentID)
	}
}

// startWSPingKeepalive sends WebSocket pings on an interval to keep the connection alive.
func startWSPingKeepalive(ws *websocket.Conn, connID string) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		connLock.Lock()
		_, alive := directConnections[connID]
		connLock.Unlock()
		if !alive {
			return
		}
		deadline := time.Now().Add(10 * time.Second)
		if err := ws.WriteControl(websocket.PingMessage, nil, deadline); err != nil {
			ws.Close()
			return
		}
	}
}
