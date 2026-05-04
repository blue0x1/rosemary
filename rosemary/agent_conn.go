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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtaci/smux"
	"golang.org/x/time/rate"
)

type recentAgentID struct {
	ID        string
	ConnID    string
	ExpiresAt time.Time
}

func agentFingerprint(osName, hostname, username string, subnets []string) string {
	cp := append([]string(nil), subnets...)
	sort.Strings(cp)
	return strings.Join([]string{osName, hostname, username, strings.Join(cp, ",")}, "\x00")
}

func rememberRecentAgentID(info *AgentInfo) {
	key := agentFingerprint(info.OS, info.Hostname, info.Username, info.Subnets)
	recentAgentIDs.Store(key, recentAgentID{
		ID:        info.ID,
		ConnID:    info.DirectWSConnID,
		ExpiresAt: time.Now().Add(2 * time.Minute),
	})
}

func reclaimRecentAgentID(registerMsg RegisterMessage) (string, bool) {
	key := agentFingerprint(registerMsg.OS, registerMsg.Hostname, registerMsg.Username, registerMsg.Subnets)
	v, ok := recentAgentIDs.Load(key)
	if !ok {
		return "", false
	}
	recent := v.(recentAgentID)
	if time.Now().After(recent.ExpiresAt) {
		recentAgentIDs.Delete(key)
		return "", false
	}
	if _, taken := connections[recent.ID]; taken {
		return "", false
	}
	return recent.ID, true
}

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
	// Collect subnets before deleting — removal is deferred by grace period.
	subnetsByAgent := make(map[string][]string)
	for id := range removedSet {
		if agentInfo, ok := connections[id]; ok {
			rememberRecentAgentID(agentInfo)
			subnetsByAgent[id] = agentInfo.Subnets
			delete(connections, id)
			log.Printf(colorBoldRed+"[-]"+colorReset+" Agent "+colorYellow+"%s"+colorReset+" disconnected and removed.", id)
		}
	}
	// For routes pointing to disconnecting agents, hand off to another
	// still-connected agent that also owns the subnet, or remove entirely.
	type subnetOp struct{ alternate string }
	subnetOps := make(map[string]subnetOp)
	for subnet, agentRouteID := range routingTable.routes {
		if !removedSet[agentRouteID] {
			continue
		}
		var alternate string
		subnetOwnersMu.Lock()
		for _, id := range subnetOwners[subnet] {
			if !removedSet[id] {
				if _, ok := connections[id]; ok {
					alternate = id
					break
				}
			}
		}
		subnetOwnersMu.Unlock()
		subnetOps[subnet] = subnetOp{alternate: alternate}
	}
	for subnet, op := range subnetOps {
		if op.alternate != "" {
			routingTable.routes[subnet] = op.alternate
		} else {
			routingTable.RemoveRoute(subnet)
		}
	}
	// Remove disconnecting agents from subnetOwners for subnets that were handed off.
	subnetOwnersMu.Lock()
	for agentID, subnets := range subnetsByAgent {
		for _, subnet := range subnets {
			owners := subnetOwners[subnet]
			kept := owners[:0]
			for _, id := range owners {
				if id != agentID {
					kept = append(kept, id)
				}
			}
			if len(kept) == 0 {
				delete(subnetOwners, subnet)
			} else {
				subnetOwners[subnet] = kept
			}
		}
	}
	subnetOwnersMu.Unlock()
	// Save port forwards before removing — restoreAgentForwards re-sends them if the same agent reconnects
	savedByAgent := make(map[string][]*PortForward)
	for listenerID, pf := range portForwards {
		if removedSet[pf.DestinationAgentID] {
			pfCopy := *pf
			savedByAgent[pf.DestinationAgentID] = append(savedByAgent[pf.DestinationAgentID], &pfCopy)
			delete(portForwards, listenerID)
			delete(portForwardLookup, fmt.Sprintf("%s:%d", pf.DestinationAgentID, pf.AgentListenPort))
		}
	}
	for agentID, fwds := range savedByAgent {
		recentForwardsByAgent.Store(agentID, fwds)
	}
	delete(directConnections, connID)
	delete(wsWriteMus, connID)
	if sess, ok := yamuxSessions[connID]; ok {
		sess.Close()
		delete(yamuxSessions, connID)
	}
	connLock.Unlock()

	// Defer iptables/route removal by 8 s so that existing tunneled TCP
	// connections survive brief agent reconnects (same behaviour as Ligolo).
	// The timer is cancelled in handleMsgRegisterWS/Bind if the agent
	// reclaims its previous ID before the timer fires.
	for agentID, subnets := range subnetsByAgent {
		t := time.AfterFunc(8*time.Second, func() {
			pendingSubnetCleanups.Delete(agentID)
			for _, subnet := range subnets {
				if subnetContainsServerIP(subnet) {
					continue
				}
				// Skip if another connected agent still owns this subnet.
				connLock.Lock()
				stillOwned := false
				for _, info := range connections {
					for _, s := range info.Subnets {
						if s == subnet {
							stillOwned = true
							break
						}
					}
					if stillOwned {
						break
					}
				}
				connLock.Unlock()
				if stillOwned {
					continue
				}
				activeSubnetRules.Delete(subnet)
				removeIptablesRule(subnet)
				removeUdpIptablesRule(subnet)
				removeIcmpIptablesRule(subnet)
				removeRoute(subnet)
			}
		})
		pendingSubnetCleanups.Store(agentID, t)
	}

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
	pendingUDPConns.Range(func(key, value interface{}) bool {
		if session, ok := value.(*udpSession); ok && removedSet[session.agentID] {
			pendingUDPConns.Delete(key)
		}
		return true
	})
	for agentID := range removedSet {
		releaseConnectSlotsForAgent(agentID)
		purgePreConnPoolsForAgent(agentID)
		agentLastSeenMu.Lock()
		delete(agentLastSeen, agentID)
		agentLastSeenMu.Unlock()
	}
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
	case "start-agent-listener-response":
		handleMsgStartAgentListenerResp(msg)
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
	case "start-agent-listener-response":
		handleMsgStartAgentListenerResp(msg)
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
			// Try to reclaim previous agent ID so forwards and tunnels survive reconnects
			if registerMsg.PrevID != "" {
				if prevInfo, occupied := connections[registerMsg.PrevID]; !occupied {
					registeringAgentID = registerMsg.PrevID
				} else {
					// Occupied — force-evict if the old connection is a zombie
					agentLastSeenMu.Lock()
					prevLastSeen := agentLastSeen[registerMsg.PrevID]
					agentLastSeenMu.Unlock()
					if time.Since(prevLastSeen) > 20*time.Second {
						prevConnID := prevInfo.DirectWSConnID
						if oldWS, wsOk := directConnections[prevConnID]; wsOk {
							go oldWS.Close() // triggers deferred cleanupAgentConn
							delete(directConnections, prevConnID)
						}
						if oldSess, sessOk := yamuxSessions[prevConnID]; sessOk {
							go oldSess.Close()
							delete(yamuxSessions, prevConnID)
						}
						delete(wsWriteMus, prevConnID)
						delete(connections, registerMsg.PrevID)
						agentLastSeenMu.Lock()
						delete(agentLastSeen, registerMsg.PrevID)
						agentLastSeenMu.Unlock()
						logWarn("Force-evicted zombie %s (stale %.0fs) — %s is reclaiming its ID",
							registerMsg.PrevID, time.Since(prevLastSeen).Seconds(), sourceID)
						registeringAgentID = registerMsg.PrevID
					}
				}
			}
			if registeringAgentID == *connID {
				if recentID, ok := reclaimRecentAgentID(registerMsg); ok {
					registeringAgentID = recentID
					logVerbose("Reclaimed recent bind agent ID %s for %s/%s", recentID, registerMsg.Hostname, registerMsg.Username)
				}
			}
			if registeringAgentID == *connID {
				if recentID, ok := reclaimRecentAgentID(registerMsg); ok {
					registeringAgentID = recentID
					logVerbose("Reclaimed recent agent ID %s for %s/%s", recentID, registerMsg.Hostname, registerMsg.Username)
				}
			}
			// Fall back to new sequential ID if PrevID unavailable
			if registeringAgentID == *connID {
				for {
					candidate := fmt.Sprintf("agent-%d", nextAgentID)
					nextAgentID++
					if _, taken := connections[candidate]; !taken {
						registeringAgentID = candidate
						break
					}
				}
			}
			directConnections[registeringAgentID] = ws
			delete(directConnections, sourceID)
			if sess, ok := yamuxSessions[sourceID]; ok {
				yamuxSessions[registeringAgentID] = sess
				delete(yamuxSessions, sourceID)
			}
			if mu, ok := wsWriteMus[sourceID]; ok {
				wsWriteMus[registeringAgentID] = mu
				delete(wsWriteMus, sourceID)
			}
			*connID = registeringAgentID
		}
		// Cancel any pending subnet cleanup so existing tunneled connections
		// survive the reconnect without their iptables rules being torn down.
		if t, ok := pendingSubnetCleanups.LoadAndDelete(registeringAgentID); ok {
			t.(*time.Timer).Stop()
			log.Printf(colorBoldGreen+"[+]"+colorReset+" Cancelled subnet cleanup for reconnecting agent "+colorYellow+"%s"+colorReset, registeringAgentID)
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
	sendControlMessageToAgent(registeringAgentID, Message{ //nolint:errcheck
		Type:            "register_ok",
		Payload:         []byte(fmt.Sprintf(`{"id": "%s"}`, registeringAgentID)),
		OriginalAgentID: registeringAgentID,
	})
	go restoreAgentForwards(registeringAgentID)
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
			// Try to reclaim previous agent ID so forwards survive reconnects
			if registerMsg.PrevID != "" {
				if prevInfo, occupied := connections[registerMsg.PrevID]; !occupied {
					registeringAgentID = registerMsg.PrevID
				} else {
					agentLastSeenMu.Lock()
					prevLastSeen := agentLastSeen[registerMsg.PrevID]
					agentLastSeenMu.Unlock()
					if time.Since(prevLastSeen) > 20*time.Second {
						prevConnID := prevInfo.DirectWSConnID
						if oldSess, sessOk := yamuxSessions[prevConnID]; sessOk {
							go oldSess.Close()
							delete(yamuxSessions, prevConnID)
						}
						delete(connections, registerMsg.PrevID)
						agentLastSeenMu.Lock()
						delete(agentLastSeen, registerMsg.PrevID)
						agentLastSeenMu.Unlock()
						logWarn("Force-evicted zombie bind %s (stale %.0fs) — reclaiming ID",
							registerMsg.PrevID, time.Since(prevLastSeen).Seconds())
						registeringAgentID = registerMsg.PrevID
					}
				}
			}
			if registeringAgentID == *connID {
				for {
					candidate := fmt.Sprintf("agent-%d", nextAgentID)
					nextAgentID++
					if _, taken := connections[candidate]; !taken {
						registeringAgentID = candidate
						break
					}
				}
			}
			if sess, ok := yamuxSessions[*connID]; ok {
				yamuxSessions[registeringAgentID] = sess
				delete(yamuxSessions, *connID)
			}
			*connID = registeringAgentID
		}
		// Cancel any pending subnet cleanup so existing tunneled connections
		// survive the reconnect without their iptables rules being torn down.
		if t, ok := pendingSubnetCleanups.LoadAndDelete(registeringAgentID); ok {
			t.(*time.Timer).Stop()
			log.Printf(colorBoldGreen+"[+]"+colorReset+" Cancelled subnet cleanup for reconnecting bind agent "+colorYellow+"%s"+colorReset, registeringAgentID)
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
	sendControlMessageToAgent(registeringAgentID, Message{ //nolint:errcheck
		Type:            "register_ok",
		Payload:         []byte(fmt.Sprintf(`{"id": "%s"}`, registeringAgentID)),
		OriginalAgentID: registeringAgentID,
	})
	go restoreAgentForwards(registeringAgentID)
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
	// If the agent reconnected within the grace period the rules are still
	// installed — re-adding with -A would duplicate them.
	if _, alreadyActive := activeSubnetRules.LoadOrStore(subnet, struct{}{}); alreadyActive {
		logVerbose("Subnet %s rules still active (reconnect within grace period), skipping re-add", subnet)
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

func handleMsgStartAgentListenerResp(msg Message) {
	var resp StartAgentListenerResponse
	if err := json.Unmarshal(msg.Payload, &resp); err != nil {
		log.Printf("Invalid start-agent-listener-response: %v", err)
		return
	}
	if ch, ok := listenerStartAcks.Load(resp.ListenerID); ok {
		select {
		case ch.(chan StartAgentListenerResponse) <- resp:
		default:
		}
	}
}

func handleMsgHeartbeat(agentID string) {
	markAgentSeen(agentID)
	triggerDashboardBroadcast()
}

func markAgentSeen(agentID string) {
	now := time.Now()
	agentLastSeenMu.Lock()
	agentLastSeen[agentID] = now
	agentLastSeenMu.Unlock()
	connLock.Lock()
	if info, ok := connections[agentID]; ok {
		info.LastSeen = now
	}
	connLock.Unlock()
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
	broadcastToListeners(header)
	isUDP := strings.ToLower(resp.Proto) == "udp"
	for _, r := range resp.Results {
		if r.Open {
			if isUDP {
				broadcastToListeners(fmt.Sprintf("  "+colorGreen+"open|filtered"+colorReset+" %5d\n", r.Port))
			} else {
				broadcastToListeners(fmt.Sprintf("  "+colorBoldGreen+"open"+colorReset+"          %5d\n", r.Port))
			}
		} else if r.Error != "" {
			broadcastToListeners(fmt.Sprintf("  "+colorRed+"err"+colorReset+"           %5d %s\n", r.Port, r.Error))
		}
	}
}

func handleMsgPortScanRespBind(msg Message, sourceID string) {
	var resp PortScanResponse
	if err := json.Unmarshal(msg.Payload, &resp); err != nil {
		return
	}
	broadcastToListeners(fmt.Sprintf("Port scan from agent %s on %s (%s)\n", sourceID, resp.Target, resp.Proto))
	isUDP := strings.ToLower(resp.Proto) == "udp"
	for _, r := range resp.Results {
		if r.Open {
			if isUDP {
				broadcastToListeners(fmt.Sprintf("  open|filtered %5d\n", r.Port))
			} else {
				broadcastToListeners(fmt.Sprintf("  open          %5d\n", r.Port))
			}
		} else if r.Error != "" {
			broadcastToListeners(fmt.Sprintf("  err           %5d %s\n", r.Port, r.Error))
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
	broadcastToListeners(output.String())
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
	broadcastToListeners(output.String())
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
			p.closeConn()
			pendingConns.Delete(dataMsg.ConnID)
		} else {
			p.send(dataMsg.Data)
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

// readWSAgentMsg reads one decrypted message from the agent connection.
// For yamux connections, stream-level read errors are retried (the session
// is still alive); only session-level errors propagate to the caller.
func readWSAgentMsg(ws *websocket.Conn, yamuxSession *smux.Session, yamuxErr error) (Message, error) {
	var msg Message
	if yamuxErr == nil {
		for {
			stream, err := yamuxSession.AcceptStream()
			if err != nil {
				return msg, err // session-level error — caller will close connection
			}
			_ = stream.SetReadDeadline(time.Now().Add(10 * time.Second))
			lenBuf := make([]byte, 4)
			if _, err := io.ReadFull(stream, lenBuf); err != nil {
				stream.Close()
				logVerbose("Server: yamux read len error (skipping stream): %v", err)
				continue
			}
			msgLen := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])
			if msgLen <= 0 || msgLen > 4<<20 {
				stream.Close()
				logVerbose("Server: yamux invalid frame length %d", msgLen)
				continue
			}
			data := make([]byte, msgLen)
			if _, err := io.ReadFull(stream, data); err != nil {
				stream.Close()
				logVerbose("Server: yamux read data error (skipping stream): %v", err)
				continue
			}
			_ = stream.SetReadDeadline(time.Time{})
			stream.Close()
			plaintext, err := decrypt(data, getEncryptionKey())
			if err != nil {
				logVerbose("Server: yamux decrypt error (skipping stream): %v", err)
				continue
			}
			return msg, json.Unmarshal(plaintext, &msg)
		}
	}
	_, encrypted, err := ws.ReadMessage()
	if err != nil {
		return msg, err
	}
	ws.SetReadDeadline(time.Now().Add(90 * time.Second))
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

	muxCfg := smux.DefaultConfig()
	muxCfg.Version = 2
	muxCfg.KeepAliveInterval = 10 * time.Second
	muxCfg.KeepAliveTimeout = 30 * time.Second
	muxCfg.MaxStreamBuffer = 512 * 1024
	yamuxSession, yamuxErr := smux.Server(newWSNetConn(ws), muxCfg)
	if yamuxErr == nil {
		connLock.Lock()
		yamuxSessions[directConnectedAgentID] = yamuxSession
		connLock.Unlock()
	}
	defer func() { cleanupAgentConn(directConnectedAgentID) }()

	// Raw WS agents send ping frames; refresh the read deadline on any
	// control traffic and reply explicitly so the agent can refresh its side.
	if yamuxErr != nil {
		pongWait := 90 * time.Second
		ws.SetReadDeadline(time.Now().Add(pongWait))
		ws.SetPingHandler(func(appData string) error {
			ws.SetReadDeadline(time.Now().Add(pongWait))
			ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
			err := ws.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(10*time.Second))
			ws.SetWriteDeadline(time.Time{})
			return err
		})
		ws.SetPongHandler(func(string) error {
			ws.SetReadDeadline(time.Now().Add(pongWait))
			return nil
		})
	}

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

	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(15 * time.Second)
		tc.SetNoDelay(true)
	}

	muxCfg := smux.DefaultConfig()
	muxCfg.Version = 2
	muxCfg.KeepAliveInterval = 10 * time.Second
	muxCfg.KeepAliveTimeout = 30 * time.Second
	muxCfg.MaxStreamBuffer = 512 * 1024
	yamuxSession, err := smux.Server(conn, muxCfg)
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

	for {
		stream, err := yamuxSession.AcceptStream()
		if err != nil {
			if !isNormalCloseError(err) {
				log.Printf("Bind agent %s read error: %v", directConnectedAgentID, err)
			}
			break
		}
		go func(s *smux.Stream) {
			defer s.Close()
			lenBuf := make([]byte, 4)
			if _, err := io.ReadFull(s, lenBuf); err != nil {
				return
			}
			msgLen := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])
			if msgLen <= 0 || msgLen > 4<<20 {
				return
			}
			data := make([]byte, msgLen)
			if _, err := io.ReadFull(s, data); err != nil {
				return
			}
			plaintext, err := decrypt(data, getEncryptionKey())
			if err != nil {
				return
			}
			var msg Message
			if err := json.Unmarshal(plaintext, &msg); err != nil {
				return
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
				return
			}
			dispatchBindMsg(msg, actualSourceAgentID, agentIP, &directConnectedAgentID)
		}(stream)
	}
}
