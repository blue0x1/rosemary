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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/user"
	"runtime"
	"sync"
	"time"

	"strings"
)

var agentBufPool = sync.Pool{New: func() interface{} { b := make([]byte, 256*1024); return &b }}

func isAgentNormalCloseError(err error) bool {
	s := err.Error()
	return strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "websocket: close 1006") ||
		strings.Contains(s, "websocket: close 1000") ||
		strings.Contains(s, "websocket: close 1001") ||
		strings.Contains(s, "EOF") ||
		strings.Contains(s, "connection reset by peer") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "io: read/write on closed pipe")
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

func agentSend(c agentTransport, _ *sync.Mutex, encrypted []byte) error {
	return c.write(encrypted)
}

func agentSendRaw(conn net.Conn, writeMu *sync.Mutex, encrypted []byte) error {
	writeMu.Lock()
	defer writeMu.Unlock()
	l := len(encrypted)
	hdr := []byte{byte(l >> 24), byte(l >> 16), byte(l >> 8), byte(l)}
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(hdr); err != nil {
		conn.SetWriteDeadline(time.Time{})
		return err
	}
	_, err := conn.Write(encrypted)
	conn.SetWriteDeadline(time.Time{})
	return err
}

func readBindFrame(conn net.Conn) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}
	msgLen := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])
	if msgLen <= 0 || msgLen > 4<<20 {
		return nil, fmt.Errorf("invalid bind frame length %d", msgLen)
	}
	data := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}
	return data, nil
}

func agent(serverAddr string, keyBase64 string, wsPath string, agentStop <-chan struct{}) {
	key, err := decodeKey(keyBase64)
	if err != nil {
		log.Fatalf("Invalid encryption key (must be 32-byte base64): %v", err)
	}
	setEncryptionKey(key)
	encryptionKey = key

	agentSleep := func(d time.Duration) bool {
		select {
		case <-time.After(d):
			return true
		case <-agentStop:
			return false
		}
	}

	backoff := 2 * time.Second
	resetBackoff := func() { backoff = 2 * time.Second }
	nextBackoff := func() time.Duration {
		d := backoff
		backoff *= 2
		if backoff > 10*time.Second {
			backoff = 10 * time.Second
		}
		return d
	}

	var persistedID string

	_ = wsPath

	for {
		logVerbose("Agent: connecting to quic://%s", serverAddr)
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			select {
			case <-agentStop:
				cancel()
			case <-ctx.Done():
			}
		}()
		var c agentTransport
		rc, err := dialRtn(ctx, serverAddr)
		if err == nil {
			c = rc
		}
		if err != nil {
			cancel()
			select {
			case <-agentStop:
				return
			default:
			}
			delay := nextBackoff()
			logVerbose("Failed to connect: %v, retrying in %s...", err, delay)
			if !agentSleep(delay) {
				return
			}
			continue
		}

		resetBackoff()

		agentAssignedID := persistedID
		var writeMu sync.Mutex
		var uploadLanesOnce sync.Once

		subnets, err := getSubnets()
		if err != nil {
			logVerbose("Agent: could not get subnets: %v, retrying...", err)
			c.Close()
			if !agentSleep(5 * time.Second) {
				return
			}
			continue
		}

		userInfo, _ := user.Current()
		hostname, _ := os.Hostname()
		registerMsg := RegisterMessage{
			Subnets:  subnets,
			OS:       runtime.GOOS,
			Hostname: hostname,
			Username: func() string {
				if userInfo != nil {
					return userInfo.Username
				}
				return ""
			}(),
			HasInternet: probeInternet(),
			PrevID:      persistedID,
		}

		payload, _ := json.Marshal(registerMsg)
		msg := Message{Type: "register", Payload: payload}
		msgPayload, _ := json.Marshal(msg)
		encrypted, err := encrypt(msgPayload, getEncryptionKey())
		if err != nil {
			logVerbose("Agent: encryption error: %v, retrying...", err)
			c.Close()
			if !agentSleep(5 * time.Second) {
				return
			}
			continue
		}
		if err := agentSend(c, &writeMu, encrypted); err != nil {
			logVerbose("Agent: register send error: %v, retrying...", err)
			c.Close()
			if !agentSleep(5 * time.Second) {
				return
			}
			continue
		}

		done := make(chan struct{})
		var targetConns sync.Map
		var targetWriters sync.Map
		var udpConns sync.Map
		var udpWriters sync.Map
		var canceledConns sync.Map

		sendDataMsg := func(connID string, data []byte, close bool) {
			dataMsg := DataMessage{ConnID: connID, Data: data, Close: close}
			if len(data) > 256 {
				if compressed, ok := compressData(data); ok {
					dataMsg.Data = compressed
					dataMsg.Compressed = true
				}
			}
			p, _ := json.Marshal(dataMsg)
			m := Message{Type: "data", Payload: p, OriginalAgentID: agentAssignedID}
			mp, _ := json.Marshal(m)
			enc, err := encrypt(mp, getEncryptionKey())
			if err != nil {
				logVerbose("Agent %s: encryption error: %v", agentAssignedID, err)
				return
			}
			if err := c.writeDataForConn(connID, enc); err != nil {
				logVerbose("Agent %s: data send error: %v", agentAssignedID, err)
			}
		}

		sendICMPResponse := func(resp ICMPResponse) {
			p, _ := json.Marshal(resp)
			m := Message{Type: "icmp-response", Payload: p, OriginalAgentID: agentAssignedID}
			mp, _ := json.Marshal(m)
			enc, err := encrypt(mp, getEncryptionKey())
			if err != nil {
				logVerbose("Agent %s: icmp-response encryption error: %v", agentAssignedID, err)
				return
			}
			agentSend(c, &writeMu, enc)
		}

		var dispatchWSAgentMsg func([]byte)
		dispatchWSAgentMsg = func(encrypted []byte) {
			plaintext, err := decrypt(encrypted, getEncryptionKey())
			if err != nil {
				logVerbose("Agent: decrypt error: %v", err)
				return
			}
			var msg Message
			if err := json.Unmarshal(plaintext, &msg); err != nil {
				logVerbose("Agent: unmarshal error: %v", err)
				return
			}

			switch msg.Type {
			case "register_ok":
				var payload struct {
					ID string `json:"id"`
				}
				json.Unmarshal(msg.Payload, &payload)
				agentAssignedID = payload.ID
				persistedID = payload.ID
				logVerbose("Agent: assigned ID: %s", agentAssignedID)
				uploadLanesOnce.Do(func() {
					c.startUploadLanes(ctx, agentAssignedID, dispatchWSAgentMsg)
				})

			case "reconnect":
				logVerbose("Agent %s: received reconnect command, reconnecting...", agentAssignedID)
				c.Close()

			case "dns_request":
				var dnsReq DNSRequestMessage
				if err := json.Unmarshal(msg.Payload, &dnsReq); err != nil {
					logVerbose("Agent: invalid dns_request: %v", err)
					return
				}
				go handleAgentDNSRequest(agentAssignedID, dnsReq, func(encrypted []byte) error {
					return agentSend(c, &writeMu, encrypted)
				})

			case "ping-sweep-request":
				var req PingSweepRequest
				if err := json.Unmarshal(msg.Payload, &req); err != nil {
					logVerbose("Agent %s: invalid ping-sweep-request: %v", agentAssignedID, err)
					return
				}
				go func(req PingSweepRequest) {
					results := doPingSweep(req)
					resp := PingSweepResponse{Subnet: req.Subnet, Results: results}
					p, _ := json.Marshal(resp)
					rm := Message{Type: "ping-sweep-response", Payload: p, OriginalAgentID: agentAssignedID, TargetAgentID: "server"}
					mp, _ := json.Marshal(rm)
					enc, err := encrypt(mp, getEncryptionKey())
					if err != nil {
						return
					}
					agentSend(c, &writeMu, enc)
				}(req)

			case "start-agent-listener":
				var req StartAgentListenerMessage
				if err := json.Unmarshal(msg.Payload, &req); err != nil {
					logVerbose("Agent %s: error unmarshalling start-agent-listener: %v", agentAssignedID, err)
					return
				}
				sendStartListenerResp := func(success bool, errMsg string) {
					resp := StartAgentListenerResponse{ListenerID: req.ListenerID, Success: success, Error: errMsg}
					p, _ := json.Marshal(resp)
					m := Message{Type: "start-agent-listener-response", Payload: p, OriginalAgentID: agentAssignedID}
					mp, _ := json.Marshal(m)
					enc, err := encrypt(mp, getEncryptionKey())
					if err != nil {
						return
					}
					agentSend(c, &writeMu, enc) //nolint:errcheck
				}
				logVerbose("Agent %s: Starting listener on port %d -> %s:%d", agentAssignedID, req.AgentListenPort, req.DestinationHost, req.DestinationPort)
				listenerCtx, listenerCancel := context.WithCancel(context.Background())
				if req.Protocol == "udp" {
					udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", req.AgentListenPort))
					if err != nil {
						logVerbose("Agent %s: Failed to resolve UDP :%d: %v", agentAssignedID, req.AgentListenPort, err)
						listenerCancel()
						sendStartListenerResp(false, err.Error())
						return
					}
					pc, err := net.ListenUDP("udp", udpAddr)
					if err != nil {
						logVerbose("Agent %s: Failed to listen UDP :%d: %v", agentAssignedID, req.AgentListenPort, err)
						listenerCancel()
						sendStartListenerResp(false, err.Error())
						return
					}
					agentSideUDPListenersLock.Lock()
					agentSideUDPListeners[req.ListenerID] = pc
					agentSideUDPListenersLock.Unlock()
					agentSideListenersLock.Lock()
					agentSideListenerCancels[req.ListenerID] = listenerCancel
					agentSideListenersLock.Unlock()
					logVerbose("Agent %s: Started UDP listening on :%d", agentAssignedID, req.AgentListenPort)
					sendStartListenerResp(true, "")
					go func(lid string) {
						<-listenerCtx.Done()
						pc.Close()
						agentSideUDPListenersLock.Lock()
						delete(agentSideUDPListeners, lid)
						agentSideUDPListenersLock.Unlock()
					}(req.ListenerID)
					go handleAgentUDPListener(pc, req.DestinationHost, req.DestinationPort, agentAssignedID, listenerCtx)
				} else {
					agentSideListenersLock.Lock()
					portInUse := false
					for _, l := range agentSideListeners {
						if lAddr, ok := l.Addr().(*net.TCPAddr); ok && lAddr.Port == req.AgentListenPort {
							portInUse = true
							break
						}
					}
					agentSideListenersLock.Unlock()
					if portInUse {
						logVerbose("Agent %s: Port %d already in use", agentAssignedID, req.AgentListenPort)
						listenerCancel()
						sendStartListenerResp(false, fmt.Sprintf("port %d already in use", req.AgentListenPort))
						return
					}
					listener, err := listenAgentTCP(fmt.Sprintf(":%d", req.AgentListenPort))
					if err != nil {
						logVerbose("Agent %s: Failed to listen on :%d: %v", agentAssignedID, req.AgentListenPort, err)
						listenerCancel()
						sendStartListenerResp(false, err.Error())
						return
					}
					agentSideListenersLock.Lock()
					agentSideListeners[req.ListenerID] = listener
					agentSideListenerCancels[req.ListenerID] = listenerCancel
					agentSideListenersLock.Unlock()
					sendStartListenerResp(true, "")
					go func(ln net.Listener, lid string, ctx context.Context) {
						<-ctx.Done()
						ln.Close()
						agentSideListenersLock.Lock()
						delete(agentSideListeners, lid)
						delete(agentSideListenerCancels, lid)
						agentSideListenersLock.Unlock()
					}(listener, req.ListenerID, listenerCtx)
					go func(ln net.Listener, ctx context.Context) {
						for {
							clientConn, err := ln.Accept()
							if err != nil {
								select {
								case <-ctx.Done():
									return
								default:
									logVerbose("Agent %s: Error accepting connection: %v", agentAssignedID, err)
									continue
								}
							}
							sendEnc := func(connID string, data []byte) error {
								return c.writeDataForConn(connID, data)
							}
							go handleAgentClientConnection(clientConn, req.DestinationHost, req.DestinationPort, agentAssignedID, sendEnc)
						}
					}(listener, listenerCtx)
				}

			case "stop-agent-listener":
				var req StopAgentListenerMessage
				if err := json.Unmarshal(msg.Payload, &req); err != nil {
					logVerbose("Agent %s: error unmarshalling stop-agent-listener: %v", agentAssignedID, err)
					return
				}
				agentSideListenersLock.Lock()
				cancelFunc, ok := agentSideListenerCancels[req.ListenerID]
				ln, lOk := agentSideListeners[req.ListenerID]
				agentSideListenersLock.Unlock()
				if ok {
					cancelFunc()
				}
				if lOk && ln != nil {
					ln.Close()
				}
				logVerbose("Agent %s: Stopped listener %s", agentAssignedID, req.ListenerID)

			case "connect":
				var req ConnectRequest
				if err := json.Unmarshal(msg.Payload, &req); err != nil {
					logVerbose("Agent %s: invalid connect request: %v", agentAssignedID, err)
					return
				}
				logVerbose("Agent %s: connect request conn=%s proto=%s target=%s:%d", agentAssignedID, req.ConnID, req.Protocol, req.TargetHost, req.TargetPort)
				sendConnectResponse := func(connID string, success bool, errMsg string) error {
					resp := ConnectResponse{ConnID: connID, Success: success, Error: errMsg}
					p, _ := json.Marshal(resp)
					m := Message{Type: "connect_response", Payload: p, OriginalAgentID: agentAssignedID}
					mp, _ := json.Marshal(m)
					enc, err := encrypt(mp, getEncryptionKey())
					if err != nil {
						return err
					}
					err = agentSend(c, &writeMu, enc)
					if err != nil {
						logVerbose("Agent %s: connect_response send failed conn=%s success=%v err=%v", agentAssignedID, connID, success, err)
					} else {
						logVerbose("Agent %s: connect_response sent conn=%s success=%v", agentAssignedID, connID, success)
					}
					return err
				}
				go func(req ConnectRequest) {
					if req.Protocol == "udp" {
						targetAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(req.TargetHost, fmt.Sprintf("%d", req.TargetPort)))
						if err != nil {
							sendConnectResponse(req.ConnID, false, err.Error())
							return
						}
						conn, err := net.DialUDP("udp", nil, targetAddr)
						if err != nil {
							sendConnectResponse(req.ConnID, false, err.Error())
							return
						}
						if _, canceled := canceledConns.LoadAndDelete(req.ConnID); canceled {
							conn.Close()
							return
						}
						udpConns.Store(req.ConnID, conn)
						udpWriters.Store(req.ConnID, newConnWriter(conn))
						if err := sendConnectResponse(req.ConnID, true, ""); err != nil {
							conn.Close()
							udpConns.Delete(req.ConnID)
							if w, ok := udpWriters.LoadAndDelete(req.ConnID); ok {
								w.(*connWriter).close()
							}
							return
						}
						bufPtr := agentBufPool.Get().(*[]byte)
						buf := *bufPtr
						for {
							n, _, err := conn.ReadFromUDP(buf)
							if err != nil {
								agentBufPool.Put(bufPtr)
								sendDataMsg(req.ConnID, nil, true)
								udpConns.Delete(req.ConnID)
								if w, ok := udpWriters.LoadAndDelete(req.ConnID); ok {
									w.(*connWriter).close()
								}
								return
							}
							sendDataMsg(req.ConnID, buf[:n], false)
						}
					} else {
						targetAddr := net.JoinHostPort(req.TargetHost, fmt.Sprintf("%d", req.TargetPort))
						targetConn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
						if err != nil {
							sendConnectResponse(req.ConnID, false, err.Error())
							return
						}
						if _, canceled := canceledConns.LoadAndDelete(req.ConnID); canceled {
							targetConn.Close()
							return
						}
						targetConns.Store(req.ConnID, targetConn)
						targetWriters.Store(req.ConnID, newConnWriter(targetConn))
						if err := sendConnectResponse(req.ConnID, true, ""); err != nil {
							targetConn.Close()
							targetConns.Delete(req.ConnID)
							if w, ok := targetWriters.LoadAndDelete(req.ConnID); ok {
								w.(*connWriter).close()
							}
							return
						}
						bufPtr := agentBufPool.Get().(*[]byte)
						buf := *bufPtr
						for {
							n, err := targetConn.Read(buf)
							if err != nil {
								agentBufPool.Put(bufPtr)
								sendDataMsg(req.ConnID, nil, true)
								targetConns.Delete(req.ConnID)
								if w, ok := targetWriters.LoadAndDelete(req.ConnID); ok {
									w.(*connWriter).close()
								}
								return
							}
							sendDataMsg(req.ConnID, buf[:n], false)
						}
					}
				}(req)

			case "data":
				var dataMsg DataMessage
				if err := json.Unmarshal(msg.Payload, &dataMsg); err != nil {
					return
				}
				if dataMsg.Compressed && len(dataMsg.Data) > 0 {
					dec, err := decompressData(dataMsg.Data)
					if err != nil {
						return
					}
					dataMsg.Data = dec
				}
				if _, ok := targetConns.Load(dataMsg.ConnID); ok {
					if dataMsg.Close {
						if v, ok := targetConns.LoadAndDelete(dataMsg.ConnID); ok {
							v.(net.Conn).Close()
						}
						if w, ok := targetWriters.LoadAndDelete(dataMsg.ConnID); ok {
							w.(*connWriter).close()
						}
					} else if w, ok := targetWriters.Load(dataMsg.ConnID); ok {
						if !w.(*connWriter).write(dataMsg.Data) {
							targetConns.Delete(dataMsg.ConnID)
							targetWriters.Delete(dataMsg.ConnID)
						}
					}
				} else if _, ok := udpConns.Load(dataMsg.ConnID); ok {
					if dataMsg.Close {
						if v, ok := udpConns.LoadAndDelete(dataMsg.ConnID); ok {
							v.(*net.UDPConn).Close()
						}
						if w, ok := udpWriters.LoadAndDelete(dataMsg.ConnID); ok {
							w.(*connWriter).close()
						}
					} else if w, ok := udpWriters.Load(dataMsg.ConnID); ok {
						if !w.(*connWriter).write(dataMsg.Data) {
							udpConns.Delete(dataMsg.ConnID)
							udpWriters.Delete(dataMsg.ConnID)
						}
					}
				} else if dataMsg.Close {
					canceledConns.Store(dataMsg.ConnID, struct{}{})
				}

			case "icmp-request":
				var req ICMPRequest
				if err := json.Unmarshal(msg.Payload, &req); err != nil {
					return
				}
				go func(req ICMPRequest) {
					if err := validatePingTarget(req.Target); err != nil {
						sendICMPResponse(ICMPResponse{Target: req.Target, Success: false, Error: err.Error()})
						return
					}
					ip := net.ParseIP(req.Target)
					if ip == nil {
						addrs, err := net.LookupIP(req.Target)
						if err != nil || len(addrs) == 0 {
							sendICMPResponse(ICMPResponse{Target: req.Target, Success: false, Error: fmt.Sprintf("DNS lookup failed: %v", err)})
							return
						}
						var chosen, first net.IP
						for _, a := range addrs {
							if first == nil {
								first = a
							}
							if v4 := a.To4(); v4 != nil {
								chosen = v4
								break
							}
						}
						if chosen != nil {
							ip = chosen
						} else {
							ip = first
						}
					}
					if ip.To4() != nil {
						pingIPv4(ip, req, sendICMPResponse)
					} else {
						pingIPv6(ip, req, sendICMPResponse)
					}
				}(req)

			case "icmp_proxy":
				var req ICMPProxyRequest
				if err := json.Unmarshal(msg.Payload, &req); err != nil {
					return
				}
				sendICMPProxyResponse := func(resp ICMPProxyResponse) {
					p, _ := json.Marshal(resp)
					m := Message{Type: "icmp_proxy_response", Payload: p, OriginalAgentID: agentAssignedID}
					mp, _ := json.Marshal(m)
					enc, err := encrypt(mp, getEncryptionKey())
					if err != nil {
						return
					}
					agentSend(c, &writeMu, enc)
				}
				go func(req ICMPProxyRequest) {
					resp := ICMPProxyResponse{ConnID: req.ConnID}
					ip := net.ParseIP(req.Target)
					if ip == nil {
						resp.Error = "invalid target IP"
						sendICMPProxyResponse(resp)
						return
					}
					proxDone := make(chan struct{}, 1)
					pingReq := ICMPRequest{Target: req.Target, Count: 1, TimeoutMs: req.TimeoutMs}
					cb := func(r ICMPResponse) {
						resp.Success = r.Success
						resp.RttMs = r.RttMs
						resp.Error = r.Error
						select {
						case proxDone <- struct{}{}:
						default:
						}
					}
					if ip.To4() != nil {
						pingIPv4(ip, pingReq, cb)
					} else {
						pingIPv6(ip, pingReq, cb)
					}
					<-proxDone
					sendICMPProxyResponse(resp)
				}(req)

			case "port-scan-request":
				var req PortScanRequest
				if err := json.Unmarshal(msg.Payload, &req); err != nil {
					return
				}
				go func(req PortScanRequest) {
					results := doLocalPortScan(req)
					resp := PortScanResponse{Target: req.Target, Proto: req.Proto, Results: results, Done: true}
					p, _ := json.Marshal(resp)
					m := Message{Type: "port-scan-response", Payload: p, OriginalAgentID: agentAssignedID}
					mp, _ := json.Marshal(m)
					enc, err := encrypt(mp, getEncryptionKey())
					if err != nil {
						return
					}
					agentSend(c, &writeMu, enc)
				}(req)

			case "agent_fwd_ack":
				var ack AgentFwdAck
				if err := json.Unmarshal(msg.Payload, &ack); err != nil {
					return
				}
				if ch, ok := agentFwdAckMap.Load(ack.ConnID); ok {
					select {
					case ch.(chan AgentFwdAck) <- ack:
					default:
					}
				}

			case "agent_fwd_data":
				var dm DataMessage
				if err := json.Unmarshal(msg.Payload, &dm); err != nil {
					return
				}
				if dm.Compressed && len(dm.Data) > 0 {
					dec, err := decompressData(dm.Data)
					if err != nil {
						return
					}
					dm.Data = dec
				}
				if value, ok := agentFwdConns.Load(dm.ConnID); ok {
					afc := value.(*agentFwdConn)
					if dm.Close {
						agentFwdConns.Delete(dm.ConnID)
						afc.close()
					} else {
						afc.send(dm.Data)
					}
				}

			case "disconnect":
				logVerbose("Agent %s: received disconnect command, exiting", agentAssignedID)
				go func() {
					time.Sleep(1 * time.Second)
					c.Close()
					os.Exit(0)
				}()
			}
		}

		c.setOnEnvelope(dispatchWSAgentMsg)
		go func() {
			<-c.closed()
			close(done)
		}()

		ticker := time.NewTicker(10 * time.Second)
	heartbeatLoop:
		for {
			select {
			case <-agentStop:
				logVerbose("Agent: interrupt, exiting")
				c.Close()
				cancel()
				return
			case <-done:
				logVerbose("Agent: connection lost")
				break heartbeatLoop
			case <-ticker.C:
				if agentAssignedID != "" {
					hb := Message{Type: "heartbeat", Payload: []byte(`{}`), OriginalAgentID: agentAssignedID}
					hbPayload, _ := json.Marshal(hb)
					enc, err := encrypt(hbPayload, encryptionKey)
					if err != nil {
						logVerbose("Agent: heartbeat encryption error: %v", err)
						break heartbeatLoop
					}
					if err := agentSend(c, &writeMu, enc); err != nil {
						logVerbose("Agent: heartbeat send failed: %v", err)
						break heartbeatLoop
					}
				}
			}
		}
		ticker.Stop()
		c.Close()
		cancel()

		agentSideListenersLock.Lock()
		for id, cancel := range agentSideListenerCancels {
			cancel()
			_ = id
		}
		for _, ln := range agentSideListeners {
			ln.Close()
		}
		agentSideListeners = make(map[string]net.Listener)
		agentSideListenerCancels = make(map[string]context.CancelFunc)
		agentSideListenersLock.Unlock()

		agentSideUDPListenersLock.Lock()
		for _, pc := range agentSideUDPListeners {
			pc.Close()
		}
		agentSideUDPListeners = make(map[string]*net.UDPConn)
		agentSideUDPListenersLock.Unlock()

		delay := nextBackoff()
		logVerbose("Agent: reconnecting in %s...", delay)
		if !agentSleep(delay) {
			return
		}
	}
}

func runAgentBind(bindAddr, keyBase64 string, agentStop <-chan struct{}) {
	key, err := decodeKey(keyBase64)
	if err != nil {
		log.Fatalf("agent-bind: invalid key: %v", err)
	}
	setEncryptionKey(key)
	encryptionKey = key

	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		log.Fatalf("agent-bind: listen %s: %v", bindAddr, err)
	}
	logVerbose("agent-bind: listening on %s", bindAddr)

	go func() {
		<-agentStop
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-agentStop:
				logVerbose("agent-bind: interrupt, exiting")
				return
			default:
			}
			logVerbose("agent-bind: accept error: %v", err)
			continue
		}
		logVerbose("agent-bind: server connected from %s", conn.RemoteAddr())
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(15 * time.Second)
			tc.SetNoDelay(true)
		}
		go runAgentBindSession(conn, agentStop)
	}
}

func runAgentBindSession(conn net.Conn, agentStop <-chan struct{}) {
	defer conn.Close()

	var agentAssignedID string
	var writeMu sync.Mutex

	subnets, err := getSubnets()
	if err != nil {
		logVerbose("agent-bind: could not get subnets: %v", err)
		return
	}
	userInfo, _ := user.Current()
	hostname, _ := os.Hostname()
	registerMsg := RegisterMessage{
		Subnets:  subnets,
		OS:       runtime.GOOS,
		Hostname: hostname,
		Username: func() string {
			if userInfo != nil {
				return userInfo.Username
			}
			return ""
		}(),
		HasInternet: probeInternet(),
	}
	payload, _ := json.Marshal(registerMsg)
	msg := Message{Type: "register", Payload: payload}
	msgPayload, _ := json.Marshal(msg)
	encrypted, err := encrypt(msgPayload, getEncryptionKey())
	if err != nil {
		logVerbose("agent-bind: encrypt register: %v", err)
		return
	}
	if err := agentSendRaw(conn, &writeMu, encrypted); err != nil {
		logVerbose("agent-bind: send register: %v", err)
		return
	}

	done := make(chan struct{})
	var targetConns sync.Map
	var udpConns sync.Map
	var canceledConns sync.Map

	sendDataMsg := func(connID string, data []byte, closeConn bool) {
		dataMsg := DataMessage{ConnID: connID, Data: data, Close: closeConn}
		if len(data) > 256 {
			if compressed, ok := compressData(data); ok {
				dataMsg.Data = compressed
				dataMsg.Compressed = true
			}
		}
		p, _ := json.Marshal(dataMsg)
		m := Message{Type: "data", Payload: p, OriginalAgentID: agentAssignedID}
		mp, _ := json.Marshal(m)
		enc, err := encrypt(mp, encryptionKey)
		if err != nil {
			return
		}
		agentSendRaw(conn, &writeMu, enc)
	}

	sendICMPResponse := func(resp ICMPResponse) {
		p, _ := json.Marshal(resp)
		m := Message{Type: "icmp-response", Payload: p, OriginalAgentID: agentAssignedID}
		mp, _ := json.Marshal(m)
		enc, err := encrypt(mp, encryptionKey)
		if err != nil {
			return
		}
		agentSendRaw(conn, &writeMu, enc)
	}

	dispatchBindAgentMsg := func(encrypted []byte) {
		plaintext, err := decrypt(encrypted, getEncryptionKey())
		if err != nil {
			logVerbose("agent-bind: decrypt: %v", err)
			return
		}
		var msg Message
		if err := json.Unmarshal(plaintext, &msg); err != nil {
			logVerbose("agent-bind: unmarshal: %v", err)
			return
		}

		switch msg.Type {
		case "register_ok":
			var payload struct {
				ID string `json:"id"`
			}
			json.Unmarshal(msg.Payload, &payload)
			agentAssignedID = payload.ID
			logVerbose("agent-bind: assigned ID: %s", agentAssignedID)

		case "reconnect":
			logVerbose("agent-bind %s: reconnect received, closing", agentAssignedID)
			conn.Close()
			return

		case "dns_request":
			var dnsReq DNSRequestMessage
			if err := json.Unmarshal(msg.Payload, &dnsReq); err != nil {
				logVerbose("agent-bind: invalid dns_request: %v", err)
				return
			}
			go handleAgentDNSRequest(agentAssignedID, dnsReq, func(encrypted []byte) error {
				return agentSendRaw(conn, &writeMu, encrypted)
			})

		case "ping-sweep-request":
			var req PingSweepRequest
			if err := json.Unmarshal(msg.Payload, &req); err != nil {
				logVerbose("agent-bind %s: invalid ping-sweep-request: %v", agentAssignedID, err)
				return
			}
			go func(req PingSweepRequest) {
				results := doPingSweep(req)
				resp := PingSweepResponse{Subnet: req.Subnet, Results: results}
				p, _ := json.Marshal(resp)
				rm := Message{Type: "ping-sweep-response", Payload: p, OriginalAgentID: agentAssignedID, TargetAgentID: "server"}
				mp, _ := json.Marshal(rm)
				enc, err := encrypt(mp, encryptionKey)
				if err != nil {
					return
				}
				agentSendRaw(conn, &writeMu, enc)
			}(req)

		case "start-agent-listener":
			var req StartAgentListenerMessage
			if err := json.Unmarshal(msg.Payload, &req); err != nil {
				logVerbose("agent-bind %s: invalid start-agent-listener: %v", agentAssignedID, err)
				return
			}
			sendStartListenerResp := func(success bool, errMsg string) {
				resp := StartAgentListenerResponse{ListenerID: req.ListenerID, Success: success, Error: errMsg}
				p, _ := json.Marshal(resp)
				m := Message{Type: "start-agent-listener-response", Payload: p, OriginalAgentID: agentAssignedID}
				mp, _ := json.Marshal(m)
				enc, err := encrypt(mp, encryptionKey)
				if err != nil {
					return
				}
				agentSendRaw(conn, &writeMu, enc) //nolint:errcheck
			}
			logVerbose("agent-bind %s: starting listener port %d -> %s:%d", agentAssignedID, req.AgentListenPort, req.DestinationHost, req.DestinationPort)

			listenerCtx, listenerCancel := context.WithCancel(context.Background())

			if req.Protocol == "udp" {
				udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", req.AgentListenPort))
				if err != nil {
					logVerbose("agent-bind %s: failed to resolve UDP :%d: %v", agentAssignedID, req.AgentListenPort, err)
					listenerCancel()
					sendStartListenerResp(false, err.Error())
					return
				}
				pc, err := net.ListenUDP("udp", udpAddr)
				if err != nil {
					logVerbose("agent-bind %s: failed to listen UDP :%d: %v", agentAssignedID, req.AgentListenPort, err)
					listenerCancel()
					sendStartListenerResp(false, err.Error())
					return
				}
				agentSideUDPListenersLock.Lock()
				agentSideUDPListeners[req.ListenerID] = pc
				agentSideUDPListenersLock.Unlock()
				agentSideListenersLock.Lock()
				agentSideListenerCancels[req.ListenerID] = listenerCancel
				agentSideListenersLock.Unlock()
				sendStartListenerResp(true, "")
				go func(lid string) {
					<-listenerCtx.Done()
					pc.Close()
					agentSideUDPListenersLock.Lock()
					delete(agentSideUDPListeners, lid)
					agentSideUDPListenersLock.Unlock()
				}(req.ListenerID)
				go handleAgentUDPListener(pc, req.DestinationHost, req.DestinationPort, agentAssignedID, listenerCtx)
			} else {
				agentSideListenersLock.Lock()
				portInUse := false
				for _, l := range agentSideListeners {
					if lAddr, ok := l.Addr().(*net.TCPAddr); ok && lAddr.Port == req.AgentListenPort {
						portInUse = true
						break
					}
				}
				agentSideListenersLock.Unlock()
				if portInUse {
					logVerbose("agent-bind %s: port %d already in use", agentAssignedID, req.AgentListenPort)
					listenerCancel()
					sendStartListenerResp(false, fmt.Sprintf("port %d already in use", req.AgentListenPort))
					return
				}

				listener, err := listenAgentTCP(fmt.Sprintf(":%d", req.AgentListenPort))
				if err != nil {
					logVerbose("agent-bind %s: failed to listen on :%d: %v", agentAssignedID, req.AgentListenPort, err)
					listenerCancel()
					sendStartListenerResp(false, err.Error())
					return
				}
				agentSideListenersLock.Lock()
				agentSideListeners[req.ListenerID] = listener
				agentSideListenerCancels[req.ListenerID] = listenerCancel
				agentSideListenersLock.Unlock()
				sendStartListenerResp(true, "")

				go func(ln net.Listener, lid string, ctx context.Context) {
					<-ctx.Done()
					ln.Close()
					agentSideListenersLock.Lock()
					delete(agentSideListeners, lid)
					delete(agentSideListenerCancels, lid)
					agentSideListenersLock.Unlock()
				}(listener, req.ListenerID, listenerCtx)

				go func(ln net.Listener, ctx context.Context) {
					for {
						clientConn, err := ln.Accept()
						if err != nil {
							select {
							case <-ctx.Done():
								return
							default:
								continue
							}
						}
						sendEnc := func(_ string, data []byte) error {
							return agentSendRaw(conn, &writeMu, data)
						}
						go handleAgentClientConnection(clientConn, req.DestinationHost, req.DestinationPort, agentAssignedID, sendEnc)
					}
				}(listener, listenerCtx)
			}

		case "stop-agent-listener":
			var req StopAgentListenerMessage
			if err := json.Unmarshal(msg.Payload, &req); err != nil {
				logVerbose("agent-bind %s: invalid stop-agent-listener: %v", agentAssignedID, err)
				return
			}
			agentSideListenersLock.Lock()
			cancelFunc, ok := agentSideListenerCancels[req.ListenerID]
			ln, lOk := agentSideListeners[req.ListenerID]
			agentSideListenersLock.Unlock()
			if ok {
				cancelFunc()
			}
			if lOk && ln != nil {
				ln.Close()
			}
			logVerbose("agent-bind %s: stopped listener %s", agentAssignedID, req.ListenerID)

		case "connect":
			var req ConnectRequest
			if err := json.Unmarshal(msg.Payload, &req); err != nil {
				logVerbose("agent-bind %s: invalid connect: %v", agentAssignedID, err)
				return
			}
			sendConnectResponse := func(connID string, success bool, errMsg string) error {
				resp := ConnectResponse{ConnID: connID, Success: success, Error: errMsg}
				p, _ := json.Marshal(resp)
				m := Message{Type: "connect_response", Payload: p, OriginalAgentID: agentAssignedID}
				mp, _ := json.Marshal(m)
				enc, err := encrypt(mp, encryptionKey)
				if err != nil {
					return err
				}
				return agentSendRaw(conn, &writeMu, enc)
			}
			go func(req ConnectRequest) {
				if req.Protocol == "udp" {
					targetAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(req.TargetHost, fmt.Sprintf("%d", req.TargetPort)))
					if err != nil {
						sendConnectResponse(req.ConnID, false, err.Error())
						return
					}
					udpConn, err := net.DialUDP("udp", nil, targetAddr)
					if err != nil {
						sendConnectResponse(req.ConnID, false, err.Error())
						return
					}
					if _, canceled := canceledConns.LoadAndDelete(req.ConnID); canceled {
						udpConn.Close()
						return
					}
					udpConns.Store(req.ConnID, udpConn)
					if err := sendConnectResponse(req.ConnID, true, ""); err != nil {
						udpConn.Close()
						udpConns.Delete(req.ConnID)
						return
					}
					bufPtr := agentBufPool.Get().(*[]byte)
					buf := *bufPtr
					for {
						n, _, err := udpConn.ReadFromUDP(buf)
						if err != nil {
							agentBufPool.Put(bufPtr)
							sendDataMsg(req.ConnID, nil, true)
							udpConns.Delete(req.ConnID)
							return
						}
						sendDataMsg(req.ConnID, buf[:n], false)
					}
				} else {
					targetAddr := net.JoinHostPort(req.TargetHost, fmt.Sprintf("%d", req.TargetPort))
					targetConn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
					if err != nil {
						sendConnectResponse(req.ConnID, false, err.Error())
						return
					}
					if _, canceled := canceledConns.LoadAndDelete(req.ConnID); canceled {
						targetConn.Close()
						return
					}
					targetConns.Store(req.ConnID, targetConn)
					if err := sendConnectResponse(req.ConnID, true, ""); err != nil {
						targetConn.Close()
						targetConns.Delete(req.ConnID)
						return
					}
					bufPtr := agentBufPool.Get().(*[]byte)
					buf := *bufPtr
					for {
						n, err := targetConn.Read(buf)
						if err != nil {
							agentBufPool.Put(bufPtr)
							sendDataMsg(req.ConnID, nil, true)
							targetConns.Delete(req.ConnID)
							return
						}
						sendDataMsg(req.ConnID, buf[:n], false)
					}
				}
			}(req)

		case "data":
			var dataMsg DataMessage
			if err := json.Unmarshal(msg.Payload, &dataMsg); err != nil {
				return
			}
			if dataMsg.Compressed && len(dataMsg.Data) > 0 {
				dec, err := decompressData(dataMsg.Data)
				if err != nil {
					return
				}
				dataMsg.Data = dec
			}
			if value, ok := targetConns.Load(dataMsg.ConnID); ok {
				tc := value.(net.Conn)
				if dataMsg.Close {
					tc.Close()
					targetConns.Delete(dataMsg.ConnID)
				} else {
					tc.SetWriteDeadline(time.Now().Add(10 * time.Second))
					if _, err := tc.Write(dataMsg.Data); err != nil {
						tc.Close()
						targetConns.Delete(dataMsg.ConnID)
					}
					tc.SetWriteDeadline(time.Time{})
				}
			} else if value, ok := udpConns.Load(dataMsg.ConnID); ok {
				uc := value.(*net.UDPConn)
				if dataMsg.Close {
					uc.Close()
					udpConns.Delete(dataMsg.ConnID)
				} else {
					uc.SetWriteDeadline(time.Now().Add(10 * time.Second))
					if _, err := uc.Write(dataMsg.Data); err != nil {
						uc.Close()
						udpConns.Delete(dataMsg.ConnID)
					}
					uc.SetWriteDeadline(time.Time{})
				}
			} else if dataMsg.Close {
				canceledConns.Store(dataMsg.ConnID, struct{}{})
			}

		case "icmp-request":
			var req ICMPRequest
			if err := json.Unmarshal(msg.Payload, &req); err != nil {
				logVerbose("agent-bind %s: invalid icmp-request: %v", agentAssignedID, err)
				return
			}
			go func(req ICMPRequest) {
				if err := validatePingTarget(req.Target); err != nil {
					sendICMPResponse(ICMPResponse{Target: req.Target, Seq: 0, Success: false, Error: err.Error()})
					return
				}
				ip := net.ParseIP(req.Target)
				if ip == nil {
					addrs, err := net.LookupIP(req.Target)
					if err != nil || len(addrs) == 0 {
						sendICMPResponse(ICMPResponse{Target: req.Target, Seq: 0, Success: false, Error: fmt.Sprintf("DNS lookup failed: %v", err)})
						return
					}
					var chosen, first net.IP
					for _, a := range addrs {
						if first == nil {
							first = a
						}
						if v4 := a.To4(); v4 != nil {
							chosen = v4
							break
						}
					}
					if chosen != nil {
						ip = chosen
					} else {
						ip = first
					}
				}
				if ip.To4() != nil {
					pingIPv4(ip, req, sendICMPResponse)
				} else {
					pingIPv6(ip, req, sendICMPResponse)
				}
			}(req)

		case "icmp_proxy":
			var req ICMPProxyRequest
			if err := json.Unmarshal(msg.Payload, &req); err != nil {
				logVerbose("agent-bind %s: invalid icmp_proxy: %v", agentAssignedID, err)
				return
			}
			sendICMPProxyResponseBind := func(resp ICMPProxyResponse) {
				p, _ := json.Marshal(resp)
				m := Message{Type: "icmp_proxy_response", Payload: p, OriginalAgentID: agentAssignedID}
				mp, _ := json.Marshal(m)
				enc, err := encrypt(mp, encryptionKey)
				if err != nil {
					return
				}
				agentSendRaw(conn, &writeMu, enc)
			}
			go func(req ICMPProxyRequest) {
				resp := ICMPProxyResponse{ConnID: req.ConnID}
				ip := net.ParseIP(req.Target)
				if ip == nil {
					resp.Error = "invalid target IP"
					sendICMPProxyResponseBind(resp)
					return
				}
				proxDone := make(chan struct{}, 1)
				pingReq := ICMPRequest{Target: req.Target, Count: 1, TimeoutMs: req.TimeoutMs}
				cb := func(r ICMPResponse) {
					resp.Success = r.Success
					resp.RttMs = r.RttMs
					resp.Error = r.Error
					select {
					case proxDone <- struct{}{}:
					default:
					}
				}
				if ip.To4() != nil {
					pingIPv4(ip, pingReq, cb)
				} else {
					pingIPv6(ip, pingReq, cb)
				}
				<-proxDone
				sendICMPProxyResponseBind(resp)
			}(req)

		case "port-scan-request":
			var req PortScanRequest
			if err := json.Unmarshal(msg.Payload, &req); err != nil {
				return
			}
			go func(req PortScanRequest) {
				results := doLocalPortScan(req)
				resp := PortScanResponse{Target: req.Target, Proto: req.Proto, Results: results, Done: true}
				p, _ := json.Marshal(resp)
				m := Message{Type: "port-scan-response", Payload: p, OriginalAgentID: agentAssignedID}
				mp, _ := json.Marshal(m)
				enc, err := encrypt(mp, encryptionKey)
				if err != nil {
					return
				}
				agentSendRaw(conn, &writeMu, enc)
			}(req)

		case "agent_fwd_ack":
			var ack AgentFwdAck
			if err := json.Unmarshal(msg.Payload, &ack); err != nil {
				logVerbose("agent-bind %s: invalid agent_fwd_ack: %v", agentAssignedID, err)
				return
			}
			if ch, ok := agentFwdAckMap.Load(ack.ConnID); ok {
				select {
				case ch.(chan AgentFwdAck) <- ack:
				default:
				}
			}

		case "agent_fwd_data":
			var dm DataMessage
			if err := json.Unmarshal(msg.Payload, &dm); err != nil {
				logVerbose("agent-bind %s: invalid agent_fwd_data: %v", agentAssignedID, err)
				return
			}
			if dm.Compressed && len(dm.Data) > 0 {
				dec, err := decompressData(dm.Data)
				if err != nil {
					logVerbose("agent-bind %s: agent_fwd_data decompress error: %v", agentAssignedID, err)
					return
				}
				dm.Data = dec
			}
			if value, ok := agentFwdConns.Load(dm.ConnID); ok {
				afc := value.(*agentFwdConn)
				if dm.Close {
					agentFwdConns.Delete(dm.ConnID)
					afc.close()
				} else {
					afc.send(dm.Data)
				}
			}

		case "disconnect":
			logVerbose("agent-bind %s: disconnect received, exiting", agentAssignedID)
			go func() {
				time.Sleep(1 * time.Second)
				conn.Close()
				os.Exit(0)
			}()
		}
	}

	go func() {
		defer close(done)
		for {
			data, err := readBindFrame(conn)
			if err != nil {
				if !isAgentNormalCloseError(err) {
					logVerbose("agent-bind: read: %v", err)
				}
				return
			}
			dispatchBindAgentMsg(data)
		}
	}()

	ticker := time.NewTicker(10 * time.Second)
heartbeatBindLoop:
	for {
		select {
		case <-agentStop:
			logVerbose("agent-bind: interrupt, exiting")
			conn.Close()
			return
		case <-done:
			logVerbose("agent-bind: connection lost")
			break heartbeatBindLoop
		case <-ticker.C:
			if agentAssignedID != "" {
				hb := Message{Type: "heartbeat", Payload: []byte(`{}`), OriginalAgentID: agentAssignedID}
				hbPayload, _ := json.Marshal(hb)
				enc, err := encrypt(hbPayload, encryptionKey)
				if err != nil {
					logVerbose("agent-bind: heartbeat encryption error: %v", err)
					break heartbeatBindLoop
				}
				if err := agentSendRaw(conn, &writeMu, enc); err != nil {
					logVerbose("agent-bind: heartbeat send failed: %v", err)
					break heartbeatBindLoop
				}
			}
		}
	}
	ticker.Stop()
}

func decodeKey(keyBase64 string) ([]byte, error) {
	key, err := base64.URLEncoding.DecodeString(keyBase64)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("key must be base64url-encoded 32 bytes")
	}
	return key, nil
}
