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
	"net/http"
	"net/url"
	"os"
	"os/user"
	"runtime"
	"sync"
	"time"

	"strings"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
)

 
var agentBufPool = sync.Pool{New: func() interface{} { b := make([]byte, 64*1024); return &b }}

func agentYamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.KeepAliveInterval = 30 * time.Second
	cfg.ConnectionWriteTimeout = 60 * time.Second
	cfg.LogOutput = io.Discard
	return cfg
}

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

 
func agentSend(yamuxClient *yamux.Session, ws *websocket.Conn, writeMu *sync.Mutex, encrypted []byte) error {
	if yamuxClient != nil {
		stream, err := yamuxClient.Open()
		if err != nil {
			return err
		}
		defer stream.Close()
		l := len(encrypted)
		buf := []byte{byte(l >> 24), byte(l >> 16), byte(l >> 8), byte(l)}
		buf = append(buf, encrypted...)
		_, err = stream.Write(buf)
		return err
	}
	writeMu.Lock()
	defer writeMu.Unlock()
	return ws.WriteMessage(websocket.TextMessage, encrypted)
}

 
func agentSendRaw(yamuxClient *yamux.Session, conn net.Conn, writeMu *sync.Mutex, encrypted []byte) error {
	if yamuxClient != nil {
		stream, err := yamuxClient.Open()
		if err != nil {
			return err
		}
		defer stream.Close()
		l := len(encrypted)
		buf := []byte{byte(l >> 24), byte(l >> 16), byte(l >> 8), byte(l)}
		buf = append(buf, encrypted...)
		_, err = stream.Write(buf)
		return err
	}
	writeMu.Lock()
	defer writeMu.Unlock()
	l := len(encrypted)
	buf := []byte{byte(l >> 24), byte(l >> 16), byte(l >> 8), byte(l)}
	buf = append(buf, encrypted...)
	_, err := conn.Write(buf)
	return err
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

	 
	backoff := 5 * time.Second
	resetBackoff := func() { backoff = 5 * time.Second }
	nextBackoff := func() time.Duration {
		d := backoff
		backoff *= 2
		if backoff > 60*time.Second {
			backoff = 60 * time.Second
		}
		return d
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		NetDialContext:   (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 15 * time.Second}).DialContext,
	}
	wsHeaders := http.Header{
		"User-Agent": []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"},
	}
	dialWS := func(u string) (*websocket.Conn, error) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			select {
			case <-agentStop:
				cancel()
			case <-ctx.Done():
			}
		}()
		c, _, err := dialer.DialContext(ctx, u, wsHeaders)
		return c, err
	}

	for {
		u := url.URL{Scheme: "ws", Host: serverAddr, Path: wsPath}
		logVerbose("Agent: connecting to %s", u.String())
		c, err := dialWS(u.String())
		if err != nil {
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
		c.SetReadLimit(1 << 20)

		 
		{
			c.SetReadDeadline(time.Now().Add(10 * time.Second))
			_, rawChallenge, err := c.ReadMessage()
			c.SetReadDeadline(time.Time{})
			if err != nil {
				logVerbose("Agent: auth challenge read error: %v, retrying...", err)
				c.Close()
				if !agentSleep(5 * time.Second) {
					return
				}
				continue
			}
			plain, err := decrypt(rawChallenge, getEncryptionKey())
			if err != nil {
				logVerbose("Agent: auth challenge decrypt error (wrong key?): %v, retrying...", err)
				c.Close()
				if !agentSleep(5 * time.Second) {
					return
				}
				continue
			}
			var challengeMsg Message
			if err := json.Unmarshal(plain, &challengeMsg); err != nil || challengeMsg.Type != "auth_challenge" {
				logVerbose("Agent: unexpected auth message type, retrying...")
				c.Close()
				if !agentSleep(5 * time.Second) {
					return
				}
				continue
			}
			 
			respMsg := Message{Type: "auth_response", Payload: challengeMsg.Payload}
			respJSON, _ := json.Marshal(respMsg)
			enc, err := encrypt(respJSON, getEncryptionKey())
			if err != nil {
				logVerbose("Agent: auth response encrypt error: %v, retrying...", err)
				c.Close()
				if !agentSleep(5 * time.Second) {
					return
				}
				continue
			}
			c.SetWriteDeadline(time.Now().Add(10 * time.Second))
			err = c.WriteMessage(websocket.BinaryMessage, enc)
			c.SetWriteDeadline(time.Time{})
			if err != nil {
				logVerbose("Agent: auth response send error: %v, retrying...", err)
				c.Close()
				if !agentSleep(5 * time.Second) {
					return
				}
				continue
			}
		}
		 
		resetBackoff()

		yamuxClient, yamuxErr := yamux.Client(newWSNetConn(c), agentYamuxConfig())
		if yamuxErr != nil {
			logVerbose("Agent: yamux client error: %v, falling back to raw WS", yamuxErr)
			yamuxClient = nil
		}

		var agentAssignedID string
		var writeMu sync.Mutex

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
		if err := agentSend(yamuxClient, c, &writeMu, encrypted); err != nil {
			logVerbose("Agent: register send error: %v, retrying...", err)
			c.Close()
			if !agentSleep(5 * time.Second) {
				return
			}
			continue
		}

		done := make(chan struct{})
		var targetConns sync.Map
		var udpConns sync.Map

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
			agentSend(yamuxClient, c, &writeMu, enc)
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
			agentSend(yamuxClient, c, &writeMu, enc)
		}

		go func() {
			defer close(done)
			var decryptFailures int
			for {
				var encrypted []byte
				var readErr error

				if yamuxClient != nil {
					stream, err := yamuxClient.Accept()
					if err != nil {
						if !isAgentNormalCloseError(err) {
							logVerbose("Agent: yamux accept error: %v", err)
						}
						return
					}
					lenBuf := make([]byte, 4)
					if _, err := io.ReadFull(stream, lenBuf); err != nil {
						stream.Close()
						logVerbose("Agent: yamux read len error: %v", err)
						return
					}
					msgLen := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])
					data := make([]byte, msgLen)
					if _, err := io.ReadFull(stream, data); err != nil {
						stream.Close()
						logVerbose("Agent: yamux read data error: %v", err)
						return
					}
					stream.Close()
					encrypted = data
				} else {
					_, encrypted, readErr = c.ReadMessage()
					if readErr != nil {
						if websocket.IsCloseError(readErr, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
							logVerbose("Agent: connection closed normally")
						} else {
							logVerbose("Agent: read error: %v", readErr)
						}
						return
					}
				}

				plaintext, err := decrypt(encrypted, getEncryptionKey())
				if err != nil {
					decryptFailures++
					if decryptFailures >= 3 {
						logVerbose("Agent: 3 consecutive decrypt failures — possible key mismatch, reconnecting")
						c.Close()
						return
					}
					logVerbose("Agent: decryption error (%d/3): %v", decryptFailures, err)
					continue
				}
				decryptFailures = 0
				var msg Message
				if err := json.Unmarshal(plaintext, &msg); err != nil {
					logVerbose("Agent: error unmarshalling message: %v", err)
					continue
				}

				switch msg.Type {
				case "register_ok":
					var payload struct{ ID string `json:"id"` }
					json.Unmarshal(msg.Payload, &payload)
					agentAssignedID = payload.ID
					logVerbose("Agent: assigned ID: %s", agentAssignedID)

				case "reconnect":
					logVerbose("Agent %s: received reconnect command, reconnecting...", agentAssignedID)
					c.Close()
					return

				case "dns_request":
					var dnsReq DNSRequestMessage
					if err := json.Unmarshal(msg.Payload, &dnsReq); err != nil {
						logVerbose("Agent: invalid dns_request: %v", err)
						continue
					}
					go handleAgentDNSRequest(agentAssignedID, dnsReq, &writeMu, c, yamuxClient)

				case "ping-sweep-request":
					var req PingSweepRequest
					if err := json.Unmarshal(msg.Payload, &req); err != nil {
						logVerbose("Agent %s: invalid ping-sweep-request: %v", agentAssignedID, err)
						continue
					}
					results := doPingSweep(req)
					resp := PingSweepResponse{Subnet: req.Subnet, Results: results}
					p, _ := json.Marshal(resp)
					rm := Message{Type: "ping-sweep-response", Payload: p, OriginalAgentID: agentAssignedID, TargetAgentID: "server"}
					mp, _ := json.Marshal(rm)
					enc, err := encrypt(mp, getEncryptionKey())
					if err != nil {
						logVerbose("Agent %s: ping-sweep encrypt error: %v", agentAssignedID, err)
						continue
					}
					agentSend(yamuxClient, c, &writeMu, enc)

				case "start-agent-listener":
					var req StartAgentListenerMessage
					if err := json.Unmarshal(msg.Payload, &req); err != nil {
						logVerbose("Agent %s: error unmarshalling start-agent-listener: %v", agentAssignedID, err)
						continue
					}
					logVerbose("Agent %s: Starting listener on port %d -> %s:%d", agentAssignedID, req.AgentListenPort, req.DestinationHost, req.DestinationPort)

					listenerCtx, listenerCancel := context.WithCancel(context.Background())

					if req.Protocol == "udp" {
						udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", req.AgentListenPort))
						if err != nil {
							logVerbose("Agent %s: Failed to resolve UDP :%d: %v", agentAssignedID, req.AgentListenPort, err)
							listenerCancel()
							continue
						}
						pc, err := net.ListenUDP("udp", udpAddr)
						if err != nil {
							logVerbose("Agent %s: Failed to listen UDP :%d: %v", agentAssignedID, req.AgentListenPort, err)
							listenerCancel()
							continue
						}
						agentSideUDPListenersLock.Lock()
						agentSideUDPListeners[req.ListenerID] = pc
						agentSideUDPListenersLock.Unlock()
						agentSideListenersLock.Lock()
						agentSideListenerCancels[req.ListenerID] = listenerCancel
						agentSideListenersLock.Unlock()
						logVerbose("Agent %s: Started UDP listening on :%d", agentAssignedID, req.AgentListenPort)
						go func(lid string) {
							<-listenerCtx.Done()
							pc.Close()
							agentSideUDPListenersLock.Lock()
							delete(agentSideUDPListeners, lid)
							agentSideUDPListenersLock.Unlock()
							logVerbose("Agent %s: Stopped UDP listener %s", agentAssignedID, lid)
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
							continue
						}

						listener, err := net.Listen("tcp", fmt.Sprintf(":%d", req.AgentListenPort))
						if err != nil {
							logVerbose("Agent %s: Failed to listen on :%d: %v", agentAssignedID, req.AgentListenPort, err)
							listenerCancel()
							continue
						}
						agentSideListenersLock.Lock()
						agentSideListeners[req.ListenerID] = listener
						agentSideListenerCancels[req.ListenerID] = listenerCancel
						agentSideListenersLock.Unlock()
						logVerbose("Agent %s: Started listening on :%d", agentAssignedID, req.AgentListenPort)

						go func(ln net.Listener, lid string, ctx context.Context) {
							<-ctx.Done()
							ln.Close()
							agentSideListenersLock.Lock()
							delete(agentSideListeners, lid)
							delete(agentSideListenerCancels, lid)
							agentSideListenersLock.Unlock()
							logVerbose("Agent %s: Stopped listener %s", agentAssignedID, lid)
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
								sendEnc := func(data []byte) error {
									return agentSend(yamuxClient, c, &writeMu, data)
								}
								go handleAgentClientConnection(clientConn, req.DestinationHost, req.DestinationPort, agentAssignedID, sendEnc)
							}
						}(listener, listenerCtx)
					}

				case "stop-agent-listener":
					var req StopAgentListenerMessage
					if err := json.Unmarshal(msg.Payload, &req); err != nil {
						logVerbose("Agent %s: error unmarshalling stop-agent-listener: %v", agentAssignedID, err)
						continue
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
						continue
					}
					sendConnectResponse := func(connID string, success bool, errMsg string) {
						resp := ConnectResponse{ConnID: connID, Success: success, Error: errMsg}
						p, _ := json.Marshal(resp)
						m := Message{Type: "connect_response", Payload: p, OriginalAgentID: agentAssignedID}
						mp, _ := json.Marshal(m)
						enc, err := encrypt(mp, getEncryptionKey())
						if err != nil {
							return
						}
						agentSend(yamuxClient, c, &writeMu, enc)
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
							sendConnectResponse(req.ConnID, true, "")
							udpConns.Store(req.ConnID, conn)
							bufPtr := agentBufPool.Get().(*[]byte)
							buf := *bufPtr
							for {
								n, _, err := conn.ReadFromUDP(buf)
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
							sendConnectResponse(req.ConnID, true, "")
							targetConns.Store(req.ConnID, targetConn)
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
						logVerbose("Agent %s: invalid data message: %v", agentAssignedID, err)
						continue
					}
					if dataMsg.Compressed && len(dataMsg.Data) > 0 {
						dec, err := decompressData(dataMsg.Data)
						if err != nil {
							logVerbose("Agent %s: decompress error: %v", agentAssignedID, err)
							continue
						}
						dataMsg.Data = dec
					}
					if value, ok := targetConns.Load(dataMsg.ConnID); ok {
						conn := value.(net.Conn)
						if dataMsg.Close {
							conn.Close()
							targetConns.Delete(dataMsg.ConnID)
						} else {
							conn.Write(dataMsg.Data)
						}
					} else if value, ok := udpConns.Load(dataMsg.ConnID); ok {
						udpConn := value.(*net.UDPConn)
						if dataMsg.Close {
							udpConn.Close()
							udpConns.Delete(dataMsg.ConnID)
						} else {
							udpConn.Write(dataMsg.Data)
						}
					}

				case "icmp-request":
					var req ICMPRequest
					if err := json.Unmarshal(msg.Payload, &req); err != nil {
						logVerbose("Agent %s: invalid icmp-request: %v", agentAssignedID, err)
						continue
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
						logVerbose("Agent %s: invalid icmp_proxy: %v", agentAssignedID, err)
						continue
					}
					sendICMPProxyResponse := func(resp ICMPProxyResponse) {
						p, _ := json.Marshal(resp)
						m := Message{Type: "icmp_proxy_response", Payload: p, OriginalAgentID: agentAssignedID}
						mp, _ := json.Marshal(m)
						enc, err := encrypt(mp, getEncryptionKey())
						if err != nil {
							return
						}
						agentSend(yamuxClient, c, &writeMu, enc)
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
						logVerbose("Agent %s: invalid port-scan-request: %v", agentAssignedID, err)
						continue
					}
					go func(req PortScanRequest) {
						results := doLocalPortScan(req)
						resp := PortScanResponse{Target: req.Target, Proto: req.Proto, Results: results, Done: true}
						p, _ := json.Marshal(resp)
						m := Message{Type: "port-scan-response", Payload: p, OriginalAgentID: agentAssignedID}
						mp, _ := json.Marshal(m)
						enc, err := encrypt(mp, getEncryptionKey())
						if err != nil {
							logVerbose("Agent %s: port-scan-response encryption error: %v", agentAssignedID, err)
							return
						}
						agentSend(yamuxClient, c, &writeMu, enc)
					}(req)

				case "agent_fwd_ack":
					var ack AgentFwdAck
					if err := json.Unmarshal(msg.Payload, &ack); err != nil {
						logVerbose("Agent %s: invalid agent_fwd_ack: %v", agentAssignedID, err)
						continue
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
						logVerbose("Agent %s: invalid agent_fwd_data: %v", agentAssignedID, err)
						continue
					}
					if dm.Compressed && len(dm.Data) > 0 {
						dec, err := decompressData(dm.Data)
						if err != nil {
							logVerbose("Agent %s: agent_fwd_data decompress error: %v", agentAssignedID, err)
							continue
						}
						dm.Data = dec
					}
					if value, ok := agentFwdConns.Load(dm.ConnID); ok {
						conn := value.(net.Conn)
						if dm.Close {
							conn.Close()
							agentFwdConns.Delete(dm.ConnID)
						} else {
							conn.Write(dm.Data) //nolint:errcheck
						}
					}

				case "disconnect":
					logVerbose("Agent %s: received disconnect command, exiting", agentAssignedID)
					 
					time.Sleep(400 * time.Millisecond)
					c.Close()
					os.Exit(0)
				}
			}
		}()

		ticker := time.NewTicker(10 * time.Second)
	heartbeatLoop:
		for {
			select {
			case <-agentStop:
				logVerbose("Agent: interrupt, exiting")
				c.Close()
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
					agentSend(yamuxClient, c, &writeMu, enc)
				}
			}
		}
		ticker.Stop()
		c.Close()
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
		}
		go runAgentBindSession(conn, agentStop)
	}
}

func runAgentBindSession(conn net.Conn, agentStop <-chan struct{}) {
	defer conn.Close()

	yamuxClient, yamuxErr := yamux.Client(conn, agentYamuxConfig())
	if yamuxErr != nil {
		logVerbose("agent-bind: yamux client error: %v, using raw framing", yamuxErr)
		yamuxClient = nil
	}

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
	if err := agentSendRaw(yamuxClient, conn, &writeMu, encrypted); err != nil {
		logVerbose("agent-bind: send register: %v", err)
		return
	}

	done := make(chan struct{})
	var targetConns sync.Map
	var udpConns sync.Map

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
		agentSendRaw(yamuxClient, conn, &writeMu, enc)
	}

	sendICMPResponse := func(resp ICMPResponse) {
		p, _ := json.Marshal(resp)
		m := Message{Type: "icmp-response", Payload: p, OriginalAgentID: agentAssignedID}
		mp, _ := json.Marshal(m)
		enc, err := encrypt(mp, encryptionKey)
		if err != nil {
			return
		}
		agentSendRaw(yamuxClient, conn, &writeMu, enc)
	}

	go func() {
		defer close(done)
		for {
			var encrypted []byte

			if yamuxClient != nil {
				stream, err := yamuxClient.Accept()
				if err != nil {
					if !isAgentNormalCloseError(err) {
						logVerbose("agent-bind: yamux accept: %v", err)
					}
					return
				}
				lenBuf := make([]byte, 4)
				if _, err := io.ReadFull(stream, lenBuf); err != nil {
					stream.Close()
					logVerbose("agent-bind: read len: %v", err)
					return
				}
				msgLen := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])
				data := make([]byte, msgLen)
				if _, err := io.ReadFull(stream, data); err != nil {
					stream.Close()
					logVerbose("agent-bind: read data: %v", err)
					return
				}
				stream.Close()
				encrypted = data
			} else {
				lenBuf := make([]byte, 4)
				if _, err := io.ReadFull(conn, lenBuf); err != nil {
					logVerbose("agent-bind: raw read len: %v", err)
					return
				}
				msgLen := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])
				data := make([]byte, msgLen)
				if _, err := io.ReadFull(conn, data); err != nil {
					logVerbose("agent-bind: raw read data: %v", err)
					return
				}
				encrypted = data
			}

			plaintext, err := decrypt(encrypted, getEncryptionKey())
			if err != nil {
				logVerbose("agent-bind: decrypt: %v", err)
				return
			}
			var msg Message
			if err := json.Unmarshal(plaintext, &msg); err != nil {
				logVerbose("agent-bind: unmarshal: %v", err)
				continue
			}

			switch msg.Type {
			case "register_ok":
				var payload struct{ ID string `json:"id"` }
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
					continue
				}
				go handleAgentDNSRequest(agentAssignedID, dnsReq, &writeMu, nil, yamuxClient)

			case "ping-sweep-request":
				var req PingSweepRequest
				if err := json.Unmarshal(msg.Payload, &req); err != nil {
					logVerbose("agent-bind %s: invalid ping-sweep-request: %v", agentAssignedID, err)
					continue
				}
				results := doPingSweep(req)
				resp := PingSweepResponse{Subnet: req.Subnet, Results: results}
				p, _ := json.Marshal(resp)
				rm := Message{Type: "ping-sweep-response", Payload: p, OriginalAgentID: agentAssignedID, TargetAgentID: "server"}
				mp, _ := json.Marshal(rm)
				enc, err := encrypt(mp, encryptionKey)
				if err != nil {
					continue
				}
				agentSendRaw(yamuxClient, conn, &writeMu, enc)

			case "start-agent-listener":
				var req StartAgentListenerMessage
				if err := json.Unmarshal(msg.Payload, &req); err != nil {
					logVerbose("agent-bind %s: invalid start-agent-listener: %v", agentAssignedID, err)
					continue
				}
				logVerbose("agent-bind %s: starting listener port %d -> %s:%d", agentAssignedID, req.AgentListenPort, req.DestinationHost, req.DestinationPort)

				listenerCtx, listenerCancel := context.WithCancel(context.Background())

				if req.Protocol == "udp" {
					udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", req.AgentListenPort))
					if err != nil {
						logVerbose("agent-bind %s: failed to resolve UDP :%d: %v", agentAssignedID, req.AgentListenPort, err)
						listenerCancel()
						continue
					}
					pc, err := net.ListenUDP("udp", udpAddr)
					if err != nil {
						logVerbose("agent-bind %s: failed to listen UDP :%d: %v", agentAssignedID, req.AgentListenPort, err)
						listenerCancel()
						continue
					}
					agentSideUDPListenersLock.Lock()
					agentSideUDPListeners[req.ListenerID] = pc
					agentSideUDPListenersLock.Unlock()
					agentSideListenersLock.Lock()
					agentSideListenerCancels[req.ListenerID] = listenerCancel
					agentSideListenersLock.Unlock()
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
						continue
					}

					listener, err := net.Listen("tcp", fmt.Sprintf(":%d", req.AgentListenPort))
					if err != nil {
						logVerbose("agent-bind %s: failed to listen on :%d: %v", agentAssignedID, req.AgentListenPort, err)
						listenerCancel()
						continue
					}
					agentSideListenersLock.Lock()
					agentSideListeners[req.ListenerID] = listener
					agentSideListenerCancels[req.ListenerID] = listenerCancel
					agentSideListenersLock.Unlock()

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
							sendEnc := func(data []byte) error {
								return agentSendRaw(yamuxClient, conn, &writeMu, data)
							}
							go handleAgentClientConnection(clientConn, req.DestinationHost, req.DestinationPort, agentAssignedID, sendEnc)
						}
					}(listener, listenerCtx)
				}

			case "stop-agent-listener":
				var req StopAgentListenerMessage
				if err := json.Unmarshal(msg.Payload, &req); err != nil {
					logVerbose("agent-bind %s: invalid stop-agent-listener: %v", agentAssignedID, err)
					continue
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
					continue
				}
				sendConnectResponse := func(connID string, success bool, errMsg string) {
					resp := ConnectResponse{ConnID: connID, Success: success, Error: errMsg}
					p, _ := json.Marshal(resp)
					m := Message{Type: "connect_response", Payload: p, OriginalAgentID: agentAssignedID}
					mp, _ := json.Marshal(m)
					enc, err := encrypt(mp, encryptionKey)
					if err != nil {
						return
					}
					agentSendRaw(yamuxClient, conn, &writeMu, enc)
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
						sendConnectResponse(req.ConnID, true, "")
						udpConns.Store(req.ConnID, udpConn)
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
						sendConnectResponse(req.ConnID, true, "")
						targetConns.Store(req.ConnID, targetConn)
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
					continue
				}
				if dataMsg.Compressed && len(dataMsg.Data) > 0 {
					dec, err := decompressData(dataMsg.Data)
					if err != nil {
						continue
					}
					dataMsg.Data = dec
				}
				if value, ok := targetConns.Load(dataMsg.ConnID); ok {
					tc := value.(net.Conn)
					if dataMsg.Close {
						tc.Close()
						targetConns.Delete(dataMsg.ConnID)
					} else {
						tc.Write(dataMsg.Data)
					}
				} else if value, ok := udpConns.Load(dataMsg.ConnID); ok {
					uc := value.(*net.UDPConn)
					if dataMsg.Close {
						uc.Close()
						udpConns.Delete(dataMsg.ConnID)
					} else {
						uc.Write(dataMsg.Data)
					}
				}

			case "icmp-request":
				var req ICMPRequest
				if err := json.Unmarshal(msg.Payload, &req); err != nil {
					logVerbose("agent-bind %s: invalid icmp-request: %v", agentAssignedID, err)
					continue
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
					continue
				}
				sendICMPProxyResponseBind := func(resp ICMPProxyResponse) {
					p, _ := json.Marshal(resp)
					m := Message{Type: "icmp_proxy_response", Payload: p, OriginalAgentID: agentAssignedID}
					mp, _ := json.Marshal(m)
					enc, err := encrypt(mp, encryptionKey)
					if err != nil {
						return
					}
					agentSendRaw(yamuxClient, conn, &writeMu, enc)
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
					continue
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
					agentSendRaw(yamuxClient, conn, &writeMu, enc)
				}(req)

			case "agent_fwd_ack":
				var ack AgentFwdAck
				if err := json.Unmarshal(msg.Payload, &ack); err != nil {
					logVerbose("agent-bind %s: invalid agent_fwd_ack: %v", agentAssignedID, err)
					continue
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
					continue
				}
				if dm.Compressed && len(dm.Data) > 0 {
					dec, err := decompressData(dm.Data)
					if err != nil {
						logVerbose("agent-bind %s: agent_fwd_data decompress error: %v", agentAssignedID, err)
						continue
					}
					dm.Data = dec
				}
				if value, ok := agentFwdConns.Load(dm.ConnID); ok {
					c := value.(net.Conn)
					if dm.Close {
						c.Close()
						agentFwdConns.Delete(dm.ConnID)
					} else {
						c.Write(dm.Data) //nolint:errcheck
					}
				}

			case "disconnect":
				logVerbose("agent-bind %s: disconnect received, exiting", agentAssignedID)
				time.Sleep(400 * time.Millisecond)
				conn.Close()
				os.Exit(0)
			}
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
					break heartbeatBindLoop
				}
				if err := agentSendRaw(yamuxClient, conn, &writeMu, enc); err != nil {
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
