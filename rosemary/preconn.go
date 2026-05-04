package main

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	preConnPoolSize = 0
	preConnTTL      = 25 * time.Second
)

type preConnEntry struct {
	connID  string
	agentID string
	born    time.Time
}

type preConnPool struct {
	mu      sync.Mutex
	ready   []preConnEntry
	filling int
	capObs  int // observed server connection cap; 0 = unknown
}

var preConnPools sync.Map

func preConnKey(agentID, host string, port int) string {
	return fmt.Sprintf("%s\x00%s:%d", agentID, host, port)
}

func getOrCreatePreConnPool(key string) *preConnPool {
	p, _ := preConnPools.LoadOrStore(key, &preConnPool{})
	return p.(*preConnPool)
}

func closePreConnAtAgent(agentID, connID string) {
	dataMsg := DataMessage{ConnID: connID, Close: true}
	payload, _ := json.Marshal(dataMsg)
	msg := Message{Type: "data", Payload: payload, TargetAgentID: agentID}
	sendControlMessageToAgent(agentID, msg) //nolint:errcheck
}

func popPreConn(key string) string {
	v, ok := preConnPools.Load(key)
	if !ok {
		return ""
	}
	p := v.(*preConnPool)
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for len(p.ready) > 0 {
		e := p.ready[0]
		p.ready = p.ready[1:]
		if now.Sub(e.born) < preConnTTL {
			logVerbose("Pre-conn pool hit for %s (connID %s, %d remaining)", key, e.connID, len(p.ready))
			return e.connID
		}
		logVerbose("Pre-conn pool: expired entry discarded for %s", key)
		go closePreConnAtAgent(e.agentID, e.connID)
	}
	return ""
}

func sweepPreConnPools() {
	preConnPools.Range(func(k, v interface{}) bool {
		p := v.(*preConnPool)
		p.mu.Lock()
		now := time.Now()
		var keep []preConnEntry
		for _, e := range p.ready {
			if now.Sub(e.born) < preConnTTL {
				keep = append(keep, e)
			} else {
				go closePreConnAtAgent(e.agentID, e.connID)
			}
		}
		p.ready = keep
		p.mu.Unlock()
		return true
	})
}

func startPreConnSweeper() {
	go func() {
		t := time.NewTicker(preConnTTL / 2)
		defer t.Stop()
		for range t.C {
			sweepPreConnPools()
		}
	}()
}

func purgePreConnPoolsForAgent(agentID string) {
	preConnPools.Range(func(k, v interface{}) bool {
		p := v.(*preConnPool)
		p.mu.Lock()
		var keep []preConnEntry
		for _, e := range p.ready {
			if e.agentID == agentID {
				go closePreConnAtAgent(e.agentID, e.connID)
				continue
			}
			keep = append(keep, e)
		}
		p.ready = keep
		p.mu.Unlock()
		if len(keep) == 0 {
			preConnPools.Delete(k)
		}
		return true
	})
}

func agentConnectionStamp(agentID string) (time.Time, bool) {
	connLock.Lock()
	defer connLock.Unlock()
	info, ok := connections[agentID]
	if !ok {
		return time.Time{}, false
	}
	return info.ConnectedAt, true
}

func fillPreConnPool(agentID, host string, port int) {
	if preConnPoolSize <= 0 {
		return
	}
	startedAt, connected := agentConnectionStamp(agentID)
	if !connected {
		return
	}
	key := preConnKey(agentID, host, port)
	p := getOrCreatePreConnPool(key)

	p.mu.Lock()
	target := preConnPoolSize
	if p.capObs > 0 && p.capObs < preConnPoolSize {
		target = p.capObs
	}
	needed := target - len(p.ready) - p.filling
	if needed <= 0 {
		p.mu.Unlock()
		return
	}
	p.filling += needed
	p.mu.Unlock()

	type result struct {
		connID string
		ok     bool
	}
	results := make(chan result, needed)

	for i := 0; i < needed; i++ {
		connID := uuid.New().String()
		ch := make(chan ConnectResponse, 1)
		respChanMap.Store(connID, ch)

		req := ConnectRequest{TargetHost: host, TargetPort: port, ConnID: connID, Protocol: "tcp"}
		payload, _ := json.Marshal(req)
		msg := Message{Type: "connect", Payload: payload, TargetAgentID: agentID}

		if err := sendControlMessageToAgent(agentID, msg); err != nil {
			respChanMap.Delete(connID)
			p.mu.Lock()
			p.filling--
			p.mu.Unlock()
			results <- result{"", false}
			continue
		}

		go func(cid string, rch chan ConnectResponse) {
			defer respChanMap.Delete(cid)
			select {
			case resp := <-rch:
				results <- result{cid, resp.Success}
			case <-time.After(20 * time.Second):
				closePreConnAtAgent(agentID, cid)
				results <- result{"", false}
			}
		}(connID, ch)
	}

	successes := 0
	for i := 0; i < needed; i++ {
		r := <-results
		currentStartedAt, stillConnected := agentConnectionStamp(agentID)
		p.mu.Lock()
		p.filling--
		if r.ok && stillConnected && currentStartedAt.Equal(startedAt) {
			successes++
			p.ready = append(p.ready, preConnEntry{
				connID:  r.connID,
				agentID: agentID,
				born:    time.Now(),
			})
		} else if r.ok {
			go closePreConnAtAgent(agentID, r.connID)
		}
		p.mu.Unlock()
	}
	// If the server rejected connections, record the observed cap so future
	// fill attempts don't exhaust the server's concurrent connection limit.
	if successes < needed {
		p.mu.Lock()
		observed := successes + len(p.ready)
		if p.capObs == 0 || observed < p.capObs {
			p.capObs = observed
		}
		p.mu.Unlock()
	}
	logVerbose("Pre-conn pool filled %d/%d for %s:%d via %s", successes, needed, host, port, agentID)
}
