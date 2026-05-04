package main

import (
	"fmt"
	"sync"
	"time"
)

const (
	maxAgentConnectDials  = 4
	maxTargetConnectDials = 1
)

var (
	agentConnectSlots  syncMapStringChan
	targetConnectSlots syncMapStringChan
)

type syncMapStringChan struct {
	m sync.Map
}

func (s *syncMapStringChan) get(key string, size int) chan struct{} {
	ch, _ := s.m.LoadOrStore(key, make(chan struct{}, size))
	return ch.(chan struct{})
}

func acquireConnectSlot(agentID, targetHost string, targetPort int) (func(), error) {
	agentCh := agentConnectSlots.get(agentID, maxAgentConnectDials)
	targetKey := fmt.Sprintf("%s\x00%s:%d", agentID, targetHost, targetPort)
	targetCh := targetConnectSlots.get(targetKey, maxTargetConnectDials)
	deadline := time.NewTimer(agentConnectResponseTimeout)
	defer deadline.Stop()

	select {
	case agentCh <- struct{}{}:
	case <-deadline.C:
		return nil, fmt.Errorf("connect queue full for agent %s", agentID)
	}

	select {
	case targetCh <- struct{}{}:
	case <-deadline.C:
		<-agentCh
		return nil, fmt.Errorf("connect already pending for %s:%d via %s", targetHost, targetPort, agentID)
	}

	var released bool
	return func() {
		if released {
			return
		}
		released = true
		<-targetCh
		<-agentCh
	}, nil
}
