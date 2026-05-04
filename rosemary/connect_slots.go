package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	maxAgentConnectDials  = 8
	maxTargetConnectDials = 4
)

type connectLease struct {
	id        string
	agentID   string
	targetKey string
	expires   time.Time
}

var connectSlots = struct {
	sync.Mutex
	agent  map[string]map[string]*connectLease
	target map[string]map[string]*connectLease
}{
	agent:  make(map[string]map[string]*connectLease),
	target: make(map[string]map[string]*connectLease),
}

func connectTargetKey(agentID, targetHost string, targetPort int) string {
	return fmt.Sprintf("%s\x00%s:%d", agentID, targetHost, targetPort)
}

func cleanupExpiredConnectSlotsLocked(now time.Time) {
	for agentID, leases := range connectSlots.agent {
		for id, lease := range leases {
			if now.After(lease.expires) {
				delete(leases, id)
				if targetLeases := connectSlots.target[lease.targetKey]; targetLeases != nil {
					delete(targetLeases, id)
					if len(targetLeases) == 0 {
						delete(connectSlots.target, lease.targetKey)
					}
				}
			}
		}
		if len(leases) == 0 {
			delete(connectSlots.agent, agentID)
		}
	}
}

func acquireConnectSlot(agentID, targetHost string, targetPort int) (func(), error) {
	targetKey := connectTargetKey(agentID, targetHost, targetPort)
	deadline := time.Now().Add(agentConnectResponseTimeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		now := time.Now()
		connectSlots.Lock()
		cleanupExpiredConnectSlotsLocked(now)

		agentLeases := connectSlots.agent[agentID]
		targetLeases := connectSlots.target[targetKey]
		if len(agentLeases) < maxAgentConnectDials && len(targetLeases) < maxTargetConnectDials {
			lease := &connectLease{
				id:        uuid.New().String(),
				agentID:   agentID,
				targetKey: targetKey,
				expires:   now.Add(agentConnectResponseTimeout + 2*time.Second),
			}
			if agentLeases == nil {
				agentLeases = make(map[string]*connectLease)
				connectSlots.agent[agentID] = agentLeases
			}
			if targetLeases == nil {
				targetLeases = make(map[string]*connectLease)
				connectSlots.target[targetKey] = targetLeases
			}
			agentLeases[lease.id] = lease
			targetLeases[lease.id] = lease
			connectSlots.Unlock()

			var once sync.Once
			return func() {
				once.Do(func() {
					connectSlots.Lock()
					if leases := connectSlots.agent[agentID]; leases != nil {
						delete(leases, lease.id)
						if len(leases) == 0 {
							delete(connectSlots.agent, agentID)
						}
					}
					if leases := connectSlots.target[targetKey]; leases != nil {
						delete(leases, lease.id)
						if len(leases) == 0 {
							delete(connectSlots.target, targetKey)
						}
					}
					connectSlots.Unlock()
				})
			}, nil
		}
		connectSlots.Unlock()

		if now.After(deadline) {
			if len(agentLeases) >= maxAgentConnectDials {
				return nil, fmt.Errorf("connect queue full for agent %s", agentID)
			}
			return nil, fmt.Errorf("connect already pending for %s:%d via %s", targetHost, targetPort, agentID)
		}

		select {
		case <-ticker.C:
		case <-time.After(time.Until(deadline)):
		}
	}
}

func releaseConnectSlotsForAgent(agentID string) {
	connectSlots.Lock()
	defer connectSlots.Unlock()

	leases := connectSlots.agent[agentID]
	for id, lease := range leases {
		if targetLeases := connectSlots.target[lease.targetKey]; targetLeases != nil {
			delete(targetLeases, id)
			if len(targetLeases) == 0 {
				delete(connectSlots.target, lease.targetKey)
			}
		}
	}
	delete(connectSlots.agent, agentID)
}
