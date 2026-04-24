package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

type consoleCmdFn func(parts []string, out *strings.Builder)

var consoleCmds = map[string]consoleCmdFn{
	"help":           consoleCmdHelp,
	"agents":         consoleCmdAgents,
	"egress":         consoleCmdEgress,
	"routes":         consoleCmdRoutes,
	"discover":       consoleCmdDiscover,
	"forwards":       consoleCmdForwards,
	"socks":          consoleCmdSocks,
	"reconnect":      consoleCmdReconnect,
	"disconnect":     consoleCmdDisconnect,
	"port":           consoleCmdPort,
	"tcp-port":       consoleCmdTCPPort,
	"udp-port":       consoleCmdUDPPort,
	"dns-port":       consoleCmdDNSPort,
	"rotate-key":     consoleCmdRotateKey,
	"settings":       consoleCmdSettings,
	"ping":           consoleCmdPing,
	"forward":        consoleCmdForward,
	"rforward":       consoleCmdRForward,
	"portscan":       consoleCmdPortScan,
	"connect":        consoleCmdConnect,
	"load-config":    consoleCmdLoadConfig,
	"save-config":    consoleCmdSaveConfig,
	"verbose":        consoleCmdVerbose,
	"exit":           consoleCmdExit,
	"token":          consoleCmdToken,
	"tag":            consoleCmdTag,
}

func consoleCmdHelp(parts []string, out *strings.Builder) {
	args := parts[1:]
	helpTopics := map[string]string{
		"agents":      "agents\n  List all connected agents with OS, hostname, subnets, last seen, and internet status.\n\nagents <agent-id>\n  Show full details for a specific agent including all subnets, tag, and connection time.",
		"tag":         "tag <agent-id> <label>\n  Set a display tag for an agent.\n  Example:\n    tag agent-2 dc-east\n\ntag <agent-id> \"\"\n  Clear the tag for an agent.",
		"routes":      "routes [list]\n  List all registered subnets with agent and enabled/disabled state.\n\nroutes enable <subnet>\n  Re-enable routing for a disabled subnet.\n\nroutes disable <subnet>\n  Disable routing for a subnet without removing it from the table.",
		"forwards":    "forwards\n  List all active port forwards.",
		"forward":     "forward add <local-port> <agent-id> <target-host> <target-port> [tcp|udp]\n  Add a port forward: agent listens on local-port and proxies to target.\n  Protocol defaults to tcp. Example:\n    forward add 8080 agent-1 192.168.1.10 80\n    forward add 5353 agent-1 8.8.8.8 53 udp\n\nforward del <listener-id>\n  Remove a port forward by its ID.",
		"rforward":    "rforward add <listen-port> <agent-id> <target-host> <target-port>\n  Add a REVERSE port forward: server listens on listen-port, when a client\n  connects the agent dials target-host:target-port and bridges the connection.\n  Useful when the agent is on an isolated host. Example:\n    rforward add 13389 agent-2 127.0.0.1 3389\n  Then: xfreerdp /v:server-ip:13389\n\nrforward del <listener-id>\n  Stop a reverse forward by its ID.\n\nrforward list\n  List active reverse forwards.",
		"socks":       "socks <agent-id> <port>\n  Start a SOCKS5 proxy via the agent on the given port.\n\nsocks list\n  List active SOCKS5 proxies.\n\nsocks stop <id>\n  Stop a SOCKS5 proxy.",
		"egress":      "egress <agent-id>\n  Set the default egress agent for all unrouted traffic (internet).\n  Example: egress agent-2\n\negress\n  Show the current default egress agent.\n\negress none\n  Clear the default egress agent.",
		"ping":        "ping <agent-id> <target> [count]\n  Send ICMP echo requests via the agent. count defaults to 4.\n  Example: ping agent-1 192.168.1.1 10",
		"discover":    "discover <agent-id> <subnet> [timeout_ms] [workers]\n  Discover live hosts on a subnet via the agent using ICMP and TCP probes.\n  Results show IP address and round-trip time for each responding host.\n  timeout_ms defaults to 300. workers defaults to 100.\n  Example: discover agent-1 192.168.1.0/24\n           discover agent-1 10.10.0.0/16 500 200",
		"portscan":    "portscan <agent-id> tcp|udp <target> [ports]\n  Scan ports on a target via the agent.\n  Example: portscan agent-1 tcp 192.168.1.10 22,80,443,8000-9000",
		"reconnect":   "reconnect <agent-id>\n  Tell the agent to drop its connection and reconnect.",
		"disconnect":  "disconnect <agent-id|all>\n  Forcefully disconnect an agent (or all agents) from the server.\n  Examples:\n    disconnect agent-1\n    disconnect all",
		"connect":     "connect <ip:port>\n  Initiate outbound connection to a bind agent.",
		"port":        "port <number>\n  Change the HTTP dashboard port (restart required).",
		"tcp-port":    "tcp-port <number>\n  Change the transparent TCP proxy port.",
		"udp-port":    "udp-port <number>\n  Change the transparent UDP proxy port.",
		"dns-port":    "dns-port <number>\n  Change the DNS proxy port.",
		"settings":    "settings\n  Show current server configuration (ports, key).",
		"rotate-key":  "rotate-key\n  Generate a new random encryption key and disconnect all agents.\n  Agents must reconnect with the new key.",
		"load-config": "load-config <path>\n  Load settings from a JSON config file.",
		"save-config": "save-config <path>\n  Save current settings to a JSON config file.",
		"exit":        "exit\n  Gracefully shut down the server.",
		"token":       "token list\n  List all API tokens.\n\ntoken view <id>\n  Show the raw token value for a given token ID.\n\ntoken create <n> <read|write|admin>\n  Create a new API token with the given permission.\n\ntoken revoke <id>\n  Revoke a token by its ID.",
	}

	if len(args) == 1 {
		topic, ok := helpTopics[args[0]]
		if ok {
			out.WriteString(colorBoldCyan + args[0] + colorReset + "\n")
			out.WriteString(topic + "\n")
		} else {
			out.WriteString(colorBoldYellow + "No help available for '" + args[0] + "'" + colorReset + "\n")
			out.WriteString("Available topics: " + colorCyan + "agents, routes, forwards, forward, rforward, socks, ping, discover, portscan, reconnect, disconnect, connect, tag, port, tcp-port, udp-port, dns-port, settings, rotate-key, load-config, save-config, token, exit" + colorReset + "\n")
		}
		return
	}

	out.WriteString(colorBoldWhite + "Commands" + colorReset + " (use '" + colorBoldCyan + "help <command>" + colorReset + "' for details):\n")
	out.WriteString("  " + colorBoldCyan + "agents" + colorReset + "               - list connected agents\n")
	out.WriteString("  " + colorBoldCyan + "routes" + colorReset + "               - list routes; enable/disable subnets\n")
	out.WriteString("  " + colorBoldCyan + "forwards" + colorReset + "             - list active port forwards\n")
	out.WriteString("  " + colorBoldCyan + "forward" + colorReset + " add|del      - add/remove port forward (tcp or udp)\n")
	out.WriteString("  " + colorBoldCyan + "rforward" + colorReset + " add|del|list- reverse port forward (server listens, agent dials)\n")
	out.WriteString("  " + colorBoldCyan + "socks" + colorReset + "                - SOCKS5 proxy via agent\n")
	out.WriteString("  " + colorBoldCyan + "egress" + colorReset + "               - set/view/clear default egress agent\n")
	out.WriteString("  " + colorBoldCyan + "ping" + colorReset + "                 - ICMP ping via agent\n")
	out.WriteString("  " + colorBoldCyan + "discover" + colorReset + "             - discover live hosts on a subnet via agent\n")
	out.WriteString("  " + colorBoldCyan + "portscan" + colorReset + "             - port scan via agent\n")
	out.WriteString("  " + colorBoldCyan + "reconnect" + colorReset + "            - tell agent to reconnect\n")
	out.WriteString("  " + colorBoldCyan + "disconnect" + colorReset + "           - disconnect an agent (use 'all' for all agents)\n")
	out.WriteString("  " + colorBoldCyan + "connect" + colorReset + "              - connect to bind agent\n")
	out.WriteString("  " + colorBoldCyan + "tag" + colorReset + "                  - set or clear a display tag for an agent\n")
	out.WriteString("  " + colorBoldCyan + "port / tcp-port / udp-port / dns-port" + colorReset + " - change ports\n")
	out.WriteString("  " + colorBoldCyan + "settings" + colorReset + "             - show current config\n")
	out.WriteString("  " + colorBoldCyan + "rotate-key" + colorReset + "           - generate new encryption key\n")
	out.WriteString("  " + colorBoldCyan + "load-config / save-config" + colorReset + " - import/export config file\n")
	out.WriteString("  " + colorBoldCyan + "token" + colorReset + "                - list, create, or revoke API tokens\n")
	out.WriteString("  " + colorBoldCyan + "verbose" + colorReset + "              - toggle verbose logging on/off\n")
	out.WriteString("  " + colorBoldCyan + "exit" + colorReset + "                 - shutdown server\n")
}

func consoleCmdAgents(parts []string, out *strings.Builder) {
	connLock.Lock()
	defer connLock.Unlock()

	if len(connections) == 0 {
		out.WriteString(colorYellow + "No agents connected." + colorReset + "\n")
		return
	}

	if len(parts) >= 2 {
		id := parts[1]
		info, ok := connections[id]
		if !ok {
			out.WriteString(colorRed + "Agent not found: " + id + colorReset + "\n")
			return
		}
		internet := colorRed + "No" + colorReset
		if info.HasInternet {
			internet = colorGreen + "Yes" + colorReset
		}
		agentTagsMu.Lock()
		tag := agentTags[id]
		agentTagsMu.Unlock()
		out.WriteString(colorBoldWhite + "Agent: " + colorCyan + id + colorReset + "\n")
		out.WriteString(fmt.Sprintf("  %-14s %s\n", "OS:", info.OS))
		out.WriteString(fmt.Sprintf("  %-14s %s\n", "Hostname:", info.Hostname))
		out.WriteString(fmt.Sprintf("  %-14s %s\n", "Username:", info.Username))
		out.WriteString(fmt.Sprintf("  %-14s %s\n", "Connected:", info.ConnectedAt.Format("2006-01-02 15:04:05")))
		out.WriteString(fmt.Sprintf("  %-14s %s\n", "Last Seen:", info.LastSeen.Format("15:04:05")))
		out.WriteString(fmt.Sprintf("  %-14s %s\n", "Internet:", internet))
		if tag != "" {
			out.WriteString(fmt.Sprintf("  %-14s %s\n", "Tag:", tag))
		}
		out.WriteString(fmt.Sprintf("  %-14s\n", "Subnets:"))
		for _, s := range info.Subnets {
			out.WriteString(fmt.Sprintf("    - %s\n", s))
		}
		return
	}

	out.WriteString(colorBoldWhite + fmt.Sprintf("%-14s %-8s %-22s %-22s %-12s %-10s %-8s\n",
		"ID", "OS", "Hostname", "Subnets", "Username", "LastSeen", "Internet") + colorReset)
	for id, info := range connections {
		subnets := "None"
		if len(info.Subnets) == 1 {
			subnets = info.Subnets[0]
		} else if len(info.Subnets) > 1 {
			subnets = fmt.Sprintf("%s (+%d)", info.Subnets[0], len(info.Subnets)-1)
		}
		internet := "No"
		if info.HasInternet {
			internet = "Yes"
		}
		out.WriteString(fmt.Sprintf("%s%-14s%s %-8s %-22s %-22s %-12s %-10s %-8s\n",
			colorCyan, id, colorReset,
			info.OS, info.Hostname, subnets, info.Username, info.LastSeen.Format("15:04:05"), internet))
	}
}

func consoleCmdTag(parts []string, out *strings.Builder) {
	if len(parts) < 3 {
		out.WriteString("Usage: tag <agent-id> <label>  (use \"\" to clear)\n")
		return
	}
	agentID := parts[1]
	tag := strings.TrimSpace(strings.Join(parts[2:], " "))
	tag = strings.Trim(tag, "\"")

	connLock.Lock()
	_, exists := connections[agentID]
	connLock.Unlock()
	if !exists {
		out.WriteString(colorRed + "Agent not found: " + agentID + colorReset + "\n")
		return
	}
	if len(tag) > 64 {
		out.WriteString(colorRed + "Tag too long (max 64 characters)." + colorReset + "\n")
		return
	}
	for _, ch := range tag {
		if ch < 0x20 || ch == '<' || ch == '>' || ch == '&' || ch == '"' || ch == '\'' {
			out.WriteString(colorRed + "Tag contains invalid characters." + colorReset + "\n")
			return
		}
	}
	agentTagsMu.Lock()
	if tag == "" {
		delete(agentTags, agentID)
		agentTagsMu.Unlock()
		out.WriteString(colorGreen + "[+] Tag cleared for " + agentID + colorReset + "\n")
	} else {
		agentTags[agentID] = tag
		agentTagsMu.Unlock()
		out.WriteString(fmt.Sprintf(colorGreen+"[+] Tag set: %s -> %s"+colorReset+"\n", agentID, tag))
	}
}

func consoleCmdEgress(parts []string, out *strings.Builder) {
	if len(parts) < 2 {
		current := getDefaultEgressAgent()
		if current == "" {
			out.WriteString("No default egress agent set. Usage: egress <agent-id|none>\n")
		} else {
			out.WriteString("Default egress agent: " + current + "\n")
		}
		return
	}
	agentID := parts[1]
	if agentID == "none" || agentID == "clear" {
		setDefaultEgressAgent("")
		if isPrivileged() {
			if err := reloadDefaultEgressRules(); err != nil {
				out.WriteString(colorBoldRed + "[-]" + colorReset + " Failed to remove egress rules: " + err.Error() + "\n")
			}
		}
		out.WriteString("[-] Default egress cleared.\n")
		return
	}
	connLock.Lock()
	_, ok := connections[agentID]
	connLock.Unlock()
	if !ok {
		out.WriteString("Agent " + agentID + " not found.\n")
		return
	}
	setDefaultEgressAgent(agentID)
	if isPrivileged() {
		if err := reloadDefaultEgressRules(); err != nil {
			out.WriteString(colorBoldRed + "[-]" + colorReset + " Failed to install egress rules: " + err.Error() + "\n")
		}
	}
	out.WriteString(colorBoldGreen + "[+]" + colorReset + " Default egress set to " + colorYellow + agentID + colorReset + "\n")
}

func consoleCmdRoutes(parts []string, out *strings.Builder) {
	args := parts[1:]
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "", "list":
		consoleCmdRoutesList(out)
	case "enable", "disable":
		consoleCmdRoutesToggle(sub, args, out)
	case "default":
		consoleCmdRoutesDefault(args, out)
	default:
		out.WriteString(colorBoldCyan + "Usage: " + colorReset + colorGreen + "routes [list] | routes enable <subnet> | routes disable <subnet> | routes default [<agentID>|off]\n" + colorReset)
	}
}

func consoleCmdRoutesList(out *strings.Builder) {
	routingTable.RLock()
	if len(routingTable.routes) == 0 {
		out.WriteString(colorYellow + "No routes." + colorReset + "\n")
	} else {
		out.WriteString(colorBoldWhite + fmt.Sprintf("%-22s  %-20s  %s", "Subnet", "Agent", "State") + colorReset + "\n")
		out.WriteString(colorDim + fmt.Sprintf("%-22s  %-20s  %s", "----------------------", "--------------------", "-------") + colorReset + "\n")
		for subnet, agentID := range routingTable.routes {
			disabledSubnetsMu.Lock()
			state := colorGreen + "enabled" + colorReset
			if disabledSubnets[subnet] {
				state = colorBoldRed + "DISABLED" + colorReset
			}
			disabledSubnetsMu.Unlock()
			out.WriteString(fmt.Sprintf("%s%-22s%s  %s%-20s%s  %s\n",
				colorYellow, subnet, colorReset,
				colorCyan, agentID, colorReset,
				state))
		}
	}
	routingTable.RUnlock()
}

func consoleCmdRoutesToggle(sub string, args []string, out *strings.Builder) {
	if len(args) < 2 {
		out.WriteString(fmt.Sprintf(colorBoldCyan+"Usage: "+colorReset+colorGreen+"routes %s <subnet>\n"+colorReset, sub))
		return
	}
	targetSubnet := args[1]
	routingTable.RLock()
	_, exists := routingTable.routes[targetSubnet]
	routingTable.RUnlock()
	if !exists {
		out.WriteString(fmt.Sprintf(colorBoldRed+"[-]"+colorReset+" Subnet %s not found in routing table.\n", targetSubnet))
		return
	}
	disabledSubnetsMu.Lock()
	isCurrentlyDisabled := disabledSubnets[targetSubnet]
	if sub == "disable" && isCurrentlyDisabled {
		disabledSubnetsMu.Unlock()
		out.WriteString(fmt.Sprintf(colorBoldYellow+"[!]"+colorReset+" Subnet %s%s%s is already disabled.\n", colorYellow, targetSubnet, colorReset))
		return
	} else if sub == "enable" && !isCurrentlyDisabled {
		disabledSubnetsMu.Unlock()
		out.WriteString(fmt.Sprintf(colorBoldYellow+"[!]"+colorReset+" Subnet %s%s%s is already enabled.\n", colorYellow, targetSubnet, colorReset))
		return
	}
	if sub == "disable" {
		disabledSubnets[targetSubnet] = true
	} else {
		delete(disabledSubnets, targetSubnet)
	}
	disabledSubnetsMu.Unlock()
	state := sub + "d"
	log.Printf("[CLI] Subnet %s routing %s", targetSubnet, state)
	appendServerLog(fmt.Sprintf("[+] Subnet %s routing %s", targetSubnet, state))
	out.WriteString(fmt.Sprintf(colorBoldGreen+"[+]"+colorReset+" Subnet %s%s%s routing %s.\n", colorYellow, targetSubnet, colorReset, state))
}

func consoleCmdRoutesDefault(args []string, out *strings.Builder) {
	if len(args) < 2 {
		egress := getDefaultEgressAgent()
		if egress == "" {
			out.WriteString(colorYellow + "No default egress agent set.\n" + colorReset)
		} else {
			out.WriteString(fmt.Sprintf(colorBoldGreen+"[+]"+colorReset+" Default egress: %s%s%s\n", colorCyan, egress, colorReset))
		}
		return
	}
	target := args[1]
	if target == "off" || target == "none" || target == "clear" {
		setDefaultEgressAgent("")
		if isPrivileged() {
			if err := reloadDefaultEgressRules(); err != nil {
				out.WriteString(fmt.Sprintf(colorBoldRed+"[-]"+colorReset+" Failed to remove egress rules: %v\n", err))
			}
		}
		out.WriteString(colorBoldGreen + "[+]" + colorReset + " Default egress agent cleared.\n")
		return
	}
	connLock.Lock()
	_, agentExists := connections[target]
	connLock.Unlock()
	if !agentExists {
		out.WriteString(fmt.Sprintf(colorBoldRed+"[-]"+colorReset+" Agent %s%s%s not found.\n", colorYellow, target, colorReset))
		return
	}
	setDefaultEgressAgent(target)
	if isPrivileged() {
		if err := reloadDefaultEgressRules(); err != nil {
			out.WriteString(fmt.Sprintf(colorBoldRed+"[-]"+colorReset+" Failed to install catch-all rules: %v\n", err))
		}
	}
	out.WriteString(fmt.Sprintf(colorBoldGreen+"[+]"+colorReset+" Default egress agent set to %s%s%s\n", colorCyan, target, colorReset))
	out.WriteString(colorDim + "    Unmatched traffic will be routed through this agent.\n" + colorReset)
}

func consoleCmdDiscover(parts []string, out *strings.Builder) {
	args := parts[1:]
	if len(args) < 2 {
		out.WriteString(colorBoldCyan + "Usage: " + colorReset + colorGreen + "discover <agent-id> <subnet> [timeout_ms] [workers]\n" + colorReset)
		out.WriteString("  Discover live hosts on a subnet via the agent using ICMP and TCP probes.\n")
		out.WriteString("  Example: discover agent-1 192.168.1.0/24\n")
		out.WriteString("           discover agent-1 10.10.0.0/16 500 200\n")
		return
	}
	agentID := args[0]
	subnet := args[1]
	timeoutMs := 300
	workers := 100
	if len(args) >= 3 {
		if v, err := strconv.Atoi(args[2]); err == nil && v > 0 {
			timeoutMs = v
		}
	}
	if len(args) >= 4 {
		if v, err := strconv.Atoi(args[3]); err == nil && v > 0 {
			workers = v
		}
	}
	connLock.Lock()
	_, ok := connections[agentID]
	connLock.Unlock()
	if !ok {
		out.WriteString(fmt.Sprintf(colorBoldRed+"[-]"+colorReset+" Agent %s%s%s not found\n", colorYellow, agentID, colorReset))
		return
	}
	req := PingSweepRequest{Subnet: subnet, TimeoutMs: timeoutMs, Workers: workers}
	payload, _ := json.Marshal(req)
	msg := Message{
		Type:            "ping-sweep-request",
		Payload:         payload,
		OriginalAgentID: "server",
		TargetAgentID:   agentID,
	}
	listenerID, resultCh := registerCLIListener(256)
	defer unregisterCLIListener(listenerID)
	if err := sendControlMessageToAgent(agentID, msg); err != nil {
		out.WriteString(fmt.Sprintf(colorBoldRed+"[-]"+colorReset+" Failed to start discovery via %s%s%s: %v\n", colorCyan, agentID, colorReset, err))
		return
	}
	out.WriteString(fmt.Sprintf(
		colorBoldCyan+"[*]"+colorReset+" Discovering hosts on %s%s%s via %s%s%s (timeout=%dms, workers=%d)\n",
		colorYellow, subnet, colorReset, colorCyan, agentID, colorReset, timeoutMs, workers,
	))
	timeout := time.NewTimer(30 * time.Second)
	defer timeout.Stop()
waitLoop:
	for {
		select {
		case line, ok := <-resultCh:
			if !ok {
				break waitLoop
			}
			out.WriteString(line)
			break waitLoop
		case <-timeout.C:
			out.WriteString(colorBoldRed + "[-]" + colorReset + " Discovery timed out after 30s\n")
			break waitLoop
		}
	}
}

func consoleCmdForwards(parts []string, out *strings.Builder) {
	connLock.Lock()
	if len(portForwards) == 0 {
		out.WriteString(colorYellow + "No port forwards." + colorReset + "\n")
	} else {
		out.WriteString(colorBoldWhite + "ID\t\tPort\tTarget" + colorReset + "\n")
		for id, pf := range portForwards {
			out.WriteString(fmt.Sprintf(
				"%s%s%s\t%s%d%s\t%s:%d via %s%s%s\n",
				colorDim, id, colorReset,
				colorYellow, pf.AgentListenPort, colorReset,
				pf.DestinationHost, pf.DestinationPort,
				colorCyan, pf.DestinationAgentID, colorReset))
		}
	}
	connLock.Unlock()
}

func consoleCmdSocks(parts []string, out *strings.Builder) {
	if len(parts) < 2 {
		out.WriteString(colorBoldCyan + "Usage:" + colorReset + "\n")
		out.WriteString("  " + colorGreen + "socks <agent-id> <port>" + colorReset + "     # Start SOCKS5\n")
		out.WriteString("  " + colorGreen + "socks list" + colorReset + "                  # List active\n")
		out.WriteString("  " + colorGreen + "socks stop <id>" + colorReset + "             # Stop\n")
		return
	}
	subcmd := parts[1]
	switch subcmd {
	case "list":
		listSocksProxies(out)
	case "stop":
		if len(parts) != 3 {
			out.WriteString(colorBoldCyan + "Usage: " + colorReset + colorGreen + "socks stop <id>\n" + colorReset)
			return
		}
		stopSocksProxy(parts[2], out)
	default:
		agentID := parts[1]
		if len(parts) < 3 {
			out.WriteString(colorBoldRed + "[-]" + colorReset + " Missing port\n")
			return
		}
		port, err := strconv.Atoi(parts[2])
		if err != nil || port < 1 || port > 65535 {
			out.WriteString(colorBoldRed + "[-]" + colorReset + " Invalid port (1-65535)\n")
			return
		}
		var socksUser, socksPass string
		if len(parts) >= 5 {
			socksUser = parts[3]
			socksPass = parts[4]
		}
		out.WriteString(startSocksProxy(agentID, port, socksUser, socksPass))
	}
}

func consoleCmdReconnect(parts []string, out *strings.Builder) {
	args := parts[1:]
	if len(args) != 1 {
		out.WriteString(colorBoldCyan + "Usage: " + colorReset + colorGreen + "reconnect <agent-id>\n" + colorReset)
		return
	}
	agentID := args[0]
	connLock.Lock()
	_, ok := connections[agentID]
	connLock.Unlock()
	if !ok {
		out.WriteString(fmt.Sprintf(colorBoldRed+"[-]"+colorReset+" Agent %s%s%s not found\n", colorYellow, agentID, colorReset))
		return
	}
	reconnectMsg := Message{
		Type:          "reconnect",
		Payload:       []byte(`{}`),
		TargetAgentID: agentID,
	}
	if err := sendControlMessageToAgent(agentID, reconnectMsg); err != nil {
		out.WriteString(fmt.Sprintf(colorBoldRed+"[-]"+colorReset+" Failed to send reconnect message: %v\n", err))
		return
	}
	out.WriteString(fmt.Sprintf(colorBoldGreen+"[+]"+colorReset+" Reconnect requested for %s%s%s\n", colorCyan, agentID, colorReset))
}

func consoleCmdDisconnect(parts []string, out *strings.Builder) {
	args := parts[1:]
	if len(args) != 1 {
		out.WriteString(colorBoldCyan + "Usage: " + colorReset + colorGreen + "disconnect <agent-id|all>\n" + colorReset)
		return
	}
	agentID := args[0]
	if agentID == "all" {
		consoleCmdDisconnectAll(out)
		return
	}
	consoleCmdDisconnectOne(agentID, out)
}

func consoleCmdDisconnectAll(out *strings.Builder) {
	connLock.Lock()
	if len(connections) == 0 {
		connLock.Unlock()
		out.WriteString(colorYellow + "No agents connected.\n" + colorReset)
		return
	}
	agentsList := make([]string, 0, len(connections))
	agentInfos := make(map[string]*AgentInfo)
	for id, info := range connections {
		agentsList = append(agentsList, id)
		agentInfos[id] = info
	}
	connLock.Unlock()

	sentCount := 0
	for _, id := range agentsList {
		disconnectMsg := Message{Type: "disconnect", Payload: []byte(`{}`), TargetAgentID: id}
		if err := sendControlMessageToAgent(id, disconnectMsg); err != nil {
			out.WriteString(fmt.Sprintf(colorBoldRed+"[-]"+colorReset+" Failed to send disconnect to %s%s%s: %v\n", colorCyan, id, colorReset, err))
		} else {
			sentCount++
		}
	}

	time.Sleep(300 * time.Millisecond)

	connLock.Lock()
	for _, id := range agentsList {
		info, stillHere := agentInfos[id]
		if !stillHere {
			continue
		}
		if directWS, ok := directConnections[info.DirectWSConnID]; ok {
			directWS.Close()
			delete(directConnections, info.DirectWSConnID)
		}
		if sess, ok := yamuxSessions[id]; ok {
			sess.Close()
			delete(yamuxSessions, id)
		}
		delete(connections, id)
	}
	connLock.Unlock()
	out.WriteString(fmt.Sprintf(colorBoldGreen+"[+]"+colorReset+" Disconnect broadcast to %s%d%s agent(s)\n", colorYellow, sentCount, colorReset))
}

func consoleCmdDisconnectOne(agentID string, out *strings.Builder) {
	connLock.Lock()
	agentInfo, ok := connections[agentID]
	connLock.Unlock()
	if !ok {
		out.WriteString(fmt.Sprintf(colorBoldRed+"[-]"+colorReset+" Agent %s%s%s not found\n", colorYellow, agentID, colorReset))
		return
	}
	disconnectMsg := Message{Type: "disconnect", Payload: []byte(`{}`), TargetAgentID: agentID}
	if err := sendControlMessageToAgent(agentID, disconnectMsg); err != nil {
		out.WriteString(fmt.Sprintf(colorBoldRed+"[-]"+colorReset+" Failed to send disconnect message: %v\n", err))
	}
	connLock.Lock()
	directWS, wsOk := directConnections[agentInfo.DirectWSConnID]
	connLock.Unlock()
	if wsOk {
		directWS.Close()
	}
	out.WriteString(fmt.Sprintf(colorBoldGreen+"[+]"+colorReset+" Disconnect initiated for %s%s%s\n", colorCyan, agentID, colorReset))
}

func consoleCmdPort(parts []string, out *strings.Builder) {
	if len(parts) < 2 {
		out.WriteString(colorBoldCyan + "Usage: " + colorReset + colorGreen + "port <number>\n" + colorReset)
		return
	}
	p, err := strconv.Atoi(parts[1])
	if err != nil || p < 1 || p > 65535 {
		out.WriteString(colorBoldRed + "[-]" + colorReset + " Invalid port number\n")
		return
	}
	settingsMu.Lock()
	currentHTTPPort = p
	settingsMu.Unlock()
	out.WriteString(fmt.Sprintf(colorBoldGreen+"[+]"+colorReset+" Restarting HTTP server on port %s%d%s...\n", colorYellow, p, colorReset))
	go restartHTTPOnPort(p)
}

func consoleCmdTCPPort(parts []string, out *strings.Builder) {
	if len(parts) < 2 {
		out.WriteString(colorBoldCyan + "Usage: " + colorReset + colorGreen + "tcp-port <number>" + colorReset)
		return
	}
	p, err := strconv.Atoi(parts[1])
	if err != nil || p < 1 || p > 65535 {
		out.WriteString(colorBoldRed + "[-]" + colorReset + " Invalid port")
		return
	}
	settingsMu.Lock()
	oldPort := currentTCPPort
	currentTCPPort = p
	proxyPort = currentTCPPort
	settingsMu.Unlock()
	if isPrivileged() && p != oldPort {
		go restartTCPProxy()
		out.WriteString(fmt.Sprintf(colorBoldGreen+"[+]"+colorReset+" TCP proxy restarting on port %s%d%s", colorYellow, p, colorReset))
	} else if p != oldPort {
		out.WriteString(fmt.Sprintf(colorBoldGreen+"[+]"+colorReset+" TCP port set to %s%d%s (restart requires root/admin)", colorYellow, p, colorReset))
	} else {
		out.WriteString(fmt.Sprintf(colorBoldGreen+"[+]"+colorReset+" TCP port already %s%d%s", colorYellow, p, colorReset))
	}
}

func consoleCmdUDPPort(parts []string, out *strings.Builder) {
	if runtime.GOOS == "windows" {
		out.WriteString(colorBoldYellow + "[!]" + colorReset + " UDP port change is not supported on Windows (the proxy uses WinDivert and does not bind to a specific port).\n")
		return
	}
	if len(parts) < 2 {
		out.WriteString(colorBoldCyan + "Usage: " + colorReset + colorGreen + "udp-port <number>" + colorReset)
		return
	}
	p, err := strconv.Atoi(parts[1])
	if err != nil || p < 1 || p > 65535 {
		out.WriteString(colorBoldRed + "[-]" + colorReset + " Invalid port")
		return
	}
	settingsMu.Lock()
	oldPort := currentUDPPort
	currentUDPPort = p
	udpProxyPort = currentUDPPort
	settingsMu.Unlock()
	if isPrivileged() && p != oldPort {
		go restartUDPProxy()
		out.WriteString(fmt.Sprintf(colorBoldGreen+"[+]"+colorReset+" UDP proxy restarting on port %s%d%s", colorYellow, p, colorReset))
	} else if p != oldPort {
		out.WriteString(fmt.Sprintf(colorBoldGreen+"[+]"+colorReset+" UDP port set to %s%d%s (restart requires root/admin)", colorYellow, p, colorReset))
	} else {
		out.WriteString(fmt.Sprintf(colorBoldGreen+"[+]"+colorReset+" UDP port already %s%d%s", colorYellow, p, colorReset))
	}
}

func consoleCmdDNSPort(parts []string, out *strings.Builder) {
	if len(parts) < 2 {
		out.WriteString(colorBoldCyan + "Usage: " + colorReset + colorGreen + "dns-port <number>" + colorReset)
		return
	}
	p, err := strconv.Atoi(parts[1])
	if err != nil || p < 1 || p > 65535 {
		out.WriteString(colorBoldRed + "[-]" + colorReset + " Invalid port")
		return
	}
	settingsMu.Lock()
	oldPort := currentDNSPort
	currentDNSPort = p
	dnsLocalPort = currentDNSPort
	settingsMu.Unlock()
	if isPrivileged() && p != oldPort {
		go restartDNSProxy()
		out.WriteString(fmt.Sprintf(colorBoldGreen+"[+]"+colorReset+" DNS proxy restarting on port %s%d%s", colorYellow, p, colorReset))
	} else if p != oldPort {
		out.WriteString(fmt.Sprintf(colorBoldGreen+"[+]"+colorReset+" DNS port set to %s%d%s (restart requires root/admin)", colorYellow, p, colorReset))
	} else {
		out.WriteString(fmt.Sprintf(colorBoldGreen+"[+]"+colorReset+" DNS port already %s%d%s", colorYellow, p, colorReset))
	}
}

func consoleCmdRotateKey(parts []string, out *strings.Builder) {
	newKey := make([]byte, 32)
	rand.Read(newKey)
	setEncryptionKey(newKey)
	encryptionKey = newKey
	keyB64 := base64.URLEncoding.EncodeToString(newKey)
	out.WriteString(fmt.Sprintf(colorBoldGreen+"[+]"+colorReset+" New encryption key: "+colorGreen+"%s"+colorReset+"\n", keyB64))
	out.WriteString(colorBoldYellow + "[!]" + colorReset + " Disconnecting all agents...\n")
	disconnectAllAgents()
	out.WriteString(fmt.Sprintf(colorBoldGreen+"[+]"+colorReset+" Done. Reconnect agents with new key: "+colorGreen+"-key %s"+colorReset+"\n", keyB64))
}

func consoleCmdSettings(parts []string, out *strings.Builder) {
	settingsMu.Lock()
	keyB64 := base64.URLEncoding.EncodeToString(encryptionKey)
	out.WriteString(colorBoldCyan + "[*]" + colorReset + colorBold + " Current Settings:" + colorReset + "\n")
	out.WriteString(fmt.Sprintf("    "+colorBoldCyan+"HTTP Port"+colorReset+"  : "+colorYellow+"%d"+colorReset+"\n", currentHTTPPort))
	out.WriteString(fmt.Sprintf("    "+colorBoldCyan+"TCP Port"+colorReset+"   : "+colorYellow+"%d"+colorReset+"\n", currentTCPPort))
	out.WriteString(fmt.Sprintf("    "+colorBoldCyan+"UDP Port"+colorReset+"   : "+colorYellow+"%d"+colorReset+"\n", currentUDPPort))
	out.WriteString(fmt.Sprintf("    "+colorBoldCyan+"DNS Port"+colorReset+"   : "+colorYellow+"%d"+colorReset+"\n", currentDNSPort))
	out.WriteString(fmt.Sprintf("    "+colorBoldCyan+"Key"+colorReset+"        : "+colorGreen+"%s"+colorReset+"\n", keyB64))
	settingsMu.Unlock()
}

func consoleCmdPing(parts []string, out *strings.Builder) {
	args := parts[1:]
	if len(args) < 2 {
		out.WriteString(colorBoldCyan + "Usage: " + colorReset + colorGreen + "ping <agent-id> <target> [count]\n" + colorReset)
		return
	}
	agentID := args[0]
	target := args[1]
	count := 4
	if len(args) >= 3 {
		if c, err := strconv.Atoi(args[2]); err == nil && c > 0 {
			count = c
		}
	}
	connLock.Lock()
	_, ok := connections[agentID]
	connLock.Unlock()
	if !ok {
		out.WriteString(fmt.Sprintf(colorBoldRed+"[-]"+colorReset+" Agent %s%s%s not found\n", colorYellow, agentID, colorReset))
		return
	}
	req := ICMPRequest{Target: target, Count: count, TimeoutMs: 1000}
	payload, _ := json.Marshal(req)
	msg := Message{
		Type:            "icmp-request",
		Payload:         payload,
		OriginalAgentID: "server",
		TargetAgentID:   agentID,
	}
	pingListenerID, pingResultCh := registerCLIListener(count + 4)
	defer unregisterCLIListener(pingListenerID)
	if err := sendControlMessageToAgent(agentID, msg); err != nil {
		out.WriteString(fmt.Sprintf(colorBoldRed+"[-]"+colorReset+" Failed to send icmp-request: %v\n", err))
		return
	}
	out.WriteString(fmt.Sprintf(
		colorBoldCyan+"[*]"+colorReset+" Sent ICMP ping to agent %s%s%s → %s%s%s (count=%d)\n",
		colorCyan, agentID, colorReset, colorYellow, target, colorReset, count,
	))
	maxWait := time.Duration(count)*(time.Duration(req.TimeoutMs)*time.Millisecond+600*time.Millisecond) + 2*time.Second
	deadline := time.NewTimer(maxWait)
	defer deadline.Stop()
	received := 0
pingWait:
	for received < count {
		select {
		case line, ok := <-pingResultCh:
			if !ok {
				break pingWait
			}
			out.WriteString(line + "\n")
			received++
		case <-deadline.C:
			break pingWait
		}
	}
}

func consoleCmdForward(parts []string, out *strings.Builder) {
	args := parts[1:]
	if len(args) < 1 {
		out.WriteString(colorBoldCyan + "Usage: " + colorReset + colorGreen + "forward add|del ...\n" + colorReset)
		return
	}
	switch args[0] {
	case "add":
		consoleCmdForwardAdd(args, out)
	case "del":
		consoleCmdForwardDel(args, out)
	default:
		out.WriteString(colorBoldCyan + "Usage: " + colorReset + colorGreen + "forward add|del ...\n" + colorReset)
	}
}

func consoleCmdForwardAdd(args []string, out *strings.Builder) {
	if len(args) < 5 || len(args) > 6 {
		out.WriteString(colorBoldCyan + "Usage: " + colorReset + colorGreen + "forward add <local-port> <agent-id> <target-host> <target-port> [tcp|udp]\n" + colorReset)
		return
	}
	localPort, err := strconv.Atoi(args[1])
	if err != nil {
		out.WriteString(colorBoldRed + "[-]" + colorReset + " Invalid local port\n")
		return
	}
	agentID := args[2]
	targetHost := args[3]
	targetPort, err := strconv.Atoi(args[4])
	if err != nil {
		out.WriteString(colorBoldRed + "[-]" + colorReset + " Invalid target port\n")
		return
	}
	protocol := "tcp"
	if len(args) == 6 {
		p := strings.ToLower(args[5])
		if p != "tcp" && p != "udp" {
			out.WriteString(colorBoldRed + "[-]" + colorReset + " Protocol must be tcp or udp\n")
			return
		}
		protocol = p
	}
	connLock.Lock()
	_, ok := connections[agentID]
	connLock.Unlock()
	if !ok {
		out.WriteString(fmt.Sprintf(colorBoldRed+"[-]"+colorReset+" Agent %s%s%s not found\n", colorYellow, agentID, colorReset))
		return
	}
	listenerKey := fmt.Sprintf("%s:%d", agentID, localPort)
	connLock.Lock()
	_, exists := portForwardLookup[listenerKey]
	connLock.Unlock()
	if exists {
		out.WriteString(fmt.Sprintf(colorBoldYellow+"[!]"+colorReset+" Agent %s%s%s already has a listener on port %s%d%s\n", colorCyan, agentID, colorReset, colorYellow, localPort, colorReset))
		return
	}
	listenerID := uuid.New().String()
	pf := &PortForward{
		AgentListenPort:    localPort,
		DestinationAgentID: agentID,
		DestinationHost:    targetHost,
		DestinationPort:    targetPort,
		ListenerID:         listenerID,
		Protocol:           protocol,
	}
	connLock.Lock()
	portForwards[listenerID] = pf
	portForwardLookup[listenerKey] = listenerID
	connLock.Unlock()
	startMsgPayload, _ := json.Marshal(StartAgentListenerMessage{
		ListenerID:      listenerID,
		AgentListenPort: localPort,
		DestinationHost: targetHost,
		DestinationPort: targetPort,
		Protocol:        protocol,
	})
	controlMessage := Message{
		Type:            "start-agent-listener",
		Payload:         startMsgPayload,
		OriginalAgentID: "server",
		TargetAgentID:   agentID,
	}
	if err := sendControlMessageToAgent(agentID, controlMessage); err != nil {
		connLock.Lock()
		delete(portForwards, listenerID)
		delete(portForwardLookup, listenerKey)
		connLock.Unlock()
		out.WriteString(fmt.Sprintf(colorBoldRed+"[-]"+colorReset+" Failed to send command: %v\n", err))
		return
	}
	out.WriteString(fmt.Sprintf(colorBoldGreen+"[+]"+colorReset+" Forward added: "+colorYellow+"localhost:%d"+colorReset+" -> agent %s%s%s -> "+colorYellow+"%s:%d"+colorReset+" (%s)\n",
		localPort, colorCyan, agentID, colorReset, targetHost, targetPort, protocol))
}

func consoleCmdForwardDel(args []string, out *strings.Builder) {
	if len(args) != 2 {
		out.WriteString(colorBoldCyan + "Usage: " + colorReset + colorGreen + "forward del <listener-id>\n" + colorReset)
		return
	}
	listenerID := args[1]
	connLock.Lock()
	pf, ok := portForwards[listenerID]
	if !ok {
		connLock.Unlock()
		out.WriteString(fmt.Sprintf(colorBoldRed+"[-]"+colorReset+" Listener %s%s%s not found\n", colorYellow, listenerID, colorReset))
		return
	}
	destAgentID := pf.DestinationAgentID
	agentListenPort := pf.AgentListenPort
	delete(portForwards, listenerID)
	delete(portForwardLookup, fmt.Sprintf("%s:%d", destAgentID, agentListenPort))
	connLock.Unlock()
	stopMsgPayload, _ := json.Marshal(StopAgentListenerMessage{ListenerID: listenerID})
	controlMessage := Message{
		Type:            "stop-agent-listener",
		Payload:         stopMsgPayload,
		OriginalAgentID: "server",
		TargetAgentID:   destAgentID,
	}
	if err := sendControlMessageToAgent(destAgentID, controlMessage); err != nil {
		out.WriteString(fmt.Sprintf(colorBoldRed+"[-]"+colorReset+" Failed to send stop command: %v\n", err))
		return
	}
	out.WriteString(fmt.Sprintf(colorBoldGreen+"[+]"+colorReset+" Forward %s%s%s removed\n", colorDim, listenerID, colorReset))
}

func consoleCmdRForward(parts []string, out *strings.Builder) {
	args := parts[1:]
	if len(args) < 1 {
		out.WriteString(colorBoldCyan + "Usage: " + colorReset + colorGreen + "rforward add|del|list ...\n" + colorReset)
		return
	}
	switch args[0] {
	case "add":
		if len(args) != 5 {
			out.WriteString(colorBoldCyan + "Usage: " + colorReset + colorGreen + "rforward add <listen-port> <agent-id> <target-host> <target-port>\n" + colorReset)
			return
		}
		listenPort, err := strconv.Atoi(args[1])
		if err != nil {
			out.WriteString(colorBoldRed + "[-]" + colorReset + " Invalid listen port\n")
			return
		}
		agentID := args[2]
		targetHost := args[3]
		targetPort, err := strconv.Atoi(args[4])
		if err != nil {
			out.WriteString(colorBoldRed + "[-]" + colorReset + " Invalid target port\n")
			return
		}
		id, err := startReverseForward(agentID, listenPort, targetHost, targetPort)
		if err != nil {
			out.WriteString(fmt.Sprintf(colorBoldRed+"[-]"+colorReset+" Failed: %v\n", err))
			return
		}
		out.WriteString(fmt.Sprintf(colorBoldGreen+"[+]"+colorReset+" Reverse forward added: %s:%d%s → agent %s%s%s → %s:%d (id: %s%s%s)\n",
			colorYellow, listenPort, colorReset,
			colorCyan, agentID, colorReset,
			targetHost, targetPort,
			colorDim, id, colorReset))
	case "del":
		if len(args) != 2 {
			out.WriteString(colorBoldCyan + "Usage: " + colorReset + colorGreen + "rforward del <listener-id>\n" + colorReset)
			return
		}
		if err := stopReverseForward(args[1]); err != nil {
			out.WriteString(fmt.Sprintf(colorBoldRed+"[-]"+colorReset+" %v\n", err))
		} else {
			out.WriteString(fmt.Sprintf(colorBoldGreen+"[+]"+colorReset+" Reverse forward %s%s%s stopped\n", colorDim, args[1], colorReset))
		}
	case "list":
		reverseForwardsLock.Lock()
		if len(reverseForwards) == 0 {
			out.WriteString(colorYellow + "No active reverse forwards." + colorReset + "\n")
		} else {
			out.WriteString(colorBoldWhite + fmt.Sprintf("%-36s  %-10s  %-15s  %-20s", "ID", "Port", "Agent", "Target") + colorReset + "\n")
			for _, rf := range reverseForwards {
				out.WriteString(fmt.Sprintf("%s%-36s%s  %s:%-9d%s  %s%-15s%s  %s:%d\n",
					colorDim, rf.ListenerID, colorReset,
					colorYellow, rf.ListenPort, colorReset,
					colorCyan, rf.AgentID, colorReset,
					rf.TargetHost, rf.TargetPort))
			}
		}
		reverseForwardsLock.Unlock()
	default:
		out.WriteString(colorBoldCyan + "Usage: " + colorReset + colorGreen + "rforward add|del|list ...\n" + colorReset)
	}
}

func consoleCmdPortScan(parts []string, out *strings.Builder) {
	args := parts[1:]
	if len(args) < 3 {
		out.WriteString(colorBoldCyan + "Usage: " + colorReset + colorGreen + "portscan <agent-id> tcp|udp <target> [ports]\n" + colorReset)
		return
	}
	agentID := args[0]
	proto := strings.ToLower(args[1])
	target := args[2]
	ports := "1-1024"
	if len(args) >= 4 {
		ports = args[3]
	}
	if proto != "tcp" && proto != "udp" {
		out.WriteString(colorBoldRed + "[-]" + colorReset + " Protocol must be tcp or udp\n")
		return
	}
	connLock.Lock()
	_, ok := connections[agentID]
	connLock.Unlock()
	if !ok {
		out.WriteString(fmt.Sprintf(colorBoldRed+"[-]"+colorReset+" Agent %s%s%s not found\n", colorYellow, agentID, colorReset))
		return
	}
	req := PortScanRequest{Target: target, Ports: ports, Proto: proto}
	payload, _ := json.Marshal(req)
	msg := Message{
		Type:            "port-scan-request",
		Payload:         payload,
		OriginalAgentID: "server",
		TargetAgentID:   agentID,
	}
	scanListenerID, scanResultCh := registerCLIListener(512)
	defer unregisterCLIListener(scanListenerID)
	if err := sendControlMessageToAgent(agentID, msg); err != nil {
		out.WriteString(fmt.Sprintf(colorBoldRed+"[-]"+colorReset+" Failed to send port-scan-request: %v\n", err))
		return
	}
	out.WriteString(fmt.Sprintf(
		colorBoldCyan+"[*]"+colorReset+" Started %s%s%s port scan via agent %s%s%s on %s%s%s ports %s\n",
		colorBold, proto, colorReset,
		colorCyan, agentID, colorReset,
		colorYellow, target, colorReset,
		ports))
	startTime := time.Now()
	drainPortScanResults(scanResultCh, out)
	duration := time.Since(startTime).Seconds()
	out.WriteString(fmt.Sprintf(colorDim+"Scan finished in %.1f seconds"+colorReset+"\n", duration))
}

func drainPortScanResults(scanResultCh <-chan string, out *strings.Builder) {
	scanTimeout := time.NewTimer(60 * time.Second)
	defer scanTimeout.Stop()
scanWait:
	for {
		select {
		case line, ok := <-scanResultCh:
			if !ok {
				break scanWait
			}
			out.WriteString(line)
			if !strings.HasSuffix(line, "\n") {
				out.WriteString("\n")
			}
			drainTimer := time.NewTimer(2 * time.Second)
		drainLoop:
			for {
				select {
				case l2, ok2 := <-scanResultCh:
					if !ok2 {
						drainTimer.Stop()
						break scanWait
					}
					out.WriteString(l2)
					if !strings.HasSuffix(l2, "\n") {
						out.WriteString("\n")
					}
					drainTimer.Reset(2 * time.Second)
				case <-drainTimer.C:
					drainTimer.Stop()
					break drainLoop
				}
			}
			break scanWait
		case <-scanTimeout.C:
			out.WriteString(colorBoldRed + "[-]" + colorReset + " Scan timed out after 60s\n")
			break scanWait
		}
	}
}

func consoleCmdConnect(parts []string, out *strings.Builder) {
	args := parts[1:]
	if len(args) < 1 {
		out.WriteString(colorBoldCyan + "Usage: " + colorReset + colorGreen + "connect <ip:port>\n" + colorReset)
		return
	}
	go connectCliToBindAgent(args[0])
	out.WriteString(fmt.Sprintf(colorBoldCyan+"[*]"+colorReset+" Connecting to bind agent at %s%s%s...\n", colorYellow, args[0], colorReset))
}

func consoleCmdLoadConfig(parts []string, out *strings.Builder) {
	args := parts[1:]
	if len(args) < 1 {
		out.WriteString(colorBoldCyan + "Usage: " + colorReset + colorGreen + "load-config <path/to/config.json>\n" + colorReset)
		return
	}
	if err := loadConfigFile(args[0]); err != nil {
		out.WriteString(fmt.Sprintf(colorBoldRed+"[-]"+colorReset+" %v\n", err))
		return
	}
	settingsMu.Lock()
	keyB64 := base64.URLEncoding.EncodeToString(encryptionKey)
	out.WriteString(fmt.Sprintf(colorBoldGreen+"[+]"+colorReset+" Config loaded from %s%s%s\n", colorYellow, args[0], colorReset))
	out.WriteString(fmt.Sprintf("    HTTP Port : %d\n", currentHTTPPort))
	out.WriteString(fmt.Sprintf("    TCP Port  : %d\n", currentTCPPort))
	out.WriteString(fmt.Sprintf("    UDP Port  : %d\n", currentUDPPort))
	out.WriteString(fmt.Sprintf("    DNS Port  : %d\n", currentDNSPort))
	out.WriteString(fmt.Sprintf("    Key       : %s\n", keyB64))
	settingsMu.Unlock()
	out.WriteString(colorBoldYellow + "[!]" + colorReset + " Restart or re-apply proxies for port changes to take effect.\n")
}

func consoleCmdSaveConfig(parts []string, out *strings.Builder) {
	args := parts[1:]
	if len(args) < 1 {
		out.WriteString(colorBoldCyan + "Usage: " + colorReset + colorGreen + "save-config <path/to/config.json>\n" + colorReset)
		return
	}
	if err := saveConfigFile(args[0]); err != nil {
		out.WriteString(fmt.Sprintf(colorBoldRed+"[-]"+colorReset+" Failed to save config: %v\n", err))
		return
	}
	out.WriteString(fmt.Sprintf(colorBoldGreen+"[+]"+colorReset+" Config saved to %s%s%s\n", colorYellow, args[0], colorReset))
}

func consoleCmdVerbose(parts []string, out *strings.Builder) {
	if atomic.LoadInt32(&currentLogLevel) >= logLevelDebug {
		atomic.StoreInt32(&currentLogLevel, logLevelInfo)
		out.WriteString(colorBoldYellow + "[!]" + colorReset + " Verbose logging " + colorRed + "disabled" + colorReset + "\n")
	} else {
		atomic.StoreInt32(&currentLogLevel, logLevelDebug)
		out.WriteString(colorBoldGreen + "[+]" + colorReset + " Verbose logging " + colorGreen + "enabled" + colorReset + "\n")
	}
}

func consoleCmdExit(parts []string, out *strings.Builder) {
	out.WriteString("Shutting down server...\n")
	go func() {
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

func consoleCmdToken(parts []string, out *strings.Builder) {
	args := parts[1:]
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "":
		out.WriteString(colorBoldCyan + "Usage: " + colorReset + colorGreen + "token list | token view <id> | token create <name> <perm> | token revoke <id>\n" + colorReset)
	case "list":
		consoleCmdTokenList(out)
	case "create":
		consoleCmdTokenCreate(args, out)
	case "view":
		consoleCmdTokenView(args, out)
	case "revoke":
		consoleCmdTokenRevoke(args, out)
	default:
		out.WriteString(colorBoldCyan + "Usage: " + colorReset + colorGreen + "token list | token view <id> | token create <name> <perm> | token revoke <id>\n" + colorReset)
	}
}

func consoleCmdTokenList(out *strings.Builder) {
	apiTokensMu.RLock()
	if len(apiTokens) == 0 {
		out.WriteString("No tokens.\n")
	} else {
		out.WriteString(fmt.Sprintf("%-10s  %-24s  %-12s  %s\n", "ID", "Name", "Perms", "Last Used"))
		out.WriteString(fmt.Sprintf("%-10s  %-24s  %-12s  %s\n", "----------", "------------------------", "------------", "---------"))
		for _, tok := range apiTokens {
			lastUsed := "never"
			if !tok.LastUsedAt.IsZero() && tok.LastUsedAt.Year() > 1 {
				lastUsed = tok.LastUsedAt.Format("2006-01-02 15:04")
			}
			out.WriteString(fmt.Sprintf("%-10s  %-24s  %-12s  %s\n",
				tok.ID, tok.Name, strings.Join(tok.Permissions, ","), lastUsed))
		}
	}
	apiTokensMu.RUnlock()
}

func consoleCmdTokenCreate(args []string, out *strings.Builder) {
	if len(args) < 3 {
		out.WriteString(colorBoldCyan + "Usage: " + colorReset + colorGreen + "token create <name> <read|write|admin>\n" + colorReset)
		return
	}
	tokenName := args[1]
	perm := strings.ToLower(args[2])
	if perm != "read" && perm != "write" && perm != "admin" {
		out.WriteString("Permission must be read, write, or admin\n")
		return
	}
	rawToken, err := generateAPIToken()
	if err != nil {
		out.WriteString(fmt.Sprintf(colorBoldRed+"[-]"+colorReset+" Failed to generate token: %v\n", err))
		return
	}
	id, _ := generateSessionToken(8)
	tok := &APIToken{
		ID:          id,
		Token:       rawToken,
		Name:        tokenName,
		CreatedAt:   time.Now(),
		Permissions: []string{perm},
	}
	apiTokensMu.Lock()
	apiTokens[rawToken] = tok
	apiTokensMu.Unlock()
	log.Printf("[CLI] Token created: name=%q id=%s perms=%v", tokenName, id, []string{perm})
	out.WriteString(fmt.Sprintf(colorBoldGreen + "[+]" + colorReset + " Token created\n"))
	out.WriteString(fmt.Sprintf("    ID    : %s\n", id))
	out.WriteString(fmt.Sprintf("    Name  : %s\n", tokenName))
	out.WriteString(fmt.Sprintf("    Perms : %s\n", perm))
	out.WriteString(fmt.Sprintf("    Token : %s\n", rawToken))
	out.WriteString(colorBoldYellow + "[!]" + colorReset + " Save this token now, it will not be shown again.\n")
}

func consoleCmdTokenView(args []string, out *strings.Builder) {
	if len(args) < 2 {
		out.WriteString(colorBoldCyan + "Usage: " + colorReset + colorGreen + "token view <id>\n" + colorReset)
		return
	}
	viewTargetID := args[1]
	apiTokensMu.RLock()
	var viewTok *APIToken
	for _, tok := range apiTokens {
		if tok.ID == viewTargetID {
			cp := *tok
			viewTok = &cp
			break
		}
	}
	apiTokensMu.RUnlock()
	if viewTok == nil {
		out.WriteString(fmt.Sprintf(colorBoldRed+"[-]"+colorReset+" No token with id %s%s%s\n", colorYellow, viewTargetID, colorReset))
		return
	}
	out.WriteString(fmt.Sprintf(colorBoldGreen+"[+]"+colorReset+" Token details for %s%s%s\n", colorCyan, viewTargetID, colorReset))
	out.WriteString(fmt.Sprintf("    ID    : %s\n", viewTok.ID))
	out.WriteString(fmt.Sprintf("    Name  : %s\n", viewTok.Name))
	out.WriteString(fmt.Sprintf("    Perms : %s\n", strings.Join(viewTok.Permissions, ",")))
	out.WriteString(fmt.Sprintf("    Token : %s\n", viewTok.Token))
}

func consoleCmdTokenRevoke(args []string, out *strings.Builder) {
	if len(args) < 2 {
		out.WriteString(colorBoldCyan + "Usage: " + colorReset + colorGreen + "token revoke <id>\n" + colorReset)
		return
	}
	targetID := args[1]
	apiTokensMu.Lock()
	var found bool
	for rawToken, tok := range apiTokens {
		if tok.ID == targetID {
			delete(apiTokens, rawToken)
			found = true
			log.Printf("[CLI] Token revoked: name=%q id=%s", tok.Name, targetID)
			out.WriteString(fmt.Sprintf(colorBoldGreen+"[+]"+colorReset+" Token %s%s%s (%s%s%s) revoked\n", colorYellow, targetID, colorReset, colorCyan, tok.Name, colorReset))
			break
		}
	}
	apiTokensMu.Unlock()
	if !found {
		out.WriteString(fmt.Sprintf(colorBoldRed+"[-]"+colorReset+" No token with id %s%s%s\n", colorYellow, targetID, colorReset))
	}
}
