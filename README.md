# Rosemary

**Cross-platform transparent tunneling platform. No TUN. No proxychains.**

[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-brightgreen.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Release](https://img.shields.io/github/v/release/blue0x1/rosemary)](https://github.com/blue0x1/rosemary/releases)
[![Downloads](https://img.shields.io/github/downloads/blue0x1/rosemary/total.svg)](https://github.com/blue0x1/rosemary/releases)
![Go Version](https://img.shields.io/badge/Go-1.25.0-00ADD8?logo=go)
[![Stars](https://img.shields.io/github/stars/blue0x1/rosemary)](https://github.com/blue0x1/rosemary/stargazers)

<br>
<img width="2124" height="900" alt="logo-dark" src="https://github.com/user-attachments/assets/f1a27759-1df3-4d37-b999-235dde6cfae6" />


---

Rosemary deploys lightweight agents on remote hosts and transparently intercepts traffic at the kernel level: no proxy settings, no TUN/TAP devices, no proxychains. Once an agent connects, you reach its entire network as if you were directly on it.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Features](#features)
- [Platforms](#platforms)
- [Screenshots](#screenshots)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [API](#api)
- [Build](#build)
- [Security](#security)
- [License](#license)
- [Author](#author)

---

## How It Works

Run the **server** on your machine and deploy an **agent** on any remote host. The agent connects back, the server installs kernel-level interception rules for the agent's subnets, and from that point all traffic to those subnets is transparently forwarded through the agent, no proxy config, no TUN device, no changes to your applications.

```
curl http://192.168.1.50   ───►  agent dials 192.168.1.50 and bridges it back
ssh  user@192.168.1.20
ping 192.168.1.1
```

Connect multiple agents at once and traffic is automatically routed to whichever agent owns the destination.

---

## Features

| Category | Capability |
|----------|------------|
| **Interception** | Transparent TCP · UDP · ICMP · DNS, no client config required |
| **Egress** | Default egress agent routes all internet traffic through a chosen agent |
| **SOCKS5** | Per-agent SOCKS5 proxy with optional username/password auth |
| **Forwards** | TCP/UDP port forwards · Reverse port forwards (server listens, agent dials) |
| **Discovery** | Ping · Ping sweep · TCP/UDP port scan via agent |
| **DNS** | Intercepts DNS, resolves through agents, private and public domains |
| **Pivoting** | Multi-hop through multiple agents (3+ hops tested) |
| **Dashboard** | Web UI with real-time agent graph, routing table, log viewer |
| **API** | Full REST API with token-based auth (`read`/`write`/`admin`) |
| **CLI** | Interactive REPL + web-based CLI panel |
| **Extension** | Chrome extension for quick access |
| **Agents** | Background mode · bind mode · auto subnet discovery · internet detection |
| **Config** | JSON import/export · live key rotation · per-port configuration |

---

## Platforms

| Platform | TCP | UDP | DNS | ICMP | SOCKS5 | Egress |
|----------|:---:|:---:|:---:|:----:|:------:|:------:|
| **Linux** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Windows** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **macOS** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **FreeBSD** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **OpenBSD** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

**Agent** runs on all platforms above. No root required on the agent side.

---

## Screenshots

### Dashboard | Agent Graph View

*Interactive network graph showing connected agents and their relationships*

<img width="1301" height="601" alt="image" src="https://github.com/user-attachments/assets/0b9e2851-77b9-450c-ac16-5710653d2b79" />


### Dashboard | Table View

*Detailed agent information including OS, hostname, subnets, and connection status*

 <img width="1291" height="669" alt="image" src="https://github.com/user-attachments/assets/b1664e26-bf14-4af0-85fa-09c2612f3d3c" />


### Chrome Extension

*Browser extension for easy access and traffic routing through the tunnel*

<img width="427" height="578" alt="image" src="https://github.com/user-attachments/assets/43c1c943-82fd-4db2-9117-537b8e275a63" />


**Installation:**

1. Open Chrome and go to `chrome://extensions/`
2. Enable **Developer mode** (toggle in top right)
3. Click **Load unpacked**
4. Select the `extension/` folder from the repository

The extension icon will appear in your browser toolbar.

### Port Forward Management

*Create and manage TCP/UDP port forwards through any agent*

<img width="499" height="541" alt="image" src="https://github.com/user-attachments/assets/9647580c-4e6d-4343-9255-ee375358291e" />



### Routing Table

*View and toggle subnet routes with real-time status*

<img width="555" height="743" alt="image" src="https://github.com/user-attachments/assets/ccb84b0a-f926-4aa2-8474-9d9b109cd1c8" />



### CLI Panel

*Built-in REPL for full server control*

<img width="1334" height="653" alt="image" src="https://github.com/user-attachments/assets/34fe5cf6-cc81-40dc-85aa-aff78a451ca1" />


### Web CLI Panel
<img width="917" height="754" alt="image" src="https://github.com/user-attachments/assets/5c6d86b3-4425-4fc5-b5e0-613dc94c664e" />




### SOCKS5 Proxy Management

*Start/stop SOCKS5 proxies through any agent with optional authentication*

<img width="917" height="246" alt="image" src="https://github.com/user-attachments/assets/c02e290b-db75-49ce-af0c-2aa951de4d8b" />



### Settings Modal

*Configure server ports, encryption keys, and API tokens*
<img width="844" height="744" alt="image" src="https://github.com/user-attachments/assets/af89afda-0074-475f-8fee-155d9c15aa3e" />





### API Tokens

*Create and manage REST API tokens with granular permissions*

<img width="844" height="744" alt="image" src="https://github.com/user-attachments/assets/621d3af3-ba79-4558-b665-0d016614e1c4" />


### Agent Context Menu

*Quick actions: tag, forward, ping, port scan, reconnect, disconnect*

<img width="489" height="625" alt="image" src="https://github.com/user-attachments/assets/9852e051-64d7-462a-81bc-686225c69f60" />



---

> **Note:** The graph view automatically layouts agents and visualizes subnet relationships. Edges between agents indicate shared subnets, enabling multi-hop pivoting visualization.

---

## Quick Start

### Install

```bash
# Install via go install
go install github.com/blue0x1/rosemary/rosemary@latest
go install github.com/blue0x1/rosemary/agent@latest # For install agent

# Copy to system path for sudo use
sudo cp ~/go/bin/rosemary /usr/local/bin/
```

Or download pre-built binaries from [Releases](https://github.com/blue0x1/rosemary/releases).

### 1. Start the Server

```bash
# Auto-generate a key
sudo rosemary

# Or provide your own
sudo rosemary -k YOUR_BASE64_KEY
```

Dashboard available at `http://server-ip:1024`: log in with your key.

### 2. Deploy an Agent

```bash
# Standard (agent connects to server)
./agent-linux-amd64 -s ws://server-ip:1024/ws -k YOUR_KEY

# Background mode
./agent-linux-amd64 -b -s ws://server-ip:1024/ws -k YOUR_KEY

# Windows
agent-windows-amd64.exe -s ws://server-ip:1024/ws -k YOUR_KEY
```

Once connected, the agent's subnets are automatically routed through it.

### 3. Bind Mode (agent behind NAT)

```bash
# On the agent host: agent listens for the server to connect
./agent-linux-amd64 -m agent-bind -l 0.0.0.0:9001 -k YOUR_KEY

# On the server CLI
rosemary> connect agent-ip:9001
```

### 4. Egress: Route All Internet Traffic

```bash
rosemary> egress agent-1
[+] Default egress set to agent-1
```

All traffic to IPs outside known agent subnets now flows through `agent-1`. DNS continues to work for both private and public domains.

---

## CLI Reference

Type `help` or `help <command>` inside the REPL for full details.

### Agents

```
agents                         List all connected agents
disconnect <agent-id|all>      Disconnect agent(s)
reconnect  <agent-id>          Force agent to reconnect
connect    <ip:port>           Connect to a bind-mode agent
```

### Routing

```
routes                         Show routing table
routes enable  <subnet>        Re-enable a disabled route
routes disable <subnet>        Disable a route without disconnecting
routes default <agent-id>      Set default egress agent
routes default off             Clear default egress
egress <agent-id>              Alias: set default egress agent
egress none                    Alias: clear default egress
```

### Port Forwards

```
forward add <local-port> <agent-id> <host> <port> [tcp|udp]
forward del <id>
forwards                       List active forwards
```

### Reverse Forwards

```
rforward add <listen-port> <agent-id> <host> <port>
rforward del <id>
rforward list
```

### SOCKS5

```
socks <agent-id> <port> [username] [password]
socks list
socks stop <id>
```

### Discovery

```
ping     <agent-id> <target> [count]
discover <agent-id> <subnet> [timeout_ms] [workers]
portscan <agent-id> tcp|udp <target> [ports]
```

### Server

```
settings                       Show current config
verbose                        Toggle debug logging
rotate-key                     Regenerate encryption key
save-config <path>             Export config to JSON
load-config <path>             Import config from JSON
token list|create|view|revoke  Manage API tokens
exit                           Shutdown
```

---

## API

Authenticate once to get a token, then use it for all requests.

```bash
# Authenticate
curl -X POST http://server:1024/api/v1/auth \
  -H "Content-Type: application/json" \
  -d '{"key":"YOUR_KEY"}'

# List agents
curl -H "Authorization: Bearer tun_xxx" \
  http://server:1024/api/v1/agents

# Port forward
curl -X POST http://server:1024/api/v1/forwards \
  -H "Authorization: Bearer tun_xxx" \
  -H "Content-Type: application/json" \
  -d '{"action":"add","agent_id":"agent-1","local_port":8080,"target_host":"192.168.1.10","target_port":80}'

# SOCKS5 proxy
curl -X POST http://server:1024/api/v1/socks \
  -H "Authorization: Bearer tun_xxx" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agent-1","port":1080}'

# Run any CLI command
curl -X POST http://server:1024/api/v1/cli \
  -H "Authorization: Bearer tun_xxx" \
  -H "Content-Type: application/json" \
  -d '{"command":"discover agent-1 10.10.10.0/24"}'
```

**Endpoints:** `/api/v1/auth` · `/api/v1/agents` · `/api/v1/routes` · `/api/v1/forwards` · `/api/v1/rforwards` · `/api/v1/socks` · `/api/v1/cli` · `/api/v1/settings` · `/api/v1/tokens` · `/api/v1/shutdown`

Token permission levels: `read` · `write` · `admin`

---

## Build

```bash
git clone https://github.com/blue0x1/rosemary.git
cd rosemary

# Build all platforms and architectures
bash build.sh

# Build specific target
bash build.sh rosemary linux amd64
bash build.sh agent  windows arm64

# Output goes to dist/
```

**Supported architectures:**
- linux, freebsd, openbsd: `amd64` `arm64` `arm` `386`
- windows: `amd64` `arm64` `386`
- darwin: `amd64` `arm64`

### Windows Server: WinDivert Requirement

The Windows server uses WinDivert for kernel-level packet interception. Before building:

1. Download **WinDivert.dll** and **WinDivert64.sys** from [reqrypt.org/windivert.html](https://reqrypt.org/windivert.html) (v2.x, 64-bit)
2. Place both files in the `rosemary/` directory

They are embedded into the binary at build time.

---

## Security

- **Encryption**: AES-256-GCM on all agent ↔ server communication
- **Authentication**: challenge-response on WebSocket connect; shared key required
- **Dashboard**: session-based login with CSRF token protection
- **API tokens**: scoped permissions: `read` / `write` / `admin`
- **Privilege separation**: agents require no root; only the server needs elevated rights

---

## License

GNU General Public License v3.0: see [LICENSE](LICENSE)

---

## Author

**blue0x1** (Chokri Hammedi)

[GitHub](https://github.com/blue0x1) · [Sponsor](https://github.com/sponsors/blue0x1)

---

> Use only on systems you own or have explicit written permission to test. Unauthorized use is prohibited.
