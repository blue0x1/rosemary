# Rosemary

**Cross-platform transparent tunneling platform. No TUN. No proxychains.**

[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-brightgreen.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Release](https://img.shields.io/github/v/release/blue0x1/rosemary)](https://github.com/blue0x1/rosemary/releases)
[![Downloads](https://img.shields.io/github/downloads/blue0x1/rosemary/total.svg)](https://github.com/blue0x1/rosemary/releases)
![Go Version](https://img.shields.io/badge/Go-1.25.0-00ADD8?logo=go)
[![Stars](https://img.shields.io/github/stars/blue0x1/rosemary)](https://github.com/blue0x1/rosemary/stargazers)

<br>
<img width="3124" height="1108" alt="logo-dark" src="https://github.com/user-attachments/assets/15a1b523-664f-428b-becc-19178e256b00" />

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

<img width="1252" height="741" alt="image" src="https://github.com/user-attachments/assets/6b358caa-bc7e-4c5c-8427-4972d66d248d" />


### Dashboard | Table View

*Detailed agent information including OS, hostname, subnets, and connection status*

<img width="1252" height="741" alt="image" src="https://github.com/user-attachments/assets/9c57a652-22cd-4738-aa6f-3dcef1c2311f" />

### Chrome Extension

*Browser extension for easy access and traffic routing through the tunnel*

<img width="434" height="577" alt="image" src="https://github.com/user-attachments/assets/4ae098b0-acef-46f7-9ba4-7cf1ba30b898" />

**Installation:**

1. Open Chrome and go to `chrome://extensions/`
2. Enable **Developer mode** (toggle in top right)
3. Click **Load unpacked**
4. Select the `extension/` folder from the repository

The extension icon will appear in your browser toolbar.

### Port Forward Management

*Create and manage TCP/UDP port forwards through any agent*

<img width="508" height="521" alt="image" src="https://github.com/user-attachments/assets/b66e02cc-b32d-496a-bee8-62127188fe31" />


### Routing Table

*View and toggle subnet routes with real-time status*

<img width="679" height="477" alt="image" src="https://github.com/user-attachments/assets/729766a8-5f41-493f-b186-f966bce2395f" />


### CLI Panel

*Built-in REPL for full server control*

<img width="1693" height="760" alt="image" src="https://github.com/user-attachments/assets/c642b328-1f6f-4f69-976b-cf1d023c22d8" />

### Web CLI Panel
<img width="978" height="885" alt="image" src="https://github.com/user-attachments/assets/5b97b0fd-8f61-4bc7-a04a-59e68f9ea0c2" />



### SOCKS5 Proxy Management

*Start/stop SOCKS5 proxies through any agent with optional authentication*

<img width="978" height="258" alt="image" src="https://github.com/user-attachments/assets/e007b85f-3722-4292-be49-4a9234df26ba" />


### Settings Modal

*Configure server ports, encryption keys, and API tokens*
<img width="802" height="732" alt="image" src="https://github.com/user-attachments/assets/9382a483-c9d1-4862-a3a8-2580bed324c6" />




### API Tokens

*Create and manage REST API tokens with granular permissions*

<img width="802" height="732" alt="image" src="https://github.com/user-attachments/assets/081177b4-193a-4f0e-88eb-50a67c0d1cc0" />

### Agent Context Menu

*Quick actions: tag, forward, ping, port scan, reconnect, disconnect*

<img width="837" height="304" alt="image" src="https://github.com/user-attachments/assets/195ded96-9c3b-483e-9b12-5fe624070191" />



---

> **Note:** The graph view automatically layouts agents and visualizes subnet relationships. Edges between agents indicate shared subnets, enabling multi-hop pivoting visualization.

---

## Quick Start

### 1. Start the Server

```bash
# Auto-generate a key
sudo ./server-linux-amd64

# Or provide your own
sudo ./server-linux-amd64 -key YOUR_BASE64_KEY
```

Dashboard available at `http://server-ip:1024`: log in with your key.

### 2. Deploy an Agent

```bash
# Standard (agent connects to server)
./agent-linux-amd64 -s server-ip:1024 -k YOUR_KEY

# Background mode
./agent-linux-amd64 -b -s server-ip:1024 -k YOUR_KEY

# Windows
agent-windows-amd64.exe -s server-ip:1024 -k YOUR_KEY
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
bash build.sh server linux amd64
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
2. Place both files in the `server/` directory

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
