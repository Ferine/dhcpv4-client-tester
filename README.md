# DHCP Client Simulator (Raw Sockets, No Scapy)

This project simulates **multiple DHCP clients** in parallel using raw sockets, without relying on Scapy or external libraries. It supports both DHCPv4 and DHCPv6 protocols.

* DHCPv4: Full DHCP handshake (DISCOVER → OFFER → REQUEST → ACK) and lease release
* DHCPv6: Full prefix delegation (SOLICIT → ADVERTISE → REQUEST → REPLY) and release

---

## ✨ Features

- ⚙️ Configurable number of clients and concurrency
- 🚀 Pure Python, no third-party dependencies
- 🔁 Full DHCP exchange per client
- 📉 Summary statistics after run
- 🧹 Sends DHCPRELEASE on Ctrl+C or normal exit
- ✅ Works well on Linux or macOS with elevated privileges
- 🌐 Supports both IPv4 and IPv6

---

## 📦 Requirements

- Python 3.7+
- Root privileges (to bind to privileged ports and send broadcasts)
- Linux or macOS (tested on both)
- Docker and Docker Compose (for container setup)

---

## 🛠️ Usage

```bash
# Standalone DHCPv4 usage
sudo python3 client/dhcp_simulator.py

# Standalone DHCPv6 usage
sudo python3 client/dhcpv6_simulator.py

# Or with Docker (runs both IPv4 and IPv6)
docker-compose up

# To run only IPv4 services
docker-compose up dhcp-server dhcp-client

# To run only IPv6 services
docker-compose up dhcpv6-server dhcpv6-client

# ==== CONFIG ====
# Edit client/dhcp_simulator.py to configure DHCPv4:
TOTAL_CLIENTS = 50         # Number of DHCP clients to simulate
MAX_CONCURRENT = 10        # Maximum concurrent clients
LEASE_DURATION = 30        # Hold leases for N seconds before releasing
INTERFACE = 'eth0'         # Interface (eth0 in Docker, may be different on host)

# Edit client/dhcpv6_simulator.py to configure DHCPv6:
TOTAL_CLIENTS = 50         # Number of DHCPv6 clients to simulate
MAX_CONCURRENT = 10        # Maximum concurrent clients
LEASE_DURATION = 30        # Hold leases for N seconds before releasing
INTERFACE = 'eth0'         # Interface (eth0 in Docker, may be different on host)
# =================
```