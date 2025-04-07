# DHCP Client Simulator (Raw Sockets, No Scapy)

This project simulates **multiple DHCP clients** in parallel using raw sockets, without relying on Scapy or external libraries. It performs the full DHCP handshake (DISCOVER → OFFER → REQUEST → ACK) and gracefully releases leases on exit.

---

## ✨ Features

- ⚙️ Configurable number of clients and concurrency
- 🚀 Pure Python, no third-party dependencies
- 🔁 Full DHCP exchange per client
- 📉 Summary statistics after run
- 🧹 Sends DHCPRELEASE on Ctrl+C or normal exit
- ✅ Works well on Linux or macOS with elevated privileges

---

## 📦 Requirements

- Python 3.7+
- Root privileges (to bind to privileged ports and send broadcasts)
- Linux or macOS (tested on both)

---

## 🛠️ Usage

```bash
# Standalone usage
sudo python3 client/dhcp_simulator.py

# Or with Docker
docker-compose up

# ==== CONFIG ====
# Edit client/dhcp_simulator.py to configure:
TOTAL_CLIENTS = 50         # Number of DHCP clients to simulate
MAX_CONCURRENT = 10        # Maximum concurrent clients
LEASE_DURATION = 30        # Hold leases for N seconds before releasing
INTERFACE = 'eth0'         # Interface (eth0 in Docker, may be different on host)
# =================
