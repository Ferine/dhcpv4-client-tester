# DHCP Client Simulator (Raw Sockets, No Scapy)

This project simulates **multiple DHCP clients** in parallel using raw sockets, without relying on Scapy or external libraries. It performs the full DHCP handshake (DISCOVER → OFFER → REQUEST → ACK) and gracefully releases leases on exit.

---

## Features

- Configurable number of clients and concurrency via environment variables
- Pure Python, no third-party dependencies
- Full DHCP exchange per client (DISCOVER → OFFER → REQUEST → ACK → RELEASE)
- Thread-safe statistics with success rate summary
- Sends DHCPRELEASE on Ctrl+C or normal exit
- Bounds-checked DHCP option parsing (handles malformed server responses)
- Works on Linux with elevated privileges

---

## Requirements

- Python 3.7+
- Root privileges (to bind to privileged ports and send broadcasts)
- Linux (tested with Docker)

---

## Usage

```bash
# Standalone usage
sudo python3 client/dhcp_simulator.py

# Or with Docker Compose
docker-compose up
```

---

## Configuration

All configuration is done via environment variables. No need to edit source files.

| Variable              | Default        | Description                                      |
|-----------------------|----------------|--------------------------------------------------|
| `TOTAL_CLIENTS`       | `50`           | Total number of DHCP clients to simulate         |
| `MAX_CONCURRENT`      | `10`           | Maximum clients running concurrently             |
| `LEASE_DURATION`      | `30`           | Seconds to hold leases before releasing          |
| `DHCP_INTERFACE`      | `eth0`         | Network interface name (informational)           |
| `DHCP_SERVER_IP`      | `172.28.0.2`   | IP address of the DHCP server (must be valid IPv4) |
| `HEALTH_CHECK_TIMEOUT`| `30`           | Seconds to wait for DHCP server readiness        |

### Example

```bash
sudo TOTAL_CLIENTS=100 MAX_CONCURRENT=20 LEASE_DURATION=60 python3 client/dhcp_simulator.py
```

### Docker Compose override

```yaml
services:
  dhcp-client:
    environment:
      - TOTAL_CLIENTS=100
      - MAX_CONCURRENT=20
      - LEASE_DURATION=60
```

---

## Output

```
Checking if DHCP server is available at 172.28.0.2...
Sending test DHCPDISCOVER...
Received DHCPOFFER from 172.28.0.2 - Server is ready!
Starting DHCP simulator: 50 clients, 10 concurrent...
[Client 0] Lease 172.28.100.10 from 172.28.0.2 (MAC: 02:00:3a:b1:c2:d3)
[Client 1] Lease 172.28.100.11 from 172.28.0.2 (MAC: 02:00:1f:44:55:66)
...
[*] Releasing leases...
[RELEASE] 172.28.100.10 -> 172.28.0.2 (MAC: 02:00:3a:b1:c2:d3)

Final Stats:
  Successful leases : 50
  Failed attempts   : 0
  Success rate      : 100.0% (50/50)
```

---

## Architecture

```
docker-compose
├── dhcp-server  (ISC DHCP server, 172.28.0.2)
│   └── dhcpd/dhcpd.conf  — Lease range: 172.28.100.10 – 172.28.100.100
└── dhcp-client  (Python simulator, 172.28.0.3)
    └── client/dhcp_simulator.py
```

The client container waits for the server healthcheck to pass before starting the simulation.
