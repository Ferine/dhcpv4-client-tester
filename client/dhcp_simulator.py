import socket
import struct
import random
import signal
import sys
import time
import os
import threading
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed


# ==== CONFIG ====
def _parse_int_env(name, default, min_val=1):
    """Parse an integer environment variable with validation."""
    raw = os.environ.get(name)
    if raw is not None:
        try:
            val = int(raw)
            if val < min_val:
                print(f"[!] {name} must be >= {min_val}, got {val}. Using default {default}.")
                return default
            return val
        except ValueError:
            print(f"[!] Invalid value for {name}: {raw!r}. Using default {default}.")
    return default


TOTAL_CLIENTS        = _parse_int_env('TOTAL_CLIENTS', 50)
MAX_CONCURRENT       = _parse_int_env('MAX_CONCURRENT', 10)
LEASE_DURATION       = _parse_int_env('LEASE_DURATION', 30)   # seconds to hold leases before releasing
INTERFACE            = os.environ.get('DHCP_INTERFACE', 'eth0')
DHCP_SERVER_IP       = os.environ.get('DHCP_SERVER_IP', '172.28.0.2')
HEALTH_CHECK_TIMEOUT = _parse_int_env('HEALTH_CHECK_TIMEOUT', 30)
# =================

# Validate DHCP_SERVER_IP at startup
try:
    socket.inet_aton(DHCP_SERVER_IP)
except socket.error:
    print(f"[!] Invalid DHCP_SERVER_IP: {DHCP_SERVER_IP!r}. Must be a valid IPv4 address.")
    sys.exit(1)

# Check if running as root
if os.geteuid() != 0:
    print("\nERROR: This script requires root privileges to use raw sockets")
    print("Please run with sudo or as root\n")
    sys.exit(1)


# Thread-safe shared state
clients = []
clients_lock = threading.Lock()

stats = {"success": 0, "failed": 0}
stats_lock = threading.Lock()

stop_requested = False


def random_mac():
    return bytes([
        0x02, 0x00,
        random.randint(0x00, 0x7f),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff)
    ])


def build_bootp(op, yiaddr, chaddr, xid):
    return struct.pack('!BBBBIHHIIII16s64s128sI',
        op, 1, 6, 0, xid, 0, 0x8000,
        0, yiaddr, 0, 0,
        chaddr + b'\x00' * 10,
        b'\x00' * 64, b'\x00' * 128,
        0x63825363
    )


def send_dhcp(sock, msg_type, mac, xid, requested_ip=None, server_id=None):
    bootp = build_bootp(1, 0, mac, xid)
    options = b'\x35\x01' + bytes([msg_type])
    options += b'\x3d\x07\x01' + mac
    if requested_ip:
        options += b'\x32\x04' + socket.inet_aton(requested_ip)
    if server_id:
        options += b'\x36\x04' + socket.inet_aton(server_id)
    if msg_type == 1:
        options += b'\x37\x03\x03\x01\x06'
    options += b'\xff'
    packet = bootp + options
    sock.sendto(packet, ('255.255.255.255', 67))


def wait_for_msg(sock, xid, expected_type):
    """
    Wait for a DHCP message of expected_type matching xid.
    Returns (data, addr) on success, (None, None) on timeout.
    Performs bounds checking on all option accesses to handle malformed packets safely.
    """
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            # Minimum valid DHCP packet: 240 bytes BOOTP header + at least 1 option byte
            if len(data) < 241:
                continue
            if data[4:8] != struct.pack('!I', xid):
                continue
            index = 240
            while index < len(data):
                if data[index] == 0xff:  # End option
                    break
                # Ensure option length byte is present
                if index + 1 >= len(data):
                    break
                opt_len = data[index + 1]
                # Ensure option data bytes are present
                if index + 2 + opt_len > len(data):
                    break
                # Option 53 is DHCP Message Type
                if data[index] == 53 and opt_len >= 1 and data[index + 2] == expected_type:
                    return data, addr
                index += 2 + opt_len
        except socket.timeout:
            return None, None


def _make_client_sock():
    """Create and bind a UDP socket suitable for DHCP client use."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind(('', 68))
    sock.settimeout(5)
    return sock


def dhcp_client_logic(client_id):
    mac = random_mac()
    xid = random.randint(0, 0xFFFFFFFF)

    try:
        sock = _make_client_sock()
    except OSError as e:
        print(f"[Client {client_id}] Failed to create socket: {e}")
        with stats_lock:
            stats["failed"] += 1
        return

    try:
        send_dhcp(sock, 1, mac, xid)  # DHCPDISCOVER
        offer, addr = wait_for_msg(sock, xid, 2)  # Wait for DHCPOFFER
        if not offer:
            print(f"[Client {client_id}] No DHCPOFFER received")
            with stats_lock:
                stats["failed"] += 1
            return

        offered_ip = socket.inet_ntoa(offer[16:20])

        # Validate offered IP - reject obviously invalid values
        if offered_ip in ('0.0.0.0', '255.255.255.255'):
            print(f"[Client {client_id}] Invalid offered IP: {offered_ip}")
            with stats_lock:
                stats["failed"] += 1
            return

        server_ip = addr[0]
        send_dhcp(sock, 3, mac, xid, requested_ip=offered_ip, server_id=server_ip)  # DHCPREQUEST

        ack, _ = wait_for_msg(sock, xid, 5)  # Wait for DHCPACK
        if not ack:
            print(f"[Client {client_id}] No DHCPACK received")
            with stats_lock:
                stats["failed"] += 1
            return

        mac_str = ':'.join(f'{b:02x}' for b in mac)
        print(f"[Client {client_id}] Lease {offered_ip} from {server_ip} (MAC: {mac_str})")
        with stats_lock:
            stats["success"] += 1

        # Register client info for lease release on exit
        with clients_lock:
            clients.append((mac, xid, offered_ip, server_ip))

    finally:
        sock.close()


def run_clients():
    """Run all DHCP clients using a thread pool, collecting any unhandled errors."""
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT) as executor:
        futures = {executor.submit(dhcp_client_logic, i): i for i in range(TOTAL_CLIENTS)}
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                client_id = futures[future]
                print(f"[Client {client_id}] Unhandled error: {e}")
                with stats_lock:
                    stats["failed"] += 1


def send_release(mac, xid, ip, server_ip):
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        s.bind(('', 68))
        bootp = build_bootp(1, 0, mac, xid)
        options = (
            b'\x35\x01\x07' +
            b'\x3d\x07\x01' + mac +
            b'\x32\x04' + socket.inet_aton(ip) +
            b'\x36\x04' + socket.inet_aton(server_ip) +
            b'\xff'
        )
        packet = bootp + options
        s.sendto(packet, (server_ip, 67))
        mac_str = ':'.join(f'{b:02x}' for b in mac)
        print(f"[RELEASE] {ip} -> {server_ip} (MAC: {mac_str})")
    except OSError as e:
        print(f"[!] Failed to send DHCPRELEASE for {ip}: {e}")
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def print_final_stats():
    total = stats['success'] + stats['failed']
    rate = (stats['success'] / total * 100) if total > 0 else 0.0
    print("\nFinal Stats:")
    print(f"  Successful leases : {stats['success']}")
    print(f"  Failed attempts   : {stats['failed']}")
    print(f"  Success rate      : {rate:.1f}% ({stats['success']}/{total})")


def handle_exit(signum, frame):
    global stop_requested
    stop_requested = True
    print("\n[*] Releasing leases...")

    with clients_lock:
        snapshot = list(clients)

    for mac, xid, ip, srv in snapshot:
        send_release(mac, xid, ip, srv)

    print_final_stats()
    sys.exit(0)


def check_dhcp_server_health():
    """
    Check if DHCP server is available and ready to serve requests.
    Returns True if server is ready, False otherwise.
    """
    print(f"Checking if DHCP server is available at {DHCP_SERVER_IP}...")

    # Ping the DHCP server; use subprocess with a list to avoid shell injection
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", DHCP_SERVER_IP],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if result.returncode != 0:
            print(f"Warning: Cannot ping DHCP server at {DHCP_SERVER_IP} (ICMP may be blocked)")
    except Exception as e:
        print(f"Warning during ping: {e}")

    # Print network interface and routing info for debugging
    try:
        os.system("ip addr")
        os.system("ip route")
    except Exception:
        pass

    # Send a test DISCOVER and wait for OFFER
    test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    test_sock.bind(('', 68))
    test_sock.settimeout(5)

    try:
        test_mac = random_mac()
        test_xid = random.randint(0, 0xFFFFFFFF)

        print("Sending test DHCPDISCOVER...")
        send_dhcp(test_sock, 1, test_mac, test_xid)

        offer, addr = wait_for_msg(test_sock, test_xid, 2)
        if offer:
            server_ip = addr[0]
            print(f"Received DHCPOFFER from {server_ip} - Server is ready!")
            return True

        print("No response to broadcast DHCPDISCOVER. Trying direct unicast to server...")

        # Fallback: send directly to the server IP
        packet = build_bootp(1, 0, test_mac, test_xid)
        options = b'\x35\x01\x01' + b'\x3d\x07\x01' + test_mac + b'\x37\x03\x03\x01\x06' + b'\xff'
        test_sock.sendto(packet + options, (DHCP_SERVER_IP, 67))

        offer, addr = wait_for_msg(test_sock, test_xid, 2)
        if offer:
            server_ip = addr[0]
            print(f"Received DHCPOFFER from {server_ip} on direct try - Server is ready!")
            return True

        print("No response to direct DHCPDISCOVER either")
        return False
    except Exception as e:
        print(f"Error during health check: {e}")
        return False
    finally:
        test_sock.close()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    # Wait for DHCP server to be ready
    start_time = time.time()
    dhcp_ready = False

    while time.time() - start_time < HEALTH_CHECK_TIMEOUT:
        if check_dhcp_server_health():
            dhcp_ready = True
            break
        remaining = int(HEALTH_CHECK_TIMEOUT - (time.time() - start_time))
        print(f"Waiting for DHCP server to be ready... (timeout in {remaining}s)")
        time.sleep(5)

    if not dhcp_ready:
        print("DHCP server health check failed. Exiting.")
        sys.exit(1)

    print(f"Starting DHCP simulator: {TOTAL_CLIENTS} clients, {MAX_CONCURRENT} concurrent...")
    try:
        run_clients()
    except KeyboardInterrupt:
        handle_exit(None, None)

    if not stop_requested:
        print(f"\nHolding leases for {LEASE_DURATION}s before release...")
        time.sleep(LEASE_DURATION)
        handle_exit(None, None)
