import socket
import struct
import random
import signal
import sys
import time
import asyncio
import os
from concurrent.futures import ThreadPoolExecutor

# ==== CONFIG ====
TOTAL_CLIENTS = 50
MAX_CONCURRENT = 10
LEASE_DURATION = 30  # seconds to "hold" the lease before exit
INTERFACE = os.environ.get('DHCP_INTERFACE', 'eth0')  # ignored on macOS; you must bind to 0.0.0.0
DHCP_SERVER_IP = os.environ.get('DHCP_SERVER_IP', '172.28.0.2')  # Default DHCP server IP in Docker
HEALTH_CHECK_TIMEOUT = 30  # seconds to wait for DHCP server to be ready
# =================

clients = []
stats = {"success": 0, "failed": 0}
stop_requested = False

# Check if running as root
if os.geteuid() != 0:
    print("\n❌ ERROR: This script requires root privileges to use raw sockets")
    print("Please run with sudo or as root\n")
    sys.exit(1)


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
        chaddr + b'\x00'*10,
        b'\x00'*64, b'\x00'*128,
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
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            if data[4:8] != struct.pack('!I', xid):
                continue
            index = 240
            while index < len(data):
                if data[index] == 0xff:
                    break
                if data[index] == 53 and data[index+2] == expected_type:
                    return data, addr
                index += 2 + data[index+1]
        except socket.timeout:
            return None, None


def dhcp_client_logic(client_id):
    global stats

    mac = random_mac()
    xid = random.randint(0, 0xFFFFFFFF)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind(('', 68))  # Use standard DHCP client port with socket reuse
    sock.settimeout(5)

    try:
        send_dhcp(sock, 1, mac, xid)  # Discover
        offer, addr = wait_for_msg(sock, xid, 2)
        if not offer:
            print(f"[Client {client_id}] ❌ No DHCPOFFER")
            stats["failed"] += 1
            return

        offered_ip = socket.inet_ntoa(offer[16:20])
        server_ip = addr[0]
        send_dhcp(sock, 3, mac, xid, requested_ip=offered_ip, server_id=server_ip)

        ack, _ = wait_for_msg(sock, xid, 5)
        if not ack:
            print(f"[Client {client_id}] ❌ No DHCPACK")
            stats["failed"] += 1
            return

        mac_str = ':'.join(f'{b:02x}' for b in mac)
        print(f"[Client {client_id}] ✅ Lease {offered_ip} from {server_ip} (MAC: {mac_str})")
        stats["success"] += 1

        # Add client info for later release
        clients.append((mac, xid, offered_ip, server_ip))

    finally:
        sock.close()


async def run_clients():
    loop = asyncio.get_event_loop()
    executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT)

    tasks = []
    for i in range(TOTAL_CLIENTS):
        tasks.append(loop.run_in_executor(executor, dhcp_client_logic, i))

    await asyncio.gather(*tasks)


def send_release(mac, xid, ip, server_ip):
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
        print(f"[RELEASE] {ip} to {server_ip} (MAC: {mac_str})")
        s.close()
    except Exception as e:
        print(f"[!] Failed to send release: {e}")


def handle_exit(signum, frame):
    global stop_requested
    stop_requested = True
    print("\n[*] Releasing leases...")

    for mac, xid, ip, srv in clients:
        send_release(mac, xid, ip, srv)

    print("\n📊 Final Stats:")
    print(f"  ✅ Successful leases: {stats['success']}")
    print(f"  ❌ Failed attempts:    {stats['failed']}")
    sys.exit(0)


def check_dhcp_server_health():
    """
    Check if DHCP server is available and ready to serve requests.
    Returns True if server is ready, False otherwise.
    """
    print(f"🔍 Checking if DHCP server is available at {DHCP_SERVER_IP}...")
    
    # Try to ping the DHCP server first
    try:
        result = os.system(f"ping -c 1 -W 1 {DHCP_SERVER_IP} > /dev/null 2>&1")
        if result != 0:
            print(f"⚠️ Warning: Cannot ping DHCP server at {DHCP_SERVER_IP}")
            # Continue anyway, as some containers might block ICMP
    except Exception as e:
        print(f"⚠️ Warning during ping: {e}")
    
    # Print network interface and routing info for debugging
    try:
        os.system("ip addr")
        os.system("ip route")
    except Exception:
        pass
        
    # Create a test socket for DHCP DISCOVER
    test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Skip the port 67 check - we're expecting server to be on another container
    
    # Send a single test DISCOVER and wait for OFFER
    try:
        test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        test_sock.bind(('', 68))
        test_sock.settimeout(5)
        
        test_mac = random_mac()
        test_xid = random.randint(0, 0xFFFFFFFF)
        
        print("📤 Sending test DHCPDISCOVER...")
        send_dhcp(test_sock, 1, test_mac, test_xid)
        
        offer, addr = wait_for_msg(test_sock, test_xid, 2)
        if offer:
            server_ip = addr[0]
            print(f"📥 Received DHCPOFFER from {server_ip} - Server is ready!")
            return True
        else:
            print("❌ No response to test DHCPDISCOVER")
            print("📤 Trying again with direct server address...")
            
            # Try sending directly to server IP as fallback
            packet = build_bootp(1, 0, test_mac, test_xid)
            options = b'\x35\x01\x01' + b'\x3d\x07\x01' + test_mac + b'\x37\x03\x03\x01\x06' + b'\xff'
            test_sock.sendto(packet + options, (DHCP_SERVER_IP, 67))
            
            offer, addr = wait_for_msg(test_sock, test_xid, 2)
            if offer:
                server_ip = addr[0]
                print(f"📥 Received DHCPOFFER from {server_ip} on direct try - Server is ready!")
                return True
            else:
                print("❌ No response to direct DHCPDISCOVER either")
                return False
    except Exception as e:
        print(f"❌ Error during health check: {e}")
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
        print(f"⏳ Waiting for DHCP server to be ready... (timeout in {int(HEALTH_CHECK_TIMEOUT - (time.time() - start_time))}s)")
        time.sleep(5)
    
    if not dhcp_ready:
        print("❌ DHCP server health check failed. Exiting.")
        sys.exit(1)
    
    print(f"🔧 Starting DHCP simulator with {TOTAL_CLIENTS} clients...")
    try:
        asyncio.run(run_clients())
    except KeyboardInterrupt:
        handle_exit(None, None)

    if not stop_requested:
        print(f"\n⏳ Holding leases for {LEASE_DURATION}s before release...")
        time.sleep(LEASE_DURATION)
        handle_exit(None, None)
