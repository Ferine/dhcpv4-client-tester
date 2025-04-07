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
INTERFACE = os.environ.get('DHCPV6_INTERFACE', 'en0' if sys.platform == 'darwin' else 'eth0')
# For macOS local testing, you need a local IPv6 address (adjust as needed based on your network)
if sys.platform == 'darwin':
    default_server = '::1'  # localhost IPv6 for testing on macOS
else:
    default_server = 'fe80::2'  # Default DHCPv6 server IP in Docker
DHCPV6_SERVER_IP = os.environ.get('DHCPV6_SERVER_IP', default_server)
HEALTH_CHECK_TIMEOUT = 30  # seconds to wait for DHCPv6 server to be ready
# =================

clients = []
stats = {"success": 0, "failed": 0}
stop_requested = False

# Check if running as root
if os.geteuid() != 0:
    print("\n❌ ERROR: This script requires root privileges to use raw sockets")
    print("Please run with sudo or as root\n")
    sys.exit(1)


def random_duid():
    """Generate a random DUID-LLT identifier"""
    # DUID-LLT (Link-layer + timestamp)
    duid_type = 1  # DUID-LLT
    hw_type = 1    # Ethernet

    # Current time (for LLT) - seconds since Jan 1, 2000 UTC
    current_time = int(time.time()) - 946684800
    
    # Random MAC address
    mac = bytes([
        0x02, 0x00,
        random.randint(0x00, 0x7f),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff)
    ])
    
    return struct.pack('!HHI', duid_type, hw_type, current_time) + mac


def create_dhcpv6_msg(msg_type, transaction_id, duid, prefix_hint=None, server_duid=None):
    """Create a DHCPv6 message with options"""
    
    # Message header: msg_type (1 byte) + transaction_id (3 bytes)
    header = bytes([msg_type]) + transaction_id
    
    # Start with empty options
    options = b''
    
    # Add Client Identifier option (code 1)
    options += struct.pack('!HH', 1, len(duid)) + duid
    
    # Add Server Identifier (code 2) if available
    if server_duid:
        options += struct.pack('!HH', 2, len(server_duid)) + server_duid
    
    # Add elapsed time option (code 8) - set to 0 for now
    options += struct.pack('!HHH', 8, 2, 0)
    
    # Add IA_PD (Prefix Delegation) option (code 25) if we're doing prefix delegation
    if prefix_hint and msg_type in (1, 3):  # SOLICIT or REQUEST
        # IA_PD has its own unique ID (random for this client)
        ia_id = random.randint(1, 0xFFFFFFFF)
        
        # T1 and T2 values: 0 means server will decide
        t1 = 0
        t2 = 0
        
        # IA_PD option header
        ia_pd = struct.pack('!III', ia_id, t1, t2)
        
        # For SOLICIT/REQUEST, add the IA_Prefix option (code 26) as sub-option with prefix hint
        if prefix_hint:
            # IA_Prefix option includes preferred/valid lifetimes, prefix length, and prefix
            preferred = 3600  # 1 hour  
            valid = 7200     # 2 hours
            prefix_len = 64  # Typically /64 for IPv6
            
            # Convert prefix hint to bytes if it's a string
            if isinstance(prefix_hint, str):
                # Convert prefix to bytes (only the network part)
                prefix_bytes = socket.inet_pton(socket.AF_INET6, prefix_hint.split('/')[0])
            else:
                prefix_bytes = prefix_hint
                
            # Create the IA_Prefix option
            ia_prefix = struct.pack('!HHBBI', 26, 25, preferred, valid, prefix_len) + prefix_bytes
            
            # Add as suboption to IA_PD
            ia_pd += ia_prefix
        
        # Add the complete IA_PD option with its length to the options list
        options += struct.pack('!HH', 25, len(ia_pd)) + ia_pd
    
    # Add Option Request option (code 6) to request info from server
    # Request DNS servers (23), domain search list (24)
    requested_options = struct.pack('!HHH', 6, 4, 23) + struct.pack('!H', 24)
    options += requested_options
    
    # Complete DHCPv6 message
    return header + options


def send_dhcpv6(sock, msg_type, duid, transaction_id, server_duid=None, prefix_hint=None):
    """Send a DHCPv6 message"""
    
    # Create the DHCPv6 message
    msg = create_dhcpv6_msg(msg_type, transaction_id, duid, prefix_hint, server_duid)
    
    if msg_type == 1:  # SOLICIT - sent to multicast
        dest = ('ff02::1:2', 547)  # All-DHCP-agents multicast address
    else:
        # For other messages, we'll send to the server unicast address
        dest = (DHCPV6_SERVER_IP, 547)
    
    sock.sendto(msg, dest)


def parse_dhcpv6_options(data, offset):
    """Parse DHCPv6 options from a response packet starting at the given offset"""
    options = {}
    while offset < len(data):
        if offset + 4 > len(data):
            break
            
        option_code = struct.unpack('!H', data[offset:offset+2])[0]
        option_len = struct.unpack('!H', data[offset+2:offset+4])[0]
        
        if offset + 4 + option_len > len(data):
            break
            
        option_data = data[offset+4:offset+4+option_len]
        options[option_code] = option_data
        
        offset += 4 + option_len
    
    return options


def extract_prefix_from_ia_pd(ia_pd_option):
    """Extract the delegated prefix from an IA_PD option"""
    if len(ia_pd_option) < 16:  # Minimum size for IA_PD with no sub-options
        return None
    
    # Skip IA_PD header (12 bytes: IAID, T1, T2)
    offset = 12
    
    while offset < len(ia_pd_option):
        if offset + 4 > len(ia_pd_option):
            break
            
        sub_option_code = struct.unpack('!H', ia_pd_option[offset:offset+2])[0]
        sub_option_len = struct.unpack('!H', ia_pd_option[offset+2:offset+4])[0]
        
        if offset + 4 + sub_option_len > len(ia_pd_option):
            break
            
        # Check if this is IA_Prefix option (code 26)
        if sub_option_code == 26 and sub_option_len >= 25:
            # Parse IA_Prefix: preferred lifetime (4), valid lifetime (4), prefix-len (1), prefix (16)
            prefix_len = ia_pd_option[offset+4+8]  # 8 bytes for lifetimes
            prefix_bytes = ia_pd_option[offset+4+9:offset+4+9+16]
            
            try:
                prefix_str = socket.inet_ntop(socket.AF_INET6, prefix_bytes)
                return f"{prefix_str}/{prefix_len}"
            except Exception:
                return None
                
        offset += 4 + sub_option_len
    
    return None


def wait_for_dhcpv6_response(sock, transaction_id, expected_type):
    """Wait and parse DHCPv6 response message"""
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            
            # Minimum length check for a valid DHCPv6 message with header
            if len(data) < 4:
                continue
                
            msg_type = data[0]
            msg_transaction_id = data[1:4]
            
            # Check if this is the response we're waiting for
            if msg_transaction_id != transaction_id or msg_type != expected_type:
                continue
                
            # Parse options
            options = parse_dhcpv6_options(data, 4)  # Start after the header
            
            return data, addr, options
            
        except socket.timeout:
            return None, None, None


def dhcpv6_client_logic(client_id):
    """Run a complete DHCPv6 client exchange"""
    global stats
    
    # Generate a random DUID and transaction ID
    duid = random_duid()
    transaction_id = bytes([
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
    ])
    
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    
    # For IPv6 we need to set IPV6_V6ONLY to 0 when binding to [::] to accept IPv4-mapped addresses
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    
    # Bind to DHCPv6 client port
    sock.bind(('::', 546))
    sock.settimeout(5)
    
    try:
        # Prefix hint based on a ULA (fd00::/8) prefix - actual server might ignore this
        prefix_hint = 'fd00:1234:5678::'  
        
        # Send SOLICIT message (msg_type 1)
        send_dhcpv6(sock, 1, duid, transaction_id, prefix_hint=prefix_hint)
        
        # Wait for ADVERTISE message (msg_type 2)
        advertise, addr, options = wait_for_dhcpv6_response(sock, transaction_id, 2)
        if not advertise:
            print(f"[Client {client_id}] ❌ No DHCPv6 ADVERTISE received")
            stats["failed"] += 1
            return
            
        # Extract server DUID from options
        if 2 not in options:
            print(f"[Client {client_id}] ❌ No server DUID in ADVERTISE")
            stats["failed"] += 1
            return
            
        server_duid = options[2]
        server_ip = addr[0]
        
        # Extract IA_PD option if present
        delegated_prefix = None
        if 25 in options:
            delegated_prefix = extract_prefix_from_ia_pd(options[25])
        
        # Send REQUEST message (msg_type 3)
        send_dhcpv6(sock, 3, duid, transaction_id, server_duid=server_duid, prefix_hint=prefix_hint)
        
        # Wait for REPLY message (msg_type 7)
        reply, _, reply_options = wait_for_dhcpv6_response(sock, transaction_id, 7)
        if not reply:
            print(f"[Client {client_id}] ❌ No DHCPv6 REPLY received")
            stats["failed"] += 1
            return
            
        # Extract final delegated prefix from REPLY
        if 25 in reply_options:
            delegated_prefix = extract_prefix_from_ia_pd(reply_options[25])
        
        print(f"[Client {client_id}] ✅ Got prefix {delegated_prefix} from {server_ip}")
        stats["success"] += 1
        
        # Add client info for later release
        clients.append((duid, transaction_id, server_duid, delegated_prefix, server_ip))
        
    finally:
        sock.close()


async def run_clients():
    """Run multiple DHCPv6 clients concurrently"""
    loop = asyncio.get_event_loop()
    executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT)
    
    tasks = []
    for i in range(TOTAL_CLIENTS):
        tasks.append(loop.run_in_executor(executor, dhcpv6_client_logic, i))
    
    await asyncio.gather(*tasks)


def send_release(duid, transaction_id, server_duid, prefix, server_ip):
    """Send a DHCPv6 RELEASE message to properly terminate a lease"""
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        sock.bind(('::', 546))
        
        # RELEASE is message type 8
        # We need to include both client DUID and server DUID
        msg = create_dhcpv6_msg(8, transaction_id, duid, server_duid=server_duid)
        
        # Send to server's address
        sock.sendto(msg, (server_ip, 547))
        print(f"[RELEASE] Prefix {prefix} to {server_ip}")
        sock.close()
    except Exception as e:
        print(f"[!] Failed to send DHCPv6 release: {e}")


def handle_exit(signum, frame):
    """Handle graceful exit by releasing leases"""
    global stop_requested
    stop_requested = True
    print("\n[*] Releasing DHCPv6 leases...")
    
    for duid, xid, server_duid, prefix, server_ip in clients:
        send_release(duid, xid, server_duid, prefix, server_ip)
    
    print("\n📊 Final Stats:")
    print(f"  ✅ Successful prefix delegations: {stats['success']}")
    print(f"  ❌ Failed attempts:              {stats['failed']}")
    sys.exit(0)


def check_dhcpv6_server_health():
    """
    Check if DHCPv6 server is available and ready to serve requests.
    Returns True if server is ready, False otherwise.
    """
    print(f"🔍 Checking if DHCPv6 server is available...")
    
    # Print network interface and routing info for debugging
    try:
        # Check for macOS vs Linux and use appropriate commands
        if sys.platform == 'darwin':
            os.system("ifconfig | grep inet6")
            os.system("netstat -rn -f inet6")
        else:
            os.system("ip -6 addr")
            os.system("ip -6 route")
    except Exception:
        pass
    
    # Create a test socket for DHCPv6 SOLICIT
    test_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    test_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    
    # Send a single test SOLICIT and wait for ADVERTISE
    try:
        test_sock.bind(('::', 546))
        test_sock.settimeout(5)
        
        test_duid = random_duid()
        test_xid = bytes([random.randint(0, 255) for _ in range(3)])
        
        print("📤 Sending test DHCPv6 SOLICIT...")
        send_dhcpv6(test_sock, 1, test_duid, test_xid)
        
        advertise, addr, options = wait_for_dhcpv6_response(test_sock, test_xid, 2)
        if advertise:
            server_ip = addr[0]
            print(f"📥 Received DHCPv6 ADVERTISE from {server_ip} - Server is ready!")
            return True
        else:
            print("❌ No response to test DHCPv6 SOLICIT")
            
            # Try sending directly to server IP as fallback
            print("📤 Trying again with direct server address...")
            
            prefix_hint = 'fd00:1234:5678::'  
            send_dhcpv6(test_sock, 1, test_duid, test_xid, prefix_hint=prefix_hint)
            
            advertise, addr, options = wait_for_dhcpv6_response(test_sock, test_xid, 2)
            if advertise:
                server_ip = addr[0]
                print(f"📥 Received DHCPv6 ADVERTISE from {server_ip} on direct try - Server is ready!")
                return True
            else:
                print("❌ No response to direct DHCPv6 SOLICIT either")
                return False
    except Exception as e:
        print(f"❌ Error during DHCPv6 health check: {e}")
        return False
    finally:
        test_sock.close()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)
    
    # Check if we're in debug mode (just test network interfaces)
    if len(sys.argv) > 1 and sys.argv[1] == "--debug":
        print("🔍 Running in debug mode - only checking network interfaces")
        print("\n== IPv6 Addresses ==")
        if sys.platform == 'darwin':
            os.system("ifconfig | grep inet6")
            print("\n== IPv6 Routes ==")
            os.system("netstat -rn -f inet6")
        else:
            os.system("ip -6 addr")
            print("\n== IPv6 Routes ==")
            os.system("ip -6 route")
        sys.exit(0)
    
    # Wait for DHCPv6 server to be ready
    start_time = time.time()
    dhcpv6_ready = False
    
    while time.time() - start_time < HEALTH_CHECK_TIMEOUT:
        if check_dhcpv6_server_health():
            dhcpv6_ready = True
            break
        print(f"⏳ Waiting for DHCPv6 server to be ready... (timeout in {int(HEALTH_CHECK_TIMEOUT - (time.time() - start_time))}s)")
        time.sleep(5)
    
    if not dhcpv6_ready:
        print("❌ DHCPv6 server health check failed. Exiting.")
        print("💡 For macOS systems, this script is designed to run inside Docker.")
        print("💡 Try running with --debug to check your network setup.")
        print("💡 Or use docker-compose to run the complete test environment.")
        sys.exit(1)
    
    print(f"🔧 Starting DHCPv6 simulator with {TOTAL_CLIENTS} clients...")
    try:
        asyncio.run(run_clients())
    except KeyboardInterrupt:
        handle_exit(None, None)
    
    if not stop_requested:
        print(f"\n⏳ Holding leases for {LEASE_DURATION}s before release...")
        time.sleep(LEASE_DURATION)
        handle_exit(None, None)