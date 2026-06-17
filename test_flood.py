import socket
import sys
import time

if len(sys.argv) < 2:
    print("Usage: python3 test_flood.py <TARGET_IP_OR_INTERFACE> [udp|tcp|udp6|arp]")
    sys.exit(1)

target = sys.argv[1]
proto = sys.argv[2] if len(sys.argv) > 2 else "udp"
proto = proto.lower()
port = 8000
data = b"X" * 1024

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
            # Sender MAC, Sender IP (10.10.0.99), Target MAC (00:00:00:00:00:00), Target IP (10.10.0.1)
            arp_body = b'\x00\x01\x08\x00\x06\x04\x00\x01' + \
                       b'\x00\x11\x22\x33\x44\x55' + socket.inet_aton("10.10.0.99") + \
                       b'\x00\x00\x00\x00\x00\x00' + socket.inet_aton("10.10.0.1")
            
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
