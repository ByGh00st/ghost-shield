#!/usr/bin/env python3
"""
Aegis / Hydra — Local Lab XDP Rate-Limit Self-Test Harness

SECURITY BOUNDARY (HARD-ENFORCED):
  - Strictly restricted to RFC 1918 private LANs, loopback (127.0.0.0/8, ::1),
    link-local (169.254.0.0/16, fe80::/10), RFC 4193 IPv6 ULA (fc00::/7), and
    IANA RFC 5737 / RFC 3849 documentation subnets.
  - Any public, global, multicast, broadcast, or unspecified target IP is
    unconditionally rejected before any socket is created.
  - Raw TCP SYN simulation uses exclusively non-routable RFC 5737 TEST-NET
    source addresses (zero external internet backscatter).
  - Execution is strictly bounded in duration (<= 30s), packet count, and
    probe payload size (32 bytes).
"""

import ipaddress
import os
import platform
import random
import socket
import struct
import sys
import time

# Hard safety ceilings — non-overridable beyond lab verification bounds
DEFAULT_DURATION_SEC: float = 10.0
HARD_MAX_DURATION_SEC: float = 30.0
HARD_MAX_PACKETS: int = 150_000
HARD_MAX_ARP_PACKETS: int = 5_000
PROBE_PORT: int = 8000
PROBE_PAYLOAD: bytes = b"AEGIS-XDP-LOCAL-SELF-TEST-PROBE\n"  # 32 bytes

# Authorized non-public laboratory networks
ALLOWED_V4_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback (RFC 1122)
    ipaddress.ip_network("10.0.0.0/8"),        # Private-Use (RFC 1918)
    ipaddress.ip_network("172.16.0.0/12"),     # Private-Use (RFC 1918)
    ipaddress.ip_network("192.168.0.0/16"),    # Private-Use (RFC 1918)
    ipaddress.ip_network("169.254.0.0/16"),    # Link-Local (RFC 3927)
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("198.18.0.0/15"),     # Benchmarking (RFC 2544)
)

ALLOWED_V6_NETWORKS = (
    ipaddress.ip_network("::1/128"),           # Loopback (RFC 4291)
    ipaddress.ip_network("fc00::/7"),          # Unique Local ULA (RFC 4193)
    ipaddress.ip_network("fe80::/10"),         # Link-Local (RFC 4291)
    ipaddress.ip_network("2001:db8::/32"),     # Documentation (RFC 3849)
)

# Non-routable RFC 5737 documentation prefixes for synthetic source simulation
RFC5737_PREFIXES = (
    (192, 0, 2),
    (198, 51, 100),
    (203, 0, 113),
)


def calc_checksum(msg: bytes) -> int:
    """Compute portable network-byte-order Internet Checksum (RFC 1071)."""
    if len(msg) % 2 != 0:
        msg += b"\x00"
    total = 0
    for i in range(0, len(msg), 2):
        word = (msg[i] << 8) | msg[i + 1]
        total += word
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def is_authorized_lab_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True ONLY if `ip_obj` belongs to an isolated non-public lab range."""
    if ip_obj.is_multicast or ip_obj.is_unspecified:
        return False
    if isinstance(ip_obj, ipaddress.IPv4Address):
        if ip_obj == ipaddress.IPv4Address("255.255.255.255"):
            return False
        return any(ip_obj in net for net in ALLOWED_V4_NETWORKS)
    return any(ip_obj in net for net in ALLOWED_V6_NETWORKS)


def resolve_and_validate_target(target: str, family: int) -> str:
    """
    Resolve `target` and verify that EVERY resolved address is strictly within
    authorized local/private lab networks. Aborts immediately on public/WAN IPs.
    """
    clean_target = target.split("%")[0]  # Strip IPv6 scope ID for validation if present
    try:
        literal_ip = ipaddress.ip_address(clean_target)
        if not is_authorized_lab_ip(literal_ip):
            raise PermissionError(
                f"[SECURITY BLOCK] Target '{target}' is a public/non-lab IP address. "
                "This self-test harness only permits RFC 1918 / loopback / lab subnets."
            )
        if family == socket.AF_INET and not isinstance(literal_ip, ipaddress.IPv4Address):
            raise ValueError(f"Expected IPv4 lab address, got IPv6 '{target}'.")
        if family == socket.AF_INET6 and not isinstance(literal_ip, ipaddress.IPv6Address):
            raise ValueError(f"Expected IPv6 lab address, got IPv4 '{target}'.")
        return target
    except ValueError as err:
        if "Expected IPv" in str(err):
            raise

    # Hostname resolution: validate ALL returned records so split-DNS / public hosts cannot pass
    infos = socket.getaddrinfo(target, PROBE_PORT, family)
    if not infos:
        raise ValueError(f"Unable to resolve target '{target}'.")

    selected_addr: str | None = None
    for info in infos:
        sockaddr_ip = info[4][0]
        parsed = ipaddress.ip_address(sockaddr_ip.split("%")[0])
        if not is_authorized_lab_ip(parsed):
            raise PermissionError(
                f"[SECURITY BLOCK] Host '{target}' resolved to public/non-lab address "
                f"'{sockaddr_ip}'. External targets are strictly prohibited."
            )
        if selected_addr is None:
            selected_addr = sockaddr_ip

    assert selected_addr is not None
    return selected_addr


def validate_local_interface(ifname: str) -> None:
    """Ensure `ifname` is an actual local network interface on Linux."""
    if not ifname or "/" in ifname or ".." in ifname:
        raise ValueError(f"Invalid network interface name '{ifname}'.")
    sysfs_path = f"/sys/class/net/{ifname}"
    if not os.path.exists(sysfs_path):
        raise ValueError(
            f"Local interface '{ifname}' not found under /sys/class/net. "
            "ARP self-test only operates on local interfaces (e.g., lo, veth0, eth0)."
        )


def random_rfc5737_source_ipv4() -> bytes:
    """Generate a non-routable RFC 5737 TEST-NET IPv4 source address."""
    a, b, c = random.choice(RFC5737_PREFIXES)
    d = random.randint(1, 254)
    return bytes((a, b, c, d))


def main() -> None:
    if len(sys.argv) < 2:
        print(
            "Usage: python3 test_flood.py <LAB_IP_OR_IFACE> [udp|tcp|udp6|arp] [duration_sec<=30]"
        )
        sys.exit(1)

    target = sys.argv[1]
    proto = sys.argv[2].lower() if len(sys.argv) > 2 else "udp"
    if proto not in ("udp", "udp6", "tcp", "arp"):
        print(f"[!] Unsupported mode '{proto}'. Choose from: udp, tcp, udp6, arp")
        sys.exit(1)

    if proto != "arp" and len(sys.argv) > 3:
        try:
            requested_dur = float(sys.argv[3])
        except ValueError:
            print(f"[!] Invalid duration '{sys.argv[3]}'.")
            sys.exit(1)
        duration_sec = min(max(requested_dur, 1.0), HARD_MAX_DURATION_SEC)
    else:
        duration_sec = DEFAULT_DURATION_SEC

    try:
        if proto in ("udp", "tcp"):
            resolved_target = resolve_and_validate_target(target, socket.AF_INET)
        elif proto == "udp6":
            resolved_target = resolve_and_validate_target(target, socket.AF_INET6)
        else:
            if platform.system().lower() != "linux":
                print("[!] Raw ARP self-test via AF_PACKET is only supported on Linux.")
                sys.exit(1)
            validate_local_interface(target)
            resolved_target = target
    except (PermissionError, ValueError, socket.gaierror) as exc:
        print(f"{exc}", file=sys.stderr)
        sys.exit(2)

    pkt_cap = HARD_MAX_ARP_PACKETS if proto == "arp" else HARD_MAX_PACKETS
    print(
        f"[+] Authorized Lab Self-Test | Target: {resolved_target} | Mode: {proto.upper()} | "
        f"Max Window: {duration_sec:.0f}s | Packet Cap: {pkt_cap}"
    )

    count = 0
    start = time.monotonic()
    deadline = start + duration_sec

    try:
        if proto == "udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                while count < pkt_cap and time.monotonic() < deadline:
                    sock.sendto(PROBE_PAYLOAD, (resolved_target, PROBE_PORT))
                    count += 1
                    if count % 10000 == 0:
                        elapsed = max(time.monotonic() - start, 1e-6)
                        print(f"[>] Lab UDPv4 Probe PPS: {count / elapsed:.2f} | Sent: {count}/{pkt_cap}")

        elif proto == "udp6":
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
                while count < pkt_cap and time.monotonic() < deadline:
                    sock.sendto(PROBE_PAYLOAD, (resolved_target, PROBE_PORT))
                    count += 1
                    if count % 10000 == 0:
                        elapsed = max(time.monotonic() - start, 1e-6)
                        print(f"[>] Lab UDPv6 Probe PPS: {count / elapsed:.2f} | Sent: {count}/{pkt_cap}")

        elif proto == "tcp":
            is_raw_supported = False
            if platform.system().lower() == "linux":
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW):
                        is_raw_supported = True
                except PermissionError:
                    print("[!] Root privileges required for Raw SYN self-test. Using local TCP connect probe...")
                except OSError as exc:
                    print(f"[!] Raw socket unavailable ({exc}). Using local TCP connect probe...")
            else:
                print("[!] Raw SYN self-test requires Linux. Using local TCP connect probe...")

            if is_raw_supported:
                print(
                    f"[+] Sending RFC 5737 TEST-NET synthetic SYN probes to {resolved_target}:{PROBE_PORT}..."
                )
                ip_daddr = socket.inet_aton(resolved_target)
                with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as raw_sock:
                    raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                    while count < pkt_cap and time.monotonic() < deadline:
                        src_octets = random_rfc5737_source_ipv4()
                        src_port = random.randint(32768, 60999)

                        ip_ihl_ver = (4 << 4) | 5
                        ip_tot_len = 40
                        ip_id = random.randint(10000, 65535)
                        ip_ttl = 1  # TTL=1 ensures frames cannot traverse beyond immediate lab hop
                        ip_proto = socket.IPPROTO_TCP

                        ip_hdr_zero = struct.pack(
                            "!BBHHHBBH4s4s",
                            ip_ihl_ver,
                            0,
                            ip_tot_len,
                            ip_id,
                            0,
                            ip_ttl,
                            ip_proto,
                            0,
                            src_octets,
                            ip_daddr,
                        )
                        ip_check = calc_checksum(ip_hdr_zero)
                        ip_header = struct.pack(
                            "!BBHHHBBH4s4s",
                            ip_ihl_ver,
                            0,
                            ip_tot_len,
                            ip_id,
                            0,
                            ip_ttl,
                            ip_proto,
                            ip_check,
                            src_octets,
                            ip_daddr,
                        )

                        tcp_seq = random.randint(0, 0xFFFFFFFF)
                        tcp_offset_res = 5 << 4
                        tcp_flags = 0x02  # SYN
                        tcp_window = 64240

                        tcp_hdr_zero = struct.pack(
                            "!HHLLBBHHH",
                            src_port,
                            PROBE_PORT,
                            tcp_seq,
                            0,
                            tcp_offset_res,
                            tcp_flags,
                            tcp_window,
                            0,
                            0,
                        )
                        pseudo_hdr = struct.pack(
                            "!4s4sBBH",
                            src_octets,
                            ip_daddr,
                            0,
                            ip_proto,
                            len(tcp_hdr_zero),
                        )
                        tcp_check = calc_checksum(pseudo_hdr + tcp_hdr_zero)
                        tcp_header = struct.pack(
                            "!HHLLBBHHH",
                            src_port,
                            PROBE_PORT,
                            tcp_seq,
                            0,
                            tcp_offset_res,
                            tcp_flags,
                            tcp_window,
                            tcp_check,
                            0,
                        )

                        try:
                            raw_sock.sendto(ip_header + tcp_header, (resolved_target, 0))
                            count += 1
                            if count % 10000 == 0:
                                elapsed = max(time.monotonic() - start, 1e-6)
                                print(
                                    f"[>] Lab SYN Probe PPS: {count / elapsed:.2f} | Sent: {count}/{pkt_cap}"
                                )
                        except OSError:
                            pass
            else:
                conn_cap = min(pkt_cap, 2_000)
                while count < conn_cap and time.monotonic() < deadline:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(0.05)
                        try:
                            sock.connect((resolved_target, PROBE_PORT))
                            sock.sendall(PROBE_PAYLOAD)
                        except OSError:
                            pass
                    count += 1
                    if count % 100 == 0:
                        elapsed = max(time.monotonic() - start, 1e-6)
                        print(f"[>] Lab TCP Connect Probes: {count}/{conn_cap} | PPS: {count / elapsed:.2f}")

        elif proto == "arp":
            sender_ip_str = sys.argv[3] if len(sys.argv) > 3 else "198.51.100.99"
            target_ip_str = sys.argv[4] if len(sys.argv) > 4 else "198.51.100.1"
            try:
                sender_ip = resolve_and_validate_target(sender_ip_str, socket.AF_INET)
                target_ip = resolve_and_validate_target(target_ip_str, socket.AF_INET)
            except (PermissionError, ValueError) as exc:
                print(f"{exc}", file=sys.stderr)
                sys.exit(2)

            print(
                f"[+] Running bounded ARP Guard self-test on '{resolved_target}' "
                f"(Sender: {sender_ip} -> Target: {target_ip})..."
            )
            try:
                with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sock:
                    sock.bind((resolved_target, 0))
                    eth_hdr = b"\xff\xff\xff\xff\xff\xff\x02\x11\x22\x33\x44\x55\x08\x06"
                    arp_body = (
                        b"\x00\x01\x08\x00\x06\x04\x00\x01"
                        + b"\x02\x11\x22\x33\x44\x55"
                        + socket.inet_aton(sender_ip)
                        + b"\x00\x00\x00\x00\x00\x00"
                        + socket.inet_aton(target_ip)
                    )
                    packet = eth_hdr + arp_body
                    while count < pkt_cap and time.monotonic() < deadline:
                        sock.send(packet)
                        count += 1
                        if count % 1000 == 0:
                            elapsed = max(time.monotonic() - start, 1e-6)
                            print(f"[>] Lab ARP Probe: {count}/{pkt_cap} | PPS: {count / elapsed:.2f}")
            except PermissionError:
                print("[!] Permission Denied. AF_PACKET ARP self-test requires root privileges.")
                sys.exit(1)

        elapsed = max(time.monotonic() - start, 1e-6)
        print(f"[+] Self-test finished cleanly: {count} probes transmitted in {elapsed:.2f}s.")

    except KeyboardInterrupt:
        print("\n[!] Self-test interrupted by operator.")


if __name__ == "__main__":
    main()
