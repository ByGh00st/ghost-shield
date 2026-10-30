#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::{lpm_trie::Key, Array, LpmTrie, LruHashMap, PerCpuArray, RingBuf},
    programs::XdpContext,
};
use aegis_common::{
    evaluate_gcra_raw, GcraState, GcraVerdict, GlobalConfig, GlobalStats, MitigationEvent,
    ACTION_BAN, ACTION_DROP, DEFAULT_BURST_NS, EVENT_VER_ARP, EVENT_VER_IPV4, EVENT_VER_IPV6,
    EVENT_VER_L2, PROTO_ARP, PROTO_L2_RAW, SYN_BURST_NS,
};

#[no_mangle]
#[link_section = ".nyx_apex"]
pub static NYX_APEX: [u8; 7] = *b"ByGhost";

// ============================================================================
// Wire-Format Protocol Headers (`packed`, align = 1, read via `read_unaligned`)
// ============================================================================

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct EthHdr {
    pub h_dest: [u8; 6],
    pub h_source: [u8; 6],
    pub h_proto: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct VlanHdr {
    pub tci: u16,
    pub encap_proto: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct ArpHdr {
    pub ar_hrd: u16,
    pub ar_pro: u16,
    pub ar_hln: u8,
    pub ar_pln: u8,
    pub ar_op: u16,
    pub ar_sha: [u8; 6],
    pub ar_sip: [u8; 4],
    pub ar_tha: [u8; 6],
    pub ar_tip: [u8; 4],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ipv4Hdr {
    pub ver_ihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub check: u16,
    pub saddr: u32,
    pub daddr: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ipv6Hdr {
    pub version_class_flow: [u8; 4],
    pub payload_len: u16,
    pub nexthdr: u8,
    pub hop_limit: u8,
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TcpHdr {
    pub source: u16,
    pub dest: u16,
    pub seq: u32,
    pub ack_seq: u32,
    pub doff_res: u8,
    pub flags: u8,
    pub window: u16,
    pub check: u16,
    pub urg_ptr: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct UdpHdr {
    pub source: u16,
    pub dest: u16,
    pub len: u16,
    pub check: u16,
}

// ============================================================================
// Kernel eBPF Maps
// ============================================================================

#[map]
static VIP_LIST: LpmTrie<[u8; 4], u32> = LpmTrie::with_max_entries(1024, 0);

#[map]
static VIP_LIST_V6: LpmTrie<[u8; 16], u32> = LpmTrie::with_max_entries(1024, 0);

#[map]
static VIP_LIST_MAC: LruHashMap<[u8; 6], u32> = LruHashMap::with_max_entries(512, 0);

#[map]
static G_CONFIG: Array<GlobalConfig> = Array::with_max_entries(1, 0);

#[map]
static G_STATS: PerCpuArray<GlobalStats> = PerCpuArray::with_max_entries(1, 0);

#[map]
static BLACKLIST: LruHashMap<u32, u64> = LruHashMap::with_max_entries(262_144, 0);

#[map]
static BLACKLIST_V6: LruHashMap<[u8; 16], u64> = LruHashMap::with_max_entries(262_144, 0);

#[map]
static BLACKLIST_MAC: LruHashMap<[u8; 6], u64> = LruHashMap::with_max_entries(65_536, 0);

#[map]
static TRAFFIC: LruHashMap<u32, GcraState> = LruHashMap::with_max_entries(262_144, 0);

#[map]
static TRAFFIC_V6: LruHashMap<[u8; 16], GcraState> = LruHashMap::with_max_entries(262_144, 0);

#[map]
static TRAFFIC_MAC: LruHashMap<[u8; 6], GcraState> = LruHashMap::with_max_entries(65_536, 0);

#[map]
static TRAFFIC_ARP: LruHashMap<[u8; 6], GcraState> = LruHashMap::with_max_entries(4096, 0);

/// Shared lockless MPSC kernel ring buffer (256 KiB, Linux 5.8+).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(262_144, 0);

// ============================================================================
// Zero-UB Raw Pointer Telemetry Helpers
// ============================================================================

#[inline(always)]
fn stat_inc_pkt() {
    if let Some(g) = G_STATS.get_ptr_mut(0) {
        unsafe {
            let p = &raw mut (*g).pkt_count;
            p.write_volatile(p.read_volatile().wrapping_add(1));
        }
    }
}

#[inline(always)]
fn stat_inc_ipv4() {
    if let Some(g) = G_STATS.get_ptr_mut(0) {
        unsafe {
            let p = &raw mut (*g).ipv4_count;
            p.write_volatile(p.read_volatile().wrapping_add(1));
        }
    }
}

#[inline(always)]
fn stat_inc_ipv6() {
    if let Some(g) = G_STATS.get_ptr_mut(0) {
        unsafe {
            let p = &raw mut (*g).ipv6_count;
            p.write_volatile(p.read_volatile().wrapping_add(1));
        }
    }
}

#[inline(always)]
fn stat_inc_arp() {
    if let Some(g) = G_STATS.get_ptr_mut(0) {
        unsafe {
            let p = &raw mut (*g).arp_count;
            p.write_volatile(p.read_volatile().wrapping_add(1));
        }
    }
}

#[inline(always)]
fn drop_and_count() -> u32 {
    if let Some(g) = G_STATS.get_ptr_mut(0) {
        unsafe {
            let p = &raw mut (*g).drop_count;
            p.write_volatile(p.read_volatile().wrapping_add(1));
        }
    }
    xdp_action::XDP_DROP
}

#[inline(always)]
fn drop_malformed() -> u32 {
    if let Some(g) = G_STATS.get_ptr_mut(0) {
        unsafe {
            let d = &raw mut (*g).drop_count;
            d.write_volatile(d.read_volatile().wrapping_add(1));
            let m = &raw mut (*g).malformed_count;
            m.write_volatile(m.read_volatile().wrapping_add(1));
        }
    }
    xdp_action::XDP_DROP
}

#[inline(always)]
fn emit_event(
    src_ip: [u8; 16],
    src_mac: [u8; 6],
    dest_port: u16,
    vlan_id: u16,
    protocol: u8,
    action: u8,
    ip_version: u8,
) {
    if let Some(mut entry) = EVENTS.reserve::<MitigationEvent>(0) {
        entry.write(MitigationEvent {
            src_ip,
            src_mac,
            dest_port,
            vlan_id,
            protocol,
            action,
            ip_version,
            _pad: [0u8; 3],
        });
        entry.submit(0);
    }
}

// ============================================================================
// Ring 0 XDP Entry Point
// ============================================================================

#[xdp]
#[allow(clippy::manual_range_contains)]
pub fn apex_shield(ctx: XdpContext) -> u32 {
    let s = ctx.data();
    let e = ctx.data_end();
    let now = unsafe { bpf_ktime_get_ns() };

    stat_inc_pkt();

    // 1. Validate L2 Ethernet Frame Header (reject runt frames instead of XDP_PASS)
    if s + core::mem::size_of::<EthHdr>() > e {
        return drop_malformed();
    }
    let eth = unsafe { (s as *const EthHdr).read_unaligned() };
    let src_mac = eth.h_source;

    // Reject IEEE 802.3 invalid source MACs (all-zero or I/G multicast/broadcast bit set in source)
    if src_mac == [0u8; 6] || (src_mac[0] & 0x01) != 0 {
        return drop_malformed();
    }

    // 1b. Unwrap up to 2 IEEE 802.1Q / 802.1ad (QinQ) VLAN headers to defeat VLAN 0 / trunk bypass
    let mut l3_offset: usize = core::mem::size_of::<EthHdr>();
    let mut proto = u16::from_be(eth.h_proto);
    let mut vlan_id: u16 = 0;

    for _ in 0..2 {
        if proto == 0x8100 || proto == 0x88A8 || proto == 0x9100 {
            if s + l3_offset + core::mem::size_of::<VlanHdr>() > e {
                return drop_malformed();
            }
            let vh = unsafe { ((s + l3_offset) as *const VlanHdr).read_unaligned() };
            vlan_id = u16::from_be(vh.tci) & 0x0FFF;
            proto = u16::from_be(vh.encap_proto);
            l3_offset += core::mem::size_of::<VlanHdr>();
        } else {
            break;
        }
    }
    // Drop 3+ nested VLAN evasion attempts
    if proto == 0x8100 || proto == 0x88A8 || proto == 0x9100 {
        return drop_malformed();
    }

    // 2. Load Precomputed Dynamic Configuration (zero division in Ring 0)
    let (
        ip_interval_ns,
        ban_duration_ns,
        arp_interval_ns,
        mac_interval_ns,
        strike_threshold,
        spoof_protection,
    ) = if let Some(c) = G_CONFIG.get(0) {
        let ip_int = if c.alert_mode == 1 {
            c.panic_interval_ns
        } else {
            c.normal_interval_ns
        };
        (
            ip_int,
            c.ban_duration_ns,
            c.arp_interval_ns,
            c.mac_interval_ns,
            c.ban_strike_threshold,
            c.spoof_protection,
        )
    } else {
        // Safe deterministic defaults: 2000 PPS IP (500us), 300s ban, 50 PPS ARP (20ms), 6000 PPS MAC (166.6us)
        (500_000, 300_000_000_000, 20_000_000, 166_666, 32, 1)
    };

    // 3. Check VIP MAC Bypass (Gateway / Core Routers)
    let is_vip_mac = unsafe { VIP_LIST_MAC.get(&src_mac).is_some() };

    // Also allow ARP packets originating from a VIP IPv4 address (live VRRP/HSRP failover safety)
    let mut is_vip_arp_sender = false;
    if proto == 0x0806 && s + l3_offset + core::mem::size_of::<ArpHdr>() <= e {
        let arp_peek = unsafe { ((s + l3_offset) as *const ArpHdr).read_unaligned() };
        let arp_key = Key::new(32, arp_peek.ar_sip);
        if VIP_LIST.get(&arp_key).is_some() {
            is_vip_arp_sender = true;
        }
    }

    // 4. L2 Source MAC Blacklist & GCRA Rate Limiting
    if !is_vip_mac && !is_vip_arp_sender {
        if let Some(ban_ts) = unsafe { BLACKLIST_MAC.get(&src_mac) } {
            if now < *ban_ts {
                return drop_and_count();
            }
        }

        if let Some(st) = TRAFFIC_MAC.get_ptr_mut(&src_mac) {
            match unsafe {
                evaluate_gcra_raw(
                    st,
                    now,
                    mac_interval_ns,
                    DEFAULT_BURST_NS,
                    strike_threshold,
                    false,
                )
            } {
                GcraVerdict::Pass => {}
                GcraVerdict::DropOnly { emit_alert } => {
                    if emit_alert {
                        emit_event(
                            [0u8; 16],
                            src_mac,
                            0,
                            vlan_id,
                            PROTO_L2_RAW,
                            ACTION_DROP,
                            EVENT_VER_L2,
                        );
                    }
                    return drop_and_count();
                }
                GcraVerdict::BanAndDrop => {
                    let ban_expiry = now.saturating_add(ban_duration_ns);
                    let _ = BLACKLIST_MAC.insert(&src_mac, &ban_expiry, 0);
                    emit_event(
                        [0u8; 16],
                        src_mac,
                        0,
                        vlan_id,
                        PROTO_L2_RAW,
                        ACTION_BAN,
                        EVENT_VER_L2,
                    );
                    return drop_and_count();
                }
            }
        } else {
            let init = GcraState {
                tat_ns: now.saturating_add(mac_interval_ns),
                last_violation_ns: 0,
                strikes: 0,
                _pad: 0,
            };
            let _ = TRAFFIC_MAC.insert(&src_mac, &init, 0);
        }
    }

    // 5. L3 / L4 Protocol Inspection & Rate Limiting
    if proto == 0x0800 {
        // ============================ IPv4 ============================
        stat_inc_ipv4();

        if s + l3_offset + core::mem::size_of::<Ipv4Hdr>() > e {
            return drop_malformed();
        }
        let ip = unsafe { ((s + l3_offset) as *const Ipv4Hdr).read_unaligned() };
        let version = ip.ver_ihl >> 4;
        let ihl = ((ip.ver_ihl & 0x0F) as usize) * 4;
        if version != 4 || ihl < 20 || ihl > 60 || s + l3_offset + ihl > e {
            return drop_malformed();
        }

        let protocol = ip.protocol;
        let src_be = ip.saddr;
        let src_octets = src_be.to_ne_bytes();
        let src_ip = u32::from_be(src_be);

        // VIP CIDR Bypass (O(prefix) LPM Trie)
        let key = Key::new(32, src_octets);
        if VIP_LIST.get(&key).is_some() {
            return xdp_action::XDP_PASS;
        }

        // Active IPv4 Blacklist Check
        if let Some(ban_ts) = unsafe { BLACKLIST.get(&src_ip) } {
            if now < *ban_ts {
                return drop_and_count();
            }
        }

        // Fragment-aware L4 Header Parsing
        let frag_field = u16::from_be(ip.frag_off);
        let is_non_first_frag = (frag_field & 0x1FFF) != 0;
        let mut dest_port: u16 = 0;
        let mut is_unverified_syn = false;

        if !is_non_first_frag {
            let l4_offset = l3_offset + ihl;
            if protocol == 6 {
                if s + l4_offset + core::mem::size_of::<TcpHdr>() > e {
                    return drop_malformed();
                }
                let tcp = unsafe { ((s + l4_offset) as *const TcpHdr).read_unaligned() };
                dest_port = u16::from_be(tcp.dest);
                // SYN == 1 (0x02) and ACK == 0 (0x10)
                is_unverified_syn = (tcp.flags & 0x12) == 0x02;
            } else if protocol == 17 {
                if s + l4_offset + core::mem::size_of::<UdpHdr>() > e {
                    return drop_malformed();
                }
                let udp = unsafe { ((s + l4_offset) as *const UdpHdr).read_unaligned() };
                dest_port = u16::from_be(udp.dest);
            }
        }

        // Unverified TCP SYNs get stricter rate interval and stateless DROP (prevents spoofed-IP self-DoS)
        let eff_interval = if is_unverified_syn {
            ip_interval_ns.saturating_mul(2)
        } else {
            ip_interval_ns
        };
        let eff_burst = if is_unverified_syn {
            SYN_BURST_NS
        } else {
            DEFAULT_BURST_NS
        };
        let stateless_syn_guard = spoof_protection != 0 && is_unverified_syn;

        if let Some(st) = TRAFFIC.get_ptr_mut(&src_ip) {
            match unsafe {
                evaluate_gcra_raw(
                    st,
                    now,
                    eff_interval,
                    eff_burst,
                    strike_threshold,
                    stateless_syn_guard,
                )
            } {
                GcraVerdict::Pass => {}
                GcraVerdict::DropOnly { emit_alert } => {
                    if emit_alert {
                        let mut event_ip = [0u8; 16];
                        event_ip[0..4].copy_from_slice(&src_octets);
                        emit_event(
                            event_ip,
                            src_mac,
                            dest_port,
                            vlan_id,
                            protocol,
                            ACTION_DROP,
                            EVENT_VER_IPV4,
                        );
                    }
                    return drop_and_count();
                }
                GcraVerdict::BanAndDrop => {
                    let ban_expiry = now.saturating_add(ban_duration_ns);
                    let _ = BLACKLIST.insert(&src_ip, &ban_expiry, 0);
                    let mut event_ip = [0u8; 16];
                    event_ip[0..4].copy_from_slice(&src_octets);
                    emit_event(
                        event_ip,
                        src_mac,
                        dest_port,
                        vlan_id,
                        protocol,
                        ACTION_BAN,
                        EVENT_VER_IPV4,
                    );
                    return drop_and_count();
                }
            }
        } else {
            let init = GcraState {
                tat_ns: now.saturating_add(eff_interval),
                last_violation_ns: 0,
                strikes: 0,
                _pad: 0,
            };
            let _ = TRAFFIC.insert(&src_ip, &init, 0);
        }
    } else if proto == 0x86DD {
        // ============================ IPv6 ============================
        stat_inc_ipv6();

        if s + l3_offset + core::mem::size_of::<Ipv6Hdr>() > e {
            return drop_malformed();
        }
        let ip6 = unsafe { ((s + l3_offset) as *const Ipv6Hdr).read_unaligned() };
        if (ip6.version_class_flow[0] >> 4) != 6 {
            return drop_malformed();
        }
        let src_ip6 = ip6.saddr;

        // Walk up to 6 IPv6 Extension Headers (Hop-by-Hop, Routing, Fragment, AH, DestOpts, Mobility)
        let mut protocol = ip6.nexthdr;
        let mut next_hdr_offset = l3_offset + core::mem::size_of::<Ipv6Hdr>();
        let mut is_non_first_frag = false;

        for _ in 0..6 {
            match protocol {
                // Hop-by-Hop (0), Routing (43), Destination Options (60), Mobility (135)
                0 | 43 | 60 | 135 => {
                    if s + next_hdr_offset + 2 > e {
                        return drop_malformed();
                    }
                    let next_proto = unsafe { *((s + next_hdr_offset) as *const u8) };
                    let hdr_len = unsafe { *((s + next_hdr_offset + 1) as *const u8) };
                    if hdr_len > 32 {
                        break;
                    }
                    let ext_bytes = ((hdr_len as usize) + 1) * 8;
                    if s + next_hdr_offset + ext_bytes > e {
                        return drop_malformed();
                    }
                    protocol = next_proto;
                    next_hdr_offset += ext_bytes;
                }
                // Fragment Header (44): fixed 8 bytes; check fragment offset bits [15:3]
                44 => {
                    if s + next_hdr_offset + 8 > e {
                        return drop_malformed();
                    }
                    let next_proto = unsafe { *((s + next_hdr_offset) as *const u8) };
                    let frag_off_m = u16::from_be(unsafe {
                        ((s + next_hdr_offset + 2) as *const u16).read_unaligned()
                    });
                    if (frag_off_m & 0xFFF8) != 0 {
                        is_non_first_frag = true;
                    }
                    protocol = next_proto;
                    next_hdr_offset += 8;
                }
                // Authentication Header (51, RFC 4302): length in 4-octet units minus 2
                51 => {
                    if s + next_hdr_offset + 2 > e {
                        return drop_malformed();
                    }
                    let next_proto = unsafe { *((s + next_hdr_offset) as *const u8) };
                    let hdr_len = unsafe { *((s + next_hdr_offset + 1) as *const u8) };
                    if hdr_len > 64 {
                        break;
                    }
                    let ah_bytes = ((hdr_len as usize) + 2) * 4;
                    if s + next_hdr_offset + ah_bytes > e {
                        return drop_malformed();
                    }
                    protocol = next_proto;
                    next_hdr_offset += ah_bytes;
                }
                _ => break,
            }
        }

        // VIP IPv6 CIDR Bypass
        let key = Key::new(128, src_ip6);
        if VIP_LIST_V6.get(&key).is_some() {
            return xdp_action::XDP_PASS;
        }

        // Active IPv6 Blacklist Check
        if let Some(ban_ts) = unsafe { BLACKLIST_V6.get(&src_ip6) } {
            if now < *ban_ts {
                return drop_and_count();
            }
        }

        // Fragment-aware L4 Header Parsing
        let mut dest_port: u16 = 0;
        let mut is_unverified_syn = false;

        if !is_non_first_frag {
            if protocol == 6 {
                if s + next_hdr_offset + core::mem::size_of::<TcpHdr>() > e {
                    return drop_malformed();
                }
                let tcp = unsafe { ((s + next_hdr_offset) as *const TcpHdr).read_unaligned() };
                dest_port = u16::from_be(tcp.dest);
                is_unverified_syn = (tcp.flags & 0x12) == 0x02;
            } else if protocol == 17 {
                if s + next_hdr_offset + core::mem::size_of::<UdpHdr>() > e {
                    return drop_malformed();
                }
                let udp = unsafe { ((s + next_hdr_offset) as *const UdpHdr).read_unaligned() };
                dest_port = u16::from_be(udp.dest);
            }
        }

        let eff_interval = if is_unverified_syn {
            ip_interval_ns.saturating_mul(2)
        } else {
            ip_interval_ns
        };
        let eff_burst = if is_unverified_syn {
            SYN_BURST_NS
        } else {
            DEFAULT_BURST_NS
        };
        let stateless_syn_guard = spoof_protection != 0 && is_unverified_syn;

        if let Some(st) = TRAFFIC_V6.get_ptr_mut(&src_ip6) {
            match unsafe {
                evaluate_gcra_raw(
                    st,
                    now,
                    eff_interval,
                    eff_burst,
                    strike_threshold,
                    stateless_syn_guard,
                )
            } {
                GcraVerdict::Pass => {}
                GcraVerdict::DropOnly { emit_alert } => {
                    if emit_alert {
                        emit_event(
                            src_ip6,
                            src_mac,
                            dest_port,
                            vlan_id,
                            protocol,
                            ACTION_DROP,
                            EVENT_VER_IPV6,
                        );
                    }
                    return drop_and_count();
                }
                GcraVerdict::BanAndDrop => {
                    let ban_expiry = now.saturating_add(ban_duration_ns);
                    let _ = BLACKLIST_V6.insert(&src_ip6, &ban_expiry, 0);
                    emit_event(
                        src_ip6,
                        src_mac,
                        dest_port,
                        vlan_id,
                        protocol,
                        ACTION_BAN,
                        EVENT_VER_IPV6,
                    );
                    return drop_and_count();
                }
            }
        } else {
            let init = GcraState {
                tat_ns: now.saturating_add(eff_interval),
                last_violation_ns: 0,
                strikes: 0,
                _pad: 0,
            };
            let _ = TRAFFIC_V6.insert(&src_ip6, &init, 0);
        }
    } else if proto == 0x0806 {
        // ============================ ARP ============================
        stat_inc_arp();

        if s + l3_offset + core::mem::size_of::<ArpHdr>() > e {
            return drop_malformed();
        }
        let arp = unsafe { ((s + l3_offset) as *const ArpHdr).read_unaligned() };
        if arp.ar_hln != 6 || arp.ar_pln != 4 {
            return drop_malformed();
        }
        let sender_ip = arp.ar_sip;

        if !is_vip_mac && !is_vip_arp_sender {
            if let Some(st) = TRAFFIC_ARP.get_ptr_mut(&src_mac) {
                match unsafe {
                    evaluate_gcra_raw(
                        st,
                        now,
                        arp_interval_ns,
                        DEFAULT_BURST_NS,
                        strike_threshold,
                        false,
                    )
                } {
                    GcraVerdict::Pass => {}
                    GcraVerdict::DropOnly { emit_alert } => {
                        if emit_alert {
                            let mut event_ip = [0u8; 16];
                            event_ip[0..4].copy_from_slice(&sender_ip);
                            emit_event(
                                event_ip,
                                src_mac,
                                0,
                                vlan_id,
                                PROTO_ARP,
                                ACTION_DROP,
                                EVENT_VER_ARP,
                            );
                        }
                        return drop_and_count();
                    }
                    GcraVerdict::BanAndDrop => {
                        let ban_expiry = now.saturating_add(ban_duration_ns);
                        let _ = BLACKLIST_MAC.insert(&src_mac, &ban_expiry, 0);
                        let mut event_ip = [0u8; 16];
                        event_ip[0..4].copy_from_slice(&sender_ip);
                        emit_event(
                            event_ip,
                            src_mac,
                            0,
                            vlan_id,
                            PROTO_ARP,
                            ACTION_BAN,
                            EVENT_VER_ARP,
                        );
                        return drop_and_count();
                    }
                }
            } else {
                let init = GcraState {
                    tat_ns: now.saturating_add(arp_interval_ns),
                    last_violation_ns: 0,
                    strikes: 0,
                    _pad: 0,
                };
                let _ = TRAFFIC_ARP.insert(&src_mac, &init, 0);
            }
        }
    }

    xdp_action::XDP_PASS
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
