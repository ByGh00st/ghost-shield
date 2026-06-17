#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{LruHashMap, LpmTrie, PerCpuArray, Array, PerfEventArray},
    programs::XdpContext,
    helpers::bpf_ktime_get_ns,
};
use aegis_common::{IPStats, GlobalStats, GlobalConfig, MitigationEvent};

#[no_mangle]
#[link_section = ".nyx_apex"]
pub static NYX_APEX: [u8; 7] = *b"ByGhost";

#[repr(C, packed)]
pub struct ethhdr {
    pub h_dest: [u8; 6],
    pub h_source: [u8; 6],
    pub h_proto: u16,
}

#[repr(C, packed)]
pub struct arphdr {
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

#[repr(C)]
pub struct iphdr {
    pub _bitfield_1: u8,
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
pub struct ipv6hdr {
    pub version_class_flow: [u8; 4],
    pub payload_len: u16,
    pub nexthdr: u8,
    pub hop_limit: u8,
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
}

#[repr(C)]
pub struct tcphdr {
    pub source: u16,
    pub dest: u16,
    pub seq: u32,
    pub ack_seq: u32,
    pub _bitfield_1: u16,
    pub window: u16,
    pub check: u16,
    pub urg_ptr: u16,
}

#[repr(C)]
pub struct udphdr {
    pub source: u16,
    pub dest: u16,
    pub len: u16,
    pub check: u16,
}

// VIP Bypasses (LPM Trie / LRU Maps)
#[map]
static VIP_LIST: LpmTrie<[u8; 4], u32> = LpmTrie::with_max_entries(1024, 0);

#[map]
static VIP_LIST_V6: LpmTrie<[u8; 16], u32> = LpmTrie::with_max_entries(1024, 0);

#[map]
static VIP_LIST_MAC: LruHashMap<[u8; 6], u32> = LruHashMap::with_max_entries(256, 0);

// Global State
#[map]
static G_CONFIG: Array<GlobalConfig> = Array::with_max_entries(1, 0);

#[map]
static G_STATS: PerCpuArray<GlobalStats> = PerCpuArray::with_max_entries(1, 0);

// Blacklists
#[map]
static BLACKLIST: LruHashMap<u32, u64> = LruHashMap::with_max_entries(524288, 0);

#[map]
static BLACKLIST_V6: LruHashMap<[u8; 16], u64> = LruHashMap::with_max_entries(524288, 0);

#[map]
static BLACKLIST_MAC: LruHashMap<[u8; 6], u64> = LruHashMap::with_max_entries(524288, 0);

// Traffic Rate Limiting
#[map]
static TRAFFIC: LruHashMap<u32, IPStats> = LruHashMap::with_max_entries(524288, 0);

#[map]
static TRAFFIC_V6: LruHashMap<[u8; 16], IPStats> = LruHashMap::with_max_entries(524288, 0);

#[map]
static TRAFFIC_MAC: LruHashMap<[u8; 6], IPStats> = LruHashMap::with_max_entries(524288, 0);

#[map]
static TRAFFIC_ARP: LruHashMap<[u8; 6], IPStats> = LruHashMap::with_max_entries(1024, 0);

// Perf Alert Events
#[map]
static EVENTS: PerfEventArray<MitigationEvent> = PerfEventArray::with_max_entries(1024, 0);

// Helper: increment drop counter and return XDP_DROP
#[inline(always)]
fn drop_and_count() -> u32 {
    if let Some(g) = unsafe { G_STATS.get_ptr_mut(0).map(|v| &mut *v) } {
        g.drop_count += 1;
    }
    xdp_action::XDP_DROP
}

#[xdp]
#[allow(unused_unsafe)]
pub fn apex_shield(ctx: XdpContext) -> u32 {
    let s = ctx.data();
    let e = ctx.data_end();
    let now = unsafe { bpf_ktime_get_ns() };

    // Mandatory Global Counter
    if let Some(g) = unsafe { G_STATS.get_ptr_mut(0).map(|v| &mut *v) } {
        g.pkt_count += 1;
    }

    // 1. Parse L2 Ethernet Header
    if s + 14 > e {
        return xdp_action::XDP_PASS;
    }
    let eth = s as *const ethhdr;
    let proto = u16::from_be(unsafe { (*eth).h_proto });
    let src_mac = unsafe { (*eth).h_source };

    // 1b. Check VIP MAC Bypass
    let is_vip_mac = unsafe { VIP_LIST_MAC.get(&src_mac).is_some() };

    // 2. Dynamic Config Extraction
    let config = unsafe { G_CONFIG.get(0) };
    let (ip_limit, ban_duration_ns, arp_limit, mac_limit) = if let Some(c) = config {
        let limit = if c.alert_mode == 1 { c.panic_mode_limit } else { c.normal_mode_limit };
        (limit, (c.ban_duration_sec as u64) * 1_000_000_000, c.arp_mode_limit, c.mac_mode_limit)
    } else {
        (2000, 300_000_000_000, 50, 6000)
    };

    // 3. L2 MAC Rate Limiting
    if !is_vip_mac {
        if let Some(ban_ts) = unsafe { BLACKLIST_MAC.get(&src_mac) } {
            if now < *ban_ts {
                return drop_and_count();
            }
        }

        // Rate-limit MAC address to prevent MAC table flooding
        if let Some(st) = unsafe { TRAFFIC_MAC.get_ptr_mut(&src_mac).map(|v| &mut *v) } {
            if now - st.last_ts < 1_000_000_000 {
                st.pkt_count += 1;
                if st.pkt_count > mac_limit {
                    let ban_expiry = now + ban_duration_ns;
                    unsafe { let _ = BLACKLIST_MAC.insert(&src_mac, &ban_expiry, 0); }
                    let event = MitigationEvent {
                        src_ip: [0u8; 16],
                        src_mac,
                        dest_port: 0,
                        protocol: 0,
                        action: 2, // BAN
                        ip_version: 0,
                    };
                    EVENTS.output(&ctx, &event, 0);
                    return drop_and_count();
                }
            } else {
                st.pkt_count = 1;
                st.last_ts = now;
            }
        } else {
            unsafe { let _ = TRAFFIC_MAC.insert(&src_mac, &IPStats { pkt_count: 1, last_ts: now }, 0); }
        }
    }

    // 4. L3/L4 Protocol Specific Rate Limiting
    if proto == 0x0800 {
        // IPv4
        if s + 14 + 20 > e {
            return xdp_action::XDP_PASS;
        }
        let ip = (s + 14) as *const iphdr;
        let first_byte = unsafe { *(s as *const u8).add(14) };
        let ihl = (first_byte & 0x0F) as usize * 4;
        if ihl < 20 || s + 14 + ihl > e {
            return xdp_action::XDP_PASS;
        }

        let protocol = unsafe { (*ip).protocol };
        let src_be = unsafe { (*ip).saddr };
        let src_ip = u32::from_be(src_be);

        // VIP Bypass
        let key = aya_ebpf::maps::lpm_trie::Key::new(32, src_be.to_ne_bytes());
        if unsafe { VIP_LIST.get(&key).is_some() } { return xdp_action::XDP_PASS; }

        // IP Blacklist Check
        if let Some(ban_ts) = unsafe { BLACKLIST.get(&src_ip) } {
            if now < *ban_ts {
                return drop_and_count();
            }
        }

        // L4 Destination Port Parsing
        let mut dest_port: u16 = 0;
        if protocol == 6 {
            let tcp_offset = 14 + ihl;
            if s + tcp_offset + 20 <= e {
                let tcp = (s + tcp_offset) as *const tcphdr;
                dest_port = u16::from_be(unsafe { (*tcp).dest });
            }
        } else if protocol == 17 {
            let udp_offset = 14 + ihl;
            if s + udp_offset + 8 <= e {
                let udp = (s + udp_offset) as *const udphdr;
                dest_port = u16::from_be(unsafe { (*udp).dest });
            }
        }

        // IP Rate Limit
        if let Some(st) = unsafe { TRAFFIC.get_ptr_mut(&src_ip).map(|v| &mut *v) } {
            if now - st.last_ts < 1_000_000_000 {
                st.pkt_count += 1;
                if st.pkt_count > ip_limit {
                    let ban_expiry = now + ban_duration_ns;
                    unsafe { let _ = BLACKLIST.insert(&src_ip, &ban_expiry, 0); }
                    let mut event_ip = [0u8; 16];
                    event_ip[0..4].copy_from_slice(&src_be.to_ne_bytes());
                    let event = MitigationEvent {
                        src_ip: event_ip,
                        src_mac,
                        dest_port,
                        protocol,
                        action: 2, // BAN
                        ip_version: 4,
                    };
                    EVENTS.output(&ctx, &event, 0);
                    return drop_and_count();
                }
            } else {
                st.pkt_count = 1;
                st.last_ts = now;
            }
        } else {
            unsafe { let _ = TRAFFIC.insert(&src_ip, &IPStats { pkt_count: 1, last_ts: now }, 0); }
        }

    } else if proto == 0x86DD {
        // IPv6
        if s + 14 + 40 > e {
            return xdp_action::XDP_PASS;
        }
        let ip6 = (s + 14) as *const ipv6hdr;
        let src_ip6 = unsafe { (*ip6).saddr };
        let protocol = unsafe { (*ip6).nexthdr };

        // VIP Bypass
        let key = aya_ebpf::maps::lpm_trie::Key::new(128, src_ip6);
        if unsafe { VIP_LIST_V6.get(&key).is_some() } { return xdp_action::XDP_PASS; }

        // IPv6 Blacklist Check
        if let Some(ban_ts) = unsafe { BLACKLIST_V6.get(&src_ip6) } {
            if now < *ban_ts {
                return drop_and_count();
            }
        }

        // L4 Destination Port Parsing
        let mut dest_port: u16 = 0;
        if protocol == 6 {
            let tcp_offset = 14 + 40;
            if s + tcp_offset + 20 <= e {
                let tcp = (s + tcp_offset) as *const tcphdr;
                dest_port = u16::from_be(unsafe { (*tcp).dest });
            }
        } else if protocol == 17 {
            let udp_offset = 14 + 40;
            if s + udp_offset + 8 <= e {
                let udp = (s + udp_offset) as *const udphdr;
                dest_port = u16::from_be(unsafe { (*udp).dest });
            }
        }

        // IPv6 Rate Limit
        if let Some(st) = unsafe { TRAFFIC_V6.get_ptr_mut(&src_ip6).map(|v| &mut *v) } {
            if now - st.last_ts < 1_000_000_000 {
                st.pkt_count += 1;
                if st.pkt_count > ip_limit {
                    let ban_expiry = now + ban_duration_ns;
                    unsafe { let _ = BLACKLIST_V6.insert(&src_ip6, &ban_expiry, 0); }
                    let event = MitigationEvent {
                        src_ip: src_ip6,
                        src_mac,
                        dest_port,
                        protocol,
                        action: 2, // BAN
                        ip_version: 6,
                    };
                    EVENTS.output(&ctx, &event, 0);
                    return drop_and_count();
                }
            } else {
                st.pkt_count = 1;
                st.last_ts = now;
            }
        } else {
            unsafe { let _ = TRAFFIC_V6.insert(&src_ip6, &IPStats { pkt_count: 1, last_ts: now }, 0); }
        }

    } else if proto == 0x0806 {
        // ARP (L2 Guard)
        if s + 14 + 28 > e {
            return xdp_action::XDP_PASS;
        }
        let arp = (s + 14) as *const arphdr;
        let sender_ip = unsafe { (*arp).ar_sip };

        if !is_vip_mac {
            // Rate limit ARP to 50 pps per source MAC to protect local bridge / switch
            if let Some(st) = unsafe { TRAFFIC_ARP.get_ptr_mut(&src_mac).map(|v| &mut *v) } {
                if now - st.last_ts < 1_000_000_000 {
                    st.pkt_count += 1;
                    if st.pkt_count > arp_limit {
                        let ban_expiry = now + ban_duration_ns;
                        unsafe { let _ = BLACKLIST_MAC.insert(&src_mac, &ban_expiry, 0); }
                        
                        let mut event_ip = [0u8; 16];
                        event_ip[0..4].copy_from_slice(&sender_ip);
                        let event = MitigationEvent {
                            src_ip: event_ip,
                            src_mac,
                            dest_port: 0,
                            protocol: 20, // Custom value representing ARP
                            action: 2, // BAN
                            ip_version: 0,
                        };
                        EVENTS.output(&ctx, &event, 0);
                        return drop_and_count();
                    }
                } else {
                    st.pkt_count = 1;
                    st.last_ts = now;
                }
            } else {
                unsafe { let _ = TRAFFIC_ARP.insert(&src_mac, &IPStats { pkt_count: 1, last_ts: now }, 0); }
            }
        }
    }

    xdp_action::XDP_PASS
}

#[panic_handler]
fn panic(_i: &core::panic::PanicInfo) -> ! { loop {} }
