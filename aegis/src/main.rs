use aegis_common::{
    GlobalConfig, GlobalStats, MitigationEvent, ACTION_BAN, ACTION_DROP, DUMMY_EBPF_MAGIC,
    EVENT_VER_ARP, EVENT_VER_IPV4, EVENT_VER_IPV6,
};
use aya::maps::{lpm_trie::Key, Array, HashMap, LpmTrie, PerCpuArray, RingBuf};
use aya::programs::{Xdp, XdpMode};
use aya::{include_bytes_aligned, Ebpf};
use std::collections::{HashMap as StdHashMap, HashSet, VecDeque};
use std::env;
use std::ffi::CString;
use std::io::IsTerminal;
use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::fs::OpenOptions;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncWriteExt, BufWriter, Interest};
use tokio::signal;
use tokio::sync::Mutex as TokioMutex;
use tokio::time::{interval, MissedTickBehavior};

const MAX_LOG_SIZE_BYTES: u64 = 100 * 1024 * 1024; // 100 MiB log rotation threshold
const LOG_CHANNEL_CAPACITY: usize = 32_768;

fn default_strike_threshold() -> u32 {
    32
}

fn default_spoof_protection() -> bool {
    true
}

#[derive(serde::Deserialize)]
struct ConfigFile {
    checkers: Vec<String>,
    global_alert_pps: u64,
    panic_mode_limit: u32,
    normal_mode_limit: u32,
    ban_duration_sec: u64,
    arp_mode_limit: u32,
    mac_mode_limit: u32,
    #[serde(default = "default_strike_threshold")]
    ban_strike_threshold: u32,
    #[serde(default = "default_spoof_protection")]
    spoof_protection: bool,
}

enum ParsedIp {
    V4(u32, [u8; 4]),
    V6(u32, [u8; 16]),
}

struct TelemetryState {
    recent_alerts: VecDeque<String>,
    ipv4_bans: StdHashMap<Ipv4Addr, u64>,
    ipv6_bans: StdHashMap<Ipv6Addr, u64>,
    mac_bans: StdHashMap<[u8; 6], u64>,
    dropped_logs: u64,
}

impl TelemetryState {
    fn new() -> Self {
        Self {
            recent_alerts: VecDeque::with_capacity(12),
            ipv4_bans: StdHashMap::new(),
            ipv6_bans: StdHashMap::new(),
            mac_bans: StdHashMap::new(),
            dropped_logs: 0,
        }
    }

    fn push_alert(&mut self, msg: String) {
        if self.recent_alerts.len() >= 10 {
            self.recent_alerts.pop_front();
        }
        self.recent_alerts.push_back(msg);
    }
}

/// Canonicalize an IPv4 address by zeroing host bits beyond `prefix`.
fn canonicalize_v4(octets: [u8; 4], prefix: u32) -> [u8; 4] {
    if prefix == 0 {
        return [0u8; 4];
    }
    if prefix >= 32 {
        return octets;
    }
    let mask = !0u32 << (32 - prefix);
    (u32::from_be_bytes(octets) & mask).to_be_bytes()
}

/// Canonicalize an IPv6 address by zeroing host bits beyond `prefix`.
fn canonicalize_v6(octets: [u8; 16], prefix: u32) -> [u8; 16] {
    if prefix == 0 {
        return [0u8; 16];
    }
    if prefix >= 128 {
        return octets;
    }
    let mask = !0u128 << (128 - prefix);
    (u128::from_be_bytes(octets) & mask).to_be_bytes()
}

fn parse_cidr(cidr_str: &str) -> Result<ParsedIp, anyhow::Error> {
    let clean = cidr_str.trim();
    if let Some((ip_str, mask_str)) = clean.split_once('/') {
        let mask: u32 = mask_str
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid CIDR prefix length in '{}'", clean))?;
        if let Ok(ip4) = ip_str.parse::<Ipv4Addr>() {
            if mask > 32 {
                return Err(anyhow::anyhow!(
                    "IPv4 CIDR prefix '{}' exceeds maximum /32 in '{}'",
                    mask,
                    clean
                ));
            }
            Ok(ParsedIp::V4(mask, canonicalize_v4(ip4.octets(), mask)))
        } else {
            let ip6 = ip_str
                .parse::<Ipv6Addr>()
                .map_err(|_| anyhow::anyhow!("Invalid IP address in CIDR '{}'", clean))?;
            if mask > 128 {
                return Err(anyhow::anyhow!(
                    "IPv6 CIDR prefix '{}' exceeds maximum /128 in '{}'",
                    mask,
                    clean
                ));
            }
            Ok(ParsedIp::V6(mask, canonicalize_v6(ip6.octets(), mask)))
        }
    } else if let Ok(ip4) = clean.parse::<Ipv4Addr>() {
        Ok(ParsedIp::V4(32, ip4.octets()))
    } else {
        let ip6 = clean
            .parse::<Ipv6Addr>()
            .map_err(|_| anyhow::anyhow!("Invalid IP or CIDR entry '{}'", clean))?;
        Ok(ParsedIp::V6(128, ip6.octets()))
    }
}

/// Raises `RLIMIT_MEMLOCK` to `RLIM_INFINITY` so Linux 5.8–5.10 kernels (prior to memcg BPF
/// accounting in 5.11) permit large `LruHashMap` and `RingBuf` allocations without `EPERM`.
fn bump_memlock_rlimit() {
    let lim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &lim) };
    if ret != 0 {
        eprintln!(
            "[WARN] setrlimit(RLIMIT_MEMLOCK) failed ({}); kernels < 5.11 may reject map creation.",
            std::io::Error::last_os_error()
        );
    }
}

/// Reads exact `CLOCK_MONOTONIC` nanoseconds via Linux vDSO (`clock_gettime`), maintaining
/// 1:1 clock-domain parity with `bpf_ktime_get_ns()` in Ring 0 across suspend/resume cycles.
fn get_monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let ret = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if ret == 0 && ts.tv_sec >= 0 && ts.tv_nsec >= 0 {
        (ts.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(ts.tv_nsec as u64)
    } else {
        0
    }
}

#[inline]
fn pps_to_interval_ns(pps: u32) -> u64 {
    (1_000_000_000u64 / (pps.max(1) as u64)).max(1)
}

fn build_global_config(cfg: &ConfigFile, alert_mode: u32) -> GlobalConfig {
    let active_ip_pps = if alert_mode == 1 {
        cfg.panic_mode_limit
    } else {
        cfg.normal_mode_limit
    };
    GlobalConfig {
        alert_mode,
        active_ip_pps,
        normal_interval_ns: pps_to_interval_ns(cfg.normal_mode_limit),
        panic_interval_ns: pps_to_interval_ns(cfg.panic_mode_limit),
        arp_interval_ns: pps_to_interval_ns(cfg.arp_mode_limit),
        mac_interval_ns: pps_to_interval_ns(cfg.mac_mode_limit),
        ban_duration_ns: cfg.ban_duration_sec.saturating_mul(1_000_000_000),
        ban_strike_threshold: cfg.ban_strike_threshold.max(1),
        spoof_protection: u32::from(cfg.spoof_protection),
    }
}

fn parse_mac_str(mac_str: &str) -> Option<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut idx = 0;
    for part in mac_str.split(':') {
        if idx >= 6 {
            return None;
        }
        mac[idx] = u8::from_str_radix(part, 16).ok()?;
        idx += 1;
    }
    if idx != 6 || mac == [0u8; 6] || (mac[0] & 0x01) != 0 {
        return None;
    }
    Some(mac)
}

fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn parse_ipv4_route_table(content: &str, dev: &str) -> Option<Ipv4Addr> {
    let mut fallback_gw: Option<Ipv4Addr> = None;

    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 8 {
            continue;
        }
        if parts[1] != "00000000" || parts[7] != "00000000" || parts[2] == "00000000" {
            continue;
        }
        let flags = u16::from_str_radix(parts[3], 16).unwrap_or(0);
        if (flags & 0x0003) != 0x0003 {
            continue;
        }
        if let Ok(gw_raw) = u32::from_str_radix(parts[2], 16) {
            let gw_ip = Ipv4Addr::from(gw_raw.to_ne_bytes());
            if parts[0] == dev {
                return Some(gw_ip);
            }
            if fallback_gw.is_none() {
                fallback_gw = Some(gw_ip);
            }
        }
    }
    fallback_gw
}

/// Parses `/proc/net/route` (`net/ipv4/fib_trie.c` -> `fib_route_seq_show`):
/// Columns: `[0]=Iface  [1]=Destination  [2]=Gateway  [3]=Flags  ...  [7]=Mask`
/// Default route has `Destination == "00000000"`, `Mask == "00000000"`, and `Flags` with
/// `RTF_UP (0x1) | RTF_GATEWAY (0x2)`. `Gateway` is printed as `(__force u32)__be32` hex.
fn get_gateway_ipv4(dev: &str) -> Option<Ipv4Addr> {
    let content = std::fs::read_to_string("/proc/net/route").ok()?;
    parse_ipv4_route_table(&content, dev)
}

fn parse_ipv6_route_table(content: &str, dev: &str) -> Option<Ipv6Addr> {
    let mut fallback_gw: Option<Ipv6Addr> = None;

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        if parts[0] != "00000000000000000000000000000000" || parts[1] != "00" {
            continue;
        }
        let nexthop_hex = parts[4];
        if nexthop_hex.len() != 32 || nexthop_hex == "00000000000000000000000000000000" {
            continue;
        }
        let flags = u32::from_str_radix(parts[8], 16).unwrap_or(0);
        if (flags & 0x0003) != 0x0003 {
            continue;
        }
        if let Ok(raw) = u128::from_str_radix(nexthop_hex, 16) {
            let gw_ip6 = Ipv6Addr::from(raw.to_be_bytes());
            if parts[9] == dev {
                return Some(gw_ip6);
            }
            if fallback_gw.is_none() {
                fallback_gw = Some(gw_ip6);
            }
        }
    }
    fallback_gw
}

/// Parses `/proc/net/ipv6_route` (`net/ipv6/ip6_fib.c` -> `ipv6_route_seq_show`):
/// Columns: `[0]=Dest  [1]=DestPrefix  [2]=Src  [3]=SrcPrefix  [4]=NextHop  ...  [8]=Flags  [9]=Iface`
fn get_gateway_ipv6(dev: &str) -> Option<Ipv6Addr> {
    let content = std::fs::read_to_string("/proc/net/ipv6_route").ok()?;
    parse_ipv6_route_table(&content, dev)
}

fn parse_arp_table(content: &str, ip: Ipv4Addr, dev: &str) -> Option<[u8; 6]> {
    let target_ip = ip.to_string();
    let mut fallback: Option<[u8; 6]> = None;

    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        // Columns: [0]=IP  [1]=HW type  [2]=Flags  [3]=HW address  [4]=Mask  [5]=Device
        if parts.len() < 6 || parts[0] != target_ip || parts[2] == "0x0" {
            continue;
        }
        if let Some(mac) = parse_mac_str(parts[3]) {
            if parts[5] == dev {
                return Some(mac);
            }
            if fallback.is_none() {
                fallback = Some(mac);
            }
        }
    }
    fallback
}

fn get_arp_mac_for_ipv4(ip: Ipv4Addr, dev: &str) -> Option<[u8; 6]> {
    let content = std::fs::read_to_string("/proc/net/arp").ok()?;
    parse_arp_table(&content, ip, dev)
}

/// Discovers L2 MAC addresses for IPv4/IPv6 default gateways and active NDP/VRRP routers
/// via `/proc/net/arp` and `ip neigh show dev <dev>`.
fn discover_gateway_macs(
    dev: &str,
    gw4: Option<Ipv4Addr>,
    gw6: Option<Ipv6Addr>,
) -> HashSet<[u8; 6]> {
    let mut macs = HashSet::new();

    if let Some(ip4) = gw4 {
        if let Some(m) = get_arp_mac_for_ipv4(ip4, dev) {
            macs.insert(m);
        }
    }

    let gw4_str = gw4.map(|ip| ip.to_string());
    let gw6_str = gw6.map(|ip| ip.to_string());

    if let Ok(output) = Command::new("ip")
        .args(["neigh", "show", "dev", dev])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let tokens: Vec<&str> = line.split_whitespace().collect();
                if tokens.is_empty() {
                    continue;
                }
                let entry_ip = tokens[0];
                let is_router = tokens.contains(&"router");
                let matches_gw4 = gw4_str.as_deref() == Some(entry_ip);
                let matches_gw6 = gw6_str.as_deref() == Some(entry_ip);

                if is_router || matches_gw4 || matches_gw6 {
                    if let Some(pos) = tokens.iter().position(|&t| t == "lladdr") {
                        if let Some(&mac_token) = tokens.get(pos + 1) {
                            if let Some(mac) = parse_mac_str(mac_token) {
                                macs.insert(mac);
                            }
                        }
                    }
                }
            }
        }
    }

    macs
}

/// Triggers kernel ARP/NDP solicitation before XDP attaches if the neighbor cache is cold.
async fn warm_gateway_neighbor_cache(dev: &str, gw4: Option<Ipv4Addr>, gw6: Option<Ipv6Addr>) {
    if let Some(ip4) = gw4 {
        if get_arp_mac_for_ipv4(ip4, dev).is_none() {
            if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
                let _ = sock.set_nonblocking(true);
                let _ = sock.send_to(&[], (ip4, 9));
            }
            tokio::time::sleep(Duration::from_millis(35)).await;
        }
    }
    if let Some(ip6) = gw6 {
        if !ip6.is_unicast_link_local() {
            if let Ok(sock) = UdpSocket::bind("[::]:0") {
                let _ = sock.set_nonblocking(true);
                let _ = sock.send_to(&[], (ip6, 9));
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

fn process_mitigation_event(
    event: &MitigationEvent,
    ban_duration_ns: u64,
    telemetry: &StdMutex<TelemetryState>,
    log_tx: &tokio::sync::mpsc::Sender<String>,
) {
    let mac_str = format_mac(&event.src_mac);
    let now_mono = get_monotonic_ns();
    let expiry_ns = now_mono.saturating_add(ban_duration_ns);

    let (ip_str, proto_str) = match event.ip_version {
        EVENT_VER_IPV4 => {
            let ip = Ipv4Addr::new(
                event.src_ip[0],
                event.src_ip[1],
                event.src_ip[2],
                event.src_ip[3],
            );
            let proto = match event.protocol {
                6 => "TCP",
                17 => "UDP",
                1 => "ICMP",
                _ => "OTHER",
            };
            if event.action == ACTION_BAN {
                if let Ok(mut st) = telemetry.lock() {
                    st.ipv4_bans.insert(ip, expiry_ns);
                }
            }
            (ip.to_string(), proto)
        }
        EVENT_VER_IPV6 => {
            let ip = Ipv6Addr::from(event.src_ip);
            let proto = match event.protocol {
                6 => "TCP",
                17 => "UDP",
                58 => "ICMPv6",
                _ => "OTHER",
            };
            if event.action == ACTION_BAN {
                if let Ok(mut st) = telemetry.lock() {
                    st.ipv6_bans.insert(ip, expiry_ns);
                }
            }
            (ip.to_string(), proto)
        }
        EVENT_VER_ARP => {
            let sender_ip = Ipv4Addr::new(
                event.src_ip[0],
                event.src_ip[1],
                event.src_ip[2],
                event.src_ip[3],
            );
            if event.action == ACTION_BAN {
                if let Ok(mut st) = telemetry.lock() {
                    st.mac_bans.insert(event.src_mac, expiry_ns);
                }
            }
            (sender_ip.to_string(), "ARP")
        }
        _ => {
            if event.action == ACTION_BAN {
                if let Ok(mut st) = telemetry.lock() {
                    st.mac_bans.insert(event.src_mac, expiry_ns);
                }
            }
            ("L2-FRAME".to_string(), "RAW")
        }
    };

    let action_str = match event.action {
        ACTION_DROP => "DROP",
        ACTION_BAN => "BAN",
        _ => "UNKNOWN",
    };

    let vlan_badge = if event.vlan_id > 0 {
        format!(" [VLAN:{}]", event.vlan_id)
    } else {
        String::new()
    };

    let alert_msg = format!(
        "[ALERT]{} MAC: {} | Src: {} -> Port: {} | Proto: {} | Action: {}",
        vlan_badge, mac_str, ip_str, event.dest_port, proto_str, action_str
    );

    let json_record = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "mac": mac_str,
        "src": ip_str,
        "dest_port": event.dest_port,
        "vlan_id": event.vlan_id,
        "protocol": proto_str,
        "action": action_str,
        "ip_version": event.ip_version,
    });
    let mut log_line = json_record.to_string();
    log_line.push('\n');

    let send_failed = log_tx.try_send(log_line).is_err();

    if let Ok(mut st) = telemetry.lock() {
        st.push_alert(alert_msg);
        if send_failed {
            st.dropped_logs = st.dropped_logs.saturating_add(1);
        }
    }
}

async fn open_log_file() -> Result<(tokio::fs::File, PathBuf, u64), anyhow::Error> {
    let primary = PathBuf::from("/var/log/hydra_waf.log");
    match OpenOptions::new().create(true).append(true).open(&primary).await {
        Ok(f) => {
            let len = f.metadata().await.map(|m| m.len()).unwrap_or(0);
            Ok((f, primary, len))
        }
        Err(_) => {
            let fallback = PathBuf::from("hydra_waf.log");
            let f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&fallback)
                .await?;
            let len = f.metadata().await.map(|m| m.len()).unwrap_or(0);
            Ok((f, fallback, len))
        }
    }
}

async fn run_buffered_log_writer(
    mut rx: tokio::sync::mpsc::Receiver<String>,
    initial_file: tokio::fs::File,
    log_path: PathBuf,
    initial_size: u64,
) {
    let mut writer = BufWriter::with_capacity(64 * 1024, initial_file);
    let mut current_size = initial_size;

    while let Some(first_entry) = rx.recv().await {
        let mut batch_bytes = first_entry.len() as u64;
        let _ = writer.write_all(first_entry.as_bytes()).await;

        // Drain up to 512 additional queued log entries before flushing to minimize syscalls
        for _ in 0..512 {
            match rx.try_recv() {
                Ok(entry) => {
                    batch_bytes += entry.len() as u64;
                    let _ = writer.write_all(entry.as_bytes()).await;
                }
                Err(_) => break,
            }
        }

        let _ = writer.flush().await;
        current_size = current_size.saturating_add(batch_bytes);

        // Rotate log file once it exceeds 100 MiB to prevent root filesystem exhaustion
        if current_size >= MAX_LOG_SIZE_BYTES {
            let mut backup_os = log_path.as_os_str().to_os_string();
            backup_os.push(".1");
            let backup_path = PathBuf::from(backup_os);

            let _ = writer.flush().await;
            drop(writer);
            let _ = tokio::fs::rename(&log_path, &backup_path).await;

            match OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&log_path)
                .await
            {
                Ok(new_file) => {
                    writer = BufWriter::with_capacity(64 * 1024, new_file);
                    current_size = 0;
                }
                Err(e) => {
                    eprintln!("[ERROR] Log rotation reopen failed for {}: {}", log_path.display(), e);
                    return;
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let dev = env::args().nth(1).unwrap_or_else(|| "eth0".to_string());
    let dev_cstr = CString::new(dev.as_str())
        .map_err(|_| anyhow::anyhow!("Invalid network interface name '{}'", dev))?;

    // Discover config.json (Executable dir -> /etc/hydra/config.json -> CWD)
    let exe_cfg = env::current_exe().ok().and_then(|mut p| {
        p.pop();
        p.push("config.json");
        p.exists().then_some(p)
    });
    let config_content = if let Some(ref p) = exe_cfg {
        std::fs::read_to_string(p)
    } else {
        Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no exe config"))
    }
    .or_else(|_| std::fs::read_to_string(Path::new("/etc/hydra/config.json")))
    .or_else(|_| std::fs::read_to_string(Path::new("config.json")))
    .map_err(|e| anyhow::anyhow!("Failed to locate or read config.json: {}", e))?;

    let config: ConfigFile = serde_json::from_str(&config_content)?;

    // Strict configuration validation
    if config.global_alert_pps == 0 {
        return Err(anyhow::anyhow!(
            "Config error: global_alert_pps cannot be 0 (would trigger instant panic mode)"
        ));
    }
    if config.panic_mode_limit == 0 || config.normal_mode_limit == 0 {
        return Err(anyhow::anyhow!(
            "Config error: panic_mode_limit and normal_mode_limit must be > 0"
        ));
    }
    if config.panic_mode_limit >= config.normal_mode_limit {
        return Err(anyhow::anyhow!(
            "Config error: panic_mode_limit ({}) must be strictly less than normal_mode_limit ({})",
            config.panic_mode_limit,
            config.normal_mode_limit
        ));
    }
    if config.ban_duration_sec == 0 {
        return Err(anyhow::anyhow!("Config error: ban_duration_sec cannot be 0"));
    }
    if config.arp_mode_limit == 0 || config.mac_mode_limit == 0 {
        return Err(anyhow::anyhow!(
            "Config error: arp_mode_limit and mac_mode_limit must be > 0"
        ));
    }

    // Parse and validate all VIP checker CIDRs upfront before touching kernel state
    let mut parsed_checkers = Vec::with_capacity(config.checkers.len());
    for checker in &config.checkers {
        parsed_checkers.push(parse_cidr(checker)?);
    }

    // Verify embedded eBPF bytecode is a real ELF binary, not the host cargo-check placeholder
    let ebpf_bytes = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/aegis-ebpf.bin"));
    if ebpf_bytes.len() <= DUMMY_EBPF_MAGIC.len()
        || &ebpf_bytes[..DUMMY_EBPF_MAGIC.len()] == DUMMY_EBPF_MAGIC
    {
        return Err(anyhow::anyhow!(
            "Embedded eBPF bytecode is a build placeholder. Build the kernel program first via `make build`."
        ));
    }

    // Unlock RLIMIT_MEMLOCK for Linux 5.8–5.10 compatibility
    bump_memlock_rlimit();

    // Pre-discover IPv4 & IPv6 gateways and warm neighbor cache BEFORE attaching XDP
    let gw4_opt = get_gateway_ipv4(&dev);
    let gw6_opt = get_gateway_ipv6(&dev);
    warm_gateway_neighbor_cache(&dev, gw4_opt, gw6_opt).await;

    let mut bpf = Ebpf::load(ebpf_bytes)?;

    // 1. Pre-populate G_CONFIG BEFORE XDP attach so packet #0 sees exact intervals
    {
        let map = bpf
            .map_mut("G_CONFIG")
            .ok_or_else(|| anyhow::anyhow!("Missing G_CONFIG map in eBPF ELF"))?;
        let mut g_conf = Array::<_, GlobalConfig>::try_from(map)?;
        g_conf.set(0, &build_global_config(&config, 0), 0)?;
    }

    // 2. Pre-populate VIP IPv4 & IPv6 LPM Tries (including gateway IPs for live VRRP/NDP safety)
    {
        let [Some(vip4_raw), Some(vip6_raw)] = bpf.maps_disjoint_mut(["VIP_LIST", "VIP_LIST_V6"])
        else {
            return Err(anyhow::anyhow!("Missing VIP_LIST or VIP_LIST_V6 maps"));
        };
        let mut vip4_map: LpmTrie<_, [u8; 4], u32> = LpmTrie::try_from(vip4_raw)?;
        let mut vip6_map: LpmTrie<_, [u8; 16], u32> = LpmTrie::try_from(vip6_raw)?;

        for parsed in &parsed_checkers {
            match parsed {
                ParsedIp::V4(prefix, octets) => {
                    let key = Key::new(*prefix, *octets);
                    vip4_map.insert(&key, &1u32, 0)?;
                }
                ParsedIp::V6(prefix, octets) => {
                    let key = Key::new(*prefix, *octets);
                    vip6_map.insert(&key, &1u32, 0)?;
                }
            }
        }

        if let Some(gw4) = gw4_opt {
            let key = Key::new(32, gw4.octets());
            vip4_map.insert(&key, &1u32, 0)?;
            println!("[INFO] Protected IPv4 Default Gateway in VIP_LIST: {}/32", gw4);
        }
        if let Some(gw6) = gw6_opt {
            let key = Key::new(128, gw6.octets());
            vip6_map.insert(&key, &1u32, 0)?;
            println!("[INFO] Protected IPv6 Default Gateway in VIP_LIST_V6: {}/128", gw6);
        }
    }

    // 3. Pre-populate Gateway / Router MACs BEFORE XDP attach to prevent startup blackout
    let mut known_gw_macs = discover_gateway_macs(&dev, gw4_opt, gw6_opt);
    {
        let map = bpf
            .map_mut("VIP_LIST_MAC")
            .ok_or_else(|| anyhow::anyhow!("Missing VIP_LIST_MAC map in eBPF ELF"))?;
        let mut vip_macs = HashMap::<_, [u8; 6], u32>::try_from(map)?;
        for mac in &known_gw_macs {
            vip_macs.insert(mac, &1u32, 0)?;
            println!(
                "[INFO] Gateway/Router MAC whitelisted pre-attach: {}",
                format_mac(mac)
            );
        }
        if known_gw_macs.is_empty() {
            println!(
                "[WARN] No gateway MAC resolved pre-attach on '{}'. Continuous VRRP/ARP discovery active.",
                dev
            );
        }
    }

    // 4. Load and Attach XDP Program (`Driver` native mode -> `Skb` generic fallback)
    {
        let prog: &mut Xdp = bpf
            .program_mut("apex_shield")
            .ok_or_else(|| anyhow::anyhow!("Missing XDP program 'apex_shield' in eBPF ELF"))?
            .try_into()?;
        prog.load()?;
        match prog.attach(&dev_cstr, XdpMode::Driver) {
            Ok(_) => println!(
                "[INFO] Apex Shield attached to '{}' in Driver (Native Zero-Copy) mode.",
                dev
            ),
            Err(e) => {
                println!(
                    "[WARN] Native Driver mode unavailable on '{}' ({}). Falling back to Skb (Generic) mode...",
                    dev, e
                );
                prog.attach(&dev_cstr, XdpMode::Skb).map_err(|e2| {
                    anyhow::anyhow!("Failed to attach XDP in Skb fallback mode on '{}': {}", dev, e2)
                })?;
                println!(
                    "[INFO] Apex Shield attached to '{}' in Skb (Generic) fallback mode.",
                    dev
                );
            }
        }
    }

    // 5. Initialize Buffered Log Writer with 100 MiB Rotation
    let (log_file, log_path, initial_size) = open_log_file().await?;
    let (log_tx, log_rx) = tokio::sync::mpsc::channel::<String>(LOG_CHANNEL_CAPACITY);
    tokio::spawn(run_buffered_log_writer(
        log_rx,
        log_file,
        log_path,
        initial_size,
    ));

    // 6. Spawn Lockless Shared RingBuf Consumer (zero per-event task spawning)
    let telemetry = Arc::new(StdMutex::new(TelemetryState::new()));
    let ban_duration_ns = config.ban_duration_sec.saturating_mul(1_000_000_000);

    if let Some(map) = bpf.take_map("EVENTS") {
        let ring_buf = RingBuf::try_from(map)?;
        let telemetry_rb = Arc::clone(&telemetry);
        let log_tx_rb = log_tx.clone();

        tokio::spawn(async move {
            // SAFETY: `RingBuf<MapData>` owns a valid open fd for its entire lifetime and never swaps it.
            let mut async_rb = match unsafe {
                AsyncFd::register_with_interest(ring_buf, Interest::READABLE)
            } {
                Ok(fd) => fd,
                Err(e) => {
                    eprintln!("[ERROR] Failed to register RingBuf with epoll reactor: {}", e);
                    return;
                }
            };

            loop {
                let mut guard = match async_rb.readable_mut().await {
                    Ok(g) => g,
                    Err(e) => {
                        eprintln!("[ERROR] RingBuf readability poll failed: {}", e);
                        break;
                    }
                };

                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    if item.len() >= std::mem::size_of::<MitigationEvent>() {
                        let ev =
                            unsafe { (item.as_ptr() as *const MitigationEvent).read_unaligned() };
                        process_mitigation_event(&ev, ban_duration_ns, &telemetry_rb, &log_tx_rb);
                    }
                }
                guard.clear_ready();
            }
        });
    }

    // 7. Spawn 1 Hz Adaptive Control Plane & HUD Renderer
    let bpf = Arc::new(TokioMutex::new(bpf));
    let bpf_ctrl = Arc::clone(&bpf);
    let telemetry_ctrl = Arc::clone(&telemetry);
    let is_tty = std::io::stdout().is_terminal();

    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(1));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        // Consume immediate first tick
        ticker.tick().await;

        let mut last_tick = Instant::now();
        let mut tick_counter: u64 = 0;
        let mut alert_active = false;
        let mut cooldown_seconds: u32 = 0;

        let mut prev_stats = GlobalStats::default();
        let mut stats_initialized = false;

        loop {
            ticker.tick().await;
            tick_counter = tick_counter.wrapping_add(1);

            let now_inst = Instant::now();
            let dt = now_inst
                .duration_since(last_tick)
                .as_secs_f64()
                .max(0.05);
            last_tick = now_inst;
            let mono_now = get_monotonic_ns();

            // Prune expired bans in O(active_bans) memory and collect expired keys for kernel cleanup
            let (
                expired_v4,
                expired_v6,
                expired_mac,
                active_v4_preview,
                active_v6_preview,
                active_mac_preview,
                v4_ban_total,
                v6_ban_total,
                mac_ban_total,
                recent_alerts_snapshot,
                dropped_logs,
            ) = {
                let mut st = telemetry_ctrl.lock().unwrap();

                let mut exp4 = Vec::new();
                st.ipv4_bans.retain(|&ip, &mut exp| {
                    if exp > mono_now {
                        true
                    } else {
                        exp4.push(ip);
                        false
                    }
                });

                let mut exp6 = Vec::new();
                st.ipv6_bans.retain(|&ip, &mut exp| {
                    if exp > mono_now {
                        true
                    } else {
                        exp6.push(ip);
                        false
                    }
                });

                let mut expm = Vec::new();
                st.mac_bans.retain(|&mac, &mut exp| {
                    if exp > mono_now {
                        true
                    } else {
                        expm.push(mac);
                        false
                    }
                });

                let v4_prev: Vec<(Ipv4Addr, u64)> = st
                    .ipv4_bans
                    .iter()
                    .take(3)
                    .map(|(&ip, &exp)| (ip, (exp - mono_now) / 1_000_000_000))
                    .collect();
                let v6_prev: Vec<(Ipv6Addr, u64)> = st
                    .ipv6_bans
                    .iter()
                    .take(2)
                    .map(|(&ip, &exp)| (ip, (exp - mono_now) / 1_000_000_000))
                    .collect();
                let mac_prev: Vec<(String, u64)> = st
                    .mac_bans
                    .iter()
                    .take(3)
                    .map(|(m, &exp)| (format_mac(m), (exp - mono_now) / 1_000_000_000))
                    .collect();

                let alerts: Vec<String> = st.recent_alerts.iter().rev().take(5).cloned().collect();

                (
                    exp4,
                    exp6,
                    expm,
                    v4_prev,
                    v6_prev,
                    mac_prev,
                    st.ipv4_bans.len(),
                    st.ipv6_bans.len(),
                    st.mac_bans.len(),
                    alerts,
                    st.dropped_logs,
                )
            };

            let mut total_pps: u64 = 0;
            let mut total_dps: u64 = 0;
            let mut ipv4_pps: u64 = 0;
            let mut ipv6_pps: u64 = 0;
            let mut arp_pps: u64 = 0;
            let mut malformed_pps: u64 = 0;

            // Refresh router/VRRP MACs every 10s (or every 1s if none resolved yet)
            let should_poll_gw = known_gw_macs.is_empty() || tick_counter.is_multiple_of(10);
            let newly_discovered_macs = if should_poll_gw {
                discover_gateway_macs(&dev, gw4_opt, gw6_opt)
            } else {
                HashSet::new()
            };

            {
                let mut bpf_guard = bpf_ctrl.lock().await;

                if should_poll_gw {
                    for mac in newly_discovered_macs {
                        if known_gw_macs.insert(mac) {
                            if let Some(map) = bpf_guard.map_mut("VIP_LIST_MAC") {
                                if let Ok(mut vip_macs) = HashMap::<_, [u8; 6], u32>::try_from(map) {
                                    let _ = vip_macs.insert(&mac, &1u32, 0);
                                }
                            }
                            // Ensure newly resolved router MAC is purged from BLACKLIST_MAC if previously banned
                            if let Some(map) = bpf_guard.map_mut("BLACKLIST_MAC") {
                                if let Ok(mut bl_mac) = HashMap::<_, [u8; 6], u64>::try_from(map) {
                                    let _ = bl_mac.remove(&mac);
                                }
                            }
                        }
                    }
                }

                // Evict only the specific bans that expired this tick (O(expired) vs O(1.57M) syscalls)
                if !expired_v4.is_empty() {
                    if let Some(map) = bpf_guard.map_mut("BLACKLIST") {
                        if let Ok(mut bl) = HashMap::<_, u32, u64>::try_from(map) {
                            for ip in &expired_v4 {
                                let key = u32::from_be_bytes(ip.octets());
                                let _ = bl.remove(&key);
                            }
                        }
                    }
                }
                if !expired_v6.is_empty() {
                    if let Some(map) = bpf_guard.map_mut("BLACKLIST_V6") {
                        if let Ok(mut bl) = HashMap::<_, [u8; 16], u64>::try_from(map) {
                            for ip in &expired_v6 {
                                let _ = bl.remove(&ip.octets());
                            }
                        }
                    }
                }
                if !expired_mac.is_empty() {
                    if let Some(map) = bpf_guard.map_mut("BLACKLIST_MAC") {
                        if let Ok(mut bl) = HashMap::<_, [u8; 6], u64>::try_from(map) {
                            for mac in &expired_mac {
                                let _ = bl.remove(mac);
                            }
                        }
                    }
                }

                // Read Per-CPU GlobalStats and normalize by exact wall-clock delta `dt`
                if let Some(map) = bpf_guard.map_mut("G_STATS") {
                    if let Ok(g_stats) = PerCpuArray::<_, GlobalStats>::try_from(map) {
                        if let Ok(per_cpu_vals) = g_stats.get(&0, 0) {
                            let mut cur = GlobalStats::default();
                            for cpu_val in per_cpu_vals.iter() {
                                cur.pkt_count = cur.pkt_count.wrapping_add(cpu_val.pkt_count);
                                cur.drop_count = cur.drop_count.wrapping_add(cpu_val.drop_count);
                                cur.ipv4_count = cur.ipv4_count.wrapping_add(cpu_val.ipv4_count);
                                cur.ipv6_count = cur.ipv6_count.wrapping_add(cpu_val.ipv6_count);
                                cur.arp_count = cur.arp_count.wrapping_add(cpu_val.arp_count);
                                cur.malformed_count =
                                    cur.malformed_count.wrapping_add(cpu_val.malformed_count);
                            }

                            if stats_initialized {
                                total_pps = ((cur.pkt_count.wrapping_sub(prev_stats.pkt_count))
                                    as f64
                                    / dt)
                                    .round() as u64;
                                total_dps = ((cur.drop_count.wrapping_sub(prev_stats.drop_count))
                                    as f64
                                    / dt)
                                    .round() as u64;
                                ipv4_pps = ((cur.ipv4_count.wrapping_sub(prev_stats.ipv4_count))
                                    as f64
                                    / dt)
                                    .round() as u64;
                                ipv6_pps = ((cur.ipv6_count.wrapping_sub(prev_stats.ipv6_count))
                                    as f64
                                    / dt)
                                    .round() as u64;
                                arp_pps = ((cur.arp_count.wrapping_sub(prev_stats.arp_count))
                                    as f64
                                    / dt)
                                    .round() as u64;
                                malformed_pps = ((cur
                                    .malformed_count
                                    .wrapping_sub(prev_stats.malformed_count))
                                    as f64
                                    / dt)
                                    .round() as u64;
                            }
                            prev_stats = cur;
                            stats_initialized = true;
                        }
                    }
                }

                // Dynamic Panic Mode state machine with 80% hysteresis & 10s cooldown
                if total_pps > config.global_alert_pps {
                    if !alert_active {
                        alert_active = true;
                        if let Some(map) = bpf_guard.map_mut("G_CONFIG") {
                            if let Ok(mut g_conf) = Array::<_, GlobalConfig>::try_from(map) {
                                let _ = g_conf.set(0, &build_global_config(&config, 1), 0);
                            }
                        }
                    }
                    cooldown_seconds = 10;
                } else if alert_active {
                    if total_pps < (config.global_alert_pps * 8 / 10) {
                        if cooldown_seconds > 0 {
                            cooldown_seconds -= 1;
                        } else {
                            alert_active = false;
                            if let Some(map) = bpf_guard.map_mut("G_CONFIG") {
                                if let Ok(mut g_conf) = Array::<_, GlobalConfig>::try_from(map) {
                                    let _ = g_conf.set(0, &build_global_config(&config, 0), 0);
                                }
                            }
                        }
                    } else {
                        cooldown_seconds = 10;
                    }
                }
            }

            let total_active_bans = v4_ban_total + v6_ban_total + mac_ban_total;
            let drop_percentage = if total_pps > 0 {
                ((total_dps as f64 / total_pps as f64) * 100.0).min(100.0)
            } else {
                0.0
            };

            // Headless systemd/journald mode: emit clean structured lines instead of ANSI clears
            if !is_tty {
                if tick_counter.is_multiple_of(5) || alert_active {
                    println!(
                        "[STATUS] mode={} iface={} rx_pps={} drop_pps={} ({:.1}%) ipv4_pps={} ipv6_pps={} arp_pps={} malformed_pps={} active_bans={} dropped_logs={}",
                        if alert_active { "PANIC" } else { "NORMAL" },
                        dev,
                        total_pps,
                        total_dps,
                        drop_percentage,
                        ipv4_pps,
                        ipv6_pps,
                        arp_pps,
                        malformed_pps,
                        total_active_bans,
                        dropped_logs
                    );
                }
                continue;
            }

            // Interactive Terminal ANSI HUD
            print!("\x1b[2J\x1b[H");
            println!("\x1b[1;35m╔══════════════════════════════════════════════════════════════════════╗\x1b[0m");
            println!("\x1b[1;35m║          🛡️  HYDRA APEX v2: KERNEL-LEVEL L2/L3/L4 XDP IPS          ║\x1b[0m");
            println!("\x1b[1;35m╚══════════════════════════════════════════════════════════════════════╝\x1b[0m");

            let status_indicator = if alert_active {
                format!(
                    "\x1b[1;91m⚠️  PANIC MODE ACTIVE (Cooldown: {}s)\x1b[0m",
                    cooldown_seconds
                )
            } else {
                "\x1b[1;92m✅  NORMAL MODE ACTIVE\x1b[0m".to_string()
            };

            println!(
                " ⚙️  Status    : {}   | Interface: \x1b[1;36m{}\x1b[0m | GW MACs: \x1b[1;32m{}\x1b[0m",
                status_indicator,
                dev,
                known_gw_macs.len()
            );
            println!(
                " ⚙️  Limits    : Normal: \x1b[1;32m{} PPS\x1b[0m | Panic: \x1b[1;91m{} PPS\x1b[0m | Ban: \x1b[1;33m{}s\x1b[0m | ARP: \x1b[1;91m{} PPS\x1b[0m | MAC: \x1b[1;91m{} PPS\x1b[0m",
                config.normal_mode_limit,
                config.panic_mode_limit,
                config.ban_duration_sec,
                config.arp_mode_limit,
                config.mac_mode_limit
            );
            println!("\x1b[35m╟──────────────────────────────────────────────────────────────────────╢\x1b[0m");

            let load_ratio = (total_pps as f64 / config.global_alert_pps as f64).min(1.0);
            let bar_blocks = (load_ratio * 15.0) as usize;
            let mut load_bar = String::with_capacity(45);
            for i in 0..15 {
                if i < bar_blocks {
                    load_bar.push('█');
                } else {
                    load_bar.push('░');
                }
            }
            let bar_color = if load_ratio > 0.8 {
                "\x1b[1;91m"
            } else if load_ratio > 0.4 {
                "\x1b[1;93m"
            } else {
                "\x1b[1;92m"
            };

            println!(" 📈 Traffic & Protocol Telemetry:");
            println!(
                "    - Incoming  : \x1b[1;97m{:>8}\x1b[0m PPS   [{}{}{}\x1b[0m] {:.0}%",
                total_pps,
                bar_color,
                load_bar,
                if load_ratio >= 1.0 {
                    " PANIC THRESHOLD EXCEEDED"
                } else {
                    ""
                },
                load_ratio * 100.0
            );
            println!(
                "    - Blocked   : \x1b[1;91m{:>8}\x1b[0m PPS   (Drop Ratio: \x1b[1;93m{:.1}%\x1b[0m | Malformed: \x1b[1;91m{} PPS\x1b[0m)",
                total_dps, drop_percentage, malformed_pps
            );
            println!(
                "    - Protocols : IPv4: \x1b[1;36m{} PPS\x1b[0m | IPv6: \x1b[1;34m{} PPS\x1b[0m | ARP: \x1b[1;35m{} PPS\x1b[0m",
                ipv4_pps, ipv6_pps, arp_pps
            );
            println!("\x1b[35m╟──────────────────────────────────────────────────────────────────────╢\x1b[0m");

            println!(" 🚫 ACTIVE BANS DATABASE (Total: {})", total_active_bans);
            if total_active_bans == 0 {
                println!("    No active bans registered in kernel memory.");
            } else {
                if !active_v4_preview.is_empty() {
                    print!("    - IPv4 ({}): ", v4_ban_total);
                    for (ip, rem) in &active_v4_preview {
                        print!("\x1b[1;93m{}\x1b[0m ({}s)  ", ip, rem);
                    }
                    if v4_ban_total > active_v4_preview.len() {
                        print!("... (+{})", v4_ban_total - active_v4_preview.len());
                    }
                    println!();
                }
                if !active_v6_preview.is_empty() {
                    print!("    - IPv6 ({}): ", v6_ban_total);
                    for (ip, rem) in &active_v6_preview {
                        print!("\x1b[1;93m{}\x1b[0m ({}s)  ", ip, rem);
                    }
                    if v6_ban_total > active_v6_preview.len() {
                        print!("... (+{})", v6_ban_total - active_v6_preview.len());
                    }
                    println!();
                }
                if !active_mac_preview.is_empty() {
                    print!("    - MACs ({}): ", mac_ban_total);
                    for (mac, rem) in &active_mac_preview {
                        print!("\x1b[1;93m{}\x1b[0m ({}s)  ", mac, rem);
                    }
                    if mac_ban_total > active_mac_preview.len() {
                        print!("... (+{})", mac_ban_total - active_mac_preview.len());
                    }
                    println!();
                }
            }
            println!("\x1b[35m╟──────────────────────────────────────────────────────────────────────╢\x1b[0m");

            println!(" 🔔 DETECTED ATTACK EVENTS & ANOMALIES (Real-time):");
            if recent_alerts_snapshot.is_empty() {
                println!("    \x1b[90mListening on XDP ring... Standing guard.\x1b[0m");
            } else {
                for alert in &recent_alerts_snapshot {
                    let formatted_alert = alert
                        .replace("Action: DROP", "Action: \x1b[1;91mDROP\x1b[0m")
                        .replace("Action: BAN", "Action: \x1b[1;41;97mBAN\x1b[0m")
                        .replace("Proto: TCP", "Proto: \x1b[1;36mTCP\x1b[0m")
                        .replace("Proto: UDP", "Proto: \x1b[1;33mUDP\x1b[0m")
                        .replace("Proto: ARP", "Proto: \x1b[1;35mARP\x1b[0m");
                    println!("    {}", formatted_alert);
                }
            }
            println!("\x1b[1;35m╚══════════════════════════════════════════════════════════════════════╝\x1b[0m");
        }
    });

    signal::ctrl_c().await?;
    println!("\n[NYX] Detaching XDP Apex Shield and releasing unpinned kernel maps...");
    // Dropping `Ebpf` closes all unpinned BPF link/map descriptors cleanly in O(1) without syscall storms.
    let _ = bpf.lock().await;
    println!("[INFO] Shutdown complete.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_v4_parses_default_gateway_and_ignores_link_routes() {
        // Regression test for VULN-01: ensure row 1 (`01000A0A` = 10.10.0.1 on little-endian)
        // is selected instead of row 2 (`Flags = 0001` misread as 1.0.0.0).
        let gw_expected = Ipv4Addr::new(10, 10, 0, 1);
        let gw_hex = format!("{:08X}", u32::from_ne_bytes(gw_expected.octets()));
        let proc_route = format!(
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
             eth0\t00000000\t{}\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
             eth0\t00000A0A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n",
            gw_hex
        );
        assert_eq!(parse_ipv4_route_table(&proc_route, "eth0"), Some(gw_expected));
    }

    #[test]
    fn route_v6_parses_default_nexthop() {
        let proc_v6 = "\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe80000000000000021122fffe334455 00000064 00000001 00000000 00050003 eth0\n";
        let gw = parse_ipv6_route_table(proc_v6, "eth0").unwrap();
        assert_eq!(gw, "fe80::211:22ff:fe33:4455".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn arp_table_ignores_incomplete_and_multicast_entries() {
        let arp = "\
IP address       HW type     Flags       HW address            Mask     Device\n\
10.10.0.1        0x1         0x0         00:00:00:00:00:00     *        eth0\n\
10.10.0.2        0x1         0x2         ff:ff:ff:ff:ff:ff     *        eth0\n\
10.10.0.3        0x1         0x2         02:aa:bb:cc:dd:ee     *        eth0\n";
        assert_eq!(parse_arp_table(arp, Ipv4Addr::new(10, 10, 0, 1), "eth0"), None);
        assert_eq!(parse_arp_table(arp, Ipv4Addr::new(10, 10, 0, 2), "eth0"), None);
        assert_eq!(
            parse_arp_table(arp, Ipv4Addr::new(10, 10, 0, 3), "eth0"),
            Some([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee])
        );
    }

    #[test]
    fn cidr_parser_canonicalizes_host_bits_and_rejects_overflow_prefixes() {
        match parse_cidr("10.10.0.42/24").unwrap() {
            ParsedIp::V4(prefix, octets) => {
                assert_eq!(prefix, 24);
                assert_eq!(octets, [10, 10, 0, 0]);
            }
            ParsedIp::V6(..) => panic!("Expected IPv4"),
        }
        assert!(parse_cidr("10.10.0.0/33").is_err());
        assert!(parse_cidr("fe80::/129").is_err());
    }
}
