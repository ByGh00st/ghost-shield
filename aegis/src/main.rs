use aya::programs::{Xdp, XdpMode};
use aya::maps::{LpmTrie, PerCpuArray, Array, HashMap, lpm_trie::Key, perf::AsyncPerfEventArray};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Ebpf};
use bytes::BytesMut;
use std::{env, net::Ipv4Addr, net::Ipv6Addr};
use std::collections::{HashSet, VecDeque};
use tokio::signal;
use std::time::{Duration, SystemTime};
use tokio::time::sleep;
use aegis_common::{GlobalConfig, GlobalStats, MitigationEvent};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;

#[derive(serde::Deserialize)]
struct ConfigFile {
    checkers: Vec<String>,
    global_alert_pps: u64,
    panic_mode_limit: u32,
    normal_mode_limit: u32,
    ban_duration_sec: u64,
    arp_mode_limit: u32,
    mac_mode_limit: u32,
}

enum ParsedIp {
    V4(u32, [u8; 4]),
    V6(u32, [u8; 16]),
}

fn parse_cidr(cidr_str: &str) -> Result<ParsedIp, anyhow::Error> {
    let clean_str = cidr_str.trim();
    if let Some((ip_str, mask_str)) = clean_str.split_once('/') {
        let mask: u32 = mask_str.parse()?;
        if let Ok(ip4) = ip_str.parse::<Ipv4Addr>() {
            Ok(ParsedIp::V4(mask, ip4.octets()))
        } else {
            let ip6 = ip_str.parse::<Ipv6Addr>()?;
            Ok(ParsedIp::V6(mask, ip6.octets()))
        }
    } else {
        if let Ok(ip4) = clean_str.parse::<Ipv4Addr>() {
            Ok(ParsedIp::V4(32, ip4.octets()))
        } else {
            let ip6 = clean_str.parse::<Ipv6Addr>()?;
            Ok(ParsedIp::V6(128, ip6.octets()))
        }
    }
}

fn get_monotonic_ns() -> u64 {
    if let Ok(uptime) = std::fs::read_to_string("/proc/uptime") {
        if let Some(first_part) = uptime.split_whitespace().next() {
            if let Ok(secs) = first_part.parse::<f64>() {
                return (secs * 1_000_000_000.0) as u64;
            }
        }
    }
    0
}

fn get_timestamp() -> String {
    if let Ok(n) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        format!("{}", n.as_secs())
    } else {
        "0".to_string()
    }
}

fn get_gateway_ip() -> Option<String> {
    if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 && parts[2] == "00000000" { 
                if let Ok(gw_hex) = u32::from_str_radix(parts[3], 16) {
                    let gw_ip = Ipv4Addr::from(gw_hex.swap_bytes());
                    return Some(gw_ip.to_string());
                }
            }
        }
    }
    None
}

fn get_mac_for_ip(ip_str: &str) -> Option<[u8; 6]> {
    if let Ok(content) = std::fs::read_to_string("/proc/net/arp") {
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 && parts[0] == ip_str {
                let mac_parts: Vec<&str> = parts[3].split(':').collect();
                if mac_parts.len() == 6 {
                    let mut mac = [0u8; 6];
                    for i in 0..6 {
                        if let Ok(val) = u8::from_str_radix(mac_parts[i], 16) {
                            mac[i] = val;
                        }
                    }
                    if mac != [0u8; 6] {
                        return Some(mac);
                    }
                }
            }
        }
    }
    None
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let dev = env::args().nth(1).unwrap_or_else(|| "eth0".to_string());
    
    // Load config.json with path discovery fallbacks (Executable dir -> /etc/hydra/config.json -> CWD)
    let config_path = env::current_exe()
        .ok()
        .and_then(|mut p| {
            p.pop();
            p.push("config.json");
            if p.exists() { Some(p) } else { None }
        })
        .unwrap_or_else(|| std::path::PathBuf::from("config.json"));

    let config_content = std::fs::read_to_string(&config_path)
        .or_else(|_| std::fs::read_to_string("/etc/hydra/config.json"))
        .or_else(|_| std::fs::read_to_string("config.json"))
        .map_err(|e| anyhow::anyhow!("Failed to locate or read config.json: {}", e))?;
    let config: ConfigFile = serde_json::from_str(&config_content)?;

    let mut bpf = Ebpf::load(include_bytes_aligned!("../../target/bpfel-unknown-none/release/aegis"))?;
    
    let prog: &mut Xdp = bpf.program_mut("apex_shield").unwrap().try_into()?;
    prog.load()?;
    let _ = prog.attach(&dev, XdpMode::Driver).or_else(|_| prog.attach(&dev, XdpMode::Skb));

    // Populate initial configs in eBPF Map
    {
        if let Some(map) = bpf.map_mut("G_CONFIG") {
            let mut g_conf = Array::<_, GlobalConfig>::try_from(map)?;
            g_conf.set(0, GlobalConfig {
                alert_mode: 0,
                normal_mode_limit: config.normal_mode_limit,
                panic_mode_limit: config.panic_mode_limit,
                ban_duration_sec: config.ban_duration_sec,
                arp_mode_limit: config.arp_mode_limit,
                mac_mode_limit: config.mac_mode_limit,
            }, 0)?;
        }
    }

    // Populate VIP MACs to protect the Gateway / core routing path
    {
        if let Some(map) = bpf.map_mut("VIP_LIST_MAC") {
            let mut vip_macs = HashMap::<_, [u8; 6], u32>::try_from(map)?;
            if let Some(gw_ip) = get_gateway_ip() {
                if let Some(gw_mac) = get_mac_for_ip(&gw_ip) {
                    let _ = vip_macs.insert(gw_mac, 1, 0);
                }
            }
        }
    }

    // Populate VIP lists (both IPv4 and IPv6) from config checkers
    {
        let mut vip4_map: LpmTrie<_, [u8; 4], u32> = LpmTrie::try_from(bpf.map_mut("VIP_LIST").unwrap())?;
        let mut vip6_map: LpmTrie<_, [u8; 16], u32> = LpmTrie::try_from(bpf.map_mut("VIP_LIST_V6").unwrap())?;
        
        for checker in &config.checkers {
            if let Ok(parsed) = parse_cidr(checker) {
                match parsed {
                    ParsedIp::V4(prefix, octets) => {
                        let key = Key::new(prefix, octets);
                        let _ = vip4_map.insert(&key, 1u32, 0);
                    }
                    ParsedIp::V6(prefix, octets) => {
                        let key = Key::new(prefix, octets);
                        let _ = vip6_map.insert(&key, 1u32, 0);
                    }
                }
            }
        }
    }

    // Open mitigation event log file
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("/var/log/hydra_waf.log")
        .await
        .or_else(|_| {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open("hydra_waf.log")
        })?;
    let log_writer = Arc::new(Mutex::new(log_file));

    // Shared state for alerts & TUI
    let recent_alerts = Arc::new(Mutex::new(VecDeque::new()));
    let recent_alerts_clone = Arc::clone(&recent_alerts);
    let log_writer_clone = Arc::clone(&log_writer);

    // Read Events from eBPF PerfEventArray
    if let Some(map) = bpf.map_mut("EVENTS") {
        let mut perf_array = AsyncPerfEventArray::try_from(map)?;
        for cpu_id in online_cpus()? {
            let mut buf = perf_array.open(cpu_id, None)?;
            let recent_alerts_local = Arc::clone(&recent_alerts_clone);
            let log_writer_local = Arc::clone(&log_writer_clone);
            
            tokio::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(1024))
                    .collect::<Vec<_>>();
                loop {
                    if let Ok(events) = buf.read_events(&mut buffers).await {
                        for buf in buffers.iter_mut().take(events.read) {
                            let ptr = buf.as_ptr() as *const MitigationEvent;
                            let event = unsafe { ptr.read_unaligned() };
                            
                            let mac_str = format!(
                                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                event.src_mac[0], event.src_mac[1], event.src_mac[2],
                                event.src_mac[3], event.src_mac[4], event.src_mac[5]
                            );

                            let (ip_str, proto_str) = match event.ip_version {
                                4 => {
                                    let ip = Ipv4Addr::new(event.src_ip[0], event.src_ip[1], event.src_ip[2], event.src_ip[3]);
                                    let proto = match event.protocol {
                                        6 => "TCP",
                                        17 => "UDP",
                                        1 => "ICMP",
                                        _ => "OTHER",
                                    };
                                    (ip.to_string(), proto)
                                }
                                6 => {
                                    let ip = Ipv6Addr::from(event.src_ip);
                                    let proto = match event.protocol {
                                        6 => "TCP",
                                        17 => "UDP",
                                        58 => "ICMPv6",
                                        _ => "OTHER",
                                    };
                                    (ip.to_string(), proto)
                                }
                                _ => {
                                    let proto = if event.protocol == 20 { "ARP" } else { "RAW" };
                                    ("L2-FRAME".to_string(), proto)
                                }
                            };

                            let action_str = match event.action {
                                1 => "DROP",
                                2 => "BAN",
                                _ => "UNKNOWN",
                            };

                            let alert_msg = format!(
                                "[ALERT] MAC: {} | Src: {} -> Port: {} | Proto: {} | Action: {}",
                                mac_str, ip_str, event.dest_port, proto_str, action_str
                            );

                            // Add to TUI alerts queue
                            {
                                let mut alerts = recent_alerts_local.lock().await;
                                alerts.push_back(alert_msg.clone());
                                if alerts.len() > 10 {
                                    alerts.pop_front();
                                }
                            }

                            // Write to JSON log file
                            let log_entry = format!(
                                "{{\"timestamp\":{},\"mac\":\"{}\",\"src\":\"{}\",\"dest_port\":{},\"protocol\":\"{}\",\"action\":\"{}\",\"ip_version\":{}}}\n",
                                get_timestamp(), mac_str, ip_str, event.dest_port, proto_str, action_str, event.ip_version
                            );
                            if let mut file_guard = log_writer_local.lock().await {
                                let _ = file_guard.write_all(log_entry.as_bytes()).await;
                            }
                        }
                    } else {
                        sleep(Duration::from_millis(50)).await;
                    }
                }
            });
        }
    }

    // Main Control & TUI update thread
    tokio::spawn(async move {
        let mut alert_active = false;
        let mut cooldown_seconds = 0;
        let mut last_pkt_count: u64 = 0;
        let mut last_drop_count: u64 = 0;

        loop {
            sleep(Duration::from_secs(1)).await;
            
            let mut total_pps: u64 = 0;
            let mut total_dps: u64 = 0;
            
            // Read Global Stats
            if let Some(map) = bpf.map_mut("G_STATS") {
                if let Ok(g_stats) = PerCpuArray::<_, GlobalStats>::try_from(map) {
                    if let Ok(vals) = g_stats.get(&0, 0) {
                        let mut current_pkt: u64 = 0;
                        let mut current_drop: u64 = 0;
                        for cpu_val in vals.iter() {
                            current_pkt += cpu_val.pkt_count;
                            current_drop += cpu_val.drop_count;
                        }
                        
                        total_pps = current_pkt.saturating_sub(last_pkt_count);
                        total_dps = current_drop.saturating_sub(last_drop_count);
                        last_pkt_count = current_pkt;
                        last_drop_count = current_drop;
                    }
                }
            }

            // Retrieve Active IPv4, IPv6, and MAC Bans
            let mut active_ipv4_bans = Vec::new();
            let mut active_ipv6_bans = Vec::new();
            let mut active_mac_bans = Vec::new();
            let mono_now = get_monotonic_ns();

            if let Some(map) = bpf.map_mut("BLACKLIST") {
                if let Ok(blacklist) = HashMap::<_, u32, u64>::try_from(map) {
                    for item in blacklist.iter() {
                        if let Ok((ip_raw, expiry)) = item {
                            let src_ip = Ipv4Addr::from(ip_raw.to_be());
                            if expiry > mono_now {
                                active_ipv4_bans.push((src_ip, (expiry - mono_now) / 1_000_000_000));
                            }
                        }
                    }
                }
            }

            if let Some(map) = bpf.map_mut("BLACKLIST_V6") {
                if let Ok(blacklist) = HashMap::<_, [u8; 16], u64>::try_from(map) {
                    for item in blacklist.iter() {
                        if let Ok((ip_raw, expiry)) = item {
                            let src_ip = Ipv6Addr::from(ip_raw);
                            if expiry > mono_now {
                                active_ipv6_bans.push((src_ip, (expiry - mono_now) / 1_000_000_000));
                            }
                        }
                    }
                }
            }

            if let Some(map) = bpf.map_mut("BLACKLIST_MAC") {
                if let Ok(blacklist) = HashMap::<_, [u8; 6], u64>::try_from(map) {
                    for item in blacklist.iter() {
                        if let Ok((mac_raw, expiry)) = item {
                            let mac_str = format!(
                                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                mac_raw[0], mac_raw[1], mac_raw[2],
                                mac_raw[3], mac_raw[4], mac_raw[5]
                            );
                            if expiry > mono_now {
                                active_mac_bans.push((mac_str, (expiry - mono_now) / 1_000_000_000));
                            }
                        }
                    }
                }
            }

            // Auto-detect panic mode thresholds
            if total_pps > config.global_alert_pps {
                if !alert_active {
                    alert_active = true;
                    if let Some(map) = bpf.map_mut("G_CONFIG") {
                        if let Ok(mut g_conf) = Array::<_, GlobalConfig>::try_from(map) {
                            let _ = g_conf.set(0, GlobalConfig {
                                alert_mode: 1,
                                normal_mode_limit: config.normal_mode_limit,
                                panic_mode_limit: config.panic_mode_limit,
                                ban_duration_sec: config.ban_duration_sec,
                                arp_mode_limit: config.arp_mode_limit,
                                mac_mode_limit: config.mac_mode_limit,
                            }, 0);
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
                        if let Some(map) = bpf.map_mut("G_CONFIG") {
                            if let Ok(mut g_conf) = Array::<_, GlobalConfig>::try_from(map) {
                                let _ = g_conf.set(0, GlobalConfig {
                                    alert_mode: 0,
                                    normal_mode_limit: config.normal_mode_limit,
                                    panic_mode_limit: config.panic_mode_limit,
                                    ban_duration_sec: config.ban_duration_sec,
                                    arp_mode_limit: config.arp_mode_limit,
                                    mac_mode_limit: config.mac_mode_limit,
                                }, 0);
                            }
                        }
                    }
                } else {
                    cooldown_seconds = 10;
                }
            }

            // Render premium TUI
            print!("\x1b[2J\x1b[H"); // Clean screen
            println!("\x1b[1;35m╔══════════════════════════════════════════════════════════════════════╗\x1b[0m");
            println!("\x1b[1;35m║             🛡️  HYDRA APEX: KERNEL-LEVEL IPS / WAF             ║\x1b[0m");
            println!("\x1b[1;35m╚══════════════════════════════════════════════════════════════════════╝\x1b[0m");
            
            let status_indicator = if alert_active {
                format!("\x1b[1;91m⚠️  PANIC MODE ACTIVE (Cooldown: {}s)\x1b[0m", cooldown_seconds)
            } else {
                "\x1b[1;92m✅  NORMAL MODE ACTIVE\x1b[0m".to_string()
            };
            
            println!(" ⚙️  Status    : {}   | Interface: \x1b[1;36m{}\x1b[0m", status_indicator, dev);
            println!(" ⚙️  Limits    : Normal: \x1b[1;32m{} PPS\x1b[0m | Panic: \x1b[1;91m{} PPS\x1b[0m | Ban: \x1b[1;33m{}s\x1b[0m | ARP: \x1b[1;91m{} PPS\x1b[0m | MAC: \x1b[1;91m{} PPS\x1b[0m", 
                config.normal_mode_limit, config.panic_mode_limit, config.ban_duration_sec, config.arp_mode_limit, config.mac_mode_limit);
            println!("\x1b[35m╟──────────────────────────────────────────────────────────────────────╢\x1b[0m");
            
            let drop_percentage = if total_pps > 0 {
                (total_dps as f64 / total_pps as f64) * 100.0
            } else {
                0.0
            };
            
            let load_ratio = (total_pps as f64 / config.global_alert_pps as f64).min(1.0);
            let bar_blocks = (load_ratio * 15.0) as usize;
            let mut load_bar = String::new();
            for i in 0..15 {
                if i < bar_blocks {
                    load_bar.push_str("█");
                } else {
                    load_bar.push_str("░");
                }
            }
            let bar_color = if load_ratio > 0.8 { "\x1b[1;91m" } else if load_ratio > 0.4 { "\x1b[1;93m" } else { "\x1b[1;92m" };

            println!(" 📈 Traffic Stats:");
            println!("    - Incoming  : \x1b[1;97m{:>7}\x1b[0m PPS   [{}{}{}\x1b[0m] {:.0}%", total_pps, bar_color, load_bar, if load_ratio >= 1.0 { " FIREWALL PANIC TRIGGERED" } else { "" }, load_ratio * 100.0);
            println!("    - Blocked   : \x1b[1;91m{:>7}\x1b[0m PPS   (Drop Ratio: \x1b[1;93m{:.1}%\x1b[0m)", total_dps, drop_percentage);
            println!("\x1b[35m╟──────────────────────────────────────────────────────────────────────╢\x1b[0m");
            
            println!(" 🚫 ACTIVE BANS DATABASE (Total: {})", active_ipv4_bans.len() + active_ipv6_bans.len() + active_mac_bans.len());
            if active_ipv4_bans.is_empty() && active_ipv6_bans.is_empty() && active_mac_bans.is_empty() {
                println!("    No active bans registered in kernel memory.");
            } else {
                if !active_ipv4_bans.is_empty() {
                    print!("    - IPv4: ");
                    for (ip, rem) in active_ipv4_bans.iter().take(3) {
                        print!("\x1b[1;93m{}\x1b[0m ({}s)  ", ip, rem);
                    }
                    if active_ipv4_bans.len() > 3 { print!("... (+{})", active_ipv4_bans.len() - 3); }
                    println!();
                }
                if !active_ipv6_bans.is_empty() {
                    print!("    - IPv6: ");
                    for (ip, rem) in active_ipv6_bans.iter().take(2) {
                        print!("\x1b[1;93m{}\x1b[0m ({}s)  ", ip, rem);
                    }
                    if active_ipv6_bans.len() > 2 { print!("... (+{})", active_ipv6_bans.len() - 2); }
                    println!();
                }
                if !active_mac_bans.is_empty() {
                    print!("    - MACs: ");
                    for (mac, rem) in active_mac_bans.iter().take(3) {
                        print!("\x1b[1;93m{}\x1b[0m ({}s)  ", mac, rem);
                    }
                    if active_mac_bans.len() > 3 { print!("... (+{})", active_mac_bans.len() - 3); }
                    println!();
                }
            }
            println!("\x1b[35m╟──────────────────────────────────────────────────────────────────────╢\x1b[0m");
            
            println!(" 🔔 DETECTED ATTACK EVENTS & ANOMALIES (Real-time):");
            {
                let alerts = recent_alerts.lock().await;
                if alerts.is_empty() {
                    println!("    \x1b[90mListening for network packets... Standing guard.\x1b[0m");
                } else {
                    for alert in alerts.iter().rev().take(5) {
                        let formatted_alert = alert
                            .replace("Action: DROP", "Action: \x1b[1;91mDROP\x1b[0m")
                            .replace("Action: BAN", "Action: \x1b[1;41;97mBAN\x1b[0m")
                            .replace("Proto: TCP", "Proto: \x1b[1;36mTCP\x1b[0m")
                            .replace("Proto: UDP", "Proto: \x1b[1;33mUDP\x1b[0m")
                            .replace("Proto: ARP", "Proto: \x1b[1;35mARP\x1b[0m");
                        println!("    {}", formatted_alert);
                    }
                }
            }
            println!("\x1b[1;35m╚══════════════════════════════════════════════════════════════════════╝\x1b[0m");
        }
    });

    signal::ctrl_c().await?;
    println!("\n[NYX] Shutting down L2/L3/L4 Apex Shield. Restoring defaults.");
    Ok(())
}
