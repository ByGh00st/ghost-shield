#![no_std]

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct LpmKey {
    pub prefixlen: u32,
    pub data: [u8; 4],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct LpmKeyV6 {
    pub prefixlen: u32,
    pub data: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GlobalConfig {
    pub alert_mode: u32,
    pub normal_mode_limit: u32,
    pub panic_mode_limit: u32,
    pub ban_duration_sec: u64,
    pub arp_mode_limit: u32,
    pub mac_mode_limit: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GlobalStats {
    pub pkt_count: u64,
    pub drop_count: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IPStats {
    pub pkt_count: u32,
    pub last_ts: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MitigationEvent {
    pub src_ip: [u8; 16],
    pub src_mac: [u8; 6],
    pub dest_port: u16,
    pub protocol: u8,   // 1=ICMP, 6=TCP, 17=UDP, 20=ARP, 58=ICMPv6
    pub action: u8,     // 1=DROP, 2=BAN
    pub ip_version: u8, // 4=IPv4, 6=IPv6, 0=Non-IP (ARP/RAW MAC)
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LpmKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for LpmKeyV6 {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for GlobalConfig {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for GlobalStats {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for IPStats {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for MitigationEvent {}
