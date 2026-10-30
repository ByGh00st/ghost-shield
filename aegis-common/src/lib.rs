#![cfg_attr(not(test), no_std)]

/// Mitigation actions emitted by Ring 0 XDP data path.
pub const ACTION_DROP: u8 = 1;
pub const ACTION_BAN: u8 = 2;

/// IP version / frame classification tags in [`MitigationEvent`].
pub const EVENT_VER_L2: u8 = 0;
pub const EVENT_VER_IPV4: u8 = 4;
pub const EVENT_VER_IPV6: u8 = 6;
pub const EVENT_VER_ARP: u8 = 20;

/// Synthetic protocol identifiers for L2 events.
pub const PROTO_L2_RAW: u8 = 0;
pub const PROTO_ARP: u8 = 20;

/// Default burst tolerance (500 ms) allowing legitimate TSO/GRO micro-bursts.
pub const DEFAULT_BURST_NS: u64 = 500_000_000;
/// Tighter burst tolerance (250 ms) for unverified TCP SYN packets.
pub const SYN_BURST_NS: u64 = 250_000_000;
/// Violation strike decay window (2 seconds of quiet resets strikes).
pub const STRIKE_DECAY_NS: u64 = 2_000_000_000;

/// Placeholder header written by `aegis/build.rs` when the eBPF ELF has not been compiled yet.
pub const DUMMY_EBPF_MAGIC: &[u8; 16] = b"NYX_DUMMY_EBPF00";

/// Outcome of a single Generic Cell Rate Algorithm (GCRA) evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GcraVerdict {
    Pass,
    DropOnly { emit_alert: bool },
    BanAndDrop,
}

/// Global runtime configuration shared between Ring 3 controller and Ring 0 XDP filter.
///
/// Layout: 56 bytes, 8-byte aligned, zero implicit padding.
/// Emission intervals (`*_interval_ns`) are precomputed in Ring 3 (`1_000_000_000 / limit_pps`)
/// to eliminate 64-bit integer divisions (`BPF_DIV64`) from the Ring 0 XDP hot path.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug)]
pub struct GlobalConfig {
    /// `0` = Normal Mode, `1` = Panic Mode
    pub alert_mode: u32,
    /// Currently active IP PPS threshold (informational)
    pub active_ip_pps: u32,
    /// Precomputed GCRA emission interval (ns) for IPv4/IPv6 in Normal Mode
    pub normal_interval_ns: u64,
    /// Precomputed GCRA emission interval (ns) for IPv4/IPv6 in Panic Mode
    pub panic_interval_ns: u64,
    /// Precomputed GCRA emission interval (ns) for ARP frames per source MAC
    pub arp_interval_ns: u64,
    /// Precomputed GCRA emission interval (ns) for L2 frames per source MAC
    pub mac_interval_ns: u64,
    /// Hard blacklist duration in nanoseconds
    pub ban_duration_ns: u64,
    /// Excess violations required after burst exhaustion before hard blacklisting
    pub ban_strike_threshold: u32,
    /// `1` = enable stateless TCP SYN anti-spoofing protection (drop excess SYNs without IP ban)
    pub spoof_protection: u32,
}

/// Per-CPU global packet and protocol telemetry counters.
///
/// Layout: 48 bytes, 8-byte aligned, zero implicit padding.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default)]
pub struct GlobalStats {
    pub pkt_count: u64,
    pub drop_count: u64,
    pub ipv4_count: u64,
    pub ipv6_count: u64,
    pub arp_count: u64,
    pub malformed_count: u64,
}

/// Generic Cell Rate Algorithm (GCRA) state with progressive strike tracking.
///
/// Replaces lossy integer-division Token Bucket to prevent sub-quantum truncation starvation.
/// Layout: 24 bytes, 8-byte aligned, zero implicit padding.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug)]
pub struct GcraState {
    /// Theoretical Arrival Time (ns) in `CLOCK_MONOTONIC`
    pub tat_ns: u64,
    /// Timestamp (ns) of the most recent rate-limit violation
    pub last_violation_ns: u64,
    /// Accumulated violations within the active decay window
    pub strikes: u32,
    /// Explicit zeroed alignment padding
    pub _pad: u32,
}

/// Security telemetry record transmitted from Ring 0 (`BPF_MAP_TYPE_RINGBUF`) to Ring 3.
///
/// Layout: 32 bytes, 8-byte aligned, zero implicit padding.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug)]
pub struct MitigationEvent {
    pub src_ip: [u8; 16],
    pub src_mac: [u8; 6],
    pub dest_port: u16,
    pub vlan_id: u16,
    pub protocol: u8,
    pub action: u8,
    pub ip_version: u8,
    /// Explicit zeroed tail padding — guarantees `aya::Pod` soundness and eBPF stack safety
    pub _pad: [u8; 3],
}

/// Evaluates Generic Cell Rate Algorithm (GCRA) over a raw [`GcraState`] pointer without
/// creating `&mut GcraState` references (eliminating SMP Rust `noalias` UB) and without
/// 64-bit integer divisions (`BPF_DIV64`) in the hot path.
///
/// # Safety
/// `st` must be a valid, 8-byte aligned pointer to a [`GcraState`] allocation.
#[inline(always)]
pub unsafe fn evaluate_gcra_raw(
    st: *mut GcraState,
    now: u64,
    interval_ns: u64,
    burst_ns: u64,
    strike_threshold: u32,
    stateless_drop_only: bool,
) -> GcraVerdict {
    let tat = unsafe { (&raw const (*st).tat_ns).read_volatile() };
    let allow_horizon = now.saturating_add(burst_ns);

    if tat <= allow_horizon {
        let base = if tat > now { tat } else { now };
        let next_tat = base.saturating_add(interval_ns);
        unsafe {
            (&raw mut (*st).tat_ns).write_volatile(next_tat);
        }
        return GcraVerdict::Pass;
    }

    let last_viol = unsafe { (&raw const (*st).last_violation_ns).read_volatile() };
    let prev_strikes = unsafe { (&raw const (*st).strikes).read_volatile() };
    let strikes = if now.saturating_sub(last_viol) > STRIKE_DECAY_NS {
        1
    } else {
        prev_strikes.saturating_add(1)
    };

    unsafe {
        (&raw mut (*st).last_violation_ns).write_volatile(now);
    }

    if stateless_drop_only {
        unsafe {
            (&raw mut (*st).strikes).write_volatile(strikes);
        }
        return GcraVerdict::DropOnly {
            emit_alert: strikes == 1,
        };
    }

    let threshold = if strike_threshold == 0 { 1 } else { strike_threshold };
    if strikes >= threshold {
        unsafe {
            (&raw mut (*st).strikes).write_volatile(0);
        }
        GcraVerdict::BanAndDrop
    } else {
        unsafe {
            (&raw mut (*st).strikes).write_volatile(strikes);
        }
        GcraVerdict::DropOnly {
            emit_alert: strikes == 1,
        }
    }
}

const _: () = {
    assert!(core::mem::size_of::<GlobalConfig>() == 56);
    assert!(core::mem::align_of::<GlobalConfig>() == 8);
    assert!(core::mem::size_of::<GlobalStats>() == 48);
    assert!(core::mem::align_of::<GlobalStats>() == 8);
    assert!(core::mem::size_of::<GcraState>() == 24);
    assert!(core::mem::align_of::<GcraState>() == 8);
    assert!(core::mem::size_of::<MitigationEvent>() == 32);
    assert!(core::mem::align_of::<MitigationEvent>() == 8);
};

#[cfg(feature = "user")]
unsafe impl aya::Pod for GlobalConfig {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for GlobalStats {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for GcraState {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for MitigationEvent {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn abi_layouts_have_zero_implicit_padding() {
        assert_eq!(size_of::<MitigationEvent>(), 32);
        assert_eq!(align_of::<MitigationEvent>(), 8);
        assert_eq!(offset_of!(MitigationEvent, src_ip), 0);
        assert_eq!(offset_of!(MitigationEvent, src_mac), 16);
        assert_eq!(offset_of!(MitigationEvent, dest_port), 22);
        assert_eq!(offset_of!(MitigationEvent, vlan_id), 24);
        assert_eq!(offset_of!(MitigationEvent, protocol), 26);
        assert_eq!(offset_of!(MitigationEvent, action), 27);
        assert_eq!(offset_of!(MitigationEvent, ip_version), 28);
        assert_eq!(offset_of!(MitigationEvent, _pad), 29);

        assert_eq!(size_of::<GcraState>(), 24);
        assert_eq!(align_of::<GcraState>(), 8);
    }

    #[test]
    fn gcra_eliminates_subquantum_truncation_starvation() {
        // Panic Mode limit = 200 PPS -> interval = 5_000_000 ns (5 ms).
        // Jittered 187.5 PPS traffic (4.9 ms, 4.9 ms, 6.2 ms repeating = 3 pkts / 16 ms)
        // previously starved the integer-division token bucket in 0.8s.
        let interval_ns = 5_000_000u64;
        let mut now = 1_000_000_000u64;
        let mut state = GcraState {
            tat_ns: now + interval_ns,
            last_violation_ns: 0,
            strikes: 0,
            _pad: 0,
        };

        let gaps = [4_900_000u64, 4_900_000u64, 6_200_000u64];
        for i in 0..10_000 {
            now += gaps[i % 3];
            let verdict = unsafe {
                evaluate_gcra_raw(&raw mut state, now, interval_ns, DEFAULT_BURST_NS, 32, false)
            };
            assert_eq!(verdict, GcraVerdict::Pass, "False positive at packet {}", i);
        }
    }

    #[test]
    fn gcra_stateless_syn_guard_drops_excess_without_blacklisting() {
        let interval_ns = 1_000_000u64; // 1000 PPS -> 1 ms
        let now = 5_000_000_000u64;
        let mut state = GcraState {
            tat_ns: now + interval_ns,
            last_violation_ns: 0,
            strikes: 0,
            _pad: 0,
        };

        // Exhaust 250 ms SYN burst (250 packets at t = now)
        for _ in 0..250 {
            let v = unsafe {
                evaluate_gcra_raw(&raw mut state, now, interval_ns, SYN_BURST_NS, 8, true)
            };
            assert_eq!(v, GcraVerdict::Pass);
        }

        // Next 500 excess SYNs must all return DropOnly (never BanAndDrop) and emit alert once
        for i in 0..500 {
            let v = unsafe {
                evaluate_gcra_raw(&raw mut state, now, interval_ns, SYN_BURST_NS, 8, true)
            };
            assert_eq!(
                v,
                GcraVerdict::DropOnly {
                    emit_alert: i == 0
                }
            );
        }
    }

    #[test]
    fn gcra_escalates_sustained_flood_to_ban_and_decays_after_quiet_window() {
        let interval_ns = 5_000_000u64; // 200 PPS
        let mut now = 10_000_000_000u64;
        let mut state = GcraState {
            tat_ns: now + DEFAULT_BURST_NS + interval_ns, // already saturated
            last_violation_ns: 0,
            strikes: 0,
            _pad: 0,
        };

        // 3 strikes below threshold=4 -> DropOnly
        for i in 0..3 {
            let v = unsafe {
                evaluate_gcra_raw(&raw mut state, now, interval_ns, DEFAULT_BURST_NS, 4, false)
            };
            assert_eq!(
                v,
                GcraVerdict::DropOnly {
                    emit_alert: i == 0
                }
            );
        }

        // Wait > 2s (STRIKE_DECAY_NS), advance `tat_ns` manually to simulate saturated bucket again
        now += STRIKE_DECAY_NS + 1_000_000;
        state.tat_ns = now + DEFAULT_BURST_NS + interval_ns;

        // Strikes decayed back to 1 (emits fresh alert, does NOT ban on strike 1)
        let v1 = unsafe {
            evaluate_gcra_raw(&raw mut state, now, interval_ns, DEFAULT_BURST_NS, 4, false)
        };
        assert_eq!(v1, GcraVerdict::DropOnly { emit_alert: true });

        // Strikes 2, 3 -> DropOnly(false); Strike 4 -> BanAndDrop!
        assert_eq!(
            unsafe {
                evaluate_gcra_raw(&raw mut state, now, interval_ns, DEFAULT_BURST_NS, 4, false)
            },
            GcraVerdict::DropOnly { emit_alert: false }
        );
        assert_eq!(
            unsafe {
                evaluate_gcra_raw(&raw mut state, now, interval_ns, DEFAULT_BURST_NS, 4, false)
            },
            GcraVerdict::DropOnly { emit_alert: false }
        );
        assert_eq!(
            unsafe {
                evaluate_gcra_raw(&raw mut state, now, interval_ns, DEFAULT_BURST_NS, 4, false)
            },
            GcraVerdict::BanAndDrop
        );
    }
}
