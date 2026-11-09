//! The XDP gate: default deny for protected destination addresses.
//!
//! Decision order for every inbound packet:
//!   1. Non-IP (ARP, etc.)               -> PASS (don't break the LAN)
//!   2. SPA port (any destination)       -> PASS (the SPA carve-out)
//!   3. Destination not protected        -> PASS (only the protected set is gated)
//!   4. Destination protected:
//!        - a grant for (source, protocol, port) that has not expired -> PASS
//!        - otherwise                                                  -> DROP
//!
//! The SPA carve-out comes before the protected lookup, so a knock survives
//! even when it shares an address with a protected service, and fwknopd (which
//! sniffs via AF_PACKET, downstream of XDP) always receives the knock that
//! opens everything else. Management traffic (SSH, WireGuard/Tailscale, etc.)
//! is expected to live on separate, unprotected addresses and is never gated.
//!
//! No crates beyond xdpgate-common, not even aya-ebpf; ADR 0002 says why.
#![no_std]
#![no_main]
// The TCP and UDP branches stay parallel, the way the decision order reads.
#![allow(clippy::collapsible_if)]

use core::ffi::c_void;

use xdpgate_common::{
    ALLOW_ICMP_TO_PROTECTED, BPF_MAP_TYPE_HASH, GRANT_MAX_ENTRIES, GrantExpiry, GrantKey4,
    GrantKey6, IPPROTO_TCP, IPPROTO_UDP, LIBBPF_PIN_BY_NAME, PROTECTED_MAX_ENTRIES, ProtectedKey4,
    ProtectedKey6, ProtectedValue, SPA_PORT,
};

// ---- what the kernel provides ------------------------------------------------
// The two XDP return codes, the context (struct xdp_md), and the two helpers,
// called by their stable IDs (BPF_FUNC_map_lookup_elem = 1,
// BPF_FUNC_ktime_get_ns = 5).

const XDP_DROP: u32 = 1;
const XDP_PASS: u32 = 2;

#[repr(C)]
pub struct XdpMd {
    data: u32,
    data_end: u32,
    data_meta: u32,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    egress_ifindex: u32,
}

#[inline(always)]
unsafe fn bpf_map_lookup_elem(map: *mut c_void, key: *const c_void) -> *mut c_void {
    let f: unsafe extern "C" fn(*mut c_void, *const c_void) -> *mut c_void =
        unsafe { core::mem::transmute(1usize) };
    unsafe { f(map, key) }
}

#[inline(always)]
unsafe fn bpf_ktime_get_ns() -> u64 {
    let f: unsafe extern "C" fn() -> u64 = unsafe { core::mem::transmute(5usize) };
    unsafe { f() }
}

// ---- the maps ----------------------------------------------------------------

/// A BTF map definition, written the way libbpf's own C macros produce it:
///
/// ```c
/// struct { __uint(type, BPF_MAP_TYPE_HASH); __type(key, K); __type(value, V);
///          __uint(max_entries, MAX); __uint(pinning, LIBBPF_PIN_BY_NAME); }
/// ```
///
/// libbpf reads each `__uint` from the length of the array a field points to,
/// and each `__type` from the pointee. The build checks the result through
/// libbpf (`check-object`), since nothing else would notice a mistake here.
#[repr(C)]
pub struct PinnedHash<K, V, const MAX: usize> {
    r#type: *const [i32; BPF_MAP_TYPE_HASH],
    key: *const K,
    value: *const V,
    max_entries: *const [i32; MAX],
    pinning: *const [i32; LIBBPF_PIN_BY_NAME],
}

unsafe impl<K, V, const MAX: usize> Sync for PinnedHash<K, V, MAX> {}

impl<K, V, const MAX: usize> PinnedHash<K, V, MAX> {
    const fn new() -> Self {
        Self {
            r#type: core::ptr::null(),
            key: core::ptr::null(),
            value: core::ptr::null(),
            max_entries: core::ptr::null(),
            pinning: core::ptr::null(),
        }
    }

    #[inline(always)]
    fn get(&self, key: &K) -> Option<*const V> {
        let p = unsafe {
            bpf_map_lookup_elem(
                self as *const Self as *mut c_void,
                key as *const K as *const c_void,
            )
        };
        if p.is_null() {
            None
        } else {
            Some(p as *const V)
        }
    }
}

// The names are the pins' names under /sys/fs/bpf/xdpgate, and must match
// xdpgate_common::{PROTECTED_V4, ...}; check-object fails the build otherwise.

#[unsafe(link_section = ".maps")]
#[unsafe(export_name = "protected_v4")]
static PROTECTED_V4: PinnedHash<ProtectedKey4, ProtectedValue, PROTECTED_MAX_ENTRIES> =
    PinnedHash::new();

#[unsafe(link_section = ".maps")]
#[unsafe(export_name = "protected_v6")]
static PROTECTED_V6: PinnedHash<ProtectedKey6, ProtectedValue, PROTECTED_MAX_ENTRIES> =
    PinnedHash::new();

#[unsafe(link_section = ".maps")]
#[unsafe(export_name = "allow_v4")]
static ALLOW_V4: PinnedHash<GrantKey4, GrantExpiry, GRANT_MAX_ENTRIES> = PinnedHash::new();

#[unsafe(link_section = ".maps")]
#[unsafe(export_name = "allow_v6")]
static ALLOW_V6: PinnedHash<GrantKey6, GrantExpiry, GRANT_MAX_ENTRIES> = PinnedHash::new();

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static _license: [u8; 4] = *b"GPL\0";

// ---- the program -------------------------------------------------------------

const ETH_HLEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;
const IPV4_HLEN: usize = 20;
const IPV6_HLEN: usize = 40;
const TCP_HLEN: usize = 20;
const UDP_HLEN: usize = 8;

/// Reads a header field. The caller has bounds-checked `addr` against
/// `data_end`, which is what the verifier requires.
#[inline(always)]
unsafe fn rd<T: Copy>(addr: usize) -> T {
    unsafe { core::ptr::read_unaligned(addr as *const T) }
}

#[inline(always)]
fn spa_carve_out(proto: u8, dport_be: u16) -> bool {
    proto == IPPROTO_UDP && dport_be == SPA_PORT.to_be()
}

#[inline(always)]
fn is_expired(grant: *const GrantExpiry) -> bool {
    // 0 means "never". Otherwise fail closed once we pass it.
    let expiry = unsafe { (*grant).expiry_ns };
    expiry != 0 && unsafe { bpf_ktime_get_ns() } > expiry
}

#[inline(always)]
fn handle_v4(end: usize, iph: usize) -> u32 {
    if iph + IPV4_HLEN > end {
        return XDP_PASS;
    }
    let version_ihl: u8 = unsafe { rd(iph) };
    let ihl = ((version_ihl & 0x0f) as usize) * 4;
    if ihl < IPV4_HLEN || iph + ihl > end {
        return XDP_PASS;
    }

    let proto: u8 = unsafe { rd(iph + 9) };
    let daddr: u32 = unsafe { rd(iph + 16) }; // network order
    let saddr: u32 = unsafe { rd(iph + 12) };
    let frag_off: u16 = unsafe { rd(iph + 6) };
    let l4 = iph + ihl;

    // Non-first fragments carry no L4 header, so no port to match.
    let is_frag_tail = (frag_off & 0x1FFFu16.to_be()) != 0;

    let mut dport: u16 = 0;
    let mut have_ports = false;
    if !is_frag_tail {
        if proto == IPPROTO_TCP {
            if l4 + TCP_HLEN <= end {
                dport = unsafe { rd(l4 + 2) };
                have_ports = true;
            }
        } else if proto == IPPROTO_UDP {
            if l4 + UDP_HLEN <= end {
                dport = unsafe { rd(l4 + 2) };
                have_ports = true;
            }
        }
    }

    if have_ports && spa_carve_out(proto, dport) {
        return XDP_PASS;
    }

    if PROTECTED_V4.get(&daddr).is_none() {
        return XDP_PASS; // not a protected destination
    }

    // The destination is protected: default deny.
    if !have_ports {
        if proto == IPPROTO_ICMP && ALLOW_ICMP_TO_PROTECTED {
            return XDP_PASS;
        }
        return XDP_DROP; // ICMP, fragment tail or unknown L4
    }

    let key = GrantKey4 {
        saddr,
        dport,
        proto,
    };
    match ALLOW_V4.get(&key) {
        Some(grant) if !is_expired(grant) => XDP_PASS,
        _ => XDP_DROP,
    }
}

#[inline(always)]
fn handle_v6(end: usize, ip6h: usize) -> u32 {
    if ip6h + IPV6_HLEN > end {
        return XDP_PASS;
    }
    let proto: u8 = unsafe { rd(ip6h + 6) }; // only the direct-L4 case is parsed
    let l4 = ip6h + IPV6_HLEN;

    let mut dport: u16 = 0;
    let mut have_ports = false;
    if proto == IPPROTO_TCP {
        if l4 + TCP_HLEN <= end {
            dport = unsafe { rd(l4 + 2) };
            have_ports = true;
        }
    } else if proto == IPPROTO_UDP {
        if l4 + UDP_HLEN <= end {
            dport = unsafe { rd(l4 + 2) };
            have_ports = true;
        }
    }

    if have_ports && spa_carve_out(proto, dport) {
        return XDP_PASS;
    }

    let daddr = ProtectedKey6 {
        addr: unsafe { rd(ip6h + 24) },
    };
    if PROTECTED_V6.get(&daddr).is_none() {
        return XDP_PASS;
    }

    if !have_ports {
        // Extension headers also land here.
        if proto == IPPROTO_ICMPV6 && ALLOW_ICMP_TO_PROTECTED {
            return XDP_PASS;
        }
        return XDP_DROP;
    }

    let key = GrantKey6 {
        saddr: unsafe { rd(ip6h + 8) },
        dport,
        proto,
    };
    match ALLOW_V6.get(&key) {
        Some(grant) if !is_expired(grant) => XDP_PASS,
        _ => XDP_DROP,
    }
}

/// The program, in the `xdp` section, which is how libbpf knows its type.
///
/// # Safety
///
/// Called only by the kernel, with a valid `ctx`.
#[unsafe(no_mangle)]
#[unsafe(link_section = "xdp")]
pub unsafe extern "C" fn xdpgate(ctx: *mut XdpMd) -> u32 {
    let data = unsafe { (*ctx).data } as usize;
    let end = unsafe { (*ctx).data_end } as usize;
    if data + ETH_HLEN > end {
        return XDP_PASS;
    }
    let h_proto: u16 = unsafe { rd(data + 12) };
    if h_proto == ETH_P_IP.to_be() {
        return handle_v4(end, data + ETH_HLEN);
    }
    if h_proto == ETH_P_IPV6.to_be() {
        return handle_v6(end, data + ETH_HLEN);
    }
    XDP_PASS // ARP and everything non-IP
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
