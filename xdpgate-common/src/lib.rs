//! The layout the XDP program and the CLIs share through the pinned maps.
//!
//! Everything here is frozen byte for byte: a gate built from any earlier
//! version, C included, may still own the pins when a new `xdpgate-ctl` runs.
//! The keys are read raw by the kernel's hash maps, so they are packed (padding
//! bytes would break key matching), and addresses and ports are in network
//! byte order, so they compare directly against the packet headers.
#![no_std]
#![forbid(unsafe_code)]

use core::ffi::CStr;

/// Where the four maps are pinned, each under its own name.
pub const PIN_DIR: &CStr = c"/sys/fs/bpf/xdpgate";

/// The protected set, one map per address family.
pub const PROTECTED_V4: &CStr = c"protected_v4";
pub const PROTECTED_V6: &CStr = c"protected_v6";
/// Grants, one map per address family.
pub const ALLOW_V4: &CStr = c"allow_v4";
pub const ALLOW_V6: &CStr = c"allow_v6";

/// Capacity of each protected map. Raise it here and rebuild if you genuinely
/// need more.
pub const PROTECTED_MAX_ENTRIES: usize = 256;
/// Capacity of each grant map.
pub const GRANT_MAX_ENTRIES: usize = 4096;

/// Every map is a hash map that libbpf pins by name.
pub const BPF_MAP_TYPE_HASH: usize = 1;
pub const LIBBPF_PIN_BY_NAME: usize = 1;

/// The SPA carve-out: UDP to this port reaches every address, protected or
/// not, so fwknopd always receives the knocks that open everything else.
pub const SPA_PORT: u16 = 62159;

/// Whether ICMP and ICMPv6 may reach protected addresses. Off, it also drops
/// path-MTU messages to them (see README); NDP is link-local and unaffected.
pub const ALLOW_ICMP_TO_PROTECTED: bool = false;

pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

/// A protected IPv4 address: the key of `protected_v4`, as on the wire.
pub type ProtectedKey4 = u32;

/// A protected IPv6 address: the key of `protected_v6`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProtectedKey6 {
    pub addr: [u8; 16],
}

/// Value of both protected maps. Only the key's presence matters.
pub type ProtectedValue = u8;

/// What a grant opens on IPv4: one source, one protocol, one port. The key of
/// `allow_v4`.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantKey4 {
    /// Source address, as on the wire.
    pub saddr: u32,
    /// Destination port, network byte order.
    pub dport: u16,
    /// `IPPROTO_TCP` or `IPPROTO_UDP`.
    pub proto: u8,
}

/// What a grant opens on IPv6. The key of `allow_v6`.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantKey6 {
    pub saddr: [u8; 16],
    /// Destination port, network byte order.
    pub dport: u16,
    pub proto: u8,
}

/// When a grant expires: the value of both grant maps.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantExpiry {
    /// Absolute `CLOCK_MONOTONIC` nanoseconds, compared against
    /// `bpf_ktime_get_ns()`. 0 means the grant never expires.
    pub expiry_ns: u64,
}

const _: () = assert!(size_of::<ProtectedKey4>() == 4);
const _: () = assert!(size_of::<ProtectedKey6>() == 16);
const _: () = assert!(size_of::<ProtectedValue>() == 1);
const _: () = assert!(size_of::<GrantKey4>() == 7);
const _: () = assert!(size_of::<GrantKey6>() == 19);
const _: () = assert!(size_of::<GrantExpiry>() == 8);
