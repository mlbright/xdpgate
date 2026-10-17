//! What the XDP program and the CLIs must agree on, byte for byte: the pinned
//! maps and their key and value layouts. These are frozen - a gate that is
//! already running owns maps in exactly this shape, and the next attach reuses
//! them by name - so any change here is a breaking change to installed gates.
//!
//! Addresses and ports in keys are in network byte order, so the XDP program
//! can compare them straight against the packet headers.

/// Where the maps are pinned, by name.
pub const pin_dir = "/sys/fs/bpf/xdpgate";

pub const protected_v4 = "protected_v4";
pub const protected_v6 = "protected_v6";
pub const allow_v4 = "allow_v4";
pub const allow_v6 = "allow_v6";

/// Capacity of each protected map, and so of each family of the declared
/// protected set.
pub const protected_max_entries = 256;
/// Capacity of each grant map.
pub const grant_max_entries = 4096;

/// fwknopd's UDP port: the SPA carve-out lets knocks to it through to any
/// address, protected or not.
pub const spa_port: u16 = 62159;

/// Whether ICMP may reach the protected set. Off means strict deny, which also
/// blackholes path MTU discovery to protected addresses (see README).
pub const allow_icmp_to_protected = false;

pub const ipproto_icmp: u8 = 1;
pub const ipproto_tcp: u8 = 6;
pub const ipproto_udp: u8 = 17;
pub const ipproto_icmpv6: u8 = 58;

/// Key of protected_v6. protected_v4 is keyed by the bare u32 address.
pub const ProtectedKey6 = extern struct {
    addr: [16]u8,
};

/// Key of allow_v4: a grant is for one source address, protocol and port.
/// Packed, so no padding byte can make two equal grants hash differently.
pub const GrantKey4 = extern struct {
    saddr: u32 align(1),
    dport: u16 align(1),
    proto: u8,
};

/// Key of allow_v6.
pub const GrantKey6 = extern struct {
    saddr: [16]u8,
    dport: u16 align(1),
    proto: u8,
};

/// Value of allow_v4 and allow_v6: when the grant expires, in CLOCK_MONOTONIC
/// nanoseconds (what the XDP program reads from bpf_ktime_get_ns). Zero means
/// it never expires.
pub const GrantExpiry = extern struct {
    expiry_ns: u64,
};

/// Value of the protected maps; only the key matters.
pub const protected_value: u8 = 1;

comptime {
    const assert = @import("std").debug.assert;
    assert(@sizeOf(ProtectedKey6) == 16);
    assert(@sizeOf(GrantKey4) == 7);
    assert(@offsetOf(GrantKey4, "dport") == 4);
    assert(@offsetOf(GrantKey4, "proto") == 6);
    assert(@sizeOf(GrantKey6) == 19);
    assert(@offsetOf(GrantKey6, "dport") == 16);
    assert(@offsetOf(GrantKey6, "proto") == 18);
    assert(@sizeOf(GrantExpiry) == 8);
}
