//! The XDP gate: default deny for the protected set.
//!
//! Decision order for every inbound packet:
//!   1. Non-IP (ARP, etc.)               -> PASS (don't break the LAN)
//!   2. SPA port (any dest)              -> PASS (the SPA carve-out)
//!   3. Destination not in protected set -> PASS (we only gate those IPs)
//!   4. Destination IS protected:
//!        - a grant for (src,proto,dport) that has not expired -> PASS
//!        - otherwise                                           -> DROP
//!
//! The SPA carve-out is checked BEFORE the protected lookup so the SPA packet
//! survives even when it shares an IP with a protected service. This is also
//! why fwknopd (which sniffs via AF_PACKET, downstream of XDP) can still
//! receive the SPA that authorises everything else. Management traffic (SSH,
//! WireGuard/Tailscale, etc.) is expected to live on separate, non-protected
//! IPs and is therefore never gated in the first place.
//!
//! Zig 0.17.0 cannot emit an object libbpf will load as-is; tools/bpf_fixup.zig
//! repairs it after the build (docs/adr/0001-xdp-program-in-zig-with-object-fixup.md).
//! Only ReleaseSmall builds load: Debug overflows the BPF stack, and ReleaseSafe's
//! checks are rejected by the verifier.
const std = @import("std");
const layout = @import("layout");
const helpers = std.os.linux.BPF.kern.helpers;

const XDP_DROP: c_int = 1;
const XDP_PASS: c_int = 2;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;

/// bpf_htons() of a constant.
inline fn htons(comptime x: u16) u16 {
    return comptime std.mem.nativeToBig(u16, x);
}

// ---- maps -------------------------------------------------------------------

/// A libbpf BTF map definition: __uint(name, N) is a pointer to an array of N
/// ints and __type(name, T) a pointer to T. The fields are [*c] pointers
/// because Zig's ?*T comes out of the BTF as a typedef libbpf does not follow.
fn HashMapDef(comptime K: type, comptime V: type, comptime max_entries: u32) type {
    const BPF_MAP_TYPE_HASH = 1;
    const LIBBPF_PIN_BY_NAME = 1;
    return extern struct {
        type: [*c]const [BPF_MAP_TYPE_HASH]c_int = null,
        max_entries: [*c]const [max_entries]c_int = null,
        key: [*c]const K = null,
        value: [*c]const V = null,
        pinning: [*c]const [LIBBPF_PIN_BY_NAME]c_int = null,
    };
}

fn Map(comptime name: []const u8, comptime Def: type) type {
    return struct {
        var def: Def = .{};
        comptime {
            @export(&def, .{ .name = name, .section = ".maps" });
        }

        /// The map is named in inline assembly so that the ld_imm64 is
        /// relocated against the map's own symbol, which is how libbpf tells
        /// the maps apart. Zig would otherwise relocate every lookup against
        /// the .maps section, and libbpf would bind them all to one map.
        inline fn lookup(key: anytype) ?*anyopaque {
            const m = asm ("%[ret] = " ++ name ++ " ll"
                : [ret] "=r" (-> *const std.os.linux.BPF.kern.MapDef),
            );
            return helpers.map_lookup_elem(m, @ptrCast(key));
        }
    };
}

const max_protected = layout.protected_max_entries;
const max_grants = layout.grant_max_entries;
const protected_v4 = Map(layout.protected_v4, HashMapDef(u32, u8, max_protected));
const protected_v6 = Map(layout.protected_v6, HashMapDef(layout.ProtectedKey6, u8, max_protected));
const allow_v4 = Map(layout.allow_v4, HashMapDef(layout.GrantKey4, layout.GrantExpiry, max_grants));
const allow_v6 = Map(layout.allow_v6, HashMapDef(layout.GrantKey6, layout.GrantExpiry, max_grants));

// ---- packet headers (as in the kernel UAPI, little-endian bitfields) --------

const xdp_md = extern struct {
    data: u32,
    data_end: u32,
    data_meta: u32,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    egress_ifindex: u32,
};

const ethhdr = extern struct {
    h_dest: [6]u8,
    h_source: [6]u8,
    h_proto: u16 align(1),
};

const iphdr = extern struct {
    ihl_version: u8, // ihl is the low nibble
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32,
    daddr: u32,
};

const ipv6hdr = extern struct {
    version_flow: [4]u8,
    payload_len: u16,
    nexthdr: u8,
    hop_limit: u8,
    saddr: [16]u8 align(4),
    daddr: [16]u8 align(4),
};

const tcphdr = extern struct {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    flags: u16,
    window: u16,
    check: u16,
    urg_ptr: u16,
};

const udphdr = extern struct {
    source: u16,
    dest: u16,
    len: u16,
    check: u16,
};

// ---- the gate ---------------------------------------------------------------

inline fn isSpaCarveOut(proto: u8, dport_be: u16) bool {
    return proto == layout.ipproto_udp and dport_be == htons(layout.spa_port);
}

inline fn isExpired(grant: *const layout.GrantExpiry) bool {
    // expiry_ns == 0 means "never". Otherwise fail-closed once we pass it.
    return grant.expiry_ns != 0 and helpers.ktime_get_ns() > grant.expiry_ns;
}

const Ports = struct { dport: u16 = 0, present: bool = false };

/// The destination port, if the L4 header is TCP or UDP and fits the packet.
inline fn destPort(proto: u8, l4: usize, data_end: usize) Ports {
    if (proto == layout.ipproto_tcp) {
        if (l4 + @sizeOf(tcphdr) <= data_end) {
            const th: *const tcphdr = @ptrFromInt(l4);
            return .{ .dport = th.dest, .present = true };
        }
    } else if (proto == layout.ipproto_udp) {
        if (l4 + @sizeOf(udphdr) <= data_end) {
            const uh: *const udphdr = @ptrFromInt(l4);
            return .{ .dport = uh.dest, .present = true };
        }
    }
    return .{};
}

inline fn handleV4(ip: usize, data_end: usize) c_int {
    if (ip + @sizeOf(iphdr) > data_end) return XDP_PASS;
    const iph: *const iphdr = @ptrFromInt(ip);

    const ihl = @as(u32, iph.ihl_version & 0x0f) * 4;
    if (ihl < @sizeOf(iphdr) or ip + ihl > data_end) return XDP_PASS;

    const proto = iph.protocol;
    var daddr = iph.daddr; // network order

    // Non-first fragments carry no L4 header -> no port to match.
    const is_frag_tail = (iph.frag_off & htons(0x1FFF)) != 0;
    const p: Ports = if (is_frag_tail) .{} else destPort(proto, ip + ihl, data_end);

    if (p.present and isSpaCarveOut(proto, p.dport)) return XDP_PASS;

    if (protected_v4.lookup(&daddr) == null)
        return XDP_PASS; // not a gated destination

    // Destination is protected: default deny.
    if (!p.present) {
        if (proto == layout.ipproto_icmp and layout.allow_icmp_to_protected)
            return XDP_PASS;
        return XDP_DROP; // ICMP / frag-tail / unknown L4
    }

    var key: layout.GrantKey4 = .{ .saddr = iph.saddr, .dport = p.dport, .proto = proto };
    const grant: *const layout.GrantExpiry = @ptrCast(@alignCast(
        allow_v4.lookup(&key) orelse return XDP_DROP,
    ));
    if (isExpired(grant)) return XDP_DROP;
    return XDP_PASS;
}

inline fn handleV6(ip: usize, data_end: usize) c_int {
    if (ip + @sizeOf(ipv6hdr) > data_end) return XDP_PASS;
    const ip6h: *const ipv6hdr = @ptrFromInt(ip);

    const proto = ip6h.nexthdr; // only the direct-L4 case is parsed
    const p = destPort(proto, ip + @sizeOf(ipv6hdr), data_end);

    if (p.present and isSpaCarveOut(proto, p.dport)) return XDP_PASS;

    var pk: layout.ProtectedKey6 = .{ .addr = ip6h.daddr };
    if (protected_v6.lookup(&pk) == null) return XDP_PASS;

    if (!p.present) {
        // Extension headers also land here.
        if (proto == layout.ipproto_icmpv6 and layout.allow_icmp_to_protected)
            return XDP_PASS;
        return XDP_DROP;
    }

    var key: layout.GrantKey6 = .{ .saddr = ip6h.saddr, .dport = p.dport, .proto = proto };
    const grant: *const layout.GrantExpiry = @ptrCast(@alignCast(
        allow_v6.lookup(&key) orelse return XDP_DROP,
    ));
    if (isExpired(grant)) return XDP_DROP;
    return XDP_PASS;
}

/// `linksection` puts the program in the "xdp" section; @export's .section is
/// ignored for functions.
fn xdpgate(ctx: *const xdp_md) linksection("xdp") callconv(.c) c_int {
    const data: usize = ctx.data;
    const data_end: usize = ctx.data_end;

    if (data + @sizeOf(ethhdr) > data_end) return XDP_PASS;
    const eth: *const ethhdr = @ptrFromInt(data);

    if (eth.h_proto == htons(ETH_P_IP)) return handleV4(data + @sizeOf(ethhdr), data_end);
    if (eth.h_proto == htons(ETH_P_IPV6)) return handleV6(data + @sizeOf(ethhdr), data_end);
    return XDP_PASS; // ARP and everything non-IP
}

const license: [4]u8 = "GPL\x00".*;

comptime {
    @export(&xdpgate, .{ .name = "xdpgate" });
    @export(&license, .{ .name = "_license", .section = "license" });
}
