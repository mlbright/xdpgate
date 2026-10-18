//! The declared protected set: the addresses protected.conf lists, and the
//! steps that make the live protected set match it. Attaching (xdpgate-load)
//! and reloading (xdpgate-ctl) apply it the same way: load, checkHard,
//! warnNotLocal, reconcile.
//!
//! The protected set is what makes the gate a gate. With nothing protected,
//! every packet takes the "destination not protected -> PASS" branch, so an
//! attached gate with an empty set passes everything while looking healthy.
//! That is why any problem with the file is fatal rather than skipped.
const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;
const layout = @import("layout");
const glibc = @import("glibc.zig");
const ip = @import("ip.zig");
const maps = @import("maps.zig");
const Output = @import("Output.zig");

pub const default_path = "/etc/xdpgate/protected.conf";
pub const path_env = "XDPGATE_CONF";

/// $XDPGATE_CONF if it is set and not empty, else the default path.
pub fn path(environ: std.process.Environ) [:0]const u8 {
    const p = environ.getPosix(path_env) orelse return default_path;
    return if (p.len == 0) default_path else p;
}

/// error.Unusable: what was wrong has already been explained on stderr.
pub const Error = error{Unusable} || Allocator.Error;

/// Addresses in network byte order, each family in the order the file lists
/// them.
pub const DeclaredSet = struct {
    v4: std.AutoArrayHashMapUnmanaged(ip.V4, void) = .empty,
    v6: std.AutoArrayHashMapUnmanaged(ip.V6, void) = .empty,

    pub fn deinit(set: *DeclaredSet, gpa: Allocator) void {
        set.v4.deinit(gpa);
        set.v6.deinit(gpa);
    }

    pub fn count(set: DeclaredSet) usize {
        return set.v4.count() + set.v6.count();
    }

    /// The addresses of one family, by address type (ip.V4 or ip.V6).
    pub fn of(set: *const DeclaredSet, comptime A: type) *const std.AutoArrayHashMapUnmanaged(A, void) {
        return if (A == ip.V4) &set.v4 else &set.v6;
    }
};

/// Reads the file at `file` and parses it.
pub fn load(gpa: Allocator, file: [:0]const u8, out: Output) Error!DeclaredSet {
    const rc = linux.open(file.ptr, .{ .ACCMODE = .RDONLY }, 0);
    const e = linux.errno(rc);
    if (e != .SUCCESS) {
        out.warn("{s}: {s}\n", .{ file, glibc.errorText(e) });
        if (e == .NOENT) explainEmpty(file, out);
        return error.Unusable;
    }
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);

    // Reading stops at the first error, as getline() did: a directory opens,
    // then reads as an empty file.
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(gpa);
    while (true) {
        try text.ensureUnusedCapacity(gpa, 4096);
        const dest = text.unusedCapacitySlice();
        const n = linux.read(fd, dest.ptr, dest.len);
        switch (linux.errno(n)) {
            .SUCCESS => if (n == 0) break else {
                text.items.len += n;
            },
            .INTR => {},
            else => break,
        }
    }
    return parse(gpa, file, text.items, out);
}

/// One address per line; '#' starts a comment. There is no partial success: a
/// typo that silently dropped a service from the protected set is the failure
/// this file exists to prevent.
pub fn parse(gpa: Allocator, file: []const u8, text: []const u8, out: Output) Error!DeclaredSet {
    var set: DeclaredSet = .{};
    errdefer set.deinit(gpa);

    var lineno: u32 = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        lineno += 1;
        // Each line reads as a C string did: it ends at a NUL.
        var entry = line[0 .. std.mem.indexOfScalar(u8, line, 0) orelse line.len];
        entry = entry[0 .. std.mem.indexOfScalar(u8, entry, '#') orelse entry.len];
        entry = std.mem.trimEnd(u8, std.mem.trimStart(u8, entry, " \t"), " \t\r");
        if (entry.len == 0) continue;

        if (std.mem.indexOfScalar(u8, entry, '/') != null) {
            out.warn(
                \\{s}:{d}: CIDR is not supported ('{s}').
                \\  The protected maps are exact-match hashes; give each
                \\  address its own line.
                \\
            , .{ file, lineno, entry });
            return error.Unusable;
        }
        if (std.mem.indexOfAny(u8, entry, " \t") != null) {
            out.warn("{s}:{d}: expected one address per line, got '{s}'\n", .{ file, lineno, entry });
            return error.Unusable;
        }

        const text_z = try gpa.dupeSentinel(u8, entry, 0);
        defer gpa.free(text_z);
        const addr = ip.Addr.parse(text_z) orelse {
            const family = if (std.mem.indexOfScalar(u8, entry, ':') != null) "IPv6" else "IPv4";
            out.warn("{s}:{d}: bad {s} address '{s}'\n", .{ file, lineno, family, entry });
            return error.Unusable;
        };
        const duplicate = switch (addr) {
            .v4 => |a| (try set.v4.getOrPut(gpa, a)).found_existing,
            .v6 => |a| (try set.v6.getOrPut(gpa, a)).found_existing,
        };
        if (duplicate)
            out.warn("{s}:{d}: warning: duplicate address '{s}', ignoring\n", .{ file, lineno, entry });
    }

    if (set.count() == 0) {
        out.warn("{s}: no addresses configured.\n", .{file});
        explainEmpty(file, out);
        return error.Unusable;
    }
    const max = layout.protected_max_entries;
    if (set.v4.count() > max or set.v6.count() > max) {
        out.warn(
            \\{s}: too many addresses (v4 {d}, v6 {d}; limit {d} per family).
            \\  Raise max_entries on protected_v4/protected_v6 in
            \\  src/layout.zig and rebuild if you genuinely need more.
            \\
        , .{ file, set.v4.count(), set.v6.count(), max });
        return error.Unusable;
    }
    return set;
}

fn explainEmpty(file: []const u8, out: Output) void {
    out.warn(
        \\  An empty protected set gates nothing: every packet takes the
        \\  "destination not protected -> PASS" branch. There is no safe
        \\  default, so {s} must name at least one address.
        \\  Copy protected.conf.example and list one address per line.
        \\
    , .{file});
}

/// Refuses a set that would cut the host off. The gate is stateless and
/// ingress-only, so protecting the source address the kernel picks for its
/// default route drops the return path of every connection the host
/// originates, the operator's own session included. This is the overlap
/// whats-on-ip grades HARD.
pub fn checkHard(set: DeclaredSet, out: Output) error{Unusable}!void {
    var hard = false;
    const probe4: linux.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, 53), .addr = @bitCast(probe_v4) };
    if (routeSource(probe4)) |src| {
        const a: ip.V4 = @bitCast(src.addr);
        if (set.v4.contains(a)) {
            explainHard("IPv4", .{ .v4 = a }, out);
            hard = true;
        }
    }
    const probe6: linux.sockaddr.in6 = .{ .port = std.mem.nativeToBig(u16, 53), .flowinfo = 0, .addr = probe_v6, .scope_id = 0 };
    if (routeSource(probe6)) |src| {
        if (set.v6.contains(src.addr)) {
            explainHard("IPv6", .{ .v6 = src.addr }, out);
            hard = true;
        }
    }
    if (hard) return error.Unusable;
}

/// Destinations for the default-route lookups: 1.1.1.1 and
/// 2606:4700:4700::1111. Nothing is ever sent to them.
const probe_v4: ip.V4 = .{ 1, 1, 1, 1 };
const probe_v6: ip.V6 = .{ 0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11 };

/// The local address the kernel would send from to reach `probe`. connect() on
/// a datagram socket is only a route lookup. Null when there is no route, and
/// so no return path to break.
fn routeSource(probe: anytype) ?@TypeOf(probe) {
    const Sockaddr = @TypeOf(probe);
    const rc = linux.socket(probe.family, linux.SOCK.DGRAM, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);

    if (linux.errno(linux.connect(fd, &probe, @sizeOf(Sockaddr))) != .SUCCESS) return null;
    var src: Sockaddr = undefined;
    var len: linux.socklen_t = @sizeOf(Sockaddr);
    if (linux.errno(linux.getsockname(fd, @ptrCast(&src), &len)) != .SUCCESS) return null;
    return src;
}

fn explainHard(family: []const u8, addr: ip.Addr, out: Output) void {
    out.warn(
        \\refusing to apply: {f} is this host's default {s} source address.
        \\  The gate is stateless and ingress-only, so protecting it drops the
        \\  return path of every connection this host originates - including
        \\  the session you are reading this in.
        \\  Move the service to a dedicated address and put that in the config.
        \\
    , .{ addr, family });
}

/// Warns, but never fails, about declared addresses this host does not have:
/// EC2 secondary and floating addresses are legitimately attached after boot.
pub fn warnNotLocal(set: DeclaredSet, out: Output) void {
    var ifaddrs: ?*glibc.IfAddrs = null;
    if (glibc.getifaddrs(&ifaddrs) != 0) return;
    defer if (ifaddrs) |list| glibc.freeifaddrs(list);

    for (set.v4.keys()) |a| if (!isAssigned(ifaddrs, .{ .v4 = a })) warnNotAssigned(.{ .v4 = a }, out);
    for (set.v6.keys()) |a| if (!isAssigned(ifaddrs, .{ .v6 = a })) warnNotAssigned(.{ .v6 = a }, out);
}

fn isAssigned(ifaddrs: ?*const glibc.IfAddrs, addr: ip.Addr) bool {
    var it = ifaddrs;
    while (it) |ifa| : (it = ifa.next) {
        const sa = ifa.addr orelse continue;
        switch (addr) {
            .v4 => |a| if (sa.family == linux.AF.INET) {
                const in: *const linux.sockaddr.in = @ptrCast(@alignCast(sa));
                if (std.mem.eql(u8, std.mem.asBytes(&in.addr), &a)) return true;
            },
            .v6 => |a| if (sa.family == linux.AF.INET6) {
                const in6: *const linux.sockaddr.in6 = @ptrCast(@alignCast(sa));
                if (std.mem.eql(u8, &in6.addr, &a)) return true;
            },
        }
    }
    return false;
}

fn warnNotAssigned(addr: ip.Addr, out: Output) void {
    out.warn("warning: {f} is not currently assigned to this host (gating it is a no-op until it is)\n", .{addr});
}

pub const Counts = struct {
    added: usize = 0,
    removed: usize = 0,
};

/// Makes the live protected maps equal the declared set: adds what is missing,
/// then deletes what the set does not name. Adds go first, so a reconcile that
/// fails part-way leaves more protected than declared, never less.
pub fn reconcile(gpa: Allocator, set: DeclaredSet, p4: maps.ProtectedV4, p6: maps.ProtectedV6, out: Output) Error!Counts {
    const live_v4 = try liveAddresses(maps.ProtectedV4, gpa, p4);
    defer gpa.free(live_v4);
    const live_v6 = try liveAddresses(maps.ProtectedV6, gpa, p6);
    defer gpa.free(live_v6);
    var p = try plan(gpa, set, live_v4, live_v6);
    defer p.deinit(gpa);

    var counts: Counts = .{};
    for (p.add_v4.items) |*a| {
        const e = p4.update(a, &layout.protected_value);
        if (e != .SUCCESS) return reportUpdateFailure(maps.ProtectedV4.name, .{ .v4 = a.* }, e, out);
        counts.added += 1;
    }
    for (p.add_v6.items) |*a| {
        const e = p6.update(a, &layout.protected_value);
        if (e != .SUCCESS) return reportUpdateFailure(maps.ProtectedV6.name, .{ .v6 = a.* }, e, out);
        counts.added += 1;
    }
    for (p.remove_v4.items) |*a| {
        if (p4.delete(a) == .SUCCESS) counts.removed += 1;
    }
    for (p.remove_v6.items) |*a| {
        if (p6.delete(a) == .SUCCESS) counts.removed += 1;
    }
    return counts;
}

/// What reconcile changes: the declared addresses missing from the live maps,
/// in the order the file lists them, and the live addresses the file does not
/// name.
pub const Plan = struct {
    add_v4: std.ArrayList(ip.V4) = .empty,
    add_v6: std.ArrayList(ip.V6) = .empty,
    remove_v4: std.ArrayList(ip.V4) = .empty,
    remove_v6: std.ArrayList(ip.V6) = .empty,

    pub fn deinit(p: *Plan, gpa: Allocator) void {
        p.add_v4.deinit(gpa);
        p.add_v6.deinit(gpa);
        p.remove_v4.deinit(gpa);
        p.remove_v6.deinit(gpa);
    }
};

pub fn plan(gpa: Allocator, set: DeclaredSet, live_v4: []const ip.V4, live_v6: []const ip.V6) Allocator.Error!Plan {
    var p: Plan = .{};
    errdefer p.deinit(gpa);
    for (set.v4.keys()) |a| if (!contains(ip.V4, live_v4, a)) try p.add_v4.append(gpa, a);
    for (set.v6.keys()) |a| if (!contains(ip.V6, live_v6, a)) try p.add_v6.append(gpa, a);
    for (live_v4) |a| if (!set.v4.contains(a)) try p.remove_v4.append(gpa, a);
    for (live_v6) |a| if (!set.v6.contains(a)) try p.remove_v6.append(gpa, a);
    return p;
}

fn contains(comptime A: type, addrs: []const A, addr: A) bool {
    for (addrs) |a| if (std.mem.eql(u8, &a, &addr)) return true;
    return false;
}

fn liveAddresses(comptime M: type, gpa: Allocator, map: M) Allocator.Error![]M.Key {
    var addrs: std.ArrayList(M.Key) = .empty;
    errdefer addrs.deinit(gpa);
    var it = map.iterator();
    while (addrs.items.len < layout.protected_max_entries) {
        try addrs.append(gpa, it.next() orelse break);
    }
    return addrs.toOwnedSlice(gpa);
}

fn reportUpdateFailure(map: []const u8, addr: ip.Addr, e: linux.E, out: Output) error{Unusable} {
    out.warn("{s}: cannot protect {f}: {s}\n", .{ map, addr, glibc.errorText(e) });
    if (e == .@"2BIG")
        out.warn("  the map is full (max_entries {d}); raise it in src/layout.zig and rebuild.\n", .{layout.protected_max_entries});
    return error.Unusable;
}

// ---- tests ------------------------------------------------------------------

const testing = std.testing;

fn expectParse(text: []const u8, v4: []const []const u8, v6: []const []const u8, warnings: []const u8) !void {
    var captured: Output.Captured = .init(testing.allocator);
    defer captured.deinit();
    var set = try parse(testing.allocator, "p.conf", text, captured.output());
    defer set.deinit(testing.allocator);
    try testing.expectEqualStrings(warnings, captured.stderr.written());
    try testing.expectEqual(v4.len, set.v4.count());
    for (v4, set.v4.keys()) |want, got| try testing.expectFmt(want, "{f}", .{ip.Addr{ .v4 = got }});
    try testing.expectEqual(v6.len, set.v6.count());
    for (v6, set.v6.keys()) |want, got| try testing.expectFmt(want, "{f}", .{ip.Addr{ .v6 = got }});
}

fn expectRejected(text: []const u8, message: []const u8) !void {
    var captured: Output.Captured = .init(testing.allocator);
    defer captured.deinit();
    try testing.expectError(error.Unusable, parse(testing.allocator, "p.conf", text, captured.output()));
    try testing.expectEqualStrings(message, captured.stderr.written());
}

test "parse: comments, blank lines, surrounding blanks, CRLF and no final newline" {
    try expectParse("\t192.0.2.10  \r\n# comment\r\n\r\n  2001:db8:1::10\t# svc\n192.0.2.11#tight", &.{ "192.0.2.10", "192.0.2.11" }, &.{"2001:db8:1::10"}, "");
}

test "parse: a line ends at a NUL, as a C string does" {
    try expectParse("192.0.2.10\x00junk\n", &.{"192.0.2.10"}, &.{}, "");
}

test "parse: duplicates are compared as addresses, warned about and dropped" {
    try expectParse("192.0.2.10\n192.0.2.10\n2001:db8:1::10\n2001:DB8:1:0::10\n", &.{"192.0.2.10"}, &.{"2001:db8:1::10"},
        \\p.conf:2: warning: duplicate address '192.0.2.10', ignoring
        \\p.conf:4: warning: duplicate address '2001:DB8:1:0::10', ignoring
        \\
    );
}

test "parse: the first bad line rejects the whole file" {
    try expectRejected("192.0.2.10\n\n192.0.2.0/24\n",
        \\p.conf:3: CIDR is not supported ('192.0.2.0/24').
        \\  The protected maps are exact-match hashes; give each
        \\  address its own line.
        \\
    );
    try expectRejected("192.0.2.10 192.0.2.11\n", "p.conf:1: expected one address per line, got '192.0.2.10 192.0.2.11'\n");
    try expectRejected("192.0.2.10\t192.0.2.11\n", "p.conf:1: expected one address per line, got '192.0.2.10\t192.0.2.11'\n");
    try expectRejected("198.051.100.7\n", "p.conf:1: bad IPv4 address '198.051.100.7'\n");
    try expectRejected("2001:db8::zz\n", "p.conf:1: bad IPv6 address '2001:db8::zz'\n");
    try expectRejected("\r192.0.2.10\n", "p.conf:1: bad IPv4 address '\r192.0.2.10'\n");
}

test "parse: an empty set is rejected" {
    try expectRejected("# nothing\n\n",
        \\p.conf: no addresses configured.
        \\  An empty protected set gates nothing: every packet takes the
        \\  "destination not protected -> PASS" branch. There is no safe
        \\  default, so p.conf must name at least one address.
        \\  Copy protected.conf.example and list one address per line.
        \\
    );
}

test "parse: each family holds at most protected_max_entries" {
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(testing.allocator);
    for (0..layout.protected_max_entries + 1) |i|
        try text.print(testing.allocator, "198.18.{d}.{d}\n", .{ i >> 8, i & 255 });
    try expectRejected(text.items,
        \\p.conf: too many addresses (v4 257, v6 0; limit 256 per family).
        \\  Raise max_entries on protected_v4/protected_v6 in
        \\  src/layout.zig and rebuild if you genuinely need more.
        \\
    );
}

test "plan: adds in file order, removes what the file does not name" {
    var captured: Output.Captured = .init(testing.allocator);
    defer captured.deinit();
    var set = try parse(testing.allocator, "p.conf", "192.0.2.12\n192.0.2.10\n2001:db8::1\n192.0.2.11\n", captured.output());
    defer set.deinit(testing.allocator);

    const live_v4 = [_]ip.V4{ .{ 192, 0, 2, 20 }, .{ 192, 0, 2, 10 } };
    const live_v6 = [_]ip.V6{ip.Addr.parse("2001:db8::1").?.v6};
    var p = try plan(testing.allocator, set, &live_v4, &live_v6);
    defer p.deinit(testing.allocator);

    try testing.expectEqualSlices(ip.V4, &.{ .{ 192, 0, 2, 12 }, .{ 192, 0, 2, 11 } }, p.add_v4.items);
    try testing.expectEqual(0, p.add_v6.items.len);
    try testing.expectEqualSlices(ip.V4, &.{.{ 192, 0, 2, 20 }}, p.remove_v4.items);
    try testing.expectEqual(0, p.remove_v6.items.len);
}
