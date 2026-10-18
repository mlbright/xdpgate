//! xdpgate-ctl: manages the pinned maps. fwknopd runs it to open and close
//! grants; an operator runs it to reload the declared protected set, make
//! runtime overrides, and list, export or reap.
//!
//!   xdpgate-ctl open  <ip> <tcp|udp> <port> [timeout_secs]
//!   xdpgate-ctl close <ip> <tcp|udp> <port>
//!   xdpgate-ctl add-protected <ip>
//!   xdpgate-ctl del-protected <ip>
//!   xdpgate-ctl reload
//!   xdpgate-ctl export
//!   xdpgate-ctl list
//!   xdpgate-ctl gc
//!
//! An address containing ':' is IPv6. Addresses and ports go into the map keys
//! in network byte order, as the XDP program reads them off the wire. Expiries
//! are CLOCK_MONOTONIC nanoseconds, the clock of bpf_ktime_get_ns().
//!
//! The protected set belongs to the config file: reload makes the live maps
//! match it, and add-protected/del-protected are runtime overrides that the
//! next reload or reboot undoes.
const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;
const layout = @import("layout");
const declared = @import("declared_set.zig");
const glibc = @import("glibc.zig");
const ip = @import("ip.zig");
const maps = @import("maps.zig");
const Output = @import("Output.zig");

/// The grant length when fwknopd passes no $TIMEOUT.
const default_timeout_secs = 30;
/// Chosen only so that a nanosecond expiry cannot wrap.
const max_timeout_secs: u64 = 100 * 365 * 24 * 3600;

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.arena.allocator(); // process lifetime: nothing to free
    var stdio: Output.Stdio = undefined;
    const out = stdio.init(init.io);
    defer out.flush();

    const ctl: Ctl = .{
        .gpa = gpa,
        .args = try init.minimal.args.toSlice(gpa),
        .conf_path = declared.path(init.minimal.environ),
        .out = out,
    };
    return ctl.run();
}

const Ctl = struct {
    gpa: Allocator,
    args: []const [:0]const u8,
    conf_path: [:0]const u8,
    out: Output,

    fn run(ctl: Ctl) Allocator.Error!u8 {
        if (ctl.args.len < 2) {
            ctl.usage();
            return 2;
        }
        const cmd = ctl.args[1];
        const eql = std.mem.eql;
        if (eql(u8, cmd, "open")) return ctl.grant(.open);
        if (eql(u8, cmd, "close")) return ctl.grant(.close);
        if (eql(u8, cmd, "add-protected")) return ctl.override(.add);
        if (eql(u8, cmd, "del-protected")) return ctl.override(.remove);
        if (eql(u8, cmd, "reload")) return ctl.reload();
        if (eql(u8, cmd, "export")) return ctl.exportSet();
        if (eql(u8, cmd, "list")) return ctl.list();
        if (eql(u8, cmd, "gc")) return ctl.gc();
        ctl.out.warn("unknown command '{s}'\n", .{cmd});
        return 2;
    }

    fn usage(ctl: Ctl) void {
        const argv0: []const u8 = if (ctl.args.len > 0) ctl.args[0] else "(null)";
        ctl.out.warn(
            \\usage: {0s} open  <ip> <tcp|udp> <port> [timeout_secs]
            \\       {0s} close <ip> <tcp|udp> <port>
            \\       {0s} add-protected <ip>      (transient - see reload)
            \\       {0s} del-protected <ip>      (transient - see reload)
            \\       {0s} reload                  apply {1s}
            \\       {0s} export                  dump the live set as config
            \\       {0s} list
            \\       {0s} gc
            \\
        , .{ argv0, ctl.conf_path });
    }

    // ---- grants -------------------------------------------------------------

    fn grant(ctl: Ctl, op: enum { open, close }) u8 {
        const args = ctl.args;
        if (args.len < 5 or (op == .open and args.len > 6)) {
            ctl.out.warn("usage: {s} {s} <ip> <tcp|udp> <port>{s}\n", .{
                args[0], args[1], if (op == .open) " [timeout_secs]" else "",
            });
            return 2;
        }
        const addr = ctl.parseAddr(args[2]) orelse return 2;
        const proto = parseProto(args[3]) orelse {
            ctl.out.warn("proto must be tcp or udp, got '{s}'\n", .{args[3]});
            return 2;
        };
        const port = parseUint(args[4], 1, 65535) orelse {
            ctl.out.warn("port must be 1-65535, got '{s}'\n", .{args[4]});
            return 2;
        };
        const dport = std.mem.nativeToBig(u16, @intCast(port));

        var expiry: ?layout.GrantExpiry = null;
        if (op == .open) {
            var secs: u64 = 0; // 0 means the default
            if (args.len == 6) secs = parseUint(args[5], 0, max_timeout_secs) orelse {
                ctl.out.warn("timeout must be 0-{d} seconds, got '{s}'\n", .{ max_timeout_secs, args[5] });
                return 2;
            };
            if (secs == 0) secs = default_timeout_secs;
            expiry = .{ .expiry_ns = monotonicNs() + secs * std.time.ns_per_s };
        }

        return switch (addr) {
            .v4 => |a| ctl.change(maps.AllowV4, .{ .saddr = @bitCast(a), .dport = dport, .proto = proto }, expiry),
            .v6 => |a| ctl.change(maps.AllowV6, .{ .saddr = a, .dport = dport, .proto = proto }, expiry),
        };
    }

    // ---- runtime overrides --------------------------------------------------

    fn override(ctl: Ctl, op: enum { add, remove }) u8 {
        const args = ctl.args;
        if (args.len != 3) {
            ctl.out.warn("usage: {s} {s} <ip>\n", .{ args[0], args[1] });
            return 2;
        }
        const addr = ctl.parseAddr(args[2]) orelse return 2;
        const value: ?u8 = if (op == .add) layout.protected_value else null;
        const status = switch (addr) {
            .v4 => |a| ctl.change(maps.ProtectedV4, a, value),
            .v6 => |a| ctl.change(maps.ProtectedV6, a, value),
        };
        if (status != 0) return status;

        // Only the live map moved, and the next reconcile moves it back. Say
        // so now rather than let it be a surprise at the next reload.
        const add = op == .add;
        ctl.out.warn(
            \\warning: runtime only - the next reload or reboot {s} this.
            \\  {s} {s} {s} {s} to make it durable.
            \\
        , .{
            if (add) "reverts" else "restores", if (add) "Add" else "Remove",
            args[2],                            if (add) "to" else "from",
            ctl.conf_path,
        });
        return 0;
    }

    /// Writes `value` under `key`, or deletes `key` when there is no value.
    /// Deleting an entry that is already gone is not an error.
    fn change(ctl: Ctl, comptime M: type, key: M.Key, value: ?M.Value) u8 {
        const map = ctl.open(M) orelse return 1;
        const e = if (value) |*v| map.update(&key, v) else map.delete(&key);
        if (e != .SUCCESS and !(value == null and e == .NOENT)) {
            ctl.out.warn("{s} failed: {s}\n", .{ ctl.args[1], glibc.errorText(e) });
            return 1;
        }
        return 0;
    }

    // ---- the declared protected set -----------------------------------------

    /// Makes the live protected maps match the config file. Grants are left
    /// alone, which is the reason this exists instead of a restart.
    fn reload(ctl: Ctl) Allocator.Error!u8 {
        const set = declared.load(ctl.gpa, ctl.conf_path, ctl.out) catch |e| return unusable(e);
        declared.checkHard(set, ctl.out) catch {
            ctl.out.warn("reload aborted; the live protected set is unchanged\n", .{});
            return 1;
        };
        declared.warnNotLocal(set, ctl.out);

        const p4 = ctl.open(maps.ProtectedV4);
        const p6 = ctl.open(maps.ProtectedV6);
        if (p4 == null or p6 == null) return 1;
        const counts = declared.reconcile(ctl.gpa, set, p4.?, p6.?, ctl.out) catch |e| return unusable(e);

        const n = set.count();
        ctl.out.print("reloaded {s}: {d} address{s} protected (+{d}, -{d})\n", .{
            ctl.conf_path, n, if (n == 1) "" else "es", counts.added, counts.removed,
        });
        return 0;
    }

    /// Prints the live protected set as a config file, so a box whose set only
    /// ever lived in the maps can capture it before its next boot needs one.
    fn exportSet(ctl: Ctl) u8 {
        const p4 = ctl.open(maps.ProtectedV4);
        const p6 = ctl.open(maps.ProtectedV6);
        if (p4 == null or p6 == null) return 1;
        ctl.out.print(
            \\# xdpgate protected set, exported from the live maps.
            \\# One address per line. '#' starts a comment; CIDR is not accepted.
            \\
        , .{});
        ctl.exportFamily(maps.ProtectedV4, p4.?);
        ctl.exportFamily(maps.ProtectedV6, p6.?);
        return 0;
    }

    fn exportFamily(ctl: Ctl, comptime M: type, map: M) void {
        var it = map.iterator();
        while (it.next()) |a| {
            var v: u8 = undefined;
            if (map.lookup(&a, &v) != .SUCCESS) continue;
            ctl.out.print("{f}\n", .{addrOf(a)});
        }
    }

    // ---- list ---------------------------------------------------------------

    fn list(ctl: Ctl) Allocator.Error!u8 {
        const clocks: Clocks = .now();
        const config = try ctl.loadQuiet();

        // The live set, runtime additions marked, then the declared addresses
        // removed at runtime. Those print on "missing" lines, so a script
        // matching "^protected v[46] " sees only addresses gated right now.
        const p4 = ctl.open(maps.ProtectedV4);
        if (p4) |map| ctl.listProtected(maps.ProtectedV4, map, config);
        const p6 = ctl.open(maps.ProtectedV6);
        if (p6) |map| ctl.listProtected(maps.ProtectedV6, map, config);
        if (config) |*set| {
            try ctl.listMissing(maps.ProtectedV4, p4, set);
            try ctl.listMissing(maps.ProtectedV6, p6, set);
        }

        ctl.listGrants(maps.AllowV4, clocks);
        ctl.listGrants(maps.AllowV6, clocks);
        return 0;
    }

    /// The declared set, for annotating the listing only. A box not yet given
    /// a config file must still be able to list its maps, so an unreadable
    /// file just means no annotations.
    fn loadQuiet(ctl: Ctl) Allocator.Error!?declared.DeclaredSet {
        if (linux.errno(linux.access(ctl.conf_path.ptr, linux.R_OK)) != .SUCCESS) return null;
        return declared.load(ctl.gpa, ctl.conf_path, ctl.out) catch |e| switch (e) {
            error.Unusable => null,
            error.OutOfMemory => |oom| oom,
        };
    }

    fn listProtected(ctl: Ctl, comptime M: type, map: M, config: ?declared.DeclaredSet) void {
        for (ctl.sortedKeys(M, map, ip.lessThan(M.Key))) |a| {
            var v: u8 = undefined;
            if (map.lookup(&a, &v) != .SUCCESS) continue;
            const runtime_only = if (config) |*set| !set.of(M.Key).contains(a) else false;
            ctl.out.print("protected {s} {f}{s}\n", .{ family(M.Key), addrOf(a), if (runtime_only) "   [runtime only]" else "" });
        }
    }

    fn listMissing(ctl: Ctl, comptime M: type, map: ?M, set: *const declared.DeclaredSet) Allocator.Error!void {
        const addrs = try ctl.gpa.dupe(M.Key, set.of(M.Key).keys());
        std.mem.sort(M.Key, addrs, {}, ip.lessThan(M.Key));
        for (addrs) |a| {
            var v: u8 = undefined;
            if (map == null or map.?.lookup(&a, &v) == .SUCCESS) continue;
            ctl.out.print("missing   {s} {f}   [in config, removed at runtime]\n", .{ family(M.Key), addrOf(a) });
        }
    }

    fn listGrants(ctl: Ctl, comptime M: type, clocks: Clocks) void {
        const map = ctl.open(M) orelse return;
        const line = if (M == maps.AllowV4) "v4 {f}:{s}/{d} {f}\n" else "v6 [{f}]:{s}/{d} {f}\n";
        for (ctl.sortedKeys(M, map, grantLessThan(M.Key))) |key| {
            var expiry: layout.GrantExpiry = undefined;
            if (map.lookup(&key, &expiry) != .SUCCESS) continue;
            ctl.out.print(line, .{
                addrOf(key.saddr),
                protoName(key.proto),
                std.mem.bigToNative(u16, key.dport),
                Expiry{ .expiry_ns = expiry.expiry_ns, .clocks = clocks },
            });
        }
    }

    /// Every key of the map, sorted: iteration runs in hash order, which
    /// reads as random.
    fn sortedKeys(ctl: Ctl, comptime M: type, map: M, comptime lessThan: fn (void, M.Key, M.Key) bool) []M.Key {
        var keys: std.ArrayList(M.Key) = .empty;
        var it = map.iterator();
        while (it.next()) |key| {
            keys.append(ctl.gpa, key) catch {
                ctl.out.warn("out of memory; listing is incomplete\n", .{});
                break;
            };
        }
        std.mem.sort(M.Key, keys.items, {}, lessThan);
        return keys.items;
    }

    // ---- gc -----------------------------------------------------------------

    fn gc(ctl: Ctl) u8 {
        const n = ctl.reapExpiredGrants(maps.AllowV4) + ctl.reapExpiredGrants(maps.AllowV6);
        ctl.out.print("gc: reaped {d} expired entr{s}\n", .{ n, if (n == 1) "y" else "ies" });
        return 0;
    }

    /// Deletes expired grants. The gate already refuses them; this frees their
    /// map slots when fwknopd's close never came. All are found before any is
    /// deleted, since deleting mid-walk would disturb the walk.
    fn reapExpiredGrants(ctl: Ctl, comptime M: type) usize {
        const map = ctl.open(M) orelse return 0;
        const now = monotonicNs();
        var expired: [layout.grant_max_entries]M.Key = undefined;
        var n: usize = 0;
        var it = map.iterator();
        while (n < expired.len) {
            const key = it.next() orelse break;
            var grant_expiry: layout.GrantExpiry = undefined;
            if (map.lookup(&key, &grant_expiry) != .SUCCESS) continue;
            if (isExpired(grant_expiry, now)) {
                expired[n] = key;
                n += 1;
            }
        }
        for (expired[0..n]) |*key| _ = map.delete(key);
        return n;
    }

    // ---- helpers ------------------------------------------------------------

    fn open(ctl: Ctl, comptime M: type) ?M {
        var map: M = undefined;
        const e = map.openPinned();
        if (e != .SUCCESS) {
            ctl.out.warn("cannot open pinned map {s}: {s}\n  (is xdpgate-load attached?)\n", .{ M.pin_path, glibc.errorText(e) });
            return null;
        }
        return map;
    }

    fn parseAddr(ctl: Ctl, text: [:0]const u8) ?ip.Addr {
        return ip.Addr.parse(text) orelse {
            ctl.out.warn("bad IP address '{s}'\n", .{text});
            return null;
        };
    }
};

fn unusable(e: declared.Error) Allocator.Error!u8 {
    return switch (e) {
        error.Unusable => 1,
        error.OutOfMemory => |oom| oom,
    };
}

/// A whole decimal number in [min, max]. Signs, blanks, trailing junk, digit
/// separators, the empty string and overflow are all rejected.
fn parseUint(text: []const u8, min: u64, max: u64) ?u64 {
    if (text.len == 0) return null;
    var v: u64 = 0;
    for (text) |c| {
        if (!std.ascii.isDigit(c)) return null;
        v = std.math.mul(u64, v, 10) catch return null;
        v = std.math.add(u64, v, c - '0') catch return null;
    }
    return if (v < min or v > max) null else v;
}

fn parseProto(text: []const u8) ?u8 {
    if (std.ascii.eqlIgnoreCase(text, "tcp")) return layout.ipproto_tcp;
    if (std.ascii.eqlIgnoreCase(text, "udp")) return layout.ipproto_udp;
    return null;
}

fn protoName(proto: u8) []const u8 {
    return switch (proto) {
        layout.ipproto_tcp => "tcp",
        layout.ipproto_udp => "udp",
        else => "?",
    };
}

fn family(comptime A: type) []const u8 {
    return if (A == ip.V4) "v4" else "v6";
}

fn addrOf(a: anytype) ip.Addr {
    return switch (@TypeOf(a)) {
        ip.V4, u32 => .{ .v4 = @bitCast(a) },
        ip.V6 => .{ .v6 = a },
        else => @compileError("not an address"),
    };
}

/// Grants by source address, then tcp before udp, then by port.
fn grantLessThan(comptime K: type) fn (void, K, K) bool {
    return struct {
        fn lessThan(_: void, a: K, b: K) bool {
            switch (std.mem.order(u8, std.mem.asBytes(&a.saddr), std.mem.asBytes(&b.saddr))) {
                .lt => return true,
                .gt => return false,
                .eq => {},
            }
            if (a.proto != b.proto) return a.proto < b.proto;
            return std.mem.bigToNative(u16, a.dport) < std.mem.bigToNative(u16, b.dport);
        }
    }.lessThan;
}

/// The gate's own rule: zero never expires, anything else once it is past.
fn isExpired(grant: layout.GrantExpiry, now_ns: u64) bool {
    return grant.expiry_ns != 0 and now_ns > grant.expiry_ns;
}

fn monotonicNs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

/// Expiries are on CLOCK_MONOTONIC, which means nothing as a date, so a
/// listing reads both clocks once and dates every expiry from that pair.
const Clocks = struct {
    mono_ns: u64,
    wall: i64,

    fn now() Clocks {
        var ts: linux.timespec = undefined;
        const mono_ns = monotonicNs();
        _ = linux.clock_gettime(.REALTIME, &ts);
        return .{ .mono_ns = mono_ns, .wall = ts.sec };
    }
};

/// The end of a grant line: "expires <date> (in <duration>)", "expired <date>
/// (<duration> ago)" or "no expiry". Whole seconds, truncated toward zero.
const Expiry = struct {
    expiry_ns: u64,
    clocks: Clocks,

    pub fn format(x: Expiry, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (x.expiry_ns == 0) return w.writeAll("no expiry");
        const left_ns = @as(i64, @bitCast(x.expiry_ns)) -% @as(i64, @bitCast(x.clocks.mono_ns));
        const left = @divTrunc(left_ns, std.time.ns_per_s);
        var date_buf: [64]u8 = undefined;
        const date = localDate(x.clocks.wall +% left, &date_buf);
        const duration: Duration = .{ .secs = @abs(left) };
        if (left < 0)
            try w.print("expired {s} ({f} ago)", .{ date, duration })
        else
            try w.print("expires {s} (in {f})", .{ date, duration });
    }
};

fn localDate(t: i64, buf: []u8) []const u8 {
    var tm: glibc.Tm = undefined;
    if (glibc.localtime_r(&t, &tm) == null) return "?";
    return buf[0..glibc.strftime(buf.ptr, buf.len, "%Y-%m-%d %H:%M:%S %Z", &tm)];
}

/// "2d 23h 51m 31s", without leading zero units ("0s" under a second).
const Duration = struct {
    secs: u64,

    pub fn format(d: Duration, w: *std.Io.Writer) std.Io.Writer.Error!void {
        const days = d.secs / 86400;
        const hours = d.secs % 86400 / 3600;
        const minutes = d.secs % 3600 / 60;
        if (days != 0) try w.print("{d}d ", .{days});
        if (days != 0 or hours != 0) try w.print("{d}h ", .{hours});
        if (days != 0 or hours != 0 or minutes != 0) try w.print("{d}m ", .{minutes});
        try w.print("{d}s", .{d.secs % 60});
    }
};

// ---- tests ------------------------------------------------------------------

const testing = std.testing;

test {
    _ = declared;
    _ = ip;
}

test "parseUint takes only plain decimal digits" {
    try testing.expectEqual(22, parseUint("22", 1, 65535));
    try testing.expectEqual(22, parseUint("0022", 1, 65535));
    try testing.expectEqual(65535, parseUint("65535", 1, 65535));
    try testing.expectEqual(0, parseUint("0", 0, max_timeout_secs));
    try testing.expectEqual(max_timeout_secs, parseUint("3153600000", 0, max_timeout_secs));
    for ([_][]const u8{ "0", "65536", "", "22x", "-1", "+22", " 22", "22 ", "0x16", "2_2", "99999999999999999999" }) |bad|
        try testing.expectEqual(null, parseUint(bad, 1, 65535));
    try testing.expectEqual(null, parseUint("18446744073709551616", 0, std.math.maxInt(u64)));
    try testing.expectEqual(std.math.maxInt(u64), parseUint("18446744073709551615", 0, std.math.maxInt(u64)));
}

test "parseProto ignores case" {
    try testing.expectEqual(layout.ipproto_udp, parseProto("UdP"));
    try testing.expectEqual(layout.ipproto_tcp, parseProto("TCP"));
    try testing.expectEqual(null, parseProto("icmp"));
}

test "Duration drops leading zero units" {
    const cases = [_]struct { u64, []const u8 }{
        .{ 0, "0s" },                          .{ 59, "59s" },
        .{ 60, "1m 0s" },                      .{ 3599, "59m 59s" },
        .{ 3600, "1h 0m 0s" },                 .{ 86399, "23h 59m 59s" },
        .{ 86400, "1d 0h 0m 0s" },             .{ 90061, "1d 1h 1m 1s" },
        .{ 3153599999, "36499d 23h 59m 59s" },
    };
    for (cases) |c| try testing.expectFmt(c[1], "{f}", .{Duration{ .secs = c[0] }});
}

test "Expiry truncates toward zero on both sides of now" {
    const clocks: Clocks = .{ .mono_ns = 100_000 * std.time.ns_per_s, .wall = 0 };
    var buf: [128]u8 = undefined;
    const cases = [_]struct { i64, []const u8 }{
        .{ 3600 * std.time.ns_per_s - 1, "(in 59m 59s)" },
        .{ 999_999_999, "(in 0s)" },
        .{ -999_999_999, "(in 0s)" },
        .{ -std.time.ns_per_s, "(1s ago)" },
        .{ -3600 * std.time.ns_per_s, "(1h 0m 0s ago)" },
    };
    for (cases) |c| {
        const expiry_ns: u64 = @intCast(@as(i64, @intCast(clocks.mono_ns)) + c[0]);
        const text = try std.fmt.bufPrint(&buf, "{f}", .{Expiry{ .expiry_ns = expiry_ns, .clocks = clocks }});
        try testing.expectStringEndsWith(text, c[1]);
    }
    try testing.expectFmt("no expiry", "{f}", .{Expiry{ .expiry_ns = 0, .clocks = clocks }});
}

test "isExpired: zero never expires, otherwise strictly after" {
    try testing.expect(!isExpired(.{ .expiry_ns = 0 }, std.math.maxInt(u64)));
    try testing.expect(!isExpired(.{ .expiry_ns = 100 }, 100));
    try testing.expect(isExpired(.{ .expiry_ns = 100 }, 101));
}

test "grants sort by numeric source address, then tcp before udp, then port" {
    const tcp = layout.ipproto_tcp;
    const udp = layout.ipproto_udp;
    const be = std.mem.nativeToBig;
    const k = struct {
        fn v4(a: ip.V4, proto: u8, port: u16) layout.GrantKey4 {
            return .{ .saddr = @bitCast(a), .dport = be(u16, port), .proto = proto };
        }
    }.v4;
    var keys = [_]layout.GrantKey4{
        k(.{ 10, 0, 0, 10 }, tcp, 22),  k(.{ 10, 0, 0, 9 }, udp, 53),
        k(.{ 10, 0, 0, 9 }, tcp, 8080), k(.{ 10, 0, 0, 9 }, tcp, 443),
        k(.{ 10, 0, 0, 9 }, tcp, 1000), k(.{ 9, 255, 255, 255 }, tcp, 22),
    };
    std.mem.sort(layout.GrantKey4, &keys, {}, grantLessThan(layout.GrantKey4));
    const want = [_]layout.GrantKey4{
        k(.{ 9, 255, 255, 255 }, tcp, 22), k(.{ 10, 0, 0, 9 }, tcp, 443),
        k(.{ 10, 0, 0, 9 }, tcp, 1000),    k(.{ 10, 0, 0, 9 }, tcp, 8080),
        k(.{ 10, 0, 0, 9 }, udp, 53),      k(.{ 10, 0, 0, 10 }, tcp, 22),
    };
    for (want, keys) |w, got| try testing.expectEqualSlices(u8, std.mem.asBytes(&w), std.mem.asBytes(&got));
}

test "protected addresses sort numerically" {
    var addrs = [_]ip.V4{ .{ 255, 255, 255, 255 }, .{ 192, 0, 2, 100 }, .{ 0, 0, 0, 0 }, .{ 192, 0, 2, 99 } };
    std.mem.sort(ip.V4, &addrs, {}, ip.lessThan(ip.V4));
    try testing.expectEqualSlices(ip.V4, &.{ .{ 0, 0, 0, 0 }, .{ 192, 0, 2, 99 }, .{ 192, 0, 2, 100 }, .{ 255, 255, 255, 255 } }, &addrs);
}
