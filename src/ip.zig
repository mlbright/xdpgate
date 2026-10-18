//! IP addresses as the maps hold them, in network byte order, read and spelled
//! by glibc's inet_pton and inet_ntop.
const std = @import("std");
const linux = std.os.linux;
const glibc = @import("glibc.zig");

pub const V4 = [4]u8;
pub const V6 = [16]u8;

pub const Addr = union(enum) {
    v4: V4,
    v6: V6,

    /// An address containing ':' is IPv6, anything else IPv4.
    pub fn parse(text: [:0]const u8) ?Addr {
        if (std.mem.indexOfScalar(u8, text, ':') != null) {
            var a: V6 = undefined;
            if (glibc.inet_pton(linux.AF.INET6, text.ptr, &a) == 1) return .{ .v6 = a };
        } else {
            var a: V4 = undefined;
            if (glibc.inet_pton(linux.AF.INET, text.ptr, &a) == 1) return .{ .v4 = a };
        }
        return null;
    }

    pub fn format(a: Addr, w: *std.Io.Writer) std.Io.Writer.Error!void {
        var buf: [46]u8 = undefined; // INET6_ADDRSTRLEN
        const text = switch (a) {
            .v4 => |*b| glibc.inet_ntop(linux.AF.INET, b, &buf, buf.len),
            .v6 => |*b| glibc.inet_ntop(linux.AF.INET6, b, &buf, buf.len),
        };
        try w.writeAll(std.mem.span(text.?));
    }
};

/// For std.mem.sort: numeric order, which in network byte order is byte order.
pub fn lessThan(comptime A: type) fn (void, A, A) bool {
    return struct {
        fn lessThan(_: void, a: A, b: A) bool {
            return std.mem.order(u8, &a, &b) == .lt;
        }
    }.lessThan;
}

test "parse picks the family by ':' and reads it as inet_pton does" {
    try std.testing.expectEqual(Addr{ .v4 = .{ 192, 0, 2, 10 } }, Addr.parse("192.0.2.10").?);
    try std.testing.expectEqual(null, Addr.parse("198.051.100.7")); // no leading zeros
    try std.testing.expectEqual(null, Addr.parse("198.51.100"));
    try std.testing.expectEqual(null, Addr.parse("localhost"));
    try std.testing.expectEqual(null, Addr.parse("192.0.2.10/24"));
    const mapped = Addr.parse("::ffff:192.0.2.10").?;
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 10 }, &mapped.v6);
    try std.testing.expectEqual(Addr.parse("2001:db8:1::10").?, Addr.parse("2001:DB8:1:0:0:0:0:10").?);
}

test "format spells addresses as inet_ntop does" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("10.0.0.9", try std.fmt.bufPrint(&buf, "{f}", .{Addr{ .v4 = .{ 10, 0, 0, 9 } }}));
    try std.testing.expectEqualStrings("2001:db8:1::10", try std.fmt.bufPrint(&buf, "{f}", .{Addr.parse("2001:DB8:1:0::10").?}));
    try std.testing.expectEqualStrings("::ffff:10.0.0.9", try std.fmt.bufPrint(&buf, "{f}", .{Addr.parse("::ffff:10.0.0.9").?}));
}
