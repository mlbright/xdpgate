//! Not a real program. It names its maps the way Zig does by default, so its
//! map lookups are relocated against the .maps section rather than each map:
//! libbpf would bind them all to one map and the gate would pass everything.
//! `zig build test` checks that tools/bpf_fixup.zig refuses it.
const std = @import("std");
const layout = @import("layout");
const helpers = std.os.linux.BPF.kern.helpers;

const Def = extern struct {
    type: [*c]const [1]c_int = null,
    max_entries: [*c]const [1]c_int = null,
    key: [*c]const u32 = null,
    value: [*c]const u8 = null,
};

var protected_v4: Def = .{};
var protected_v6: Def = .{};
var allow_v4: Def = .{};
var allow_v6: Def = .{};

fn xdpgate(ctx: *const anyopaque) linksection("xdp") callconv(.c) c_int {
    var key: u32 = @truncate(@intFromPtr(ctx));
    var found: c_int = 0;
    inline for (.{ &protected_v4, &protected_v6, &allow_v4, &allow_v6 }) |map| {
        if (helpers.map_lookup_elem(@ptrCast(map), &key) != null) found += 1;
    }
    return found;
}

const license: [4]u8 = "GPL\x00".*;

comptime {
    @export(&xdpgate, .{ .name = "xdpgate" });
    @export(&license, .{ .name = "_license", .section = "license" });
    @export(&protected_v4, .{ .name = layout.protected_v4, .section = ".maps" });
    @export(&protected_v6, .{ .name = layout.protected_v6, .section = ".maps" });
    @export(&allow_v4, .{ .name = layout.allow_v4, .section = ".maps" });
    @export(&allow_v6, .{ .name = layout.allow_v6, .section = ".maps" });
}
