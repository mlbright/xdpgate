//! The pinned maps, reached with the bpf(2) syscall directly. Every call
//! returns the errno it ended with, .SUCCESS included, because the CLIs report
//! failures in strerror's words, exactly as they did through libbpf.
const std = @import("std");
const linux = std.os.linux;
const BPF = linux.BPF;
const layout = @import("layout");
const ip = @import("ip.zig");

pub const E = linux.E;

pub const ProtectedV4 = Map(layout.protected_v4, ip.V4, u8);
pub const ProtectedV6 = Map(layout.protected_v6, ip.V6, u8); // a layout.ProtectedKey6
pub const AllowV4 = Map(layout.allow_v4, layout.GrantKey4, layout.GrantExpiry);
pub const AllowV6 = Map(layout.allow_v6, layout.GrantKey6, layout.GrantExpiry);

comptime {
    std.debug.assert(@sizeOf(ip.V6) == @sizeOf(layout.ProtectedKey6));
}

fn Map(comptime map_name: []const u8, comptime K: type, comptime V: type) type {
    return struct {
        fd: linux.fd_t,

        const Self = @This();
        pub const Key = K;
        pub const Value = V;
        pub const name = map_name;
        pub const pin_path = layout.pin_dir ++ "/" ++ map_name;

        /// The map pinned at pin_path, as bpf_obj_get() opens it.
        pub fn openPinned(map: *Self) E {
            var attr: BPF.Attr = .{ .obj = std.mem.zeroes(BPF.ObjAttr) };
            attr.obj.pathname = @intFromPtr(pin_path.ptr);
            const rc = linux.bpf(.obj_get, &attr, @sizeOf(BPF.ObjAttr));
            const e = linux.errno(rc);
            if (e == .SUCCESS) map.fd = @intCast(rc);
            return e;
        }

        pub fn lookup(map: Self, key: *const Key, value: *Value) E {
            return elem(.map_lookup_elem, map.fd, @intFromPtr(key), @intFromPtr(value), 0);
        }

        /// Creates or replaces the entry (BPF_ANY).
        pub fn update(map: Self, key: *const Key, value: *const Value) E {
            return elem(.map_update_elem, map.fd, @intFromPtr(key), @intFromPtr(value), BPF.ANY);
        }

        pub fn delete(map: Self, key: *const Key) E {
            return elem(.map_delete_elem, map.fd, @intFromPtr(key), 0, 0);
        }

        /// The keys in hash order, each one the cursor for the next.
        pub fn iterator(map: Self) Iterator {
            return .{ .map = map };
        }

        pub const Iterator = struct {
            map: Self,
            cursor: ?Key = null,

            pub fn next(it: *Iterator) ?Key {
                var key: Key = undefined;
                const cursor: usize = if (it.cursor) |*c| @intFromPtr(c) else 0;
                if (elem(.map_get_next_key, it.map.fd, cursor, @intFromPtr(&key), 0) != .SUCCESS)
                    return null;
                it.cursor = key;
                return key;
            }
        };
    };
}

fn elem(cmd: BPF.Cmd, fd: linux.fd_t, key: usize, value: usize, flags: u64) E {
    var attr: BPF.Attr = .{ .map_elem = std.mem.zeroes(BPF.MapElemAttr) };
    attr.map_elem.map_fd = fd;
    attr.map_elem.key = key;
    attr.map_elem.result.value = value;
    attr.map_elem.flags = flags;
    return linux.errno(linux.bpf(cmd, &attr, @sizeOf(BPF.MapElemAttr)));
}
