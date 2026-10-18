//! xdpgate-load: loads the XDP gate, arms it with the declared protected set,
//! and attaches it in generic (SKB) mode.
//!
//!   xdpgate-load attach <iface> [obj.o]   load, seed the protected set from
//!                                         /etc/xdpgate/protected.conf, attach,
//!                                         and pin the maps under
//!                                         /sys/fs/bpf/xdpgate
//!   xdpgate-load detach <iface>           detach and remove the pins
//!
//! Seeding happens between load and attach. libbpf creates and pins the maps
//! while loading, so they can be written before the program is wired to the
//! netdev: the gate knows what it is guarding by the time it goes live. Any
//! problem with the config stops the attach, so the gate is either armed and
//! correct or not attached at all. It can never be attached with an empty
//! protected set, which would pass every packet while looking healthy.
//!
//! The attachment outlives this process, since the netdev holds the program,
//! and the maps stay pinned for xdpgate-ctl.
const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;
const layout = @import("layout");
const declared = @import("declared_set.zig");
const glibc = @import("glibc.zig");
const libbpf = @import("libbpf.zig");
const maps = @import("maps.zig");
const Output = @import("Output.zig");

const default_obj = "xdpgate.bpf.o";

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.arena.allocator(); // process lifetime: nothing to free
    var stdio: Output.Stdio = undefined;
    const out = stdio.init(init.io);
    defer out.flush();

    const args = try init.minimal.args.toSlice(gpa);
    const conf_path = declared.path(init.minimal.environ);
    if (args.len < 3) {
        out.warn(
            \\usage: {0s} attach <iface> [obj.o]
            \\       {0s} detach <iface>
            \\
            \\the protected set is read from {1s}
            \\(override with ${2s})
            \\
        , .{ if (args.len > 0) args[0] else "(null)", conf_path, declared.path_env });
        return 2;
    }

    const ifindex = glibc.if_nametoindex(args[2]);
    if (ifindex == 0) {
        out.warn("unknown interface '{s}'\n", .{args[2]});
        return 2;
    }
    if (std.mem.eql(u8, args[1], "attach"))
        return attach(gpa, ifindex, if (args.len > 3) args[3] else default_obj, conf_path, out);
    if (std.mem.eql(u8, args[1], "detach"))
        return detach(ifindex, out);
    out.warn("unknown command '{s}'\n", .{args[1]});
    return 2;
}

fn attach(gpa: Allocator, ifindex: c_uint, obj_path: [:0]const u8, conf_path: [:0]const u8, out: Output) Allocator.Error!u8 {
    // Remember whether the pin directory is ours, so that a failed attach
    // removes only pins it created and never tears down a live gate's maps.
    var created_pin_dir = false;
    switch (linux.errno(linux.mkdir(layout.pin_dir, 0o700))) {
        .SUCCESS => created_pin_dir = true,
        .EXIST => {},
        else => |e| {
            out.warn("mkdir {s}: {s}\n", .{ layout.pin_dir, glibc.errorText(e) });
            out.warn("is the bpf filesystem mounted at /sys/fs/bpf?\n", .{});
            return 1;
        },
    }

    if (!try loadAndAttach(gpa, ifindex, obj_path, conf_path, out)) {
        if (created_pin_dir) removePins();
        return 1;
    }
    out.print("attached xdpgate (generic mode) to ifindex {d}; maps pinned at {s}\n", .{ ifindex, layout.pin_dir });
    return 0;
}

/// Leaves the program attached and the maps pinned (by name, under
/// pin_root_path) once the object is closed.
fn loadAndAttach(gpa: Allocator, ifindex: c_uint, obj_path: [:0]const u8, conf_path: [:0]const u8, out: Output) Allocator.Error!bool {
    const opts: libbpf.ObjectOpenOpts = .{ .pin_root_path = layout.pin_dir };
    const obj = libbpf.bpf_object__open_file(obj_path, &opts) orelse {
        out.warn("open {s} failed: {s}\n", .{ obj_path, glibc.errnumText(glibc.errno()) });
        return false;
    };
    defer libbpf.bpf_object__close(obj);

    const err = libbpf.bpf_object__load(obj);
    if (err != 0) {
        out.warn("load failed: {s}\n", .{glibc.errnumText(-err)});
        return false;
    }
    const prog = libbpf.bpf_object__find_program_by_name(obj, "xdpgate") orelse {
        out.warn("program 'xdpgate' not found in object\n", .{});
        return false;
    };

    // Arm the maps before arming the datapath.
    if (!try seedProtected(gpa, obj, conf_path, out)) {
        out.warn("refusing to attach: the protected set is unusable\n", .{});
        return false;
    }

    const flags = libbpf.XDP_FLAGS_SKB_MODE | libbpf.XDP_FLAGS_UPDATE_IF_NOEXIST;
    const attach_err = libbpf.bpf_xdp_attach(@intCast(ifindex), libbpf.bpf_program__fd(prog), flags, null);
    if (attach_err != 0) {
        out.warn("xdp attach (generic) failed: {s}\n", .{glibc.errnumText(-attach_err)});
        return false;
    }
    return true;
}

/// Applies the declared protected set to the freshly loaded maps. False means
/// do not attach; why has been explained.
fn seedProtected(gpa: Allocator, obj: *libbpf.Object, conf_path: [:0]const u8, out: Output) Allocator.Error!bool {
    const m4 = libbpf.bpf_object__find_map_by_name(obj, maps.ProtectedV4.name);
    const m6 = libbpf.bpf_object__find_map_by_name(obj, maps.ProtectedV6.name);
    if (m4 == null or m6 == null) {
        out.warn("protected maps not found in object\n", .{});
        return false;
    }

    const set = declared.load(gpa, conf_path, out) catch |e| return usable(e);
    // Check before touching a map: a reconcile that has started cannot be
    // undone, and this check exists to stop exactly that.
    declared.checkHard(set, out) catch return false;
    declared.warnNotLocal(set, out);

    const p4: maps.ProtectedV4 = .{ .fd = libbpf.bpf_map__fd(m4.?) };
    const p6: maps.ProtectedV6 = .{ .fd = libbpf.bpf_map__fd(m6.?) };
    const counts = declared.reconcile(gpa, set, p4, p6, out) catch |e| return usable(e);

    const n = set.count();
    out.print("protected set seeded from {s}: {d} address{s} (+{d}, -{d})\n", .{
        conf_path, n, if (n == 1) "" else "es", counts.added, counts.removed,
    });
    return true;
}

fn usable(e: declared.Error) Allocator.Error!bool {
    return switch (e) {
        error.Unusable => false,
        error.OutOfMemory => |oom| oom,
    };
}

fn detach(ifindex: c_uint, out: Output) u8 {
    const err = libbpf.bpf_xdp_detach(@intCast(ifindex), libbpf.XDP_FLAGS_SKB_MODE, null);
    if (err != 0) {
        out.warn("detach failed: {s}\n", .{glibc.errnumText(-err)});
        return 1;
    }
    removePins(); // best effort
    out.print("detached from ifindex {d} and removed pins\n", .{ifindex});
    return 0;
}

fn removePins() void {
    inline for (.{ maps.ProtectedV4, maps.ProtectedV6, maps.AllowV4, maps.AllowV6 }) |M|
        _ = linux.unlink(M.pin_path);
    _ = linux.rmdir(layout.pin_dir);
}
