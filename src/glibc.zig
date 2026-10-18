//! The glibc functions the CLIs call, declared by hand (Zig 0.17 has no
//! @cImport). Each is here because its output is part of the CLIs' interface:
//! error texts, the spelling of addresses and local dates read exactly as they
//! did when the CLIs were C.
const std = @import("std");
const linux = std.os.linux;

pub extern "c" fn strerror(errnum: c_int) [*:0]const u8;
pub extern "c" fn inet_pton(af: c_int, src: [*:0]const u8, dst: *anyopaque) c_int;
pub extern "c" fn inet_ntop(af: c_int, src: *const anyopaque, dst: [*]u8, size: u32) ?[*:0]const u8;
pub extern "c" fn localtime_r(timep: *const i64, result: *Tm) ?*Tm;
pub extern "c" fn strftime(s: [*]u8, max: usize, format: [*:0]const u8, tm: *const Tm) usize;
pub extern "c" fn getifaddrs(ifap: *?*IfAddrs) c_int;
pub extern "c" fn freeifaddrs(ifa: *IfAddrs) void;
pub extern "c" fn if_nametoindex(ifname: [*:0]const u8) c_uint;
extern "c" fn __errno_location() *c_int;

/// struct tm.
pub const Tm = extern struct {
    sec: c_int,
    min: c_int,
    hour: c_int,
    mday: c_int,
    mon: c_int,
    year: c_int,
    wday: c_int,
    yday: c_int,
    isdst: c_int,
    gmtoff: c_long,
    zone: ?[*:0]const u8,
};

/// struct ifaddrs.
pub const IfAddrs = extern struct {
    next: ?*IfAddrs,
    name: [*:0]const u8,
    flags: c_uint,
    addr: ?*const linux.sockaddr,
    netmask: ?*const linux.sockaddr,
    broadaddr_or_dstaddr: ?*const linux.sockaddr,
    data: ?*anyopaque,
};

/// strerror(e), as the C printed it.
pub fn errorText(e: linux.E) [:0]const u8 {
    return errnumText(@backingInt(e));
}

/// strerror(n) for any error number, libbpf's own (4000 and up) included.
pub fn errnumText(n: c_int) [:0]const u8 {
    return std.mem.span(strerror(n));
}

/// errno, as a libbpf call left it.
pub fn errno() c_int {
    return __errno_location().*;
}
