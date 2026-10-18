//! The CLIs' stdout and stderr, behaving as C stdio did, since what they print
//! must match the C build's byte for byte: stdout is line-buffered on a
//! terminal and fully buffered otherwise, stderr goes out one message at a
//! time, and a failed write changes nothing (a closed pipe still raises
//! SIGPIPE).
const std = @import("std");
const Output = @This();

stdout: *std.Io.Writer,
stderr: *std.Io.Writer,
line_buffered: bool,

pub fn print(o: Output, comptime fmt: []const u8, args: anytype) void {
    o.stdout.print(fmt, args) catch {};
    if (o.line_buffered) o.flush();
}

pub fn warn(o: Output, comptime fmt: []const u8, args: anytype) void {
    o.stderr.print(fmt, args) catch {};
    o.stderr.flush() catch {};
}

pub fn flush(o: Output) void {
    o.stdout.flush() catch {};
}

/// Output for a unit test, writing into two buffers.
pub const Captured = struct {
    stdout: std.Io.Writer.Allocating,
    stderr: std.Io.Writer.Allocating,

    pub fn init(gpa: std.mem.Allocator) Captured {
        return .{ .stdout = .init(gpa), .stderr = .init(gpa) };
    }

    pub fn deinit(c: *Captured) void {
        c.stdout.deinit();
        c.stderr.deinit();
    }

    pub fn output(c: *Captured) Output {
        return .{ .stdout = &c.stdout.writer, .stderr = &c.stderr.writer, .line_buffered = false };
    }
};
