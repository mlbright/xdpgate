const std = @import("std");

// Builds xdpgate with Zig's toolchain:
//
//   zig-out/bin/xdpgate-load, zig-out/bin/xdpgate-ctl   the CLIs
//   zig-out/lib/xdpgate.bpf.o                            the XDP program
//
// For now these are still the C sources, compiled with `zig cc` and the same
// flags the Makefile used. The headers come from libbpf-dev; the CLIs link the
// system libbpf.so.1 by path, so no development symlink is needed at runtime.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const arch = target.result.cpu.arch;
    const multiarch = b.fmt("{s}-linux-gnu", .{@tagName(arch)});
    const target_arch = switch (arch) {
        .x86_64 => "x86",
        .aarch64 => "arm64",
        else => @tagName(arch),
    };

    const bpf = std.Build.Step.Run.create(b, "compile xdpgate.bpf.c");
    bpf.addFileArg(.zig_exe);
    // Unlike clang, `zig cc` emits unwind tables for BPF by default, and
    // libbpf complains about .eh_frame on every load.
    bpf.addArgs(&.{
        "cc",
        "-target",
        "bpfel-freestanding",
        "-O2",
        "-g",
        "-Wall",
        "-fno-unwind-tables",
        "-fno-asynchronous-unwind-tables",
        b.fmt("-D__TARGET_ARCH_{s}", .{target_arch}),
        b.fmt("-I/usr/include/{s}", .{multiarch}),
        "-I/usr/include",
        "-c",
    });
    bpf.addFileArg(b.path("xdpgate.bpf.c"));
    bpf.addFileInput(b.path("common.h"));
    bpf.addArg("-o");
    const bpf_obj = bpf.addOutputFileArg("xdpgate.bpf.o");
    b.getInstallStep().dependOn(&b.addInstallLibFile(bpf_obj, "xdpgate.bpf.o").step);

    // Only <bpf/...> is taken from /usr/include, so the CLIs otherwise compile
    // against Zig's own libc and kernel headers.
    const libbpf_headers = b.addWriteFiles();
    _ = libbpf_headers.addCopyDirectory(b.graph.cwdRelativePath("/usr/include/bpf"), "bpf", .{});
    const libbpf = b.graph.cwdRelativePath(b.fmt("/usr/lib/{s}/libbpf.so.1", .{multiarch}));

    for ([_][2][]const u8{
        .{ "xdpgate-load", "xdpgate_load.c" },
        .{ "xdpgate-ctl", "xdpgate_ctl.c" },
    }) |cli| {
        const mod = b.createModule(.{
            .target = target,
            .optimize = .ReleaseFast, // -O2, as before
            .link_libc = true,
        });
        mod.addCSourceFiles(.{
            .files = &.{ cli[1], "protected_conf.c" },
            .flags = &.{ "-g", "-Wall" },
        });
        mod.addIncludePath(libbpf_headers.getDirectory());
        mod.addObjectFile(libbpf);
        b.installArtifact(b.addExecutable(.{ .name = cli[0], .root_module = mod }));
    }

    _ = b.step("test", "Run the unit tests");
}
