const std = @import("std");

// Builds xdpgate:
//
//   zig-out/bin/xdpgate-load, zig-out/bin/xdpgate-ctl   the CLIs
//   zig-out/lib/xdpgate.bpf.o                            the XDP program
//
// The XDP program is Zig, repaired after the build by tools/bpf_fixup.zig
// (docs/adr/0001-xdp-program-in-zig-with-object-fixup.md). xdpgate-ctl is Zig,
// built ReleaseSafe. xdpgate-load is still the C source, compiled with `zig cc`
// and the flags the Makefile used; its headers come from libbpf-dev, and it
// links the system libbpf.so.1 by path.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const multiarch = b.fmt("{s}-linux-gnu", .{@tagName(target.result.cpu.arch)});
    const layout = b.createModule(.{ .root_source_file = b.path("src/layout.zig") });

    const fixup = b.addExecutable(.{
        .name = "bpf_fixup",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/bpf_fixup.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
            .imports = &.{.{ .name = "layout", .module = layout }},
        }),
    });

    const bpf = addBpfObject(b, "xdpgate", b.path("src/bpf/xdpgate.zig"), layout);
    const fix_bpf = b.addRunArtifact(fixup);
    fix_bpf.addFileArg(bpf.getEmittedBin());
    const bpf_obj = fix_bpf.addOutputFileArg("xdpgate.bpf.o");
    b.getInstallStep().dependOn(&b.addInstallLibFile(bpf_obj, "xdpgate.bpf.o").step);

    // Only <bpf/...> is taken from /usr/include, so the CLIs otherwise compile
    // against Zig's own libc and kernel headers.
    const libbpf_headers = b.addWriteFiles();
    _ = libbpf_headers.addCopyDirectory(b.graph.cwdRelativePath("/usr/include/bpf"), "bpf", .{});
    const libbpf = b.graph.cwdRelativePath(b.fmt("/usr/lib/{s}/libbpf.so.1", .{multiarch}));

    const load = b.createModule(.{
        .target = target,
        .optimize = .ReleaseFast, // -O2, as before
        .link_libc = true,
    });
    load.addCSourceFiles(.{
        .files = &.{ "xdpgate_load.c", "protected_conf.c" },
        .flags = &.{ "-g", "-Wall" },
    });
    load.addIncludePath(libbpf_headers.getDirectory());
    load.addObjectFile(libbpf);
    b.installArtifact(b.addExecutable(.{ .name = "xdpgate-load", .root_module = load }));

    // glibc is linked for the handful of functions in src/glibc.zig.
    const ctl = b.createModule(.{
        .root_source_file = b.path("src/ctl.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
        .link_libc = true,
        .imports = &.{.{ .name = "layout", .module = layout }},
    });
    b.installArtifact(b.addExecutable(.{ .name = "xdpgate-ctl", .root_module = ctl }));

    const test_step = b.step("test", "Run the unit tests");
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = ctl })).step);

    // The C half of the frozen layout must agree with src/layout.zig.
    const c_layout = b.createModule(.{ .target = target, .link_libc = true });
    c_layout.addCSourceFile(.{ .file = b.path("tests/layout_check.c") });
    test_step.dependOn(&b.addObject(.{ .name = "layout_check", .root_module = c_layout }).step);

    // The fix-up pass must refuse the relocation that would bind every map
    // lookup to one map.
    const bad = addBpfObject(b, "section_relocated_maps", b.path("tests/bpf/section_relocated_maps.zig"), layout);
    const refuse = b.addRunArtifact(fixup);
    refuse.addFileArg(bad.getEmittedBin());
    _ = refuse.addOutputFileArg("refused.o");
    refuse.expectExitCode(1);
    refuse.expectStdErrMatch("map reference through the section symbol");
    test_step.dependOn(&refuse.step);
}

/// A BPF object as the fix-up pass expects it: ReleaseSmall (Debug overflows
/// the BPF stack and ReleaseSafe's checks fail the verifier), with debug info,
/// which is where the BTF comes from, and without unwind tables.
fn addBpfObject(b: *std.Build, name: []const u8, root: std.Build.LazyPath, layout: *std.Build.Module) *std.Build.Step.Compile {
    return b.addObject(.{
        .name = name,
        .root_module = b.createModule(.{
            .root_source_file = root,
            .target = b.resolveTargetQuery(.{ .cpu_arch = .bpfel, .os_tag = .freestanding }),
            .optimize = .ReleaseSmall,
            .strip = false,
            .unwind_tables = .none,
            .imports = &.{.{ .name = "layout", .module = layout }},
        }),
    });
}
