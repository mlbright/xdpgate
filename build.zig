const std = @import("std");

// Builds xdpgate:
//
//   zig-out/bin/xdpgate-load, zig-out/bin/xdpgate-ctl   the CLIs
//   zig-out/lib/xdpgate.bpf.o                            the XDP program
//
// The XDP program is repaired after the build by tools/bpf_fixup.zig
// (docs/adr/0001-xdp-program-in-zig-with-object-fixup.md). The CLIs are built
// ReleaseSafe and link glibc; xdpgate-load also links the system's
// libbpf.so.1, by path, so building needs no libbpf headers.
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

    const load = addCli(b, "src/load.zig", target, layout);
    load.addObjectFile(b.graph.cwdRelativePath(b.fmt("/usr/lib/{s}/libbpf.so.1", .{multiarch})));
    b.installArtifact(b.addExecutable(.{ .name = "xdpgate-load", .root_module = load }));
    const ctl = addCli(b, "src/ctl.zig", target, layout);
    b.installArtifact(b.addExecutable(.{ .name = "xdpgate-ctl", .root_module = ctl }));

    const test_step = b.step("test", "Run the unit tests");
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = ctl })).step);

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

fn addCli(b: *std.Build, root: []const u8, target: std.Build.ResolvedTarget, layout: *std.Build.Module) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path(root),
        .target = target,
        .optimize = .ReleaseSafe,
        .link_libc = true,
        .imports = &.{.{ .name = "layout", .module = layout }},
    });
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
