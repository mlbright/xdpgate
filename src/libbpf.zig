//! The libbpf calls xdpgate-load makes, declared by hand (Zig 0.17 has no
//! @cImport) and resolved against the system's libbpf.so.1, which build.zig
//! links by path. libbpf loads the object, creates the pinned maps or reuses
//! the ones already pinned, and attaches the program, exactly as it did for the
//! C loader; its own warnings go to stderr as before.
pub const Object = opaque {};
pub const Program = opaque {};
pub const Map = opaque {};

/// struct bpf_object_open_opts, up to the last field xdpgate sets. libbpf
/// versions its option structs by `sz` and reads any field past it as zero,
/// so this prefix is a complete struct to every libbpf 1.x.
pub const ObjectOpenOpts = extern struct {
    sz: usize = @sizeOf(ObjectOpenOpts),
    object_name: ?[*:0]const u8 = null,
    relaxed_maps: bool = false,
    pin_root_path: ?[*:0]const u8 = null,
};

/// Failures return null or a negative errno, and libbpf also sets errno.
pub extern fn bpf_object__open_file(path: [*:0]const u8, opts: ?*const ObjectOpenOpts) ?*Object;
pub extern fn bpf_object__load(obj: *Object) c_int;
pub extern fn bpf_object__close(obj: *Object) void;
pub extern fn bpf_object__find_program_by_name(obj: *const Object, name: [*:0]const u8) ?*Program;
pub extern fn bpf_object__find_map_by_name(obj: *const Object, name: [*:0]const u8) ?*Map;
pub extern fn bpf_program__fd(prog: *const Program) c_int;
pub extern fn bpf_map__fd(map: *const Map) c_int;
pub extern fn bpf_xdp_attach(ifindex: c_int, prog_fd: c_int, flags: u32, opts: ?*const anyopaque) c_int;
pub extern fn bpf_xdp_detach(ifindex: c_int, flags: u32, opts: ?*const anyopaque) c_int;

/// From linux/if_link.h.
pub const XDP_FLAGS_UPDATE_IF_NOEXIST: u32 = 1 << 0;
pub const XDP_FLAGS_SKB_MODE: u32 = 1 << 1;
