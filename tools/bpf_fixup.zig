//! Post-build fix-up of the XDP program's object file.
//!
//!   bpf_fixup IN.o OUT.o
//!
//! Zig 0.17.0 emits a BPF object that libbpf and the kernel reject as-is. This
//! pass makes the few repairs needed and nothing else, and it refuses to write
//! anything unless the object looks exactly as expected: an object it does not
//! understand fails the build instead of reaching the gate. Delete it once Zig
//! emits loadable BPF objects (docs/adr/0001-xdp-program-in-zig-with-object-fixup.md).
//!
//! The repairs:
//!   - Zig exports a function as a LOCAL FUNC plus a GLOBAL alias, and libbpf
//!     refuses the LOCAL one as a static program. It becomes a NOTYPE.
//!   - BTF names each map's VAR after its Zig declaration, but libbpf takes the
//!     map name from the VAR, and the kernel only accepts identifiers. Map VARs
//!     get their exported names, and global linkage like the C ones have.
//!   - Zig's type names are namespaced ("layout.GrantKey4"), which the kernel
//!     rejects; '.' and other non-identifier characters become '_'.
//!   - The kernel requires named function arguments; unnamed ones become argN.
//!
//! Map relocations are deliberately NOT repaired, only checked: the program
//! names each map in inline assembly so they are right to begin with. A
//! relocation against the .maps section instead would bind every lookup to one
//! map, which loads cleanly and passes all traffic.
const std = @import("std");
const layout = @import("layout");

const program = "xdpgate";
const program_section = "xdp";
const map_names = [_][]const u8{ layout.protected_v4, layout.protected_v6, layout.allow_v4, layout.allow_v6 };

const Ehdr = extern struct {
    ident: [16]u8,
    type: u16,
    machine: u16,
    version: u32,
    entry: u64,
    phoff: u64,
    shoff: u64,
    flags: u32,
    ehsize: u16,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
};
const Shdr = extern struct { name: u32, type: u32, flags: u64, addr: u64, offset: u64, size: u64, link: u32, info: u32, addralign: u64, entsize: u64 };
const Sym = extern struct { name: u32, info: u8, other: u8, shndx: u16, value: u64, size: u64 };
const Rel = extern struct { offset: u64, info: u64 };
const BtfHdr = extern struct { magic: u16, version: u8, flags: u8, hdr_len: u32, type_off: u32, type_len: u32, str_off: u32, str_len: u32 };

const ET_REL = 1;
const EM_BPF = 247;
const SHT_SYMTAB = 2;
const SHT_RELA = 4;
const SHT_REL = 9;
const SHF_EXECINSTR = 4;
const STB_LOCAL = 0;
const STB_GLOBAL = 1;
const STT_NOTYPE = 0;
const STT_OBJECT = 1;
const STT_FUNC = 2;
const STT_SECTION = 3;
const R_BPF_64_64 = 1;
const BPF_LD_IMM64 = 0x18;

const BTF_MAGIC = 0xeb9f;
const BTF_KIND_STRUCT = 4;
const BTF_KIND_UNION = 5;
const BTF_KIND_ENUM = 6;
const BTF_KIND_FWD = 7;
const BTF_KIND_TYPEDEF = 8;
const BTF_KIND_FUNC = 12;
const BTF_KIND_FUNC_PROTO = 13;
const BTF_KIND_VAR = 14;
const BTF_KIND_DATASEC = 15;
const BTF_KIND_ENUM64 = 19;
const BTF_VAR_GLOBAL_ALLOCATED = 1;

fn refuse(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("bpf_fixup: refusing: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

fn cstr(bytes: []const u8, off: usize) []const u8 {
    if (off >= bytes.len) refuse("string offset {d} out of range", .{off});
    return std.mem.sliceTo(bytes[off..], 0);
}

fn rd32(b: []const u8, off: usize) u32 {
    return std.mem.readInt(u32, b[off..][0..4], .little);
}

fn wr32(b: []u8, off: usize, v: u32) void {
    std.mem.writeInt(u32, b[off..][0..4], v, .little);
}

fn table(comptime T: type, file: []u8, off: u64, size: u64) []align(1) T {
    if (off + size > file.len or size % @sizeOf(T) != 0) refuse("table at {d}+{d} out of range", .{ off, size });
    return @as([*]align(1) T, @ptrCast(file[@intCast(off)..].ptr))[0..@intCast(size / @sizeOf(T))];
}

fn mapIndex(name: []const u8) ?usize {
    for (map_names, 0..) |m, i| if (std.mem.eql(u8, m, name)) return i;
    return null;
}

fn isIdentifier(name: []const u8) bool {
    if (name.len == 0 or std.ascii.isDigit(name[0])) return false;
    for (name) |c| if (!std.ascii.isAlphanumeric(c) and c != '_') return false;
    return true;
}

const Object = struct {
    file: []u8,
    shoff: u64,
    shdrs: []align(1) Shdr,
    shstr: []const u8,
    syms: []align(1) Sym,
    symstr: []const u8,

    fn sectionName(o: Object, i: usize) []const u8 {
        return cstr(o.shstr, o.shdrs[i].name);
    }

    fn section(o: Object, name: []const u8) ?usize {
        for (0..o.shdrs.len) |i| if (std.mem.eql(u8, o.sectionName(i), name)) return i;
        return null;
    }

    fn mustSection(o: Object, name: []const u8) usize {
        return o.section(name) orelse refuse("no {s} section", .{name});
    }

    fn symName(o: Object, s: Sym) []const u8 {
        return cstr(o.symstr, s.name);
    }

    /// The one GLOBAL symbol in section `shndx` at `value`.
    fn globalAt(o: Object, shndx: usize, value: u64) ?usize {
        for (o.syms, 0..) |s, i| {
            if (s.info >> 4 == STB_GLOBAL and s.shndx == shndx and s.value == value) return i;
        }
        return null;
    }
};

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator(); // process lifetime: nothing to free
    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 3) refuse("usage: bpf_fixup IN.o OUT.o", .{});
    const cwd = std.Io.Dir.cwd();
    const file = try cwd.readFileAllocOptions(init.io, args[1], arena, .unlimited, .@"8", null);

    const o = parseElf(file);
    fixSymbols(o);
    checkMapRelocations(o);
    const out = try fixBtf(o, arena);
    try cwd.writeFile(init.io, .{ .sub_path = args[2], .data = out });
}

fn parseElf(file: []u8) Object {
    if (file.len < @sizeOf(Ehdr)) refuse("not an ELF file", .{});
    const eh = std.mem.bytesToValue(Ehdr, file[0..@sizeOf(Ehdr)]);
    if (!std.mem.eql(u8, eh.ident[0..4], "\x7fELF") or eh.ident[4] != 2 or eh.ident[5] != 1)
        refuse("not a little-endian ELF64 file", .{});
    if (eh.type != ET_REL or eh.machine != EM_BPF) refuse("not a BPF relocatable object", .{});
    if (eh.shentsize != @sizeOf(Shdr)) refuse("unexpected section header size", .{});

    const shdrs = table(Shdr, file, eh.shoff, @as(u64, eh.shnum) * @sizeOf(Shdr));
    if (eh.shstrndx >= shdrs.len) refuse("bad section name table index", .{});
    var o: Object = .{
        .file = file,
        .shoff = eh.shoff,
        .shdrs = shdrs,
        .shstr = file[@intCast(shdrs[eh.shstrndx].offset)..],
        .syms = undefined,
        .symstr = undefined,
    };

    var symtab: ?usize = null;
    for (shdrs, 0..) |h, i| {
        const name = o.sectionName(i);
        if (h.offset + h.size > file.len and h.type != 8) refuse("section {s} out of range", .{name});
        if (h.type == SHT_SYMTAB) {
            if (symtab != null) refuse("more than one symbol table", .{});
            symtab = i;
        }
        if (h.type == SHT_RELA) refuse("RELA section {s}", .{name});
        if (h.flags & SHF_EXECINSTR != 0 and h.size != 0 and !std.mem.eql(u8, name, program_section))
            refuse("code outside the {s} section, in {s}", .{ program_section, name });
        if (h.type == SHT_REL and h.info >= shdrs.len) refuse("relocations for no section in {s}", .{name});
        if (h.type == SHT_REL and shdrs[h.info].flags & SHF_EXECINSTR != 0 and
            !std.mem.eql(u8, name, ".rel" ++ program_section))
            refuse("relocations against code in {s}", .{name});
        for ([_][]const u8{ ".eh_frame", ".data", ".rodata", ".bss" }) |bad| {
            if (std.mem.startsWith(u8, name, bad)) refuse("unexpected section {s}", .{name});
        }
    }
    for ([_][]const u8{ program_section, ".rel" ++ program_section, "license", ".maps", ".BTF", ".BTF.ext" }) |name| {
        _ = o.mustSection(name);
    }
    const sh_sym = shdrs[symtab orelse refuse("no symbol table", .{})];
    o.syms = table(Sym, file, sh_sym.offset, sh_sym.size);
    o.symstr = file[@intCast(shdrs[sh_sym.link].offset)..];
    return o;
}

/// Exactly the program, the license and the maps are GLOBAL. Zig's LOCAL
/// alias of the program is turned into a NOTYPE so libbpf ignores it.
fn fixSymbols(o: Object) void {
    const xdp = o.mustSection(program_section);
    const maps = o.mustSection(".maps");
    const license = o.mustSection("license");
    var seen_program = false;
    var seen_license = false;
    var seen_maps: [map_names.len]bool = @splat(false);

    for (o.syms) |*s| {
        const name = o.symName(s.*);
        const bind = s.info >> 4;
        const kind = s.info & 0xf;
        if (bind == STB_LOCAL) {
            if (kind != STT_FUNC) continue;
            const g = o.globalAt(s.shndx, s.value) orelse refuse("static function {s}", .{name});
            if (!std.mem.eql(u8, o.symName(o.syms[g]), program) or o.syms[g].size != s.size)
                refuse("static function {s}", .{name});
            s.info = STB_LOCAL << 4 | STT_NOTYPE;
            continue;
        }
        if (bind != STB_GLOBAL) refuse("weak symbol {s}", .{name});
        if (kind == STT_FUNC and std.mem.eql(u8, name, program) and s.shndx == xdp and s.value == 0) {
            seen_program = true;
        } else if (kind == STT_OBJECT and std.mem.eql(u8, name, "_license") and s.shndx == license) {
            seen_license = true;
        } else if (kind == STT_OBJECT and s.shndx == maps) {
            const i = mapIndex(name) orelse refuse("unexpected map {s}", .{name});
            if (seen_maps[i]) refuse("map {s} defined twice", .{name});
            seen_maps[i] = true;
        } else {
            refuse("unexpected global symbol {s}", .{name});
        }
    }
    if (!seen_program) refuse("no program {s} in section {s}", .{ program, program_section });
    if (!seen_license) refuse("no _license", .{});
    for (map_names, seen_maps) |m, seen| if (!seen) refuse("no map {s}", .{m});
}

/// Every relocation in the program must load one map's own symbol, and every
/// map must be used.
fn checkMapRelocations(o: Object) void {
    const xdp = o.mustSection(program_section);
    const rel = o.shdrs[o.mustSection(".rel" ++ program_section)];
    const code = o.file[@intCast(o.shdrs[xdp].offset)..][0..@intCast(o.shdrs[xdp].size)];
    var used: [map_names.len]bool = @splat(false);
    for (table(Rel, o.file, rel.offset, rel.size)) |r| {
        const sym_index: usize = @intCast(r.info >> 32);
        if (sym_index >= o.syms.len) refuse("relocation symbol out of range", .{});
        const s = o.syms[sym_index];
        const name = o.symName(s);
        if (r.info & 0xffffffff != R_BPF_64_64) refuse("relocation of type {d}", .{r.info & 0xffffffff});
        if (s.info & 0xf == STT_SECTION) refuse("map reference through the section symbol (every lookup would hit one map)", .{});
        const i = mapIndex(name) orelse refuse("relocation against {s}", .{name});
        if (r.offset + 16 > code.len or code[@intCast(r.offset)] != BPF_LD_IMM64)
            refuse("relocation for {s} is not on a 64-bit load", .{name});
        if (rd32(code, @intCast(r.offset + 4)) != 0 or rd32(code, @intCast(r.offset + 12)) != 0)
            refuse("map reference to {s} has an addend", .{name});
        used[i] = true;
    }
    for (map_names, used) |m, u| if (!u) refuse("map {s} is never used", .{m});
}

/// Rewrites the type and string sections of .BTF. Types are edited in place;
/// new names are appended to the string section, so every existing string
/// offset (including those .BTF.ext holds) stays valid.
fn fixBtf(o: Object, arena: std.mem.Allocator) ![]u8 {
    const bi = o.mustSection(".BTF");
    const raw = o.file[@intCast(o.shdrs[bi].offset)..][0..@intCast(o.shdrs[bi].size)];
    if (raw.len < @sizeOf(BtfHdr)) refuse(".BTF too short", .{});
    var hdr = std.mem.bytesToValue(BtfHdr, raw[0..@sizeOf(BtfHdr)]);
    if (hdr.magic != BTF_MAGIC or hdr.version != 1 or hdr.hdr_len != @sizeOf(BtfHdr))
        refuse("unexpected .BTF header", .{});
    // Strings must follow types directly: they are re-written after them.
    if (hdr.str_off != hdr.type_off + hdr.type_len or hdr.hdr_len + hdr.str_off + hdr.str_len != raw.len)
        refuse("unexpected .BTF layout", .{});
    const types = raw[hdr.hdr_len + hdr.type_off ..][0..hdr.type_len];
    var strs: std.ArrayList(u8) = .empty;
    try strs.appendSlice(arena, raw[hdr.hdr_len + hdr.str_off ..][0..hdr.str_len]);

    var offs: std.ArrayList(usize) = .empty; // type id -> offset in `types`
    try offs.append(arena, 0); // id 0 is void
    var p: usize = 0;
    while (p < types.len) {
        if (p + 12 > types.len) refuse("truncated BTF type", .{});
        try offs.append(arena, p);
        const info = rd32(types, p + 4);
        const vlen: usize = info & 0xffff;
        p += 12 + switch ((info >> 24) & 0x1f) {
            1, 14, 17 => 4, // INT, VAR, DECL_TAG
            3 => 12, // ARRAY
            4, 5, 15, 19 => 12 * vlen, // STRUCT, UNION, DATASEC, ENUM64
            6, 13 => 8 * vlen, // ENUM, FUNC_PROTO
            2, 7, 8, 9, 10, 11, 12, 16, 18 => 0,
            else => |k| refuse("unknown BTF kind {d}", .{k}),
        };
    }
    if (p != types.len) refuse("truncated BTF types", .{});

    const kindOf = struct {
        fn f(t: []const u8, off: usize) u32 {
            return (rd32(t, off + 4) >> 24) & 0x1f;
        }
    }.f;
    const name = struct {
        fn f(l: *std.ArrayList(u8), t: []const u8, off: usize) []const u8 {
            return cstr(l.items, rd32(t, off));
        }
    }.f;
    const add = struct {
        fn f(a: std.mem.Allocator, l: *std.ArrayList(u8), s: []const u8) !u32 {
            const off: u32 = @intCast(l.items.len);
            try l.appendSlice(a, s);
            try l.append(a, 0);
            return off;
        }
    }.f;

    var datasec_vars: usize = 0;
    var funcs: usize = 0;
    var vars: usize = 0;
    for (offs.items[1..]) |t| {
        const vlen: usize = rd32(types, t + 4) & 0xffff;
        switch (kindOf(types, t)) {
            BTF_KIND_DATASEC => {
                const sec_name = try arena.dupe(u8, name(&strs, types, t));
                const shndx = o.section(sec_name) orelse refuse("DATASEC {s} has no section", .{sec_name});
                const is_maps = std.mem.eql(u8, sec_name, ".maps");
                if (!is_maps and !std.mem.eql(u8, sec_name, "license")) refuse("global data in {s}", .{sec_name});
                if (vlen != if (is_maps) map_names.len else 1) refuse("DATASEC {s} has {d} variables", .{ sec_name, vlen });
                for (0..vlen) |i| {
                    const entry = t + 12 + i * 12;
                    const var_id = rd32(types, entry);
                    if (var_id == 0 or var_id >= offs.items.len or kindOf(types, offs.items[var_id]) != BTF_KIND_VAR)
                        refuse("DATASEC {s} entry is not a VAR", .{sec_name});
                    const g = o.globalAt(shndx, rd32(types, entry + 4)) orelse
                        refuse("no symbol for a variable in {s}", .{sec_name});
                    const v = offs.items[var_id];
                    wr32(types, v, try add(arena, &strs, o.symName(o.syms[g])));
                    wr32(types, v + 12, BTF_VAR_GLOBAL_ALLOCATED);
                    datasec_vars += 1;
                }
            },
            BTF_KIND_FUNC_PROTO => for (0..vlen) |i| {
                const param = t + 12 + i * 8;
                if (rd32(types, param) == 0) {
                    var buf: [16]u8 = undefined;
                    wr32(types, param, try add(arena, &strs, try std.fmt.bufPrint(&buf, "arg{d}", .{i})));
                }
            },
            BTF_KIND_STRUCT, BTF_KIND_UNION, BTF_KIND_ENUM, BTF_KIND_ENUM64, BTF_KIND_FWD, BTF_KIND_TYPEDEF => {
                const old = name(&strs, types, t);
                if (old.len == 0 or isIdentifier(old)) continue;
                const fixed = try arena.dupe(u8, old);
                for (fixed) |*c| if (!std.ascii.isAlphanumeric(c.*) and c.* != '_') {
                    c.* = '_';
                };
                if (!isIdentifier(fixed)) refuse("type name {s}", .{old});
                wr32(types, t, try add(arena, &strs, fixed));
            },
            BTF_KIND_FUNC => {
                if (!std.mem.eql(u8, name(&strs, types, t), program))
                    refuse("BTF function {s}", .{name(&strs, types, t)});
                funcs += 1;
            },
            BTF_KIND_VAR => vars += 1,
            else => {},
        }
    }
    if (funcs != 1) refuse("{d} BTF functions", .{funcs});
    if (vars != datasec_vars or vars != map_names.len + 1) refuse("{d} BTF variables", .{vars});

    // Append the rebuilt .BTF at the end of the file and repoint its header.
    hdr.str_len = @intCast(strs.items.len);
    const keep = hdr.hdr_len + hdr.str_off; // header and types
    const base = std.mem.alignForward(usize, o.file.len, 8);
    const out = try arena.alloc(u8, base + keep + strs.items.len);
    @memset(out, 0);
    @memcpy(out[0..o.file.len], o.file);
    @memcpy(out[base..][0..keep], raw[0..keep]);
    @memcpy(out[base..][0..@sizeOf(BtfHdr)], std.mem.asBytes(&hdr));
    @memcpy(out[base + keep ..], strs.items);
    const out_shdrs = table(Shdr, out, o.shoff, o.shdrs.len * @sizeOf(Shdr));
    out_shdrs[bi].offset = base;
    out_shdrs[bi].size = keep + strs.items.len;
    return out;
}
