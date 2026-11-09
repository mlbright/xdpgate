---
status: accepted
---

# The XDP program is in Rust, with its maps defined by hand

The XDP program is written in Rust so that it and the CLIs share one definition of the key layouts and constants, in a small `no_std` crate. It uses no crates at all, not even aya-ebpf. aya-ebpf's map types do not fit: its BTF maps have no `pinning` member, and its legacy maps use the `maps` section, which libbpf 1.0 and later refuse. What remained to take from it (two return codes, the context struct, two helpers called by their stable IDs, and the section name) is about 25 lines, against roughly 30 crates, several of which run build scripts or proc macros on the build machine. So each of the four maps is a hand-written `#[repr(C)]` struct in `.maps`, shaped the way libbpf's own `__uint`/`__type` macros are, and the system libbpf loads the object as it is.

This supersedes ADR 0001, which wrote the program in Zig and repaired its object after every build; the Rust object needs no repair.

## Considered Options

- **Keep `xdpgate.bpf.c` in C.** Everything Rust would build on stable, but the key layouts would live in two languages, and the conversion would stop about 200 lines short.
- **aya-ebpf's `btf_maps`.** Loads, but pins nothing. The loader still reports the maps as pinned, so `xdpgate-ctl` and reload would quietly lose the gate after attach.
- **aya-ebpf for the context and helpers only.** Works, and was the first choice, but brings about 30 crates for what is 25 lines by hand. Worth revisiting if aya-ebpf's map types gain pinning.

## Consequences

This crate alone needs a nightly compiler and `bpf-linker`, and `bpf-linker`'s LLVM must match rustc's.

A hand-written map definition can be wrong without anything noticing, and a nightly or kernel change can alter what the program does without any code changing. Three guardrails cover that:

- the key and value sizes (7, 19, 16 and 8 bytes) are asserted at compile time;
- the build asks libbpf to open the finished object and fails unless all four maps are present with the right names, hash type, sizes, max entries and pin-by-name;
- `make install` runs the netns traffic suite against the exact files it is about to copy, on the kernel they will run on, and installs nothing if any check fails.
