---
status: accepted
---

# The XDP program is written in Zig, and its object is fixed up after the build

Zig 0.17.0 compiles a BPF program that libbpf and the kernel reject as-is (Zig issue #24357 and related emission details), but the rest of xdpgate is in Zig and we want the key layouts and constants defined once for both sides. So the XDP program is Zig source, and a small post-build pass we own rewrites the object before it is installed; delete the pass once Zig emits loadable BPF objects.

## Considered Options

- **Keep `xdpgate.bpf.c` and compile it with `zig cc`.** Loads cleanly with no fix-up, but the C side must mirror the Zig layouts and needs `bpf_helpers.h`. This is the fallback if the pass becomes a burden.
- **Use zbpf.** Pinned to Zig 0.15.2 and does not build on 0.17.0; its sanitizer also lacks the fixes 0.17.0 needs (symbol linkage, map VAR names).

## Consequences

The pass depends on how Zig names, links and relocates symbols, so any Zig upgrade can break it. Three guardrails keep that from becoming a silent fail-open:

- Map references are made with inline assembly, so the pass never rewrites relocations. (Rewriting them wrongly binds every lookup to one map, which loads cleanly and passes all traffic.)
- The pass refuses to emit an object that does not look exactly as it expects, so a changed layout fails the build instead of the gate.
- A netns test of drop, pass, SPA carve-out and grant behaviour must pass before every install: `make install` runs it against the exact object it is about to copy, on the kernel the gate will run on, and refuses to install on failure. A Zig upgrade or a kernel upgrade therefore cannot reach the gate untested.

Only ReleaseSmall/ReleaseFast builds are usable: Debug exceeds the BPF stack limit and ReleaseSafe's safety checks are rejected by the verifier.
