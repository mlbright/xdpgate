---
status: accepted
---

# Userspace calls the system libbpf through a hand-written binding

`xdpgate-load`, `xdpgate-ctl` and the build's object check call the system `libbpf.so.1` (1.3.0 on Ubuntu 24.04) through one small module of hand-written declarations: the 13 functions the C called, a few map getters for the object check, and the open-options struct. All `unsafe` stays in that module. Being the same library making the same calls as the C, it keeps the C's pin-reuse check, netlink attach and detach, `errno` values and libbpf's own messages, all of which the goldens freeze.

## Considered Options

- **Aya.** Rejected, and the reason is not obvious. When a pin already exists at a map's path, Aya reuses it without comparing its type, key size, value size or max entries; libbpf refuses every such mismatch. A probe turned this into a fail-open: a stale `allow_v4` pin with a 4-byte key made a grant for one port pass every port from that source. Aya also attaches XDP through a BPF link, so the C `detach` cannot remove an Aya-attached gate and Aya cannot attach over a running C gate, which breaks installing the port over a live C gate.
- **libbpf-rs against the system libbpf.** Works, but current releases need libbpf-sys 1.7 bindings while Ubuntu 24.04 ships 1.3.0, so any call newer than 1.3 fails at link or run time. Adds crates to audit.
- **libbpf-rs with libbpf 1.7 built in.** Closes that gap, but brings a C build of libbpf, libelf and zlib back, stops Ubuntu's libbpf security fixes from reaching the gate, and may change libbpf messages the goldens record.
- **Raw `bpf()` syscalls.** Fine for map access (about 90 lines), but loading, pin reuse and attach would be ours to get right.

## Consequences

The declarations must match libbpf 1.3.0's ABI. Moving to a newer libbpf is a deliberate change: check the declarations and re-record the goldens that contain libbpf's messages.

The kernel copies a map's own key and value sizes in and out of whatever buffers it is handed, so a pin with a different layout (left by another version, or made by hand) would let it write past them. The C never checked. Every map handle in the binding therefore asks the kernel for the map's key and value sizes first (`bpf_obj_get_info_by_fd`, one call the C did not make) and refuses a mismatch with a message naming both layouts. That is the port's one addition to the C's behaviour, and well-formed maps never see it.
