# xdpgate Makefile
# Development platform: Ubuntu 24.04 LTS (Noble Numbat). The build needs
# rustup, LLVM 23 from apt.llvm.org and bpf-linker; see README.md.
#
# Build as yourself, install as root: `make && sudo make install`. Installing
# never builds, so root needs no Rust toolchain.
#
# The CLIs are built by the stable toolchain pinned in rust-toolchain.toml,
# the XDP program by the nightly pinned in xdpgate-ebpf/ with bpf-linker.
CARGO    ?= cargo

EBPF_OUT := xdpgate-ebpf/target/bpfel-unknown-none/release/xdpgate

all: xdpgate.bpf.o xdpgate-load xdpgate-ctl

# Every Rust binary in the workspace: the two CLIs and check-object.
cargo-build:
	$(CARGO) build --release --locked

# The XDP program, then the build check from ADR 0001: libbpf must see exactly
# the four maps, with the frozen sizes and capacities, pinned by name.
xdpgate.bpf.o: cargo-build
	@command -v bpf-linker >/dev/null || { \
		echo "bpf-linker not found. It needs LLVM 23 from apt.llvm.org (see README.md), then:"; \
		echo "  LLVM_PREFIX=/usr/lib/llvm-23 cargo install bpf-linker --version 0.11.0 \\"; \
		echo "    --locked --no-default-features --features llvm-23"; \
		exit 1; } >&2
	cd xdpgate-ebpf && $(CARGO) build --release --locked
	target/release/check-object $(EBPF_OUT)
	cp $(EBPF_OUT) $@

xdpgate-load xdpgate-ctl: cargo-build
	cp target/release/$@ $@

# Unit tests, then the golden-transcript and netns traffic suites (tests/).
# The suites run in throwaway namespaces and ask sudo for them, so the build
# never runs as root.
check: all
	$(CARGO) test --locked
	sudo tests/goldens.sh .
	sudo tests/traffic.sh .

# Verify the program loads + passes the verifier without attaching to a NIC.
# Run as root, after `make`. Needs bpftool, which ships in the kernel tooling:
# apt-get install linux-tools-$(uname -r)
verify:
	@test -f xdpgate.bpf.o || { echo "no xdpgate.bpf.o; run \`make\` first" >&2; exit 1; }
	bpftool prog load xdpgate.bpf.o /sys/fs/bpf/xdpgate_verify_test \
		type xdp && bpftool prog | tail -3 && \
		rm -f /sys/fs/bpf/xdpgate_verify_test

# Audit which listeners are exposed on each local IP (uses ss; run as root for
# process names). Helps pick an IP that does NOT share the management plane.
audit:
	@./whats-on-ip --self

# Preflight: fail if any protected IP carries Tailscale underlay / management
# traffic. Run after seeding the protected set, before relying on the gate.
preflight:
	@./whats-on-ip --preflight

clean:
	rm -f xdpgate.bpf.o xdpgate-load xdpgate-ctl
	$(CARGO) clean
	cd xdpgate-ebpf && $(CARGO) clean

# Runs the traffic suite against the files it is about to copy, on this
# kernel, and installs nothing if any check fails. See install.sh.
install:
	./install.sh

.PHONY: all cargo-build check clean verify audit preflight install
