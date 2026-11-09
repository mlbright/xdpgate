# xdpgate Makefile
# Development platform: Ubuntu 24.04 LTS (Noble Numbat).
#
# Build as yourself, install as root: `make && sudo make install`. Installing
# never builds, so root needs no Rust toolchain.
#
# The XDP program is built by the nightly pinned in xdpgate-ebpf/ with
# bpf-linker, xdpgate-ctl by the stable toolchain pinned in
# rust-toolchain.toml. xdpgate-load is still C, built with `make deps`'s
# packages.
CC       ?= cc
CARGO    ?= cargo

# Build dependencies of the C loader (apt package names on Ubuntu 24.04 LTS).
# The optional `verify` target also needs bpftool, which ships in the
# kernel tooling: apt-get install linux-tools-$(shell uname -r)
APT_DEPS := gcc libbpf-dev make

USR_CFLAGS := -O2 -g -Wall
LIBS       := -lbpf

EBPF_OUT := xdpgate-ebpf/target/bpfel-unknown-none/release/xdpgate

all: xdpgate.bpf.o xdpgate-load xdpgate-ctl

# Every Rust binary in the workspace: xdpgate-ctl and check-object.
cargo-build:
	$(CARGO) build --release --locked

# Install the core build dependencies (Ubuntu 24.04 LTS).
deps:
	sudo apt-get update
	sudo apt-get install -y $(APT_DEPS)

# The XDP program, then the build check from ADR 0002: libbpf must see exactly
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

# The protected set is config-driven. The C loader applies it through
# protected_conf.c, xdpgate-ctl through the same parse/check/reconcile steps
# in xdpgate/src/protected.rs, and the goldens hold both to the same output.
protected_conf.o: protected_conf.c protected_conf.h common.h
	$(CC) $(USR_CFLAGS) -c $< -o $@

xdpgate-load: xdpgate_load.c protected_conf.o common.h protected_conf.h
	$(CC) $(USR_CFLAGS) $< protected_conf.o -o $@ $(LIBS)

xdpgate-ctl: cargo-build
	cp target/release/xdpgate-ctl $@

# Unit tests, then the golden-transcript and netns traffic suites (tests/).
# The suites run in throwaway namespaces and ask sudo for them, so the build
# never runs as root.
check: all
	$(CARGO) test --locked
	sudo tests/goldens.sh .
	sudo tests/traffic.sh .

# Verify the program loads + passes the verifier without attaching to a NIC.
# Run as root, after `make`.
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
	rm -f xdpgate.bpf.o protected_conf.o xdpgate-load xdpgate-ctl
	$(CARGO) clean
	cd xdpgate-ebpf && $(CARGO) clean

# Runs the traffic suite against the files it is about to copy, on this
# kernel, and installs nothing if any check fails. See install.sh.
install:
	./install.sh

.PHONY: all cargo-build deps check clean verify audit preflight install
