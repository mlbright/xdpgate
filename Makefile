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

# The release tag at a tagged commit, else what git describe says about this
# one: "0.2.0-3-gabc1234", with "-dirty" for uncommitted changes.
BUILD_VERSION := $(shell git describe --tags --match '[0-9]*.[0-9]*.[0-9]*' \
	--dirty 2>/dev/null || echo unknown)
ARCH := $(shell uname -m | sed 's/^x86_64$$/amd64/; s/^aarch64$$/arm64/')
DIST := xdpgate-$(BUILD_VERSION)-linux-$(ARCH)

all: xdpgate.bpf.o xdpgate-load xdpgate-ctl VERSION

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

# install.sh installs it as /usr/local/lib/xdpgate/VERSION.
VERSION: FORCE
	@echo $(BUILD_VERSION) >$@.new
	@cmp -s $@.new $@ && rm $@.new || mv $@.new $@

# A release tarball for this machine's architecture. It is laid out like the
# top of the checkout, so install.sh, and the traffic suite it runs first,
# work from it unchanged. Metadata is fixed, so the same files make the same
# tarball.
dist: all
	rm -rf dist/$(DIST)
	mkdir -p dist/$(DIST)/tests
	install -m 0755 xdpgate-load xdpgate-ctl whats-on-ip install.sh dist/$(DIST)/
	install -m 0644 xdpgate.bpf.o VERSION README.md LICENSE \
		xdpgate.service xdpgate-gc.service xdpgate-gc.timer \
		protected.conf.example access.conf.example dist/$(DIST)/
	install -m 0755 tests/traffic.sh dist/$(DIST)/tests/
	install -m 0644 tests/traffic.py tests/lib.sh dist/$(DIST)/tests/
	tar -C dist --sort=name --owner=0 --group=0 --numeric-owner --mode=go-w \
		--mtime=@$$(git log -1 --format=%ct 2>/dev/null || echo 0) \
		-cf - $(DIST) | gzip -9n >dist/$(DIST).tar.gz
	@echo dist/$(DIST).tar.gz

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
	rm -f xdpgate.bpf.o xdpgate-load xdpgate-ctl VERSION
	rm -rf dist
	$(CARGO) clean
	cd xdpgate-ebpf && $(CARGO) clean

# Runs the traffic suite against the files it is about to copy, on this
# kernel, and installs nothing if any check fails. See install.sh.
install:
	./install.sh

# Release VERSION (x.y.z, no "v"): checks the tree is the tip of main, runs
# `make check`, then tags it and pushes the tag. The release workflow builds,
# tests and publishes both architectures. See scripts/publish.sh, ADR 0003.
publish:
	REMOTE="$(REMOTE)" scripts/publish.sh "$(VERSION)"

.PHONY: all cargo-build check clean dist verify audit preflight install publish FORCE
FORCE:
