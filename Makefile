# xdpgate Makefile - a thin wrapper over `zig build`.
# Development platform: Ubuntu 24.04 LTS (Noble Numbat).
# Building needs Zig 0.17.0 on PATH (https://ziglang.org/download/).
#
# Build as yourself, install as root: `make && sudo make install`. Installing
# never builds, so root does not need Zig on its PATH.
ZIG ?= zig
OUT := zig-out
ARTIFACTS := $(OUT)/bin/xdpgate-load $(OUT)/bin/xdpgate-ctl $(OUT)/lib/xdpgate.bpf.o

all:
	$(ZIG) build

# Unit tests, then the golden-transcript and netns traffic suites (tests/),
# which run in throwaway namespaces and ask sudo for them.
check: all
	$(ZIG) build test
	sudo tests/goldens.sh $(OUT)
	sudo tests/traffic.sh $(OUT)

$(ARTIFACTS):
	@echo "$@ is missing: run 'make' first, as yourself" >&2; exit 1

# Verify the program loads + passes the verifier without attaching to a NIC.
verify: $(OUT)/lib/xdpgate.bpf.o
	bpftool prog load $< /sys/fs/bpf/xdpgate_verify_test \
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
	rm -rf $(OUT) .zig-cache

# Installs what `make` built, after the netns traffic test has passed on those
# exact files on this kernel: a build that does not gate correctly is never
# installed.
# Never installs protected.conf itself: an existing protected set is operator
# data, and a generated one would be a guess at what to gate.
install: $(ARTIFACTS)
	tests/traffic.sh $(OUT)
	install -d /usr/local/sbin /usr/local/lib/xdpgate /etc/xdpgate
	install -m 0755 $(OUT)/bin/xdpgate-load $(OUT)/bin/xdpgate-ctl whats-on-ip /usr/local/sbin/
	install -m 0644 $(OUT)/lib/xdpgate.bpf.o /usr/local/lib/xdpgate/
	install -m 0644 protected.conf.example /etc/xdpgate/
	install -m 0644 xdpgate.service xdpgate-gc.service xdpgate-gc.timer \
		/etc/systemd/system/
	@echo
	@echo "Next, in order:"
	@echo "  1. cp /etc/xdpgate/protected.conf.example /etc/xdpgate/protected.conf"
	@echo "     and list the addresses to gate (upgrading? use: xdpgate-ctl export)"
	@echo "  2. edit IFACE= in /etc/systemd/system/xdpgate.service"
	@echo "  3. systemctl daemon-reload"
	@echo "  4. systemctl enable --now xdpgate.service xdpgate-gc.timer"
	@echo
	@echo "The gate refuses to attach without a non-empty protected.conf."

.PHONY: all check clean verify audit preflight install
