# xdpgate Makefile
# Development platform: Ubuntu 24.04 LTS (Noble Numbat).
# Install the build toolchain with `make deps` (or see the package list below).
CLANG    ?= clang
CC       ?= cc
ARCH     := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')
MULTIARCH := $(shell uname -m)-linux-gnu

# Core build dependencies (apt package names on Ubuntu 24.04 LTS).
# The optional `verify` target also needs bpftool, which ships in the
# kernel tooling: apt-get install linux-tools-$(shell uname -r)
APT_DEPS := clang llvm libbpf-dev libelf-dev make

BPF_CFLAGS := -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(ARCH) -I/usr/include/$(MULTIARCH)
USR_CFLAGS := -O2 -g -Wall
LIBS       := -lbpf

all: xdpgate.bpf.o xdpgate-load xdpgate-ctl

# Install the core build dependencies (Ubuntu 24.04 LTS).
deps:
	sudo apt-get update
	sudo apt-get install -y $(APT_DEPS)

xdpgate.bpf.o: xdpgate.bpf.c common.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# The protected set is config-driven; both binaries apply it through the same
# parse/check/reconcile routines so attach and reload cannot drift apart.
protected_conf.o: protected_conf.c protected_conf.h common.h
	$(CC) $(USR_CFLAGS) -c $< -o $@

xdpgate-load: xdpgate_load.c protected_conf.o common.h protected_conf.h
	$(CC) $(USR_CFLAGS) $< protected_conf.o -o $@ $(LIBS)

xdpgate-ctl: xdpgate_ctl.c protected_conf.o common.h protected_conf.h
	$(CC) $(USR_CFLAGS) $< protected_conf.o -o $@ $(LIBS)

# Verify the program loads + passes the verifier without attaching to a NIC.
verify: xdpgate.bpf.o
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

# Never installs protected.conf itself: an existing protected set is operator
# data, and a generated one would be a guess at what to gate.
install: all
	install -d /usr/local/sbin /usr/local/lib/xdpgate /etc/xdpgate
	install -m 0755 xdpgate-load xdpgate-ctl whats-on-ip /usr/local/sbin/
	install -m 0644 xdpgate.bpf.o /usr/local/lib/xdpgate/
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

.PHONY: all deps clean verify audit preflight install
