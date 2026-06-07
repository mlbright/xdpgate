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

xdpgate-load: xdpgate_load.c common.h
	$(CC) $(USR_CFLAGS) $< -o $@ $(LIBS)

xdpgate-ctl: xdpgate_ctl.c common.h
	$(CC) $(USR_CFLAGS) $< -o $@ $(LIBS)

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
	rm -f xdpgate.bpf.o xdpgate-load xdpgate-ctl

install: all
	install -d /usr/local/sbin /usr/local/lib/xdpgate
	install -m 0755 xdpgate-load xdpgate-ctl whats-on-ip /usr/local/sbin/
	install -m 0644 xdpgate.bpf.o /usr/local/lib/xdpgate/
	install -m 0644 xdpgate.service xdpgate-gc.service xdpgate-gc.timer \
		/etc/systemd/system/
	@echo "Edit IFACE= in /etc/systemd/system/xdpgate.service, then:"
	@echo "  systemctl daemon-reload && systemctl enable --now xdpgate.service xdpgate-gc.timer"

.PHONY: all deps clean verify audit preflight install
