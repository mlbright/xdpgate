# Sourced by the test suites and by scenario setup scripts.
#
# The suites re-run themselves under `unshare --mount --net`, so everything they
# do lands in a throwaway mount and network namespace: a fresh bpffs hides the
# pins of any gate running on the host, and the only interfaces in reach are
# the veth pair created here.

TESTS=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PY="/usr/bin/python3 -I"

die() {
	echo "$(basename "$0"): $*" >&2
	exit 2
}

need_root() {
	[ "$(id -u)" = 0 ] || die "must run as root, inside throwaway namespaces it creates itself"
}

# Find xdpgate-load, xdpgate-ctl and xdpgate.bpf.o in $1, either all at the top
# (the C build) or under bin/ and lib/ (zig-out). Sets LOAD, CTL and OBJ.
find_artifacts() {
	local d
	LOAD='' CTL='' OBJ=''
	for d in "$1" "$1/bin" "$1/lib"; do
		[ -z "$LOAD" ] && [ -x "$d/xdpgate-load" ] && LOAD=$(realpath "$d/xdpgate-load")
		[ -z "$CTL" ] && [ -x "$d/xdpgate-ctl" ] && CTL=$(realpath "$d/xdpgate-ctl")
		[ -z "$OBJ" ] && [ -f "$d/xdpgate.bpf.o" ] && OBJ=$(realpath "$d/xdpgate.bpf.o")
	done
	[ -n "$LOAD" ] || die "no xdpgate-load in $1"
	[ -n "$CTL" ] || die "no xdpgate-ctl in $1"
	[ -n "$OBJ" ] || die "no xdpgate.bpf.o in $1"
}

# --- helpers for scenario setup scripts ---------------------------------------
# A setup script runs with `set -e` in the scenario's working directory, with
# the build under test on PATH. Map writes go through bpftool, not xdpgate-ctl.

attach() { xdpgate-load attach gate0 >/dev/null; }
write_conf() { printf '%s\n' "$@" >/etc/xdpgate/protected.conf; }
grant() { echo "$*" | grants; }
grants() { $PY "$TESTS/state.py" grants; }
protect() { $PY "$TESTS/state.py" protect "$1"; }
unprotect() { $PY "$TESTS/state.py" unprotect "$1"; }
fill() { $PY "$TESTS/state.py" fill "$1" "$2"; }
