#!/bin/bash
# Netns traffic test: attach a build of xdpgate to a veth pair and check what
# actually gets through on this kernel - drop, pass, the SPA carve-out, grants,
# expired grants and reload, over IPv4 and IPv6.
#
#   sudo tests/traffic.sh DIR [CTL_DIR]
#
# DIR holds the build to test, as for goldens.sh. CTL_DIR, if given, supplies
# xdpgate-ctl instead, to check one build's ctl against another build's maps.
#
# `make install` runs this before copying anything, so it needs nothing beyond
# unshare, ip and /usr/bin/python3. The gated side is a private network and
# mount namespace with its own bpffs; the client is a second network namespace
# that lives only as long as the test.
set -u
. "$(dirname "$0")/lib.sh"

failed=0 passed=0

check() {
	local want=$1 what=$2 got
	shift 2
	got=$(client $PY "$TESTS/traffic.py" probe "$@")
	if [ "$got" = "$want" ]; then
		printf 'ok    %-4s  %s\n' "$want" "$what"
		passed=$((passed + 1))
	else
		printf 'FAIL  %s: wanted %s, got %s\n' "$what" "$want" "${got:-nothing}"
		failed=$((failed + 1))
	fi
}

# Steps the checks depend on: if one fails, nothing after it means anything.
must() {
	local out
	if ! out=$("$@" 2>&1); then
		echo "FAIL  could not run: $*"
		echo "$out" | sed 's/^/      /'
		exit 1
	fi
}

client() { nsenter --net="/proc/$CLIENT/ns/net" "$@"; }
ctl() { must "$CTL" "$@"; }

inner() {
	local tmp=$1
	set -e
	mount -t bpf bpf /sys/fs/bpf
	mount -t tmpfs tmpfs "$tmp"
	ip link set lo up

	unshare --net sleep infinity &
	CLIENT=$!
	server=
	trap 'kill $server $CLIENT 2>/dev/null' EXIT
	while [ "$(readlink /proc/$CLIENT/ns/net)" = "$(readlink /proc/self/ns/net)" ]; do
		sleep 0.01
	done
	ip link add gate0 type veth peer name client0 netns "$CLIENT"
	ip addr add 10.231.0.1/24 dev gate0
	ip addr add 10.231.0.3/24 dev gate0
	ip -6 addr add fd00:231::1/64 dev gate0 nodad
	ip -6 addr add fd00:231::3/64 dev gate0 nodad
	ip link set gate0 up
	client ip link set lo up
	client ip addr add 10.231.0.2/24 dev client0
	client ip -6 addr add fd00:231::2/64 dev client0 nodad
	client ip link set client0 up

	export XDPGATE_CONF=$tmp/protected.conf
	printf '10.231.0.1\nfd00:231::1\n' >"$XDPGATE_CONF"

	$PY "$TESTS/traffic.py" serve >"$tmp/serve.log" 2>&1 &
	server=$!
	while ! grep -q ready "$tmp/serve.log"; do
		kill -0 $server 2>/dev/null || die "listeners failed: $(cat "$tmp/serve.log")"
		sleep 0.01
	done
	set +e

	echo "# without the gate, so that every drop below means something"
	check pass "tcp to a protected-to-be v4 address" tcp 10.231.0.1 8080
	check pass "tcp to a protected-to-be v6 address" tcp fd00:231::1 8080
	[ $failed = 0 ] || exit 1

	must "$LOAD" attach gate0 "$OBJ"
	client ip neigh flush dev client0

	echo "# IPv4, gate attached"
	check pass "arp, then tcp to an unprotected address" tcp 10.231.0.3 8080
	check drop "tcp to a protected address" tcp 10.231.0.1 8080
	check pass "udp to the SPA port of a protected address" udp 10.231.0.1 62159
	check drop "udp to another port of a protected address" udp 10.231.0.1 5353
	check drop "icmp to a protected address" icmp 10.231.0.1
	check pass "icmp to an unprotected address" icmp 10.231.0.3
	ctl open 10.231.0.2 tcp 9090
	ctl open 10.231.0.99 tcp 8080
	check pass "tcp with a grant" tcp 10.231.0.1 9090
	check drop "tcp to a port the grant does not cover" tcp 10.231.0.1 8080
	ctl open 10.231.0.2 udp 5353
	check pass "udp with a grant" udp 10.231.0.1 5353
	ctl close 10.231.0.2 tcp 9090
	check drop "tcp after the grant is closed" tcp 10.231.0.1 9090

	echo "# IPv6, gate attached"
	check pass "ndp, then tcp to an unprotected address" tcp fd00:231::3 8080
	check drop "tcp to a protected address" tcp fd00:231::1 8080
	check pass "udp to the SPA port of a protected address" udp fd00:231::1 62159
	check drop "udp to another port of a protected address" udp fd00:231::1 5353
	check drop "icmpv6 to a protected address" icmp fd00:231::1
	check pass "icmpv6 to an unprotected address" icmp fd00:231::3
	ctl open fd00:231::2 tcp 9090
	ctl open fd00:231::99 tcp 8080
	check pass "tcp with a grant" tcp fd00:231::1 9090
	check drop "tcp to a port the grant does not cover" tcp fd00:231::1 8080
	ctl close fd00:231::2 tcp 9090
	check drop "tcp after the grant is closed" tcp fd00:231::1 9090

	echo "# grants expire"
	ctl open 10.231.0.2 tcp 8080 1
	ctl open fd00:231::2 tcp 8080 1
	check pass "v4 tcp with a 1s grant" tcp 10.231.0.1 8080
	check pass "v6 tcp with a 1s grant" tcp fd00:231::1 8080
	sleep 1.1
	check drop "v4 tcp once the grant has expired" tcp 10.231.0.1 8080
	check drop "v6 tcp once the grant has expired" tcp fd00:231::1 8080

	echo "# reload moves the protected set"
	printf '10.231.0.3\nfd00:231::3\n' >"$XDPGATE_CONF"
	ctl reload
	check pass "v4 tcp to an address no longer protected" tcp 10.231.0.1 8080
	check drop "v4 tcp to a newly protected address" tcp 10.231.0.3 8080
	check pass "v6 tcp to an address no longer protected" tcp fd00:231::1 8080
	check drop "v6 tcp to a newly protected address" tcp fd00:231::3 8080

	echo "# detach"
	must "$LOAD" detach gate0
	check pass "v4 tcp after detach" tcp 10.231.0.3 8080
	check pass "v6 tcp after detach" tcp fd00:231::3 8080

	echo "traffic: $passed passed, $failed failed"
	[ $failed = 0 ]
}

if [ "${1:-}" = --inner ]; then
	shift
	inner "$@"
	exit
fi

[ $# -ge 1 ] && [ $# -le 2 ] || die "usage: $0 DIR [CTL_DIR]"
need_root
find_artifacts "$1"
if [ $# = 2 ]; then
	CTL=
	for d in "$2" "$2/bin"; do
		[ -z "$CTL" ] && [ -x "$d/xdpgate-ctl" ] && CTL=$(realpath "$d/xdpgate-ctl")
	done
	[ -n "$CTL" ] || die "no xdpgate-ctl in $2"
fi
export LOAD CTL OBJ

tmp=$(mktemp -d /tmp/xdpgate-traffic.XXXXXX)
trap 'rm -rf "$tmp"' EXIT
unshare --mount --net --propagation private "$0" --inner "$tmp"
