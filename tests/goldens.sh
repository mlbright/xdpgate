#!/bin/bash
# Golden-transcript suite: proves a build behaves exactly like the original C.
#
#   sudo tests/goldens.sh [--record] DIR [SCENARIO...]
#
# DIR holds xdpgate-load, xdpgate-ctl and xdpgate.bpf.o, at the top or under
# bin/ and lib/. Each directory in tests/goldens/ is one scenario:
#
#   cmd        one shell command line: the thing under test
#   conf       optional; installed as /etc/xdpgate/protected.conf
#   setup      optional; run first with `set -e` (helpers in lib.sh)
#   unordered  optional; stdout is a set of lines (hash order), stored sorted
#
# plus what the C build did, which every build must reproduce byte for byte:
#
#   stdout, stderr, exit   of cmd
#   state                  XDP attachment, pins and map contents afterwards
#
# Only dates are masked; durations, counts and messages must match exactly.
# Every scenario gets its own fresh namespaces, with a veth pair gate0/peer0
# carrying 192.0.2.{1,10,11}/24 and 2001:db8:1::{1,10,11}/64 on gate0, and
# default routes whose source addresses are 192.0.2.1 and 2001:db8:1::1.
#
# --record overwrites the expected files instead; see tests/rerecord.sh.
set -u
. "$(dirname "$0")/lib.sh"

mask() {
	sed -E 's/[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}/YYYY-MM-DD hh:mm:ss/g'
}

# Runs inside the namespaces: build the sandbox, run one scenario, and leave
# its raw results in $2.
inner() {
	local scen=$1 out=$2 sb=$3
	local path=$sb/bin:/usr/sbin:/usr/bin:/sbin:/bin

	set -e
	ip link set lo up
	ip link add gate0 type veth peer name peer0
	ip link set gate0 up
	ip link set peer0 up
	local a
	for a in 192.0.2.1 192.0.2.10 192.0.2.11; do
		ip addr add "$a/24" dev gate0
	done
	for a in 2001:db8:1::1 2001:db8:1::10 2001:db8:1::11; do
		ip -6 addr add "$a/64" dev gate0 nodad
	done
	ip route add default via 192.0.2.254 src 192.0.2.1
	ip -6 route add default via 2001:db8:1::fe src 2001:db8:1::1

	mount -t bpf bpf /sys/fs/bpf
	mount -t tmpfs tmpfs "$sb"
	mkdir "$sb/upper" "$sb/ovl" "$sb/bin" "$sb/work"
	mount -t overlay overlay \
		-o "lowerdir=/etc,upperdir=$sb/upper,workdir=$sb/ovl" /etc
	rm -rf /etc/xdpgate
	mkdir /etc/xdpgate
	[ -f "$scen/conf" ] && cp "$scen/conf" /etc/xdpgate/protected.conf

	ln -s "$LOAD" "$sb/bin/xdpgate-load"
	ln -s "$CTL" "$sb/bin/xdpgate-ctl"
	ln -s "$TESTS/../whats-on-ip" "$sb/bin/whats-on-ip"
	cp "$OBJ" "$sb/work/xdpgate.bpf.o"
	cd "$sb/work"
	set +e

	local run=(env -i "PATH=$path" HOME=/root TZ=UTC LC_ALL=C "TESTS=$TESTS"
		bash --noprofile --norc)
	if [ -f "$scen/setup" ]; then
		if ! "${run[@]}" -c '. "$TESTS/lib.sh"; set -e; . "$1"' setup \
			"$scen/setup" >"$out/setup.log" 2>&1; then
			echo "setup failed" >"$out/error"
			return
		fi
	fi
	"${run[@]}" -c "$(cat "$scen/cmd")" >"$out/stdout" 2>"$out/stderr" </dev/null
	echo $? >"$out/exit"
	$PY "$TESTS/state.py" dump gate0 >"$out/state" 2>&1
}

if [ "${1:-}" = --inner ]; then
	shift
	inner "$@"
	exit 0
fi

record=0
[ "${1:-}" = --record ] && { record=1; shift; }
[ $# -ge 1 ] || die "usage: $0 [--record] DIR [SCENARIO...]"
need_root
find_artifacts "$1"
shift
export LOAD CTL OBJ

if [ $# -gt 0 ]; then
	scenarios=("$@")
else
	scenarios=("$TESTS"/goldens/*/)
fi

work=$(mktemp -d /tmp/xdpgate-goldens.XXXXXX)
trap 'rm -rf "$work"' EXIT
mkdir "$work/sb"

pass=0 fail=0
for scen in "${scenarios[@]}"; do
	[ -d "$scen" ] || scen=$TESTS/goldens/$scen
	scen=$(realpath "$scen")
	name=$(basename "$scen")
	[ -f "$scen/cmd" ] || die "$name: no cmd"
	out=$work/$name
	mkdir "$out"

	if ! unshare --mount --net --propagation private "$0" --inner "$scen" "$out" "$work/sb"; then
		echo "FAIL $name: could not build the sandbox"
		fail=$((fail + 1))
		continue
	fi
	if [ -f "$out/error" ]; then
		echo "FAIL $name: $(cat "$out/error")"
		sed 's/^/    /' "$out/setup.log"
		fail=$((fail + 1))
		continue
	fi
	for f in stdout stderr; do
		mask <"$out/$f" >"$out/$f.masked"
		mv "$out/$f.masked" "$out/$f"
	done

	if [ $record = 1 ]; then
		if [ -f "$scen/unordered" ]; then
			LC_ALL=C sort "$out/stdout" >"$out/stdout.sorted"
			mv "$out/stdout.sorted" "$out/stdout"
		fi
		for f in stdout stderr exit state; do
			cp "$out/$f" "$scen/$f"
			chown --reference="$scen" "$scen/$f"
		done
		echo "recorded $name"
		continue
	fi

	ok=1
	for f in stdout stderr exit state; do
		exp=$scen/$f act=$out/$f
		if [ ! -f "$exp" ]; then
			echo "FAIL $name: no expected $f (record it first)"
			ok=0
			continue
		fi
		if [ "$f" = stdout ] && [ -f "$scen/unordered" ]; then
			LC_ALL=C sort "$exp" >"$out/exp.sorted"
			LC_ALL=C sort "$act" >"$out/act.sorted"
			exp=$out/exp.sorted act=$out/act.sorted
		fi
		if ! diff -u --label "expected $f" --label "actual $f" "$exp" "$act" \
			>"$out/diff"; then
			[ $ok = 1 ] && echo "FAIL $name"
			sed 's/^/    /' "$out/diff"
			ok=0
		fi
	done
	if [ $ok = 1 ]; then
		pass=$((pass + 1))
	else
		fail=$((fail + 1))
	fi
done

if [ $record = 1 ]; then
	[ $fail = 0 ]
	exit
fi
echo "goldens: $pass passed, $fail failed"
[ $fail = 0 ]
