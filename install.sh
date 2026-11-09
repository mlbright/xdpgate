#!/bin/bash
# Install xdpgate, from a built checkout (`sudo make install`) or an unpacked
# release tarball (`sudo ./install.sh`). Never builds anything.
#
# Before copying anything, it runs the netns traffic suite (tests/traffic.sh)
# against the exact files it is about to install, on this host's kernel, and
# installs nothing if any check fails. The suite runs in throwaway namespaces
# with their own bpffs, so a gate already running here is never touched. That
# gate keeps its program until restarted, and the new xdpgate-ctl works on its
# maps, whichever version created them.
#
# DESTDIR, if set, installs under that directory instead of /. The traffic
# suite still runs first.
#
# It never installs protected.conf itself: an existing protected set is
# operator data, and a generated one would be a guess at what to gate.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
dest=${DESTDIR:-}

for f in xdpgate-load xdpgate-ctl xdpgate.bpf.o; do
	if [ ! -f "$here/$f" ]; then
		echo "install.sh: no $f in $here; run \`make\` first" >&2
		exit 1
	fi
done
if [ "$(id -u)" != 0 ]; then
	echo "install.sh: must run as root" >&2
	exit 1
fi

echo "Testing these files on this kernel before installing them:"
if ! "$here/tests/traffic.sh" "$here"; then
	echo "install.sh: the traffic suite failed, so nothing was installed" >&2
	exit 1
fi

install -d "$dest/usr/local/sbin" "$dest/usr/local/lib/xdpgate" \
	"$dest/etc/xdpgate" "$dest/etc/systemd/system"
install -m 0755 "$here/xdpgate-load" "$here/xdpgate-ctl" "$here/whats-on-ip" \
	"$dest/usr/local/sbin/"
install -m 0644 "$here/xdpgate.bpf.o" "$dest/usr/local/lib/xdpgate/"
install -m 0644 "$here/protected.conf.example" "$dest/etc/xdpgate/"
install -m 0644 "$here/xdpgate.service" "$here/xdpgate-gc.service" \
	"$here/xdpgate-gc.timer" "$dest/etc/systemd/system/"

cat <<'EOF'

Next, in order:
  1. cp /etc/xdpgate/protected.conf.example /etc/xdpgate/protected.conf
     and list the addresses to gate (upgrading? use: xdpgate-ctl export)
  2. edit IFACE= in /etc/systemd/system/xdpgate.service
  3. systemctl daemon-reload
  4. systemctl enable --now xdpgate.service xdpgate-gc.timer

The gate refuses to attach without a non-empty protected.conf.
EOF
