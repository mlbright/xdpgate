#!/bin/bash
# Re-record golden transcripts from the C build, after adding or changing a
# scenario. Run it as yourself; it uses sudo only for the recording itself.
#
#   tests/rerecord.sh [SCENARIO...]
#
# The goldens describe what the original C did, so they are always recorded
# from C: HEAD while it still has the C, and afterwards the last commit that
# had all of it. Recording applies goldens/deviations.sed on top. Review the
# result with `git diff`: a change to an existing golden means the C does
# something other than what was recorded before.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
top=$(git -C "$here" rev-parse --show-toplevel)

if git -C "$top" cat-file -e HEAD:xdpgate.bpf.c 2>/dev/null; then
	rev=HEAD
else
	rev=$(git -C "$top" rev-list -1 HEAD -- xdpgate.bpf.c)^
fi

src=$(mktemp -d /tmp/xdpgate-c.XXXXXX)
trap 'rm -rf "$src"' EXIT
git -C "$top" archive "$rev" | tar -x -C "$src"
echo "building the C from $(git -C "$top" rev-parse --short "$rev")"
make -C "$src" >/dev/null
dir=$src
[ -d "$src/zig-out" ] && dir=$src/zig-out

sudo "$here/goldens.sh" --record "$dir" "$@"
