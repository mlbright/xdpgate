#!/bin/bash
# Release a version: check, test, tag, push the tag. Run by `make publish`.
#
#   make publish VERSION=0.2.0 [REMOTE=name]
#
# Nothing is built or uploaded from here. Pushing the tag starts the release
# workflow (.github/workflows/ci.yml), which builds and tests both
# architectures natively and publishes the GitHub Release with checksums and
# build attestations (ADR 0004). If that run fails, the tag stays without a
# release: fix the problem and release the next patch version. Tags never
# move, so a version always means one commit.
#
# REMOTE defaults to whichever git remote pushes to $REPO.
set -eu
cd "$(dirname "$0")/.."
REPO=${REPO:-mlbright/xdpgate}
version=${1:-}

die() {
	echo "publish: $*" >&2
	exit 1
}

[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
	die "usage: make publish VERSION=x.y.z (digits only, no 'v')"

remote=${REMOTE:-}
if [ -z "$remote" ]; then
	while read -r name url kind; do
		[ "$kind" = "(push)" ] || continue
		case $url in
		*[/:]"$REPO" | *[/:]"$REPO.git") remote=$name && break ;;
		esac
	done < <(git remote -v)
fi
[ -n "$remote" ] || die "no git remote pushes to $REPO; name one with REMOTE="

# What gets tested here must be exactly what gets tagged. Untracked files are
# not part of the commit, so they don't count.
[ -z "$(git status --porcelain --untracked-files=no)" ] ||
	die "the working tree has uncommitted changes"

git fetch --quiet "$remote" main
[ "$(git rev-parse HEAD)" = "$(git rev-parse FETCH_HEAD)" ] ||
	die "HEAD is not the tip of main on $remote; releases are cut from main"

if git rev-parse -q --verify "refs/tags/$version" >/dev/null; then
	die "tag $version already exists here"
fi
# --exit-code: 2 means no such tag; anything else but 0 is a failure to ask.
rc=0
git ls-remote --exit-code --tags "$remote" "refs/tags/$version" >/dev/null || rc=$?
case $rc in
0) die "tag $version already exists on $remote" ;;
2) ;;
*) die "could not list the tags on $remote" ;;
esac

echo "publish: testing $(git rev-parse --short HEAD) before tagging it $version"
make check

git tag -a "$version" -m "xdpgate $version"
git push "$remote" "refs/tags/$version"

echo
echo "Tagged $version and pushed it to $remote. The release workflow builds,"
echo "tests and publishes it:"
echo "  https://github.com/$REPO/actions/workflows/ci.yml"
echo "  https://github.com/$REPO/releases/tag/$version (once it finishes)"
