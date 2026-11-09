---
status: accepted
---

# Releases are tarballs built only by CI and installed by a test-first script

A release is a GitHub Release on mlbright/xdpgate holding one tarball per architecture (amd64 and arm64, for Ubuntu 24.04), a SHA256SUMS file, and a GitHub build attestation for each file. Only the workflow that a version tag triggers builds and uploads them: it builds and tests each architecture natively, arm64 on GitHub's `ubuntu-24.04-arm` runners, and publishes only if both pass. `make publish` never builds or uploads. It checks that the tree is the tip of main, runs `make check`, and pushes the tag. Operators install with the tarball's `install.sh`, which runs the traffic suite against those exact files on the host's own kernel and copies nothing if any check fails.

## Considered Options

- **A `.deb` per architecture, or an apt repository.** This is the native way to install on Ubuntu, but dpkg puts the new files in place before any maintainer script can test them, so "installs nothing on failure" would become "installs, then fails". Debian packages also belong in `/usr`, which would move every path in the units and the README.
- **`make publish` builds and uploads from the developer's machine.** Only GitHub Actions can produce build attestations, and arm64 has to be built and tested on arm64. An amd64 workstation can do neither.
- **An S3 bucket.** This suits an AWS-only rollout where instances fetch with their roles, but it needs a bucket, a policy and AWS credentials in CI, for a public project.

## Consequences

- A release run that fails leaves its tag without a release. The fix ships as the next patch version, because tags never move.
- "AWS Graviton is a first-class target" means arm64 passes the same tests as amd64 before every release. GitHub's arm64 runners are Azure Cobalt 100, the same Arm family as Graviton, not Graviton itself. The test on real Graviton hardware is `install.sh`'s traffic run on the instance. A self-hosted Graviton runner would add one before release, at the cost of AWS credentials and of locking down a self-hosted runner on a public repo.
- Amazon Linux 2023 is not a target. Its libbpf is 1.6.1 and its glibc 2.34, so the binaries would probably run there, but nothing tests them there.
- Every action is pinned to a commit hash, and release builds restore no cache. LLVM 23 from apt.llvm.org cannot be pinned to an exact build, so ADR 0001's guardrails (the object check and the traffic suite) run in every release build to catch what a rebuilt LLVM changes.
