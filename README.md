# xdpgate — XDP default-deny gate for use with fwknop SPA

A default-deny gate for a set of **protected destination IPs** (v4 and v6).
Traffic to a protected IP is dropped at the XDP hook unless a valid SPA has
opened the specific `(source IP, proto, dest port)` tuple. fwknopd drives the
map via `CMD_CYCLE_OPEN`/`CMD_CYCLE_CLOSE`; the kernel enforces expiry.

The protected set is declared in **`/etc/xdpgate/protected.conf`** and applied
as part of attaching. The gate refuses to attach without it: an empty protected
set passes every packet, and a gate that reports itself healthy while gating
nothing is worse than no gate at all.

```
inbound packet
   │
   ├─ non-IP (ARP…) ─────────────────────────────► PASS
   ├─ UDP/62159 (SPA) ── unconditional carve-out ─► PASS
   ├─ dest ∉ protected set ──────────────────────► PASS
   └─ dest ∈ protected set:
        (src,proto,dport) in allow map & unexpired ► PASS
        otherwise ────────────────────────────────► DROP
```

## Components

- `xdpgate.bpf.c` — the XDP program (verifier-clean on kernel 6.8).
- `xdpgate-load` — loads the object, attaches XDP in **generic/SKB mode**, pins
  the four maps under `/sys/fs/bpf/xdpgate`. Run once at boot.
- `protected_conf.c` — parses `protected.conf`, refuses configurations that
  would cut the host off, and reconciles the live maps to the file. Compiled
  into **both** binaries so attach and reload cannot drift apart.
- `xdpgate-ctl` — per-SPA map editor + operator tooling
  (`open`/`close`/`reload`/`export`/`add-protected`/`del-protected`/`list`/`gc`).
- `whats-on-ip` — audit helper. Lists which listening sockets are actually
  reachable on a given local IP (wildcard binds answer on *every* address, so
  "nothing bound specifically to X" ≠ "nothing listening on X"). Its
  `--preflight` mode grades each protected IP's overlap with the management
  plane as HARD (default-route source — fails) or SOFT (candidate Tailscale
  endpoint — warns; `--strict` fails). Used by `make audit` / `make preflight`.
- `protected.conf.example`, `access.conf.example`, systemd units.

## Build & install

Developed and tested on **Ubuntu 24.04 LTS (Noble Numbat)**.

```sh
make deps               # installs clang llvm libbpf-dev libelf-dev make (via apt)
make
make install            # /usr/local/sbin + /usr/local/lib/xdpgate + units
```

The optional `make verify` target additionally needs `bpftool`, which ships in
the kernel tooling: `apt-get install linux-tools-$(uname -r)`.

## The protected set is a config file

`/etc/xdpgate/protected.conf` is the source of truth. One address per line,
`#` comments, blank lines ignored. CIDR is not accepted — the protected maps are
exact-match hashes, so give each address its own line (256 per family).

```
# /etc/xdpgate/protected.conf
2001:db8::1234      # a service /128
203.0.113.50        # a dedicated IPv4 service address
```

`xdpgate-load` applies it between loading the object and attaching the program:
libbpf creates and pins the maps during load, so they are already populated at
the instant the gate goes live. **Applying is reconciliation, not accumulation**
— after it runs the map equals the file, so removing a line and reloading stops
gating that address.

Change the set on a running gate with `systemctl reload xdpgate`. That reconciles
the protected maps in place: live SPA grants survive and XDP never leaves the
netdev, neither of which is true of a restart.

`xdpgate-ctl add-protected` / `del-protected` still work, but they are **runtime
overrides**: they change the map, not the file, and the next reload or reboot
undoes them. `xdpgate-ctl list` marks them `[runtime only]`, and flags addresses
the file names but the map has lost. Use them for incidents; put anything you
want to survive into the file.

### It refuses to arm a config that would lock you out

The gate is stateless and ingress-only, so protecting the source address the
kernel picks for the default route drops the return path of **every connection
this host originates**, including the SSH session you are watching it from.
Because seeding now happens unattended at boot, `xdpgate-load` checks for that
itself — a UDP `connect()` + `getsockname()` per family, which is a pure route
lookup — and refuses to attach rather than brick the box:

```
refusing to apply: 10.0.1.250 is this host's default IPv4 source address.
  The gate is stateless and ingress-only, so protecting it drops the
  return path of every connection this host originates - including
  the session you are reading this in.
```

That is the same overlap `whats-on-ip` grades **HARD**. The softer SOFT grade
(a candidate Tailscale endpoint a peer *might* pick) still needs
`whats-on-ip --preflight`, which has the Tailscale CLI available to it.

## Deploy without locking yourself out

The order matters. Keep an SSH session open throughout, and **make sure your
management plane (SSH, WireGuard/Tailscale, etc.) lives on IPs you never add to
the protected set** — the only carve-out is the SPA port, so anything on a
protected IP is gated.

1. `make install`. This drops `protected.conf.example` in `/etc/xdpgate/` and
   never overwrites a real `protected.conf`.
2. Pick a service address. `sudo whats-on-ip --self` shows what each local IP
   actually exposes; choose one that shares nothing with the management plane —
   typically an address you assign solely to the service.
3. Write `/etc/xdpgate/protected.conf`. **Upgrading a box whose protected set
   only ever lived in the kernel maps?** Capture it before the next reboot:
   ```sh
   xdpgate-ctl export > /etc/xdpgate/protected.conf
   ```
4. Set `IFACE=` in `/etc/systemd/system/xdpgate.service` to your primary ENI.
5. `systemctl enable --now xdpgate.service`. This attaches **and** arms in one
   step — there is no intermediate state where the gate is up but gating
   nothing. If the config names your default-route source it refuses to attach
   and the unit fails; fix the file and start it again.
6. `sudo whats-on-ip --preflight` (or `make preflight`) for the SOFT grade:
   an address that is merely a candidate Tailscale endpoint. It **warns**
   (exit 0); pass `--strict` to fail on those too. It now also **fails** if the
   gate is attached with an empty protected set.
7. Wire up fwknopd (see `access.conf.example`) and `systemctl enable --now
   xdpgate-gc.timer`.
8. Verify from a second host: connection to the protected service should fail;
   after a successful `fwknop` knock it should succeed for the timeout window.
   `xdpgate-ctl list` shows live grants and countdowns.

Only protected *destinations* are gated, so the management plane survives as
long as it does **not** share an IP with a protected service. There is no
carve-out for SSH or WireGuard/Tailscale: keep those (and any other essential
traffic) on separate IPs — typically distinct IPv6 addresses — that you never
add to the protected set. The SPA port (udp/62159) is the only unconditional
carve-out, and it exists purely so fwknopd can receive the knock.

## Why the SPA carve-out is mandatory (even in generic mode)

fwknopd captures SPA packets with libpcap/AF_PACKET, which sits **downstream**
of XDP — `XDP_DROP` frees the buffer before pcap ever sees it. This is true in
generic/SKB mode too: `do_xdp_generic()` runs before the `ptype_all` delivery
that feeds AF_PACKET. So if the gate dropped everything to a protected IP it
would also drop the SPA that authorises access. UDP/62159 is therefore an
unconditional `XDP_PASS`.

## Expiry is fail-closed

The allow value stores an absolute **`CLOCK_MONOTONIC`** nanosecond deadline.
The XDP program compares it against `bpf_ktime_get_ns()` (same clock) and drops
once passed — so a missed or failed `CMD_CYCLE_CLOSE` does **not** leak an open
grant. The GC timer only reclaims map slots after the fact. Keep the
`xdpgate-ctl open … <timeout>` value equal to `CMD_CYCLE_TIMER`.

## Caveats you should know about

- **Key is `(src, proto, dport)`, not destination-scoped.** An SPA for
  `tcp/443` from X opens `tcp/443` from X to *any* protected IP. To scope per
  destination, add `$DST` to `xdpgate-ctl open`, add a `daddr` field to
  `allow_*_key` in `common.h`, and set it in the XDP lookup. One-field change
  on each side.
- **Multi-port SPA opens only the first port** (mrash/fwknop#327). Use one port
  per SPA, or extend the value to a port set.
- **`$SRC` vs `$PKT_SRC`.** We key on `$SRC` (the IP fwknop authorises, which is
  what subsequent connections use). If clients are behind NAT and the connecting
  IP differs from the SPA-embedded IP, switch the access.conf token or have
  clients use `-R`/resolve-ip.
- **ICMP / PMTUD.** With `ALLOW_ICMP_TO_PROTECTED=0` (default, strict), ICMP and
  ICMPv6 to protected IPs are dropped — this blackholes Path MTU Discovery
  ("frag needed" / "packet too big") to those services. IPv6 NDP is link-local
  and unaffected. Flip the flag in `common.h` and rebuild if PMTUD matters.
- **Fragments.** Non-first IPv4 fragments (no L4 header) to a protected dest are
  dropped; the first fragment must carry the real port to match. Fine for
  TCP-with-PMTUD services; relevant if you gate something that fragments.
- **IPv6 extension headers.** Only the direct-L4 case (`nexthdr` is TCP/UDP) is
  parsed; packets with ext headers to a protected dest hit the no-L4 path and
  are dropped (fail-closed). Add a header walk if you need them.
- **`--rand-port` SPAs** break the single UDP/62159 carve-out. Widen the
  `SPA_PORT` check to a range in `xdpgate.bpf.c` if you use random SPA ports.
- **Generic mode** runs after GRO and is slower than native `ena` XDP, but it's
  the right call for portability and for not perturbing the data path. Moving to
  native later is just an attach-flag change.

## Quick reference

```sh
vim /etc/xdpgate/protected.conf             # the protected set lives here
systemctl reload xdpgate                   # apply it; live grants survive
xdpgate-ctl export > /etc/xdpgate/protected.conf   # capture a live set

xdpgate-ctl open  203.0.113.9 tcp 443 30   # grant, 30s
xdpgate-ctl close 203.0.113.9 tcp 443      # revoke now
xdpgate-ctl add-protected 203.0.113.50     # gate a dest UNTIL the next reload
xdpgate-ctl list                           # protected set (+provenance) + grants
xdpgate-ctl gc                             # reap expired (timer does this)
whats-on-ip --self                         # audit: what's exposed per local IP
whats-on-ip --preflight                    # fail on empty set / HARD overlap
xdpgate-load detach ens5                   # remove gate + pins
```
