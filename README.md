# xdpgate — XDP default-deny gate driven by fwknop SPA

A default-deny gate for a set of **protected destination IPs** (v4 and v6).
Traffic to a protected IP is dropped at the XDP hook unless a valid SPA has
opened the specific `(source IP, proto, dest port)` tuple. fwknopd drives the
map via `CMD_CYCLE_OPEN`/`CMD_CYCLE_CLOSE`; the kernel enforces expiry.

```
inbound packet
   │
   ├─ non-IP (ARP…) ─────────────────────────────► PASS
   ├─ UDP/62201 (SPA)  ┐
   ├─ UDP/41641 (WG)   ├─ unconditional carve-outs ► PASS
   ├─ TCP/22  (SSH)    ┘
   ├─ dest ∉ protected set ──────────────────────► PASS
   └─ dest ∈ protected set:
        (src,proto,dport) in allow map & unexpired ► PASS
        otherwise ────────────────────────────────► DROP
```

## Components

- `xdpgate.bpf.c` — the XDP program (verifier-clean on kernel 6.8).
- `xdpgate-load` — loads the object, attaches XDP in **generic/SKB mode**, pins
  the four maps under `/sys/fs/bpf/xdpgate`. Run once at boot.
- `xdpgate-ctl` — per-SPA map editor + operator tooling
  (`open`/`close`/`add-protected`/`del-protected`/`list`/`gc`).
- `access.conf.example`, systemd units.

## Build & install

```sh
# Ubuntu 24.04 deps:
apt-get install -y clang llvm libbpf-dev libelf-dev make
make
make install            # /usr/local/sbin + /usr/local/lib/xdpgate + units
```

## Deploy without locking yourself out

The order matters. Keep an SSH session open throughout.

1. `make install`, set `IFACE=` in `xdpgate.service` to your primary ENI.
2. `systemctl enable --now xdpgate.service` — attaches the gate. At this point
   **nothing is gated yet** (the protected set is empty), so this is safe.
3. Seed the protected destinations *last*:

   ```sh
   xdpgate-ctl add-protected 2001:db8::1234     # a service /128
   xdpgate-ctl add-protected 203.0.113.50
   ```

4. Wire up fwknopd (see `access.conf.example`) and `systemctl enable --now
   xdpgate-gc.timer`.
5. Verify from a second host: connection to the protected service should fail;
   after a successful `fwknop` knock it should succeed for the timeout window.
   `xdpgate-ctl list` shows live grants and countdowns.

Because **SSH (tcp/22) and Tailscale (udp/41641) are unconditional carve-outs**
and only protected *destinations* are gated, the management plane survives even
if it shares an IP with a protected service. Still, prefer to keep your
SSH/Tailscale IP distinct from the protected service IPs — the carve-outs are a
backstop, not the primary safety mechanism.

## Why the SPA carve-out is mandatory (even in generic mode)

fwknopd captures SPA packets with libpcap/AF_PACKET, which sits **downstream**
of XDP — `XDP_DROP` frees the buffer before pcap ever sees it. This is true in
generic/SKB mode too: `do_xdp_generic()` runs before the `ptype_all` delivery
that feeds AF_PACKET. So if the gate dropped everything to a protected IP it
would also drop the SPA that authorises access. UDP/62201 is therefore an
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
- **`--rand-port` SPAs** break the single UDP/62201 carve-out. Widen the
  `SPA_PORT` check to a range in `xdpgate.bpf.c` if you use random SPA ports.
- **Generic mode** runs after GRO and is slower than native `ena` XDP, but it's
  the right call for portability and for not perturbing the data path. Moving to
  native later is just an attach-flag change.

## Quick reference

```sh
xdpgate-ctl open  203.0.113.9 tcp 443 30   # grant, 30s
xdpgate-ctl close 203.0.113.9 tcp 443      # revoke now
xdpgate-ctl add-protected 203.0.113.50     # start gating a dest
xdpgate-ctl list                           # protected set + live grants
xdpgate-ctl gc                             # reap expired (timer does this)
xdpgate-load detach ens5                   # remove gate + pins
```
