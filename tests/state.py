"""Read and write the gate's kernel state with bpftool, for the test suites.

    state.py dump IFACE                        print the state, stable and diffable
    state.py grants < SPECS                    write grants, one per line:
                                               v4|v6 SRC tcp|udp PORT AGE, where AGE
                                               is +N/-N seconds from now, or "never"
    state.py protect ADDR | unprotect ADDR     add/remove a runtime override
    state.py fill MAP COUNT                    add COUNT made-up entries to MAP

Everything goes through bpftool rather than xdpgate-ctl, so a bug in the tool
under test cannot hide itself in its own test setup or results. Run with the
system interpreter in isolated mode: /usr/bin/python3 -I tests/state.py ...
"""
import ipaddress
import json
import os
import struct
import subprocess
import sys
import tempfile
import time

PIN_DIR = "/sys/fs/bpf/xdpgate"
MAPS = ("allow_v4", "allow_v6", "protected_v4", "protected_v6")
PROTO = {"tcp": 6, "udp": 17}
PROTO_NAME = {v: k for k, v in PROTO.items()}
XDP_MODE = {1: "driver", 2: "generic", 3: "offload", 4: "multi"}
MAX_SHOWN = 300   # a full protected map is listed, a full allow map is counted


def bpftool(*args):
    res = subprocess.run(["bpftool", *args], capture_output=True, text=True)
    if res.returncode:
        sys.exit("bpftool %s: %s" % (" ".join(args), res.stderr.strip()))
    return res.stdout


def now_ns():
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC)


def addr_bytes(text):
    return ipaddress.ip_address(text).packed


def hexargs(raw):
    return ["%02x" % b for b in raw]


# --- dump -----------------------------------------------------------------

def xdp_line(iface):
    res = subprocess.run(["ip", "-j", "-d", "link", "show", "dev", iface],
                         capture_output=True, text=True)
    if res.returncode:
        return "xdp %s: no such interface" % iface
    xdp = json.loads(res.stdout)[0].get("xdp")
    if not xdp or not xdp.get("mode"):
        return "xdp %s: none" % iface
    mode = XDP_MODE.get(xdp["mode"], str(xdp["mode"]))
    return "xdp %s: %s %s" % (iface, mode, xdp.get("prog", {}).get("name", "?"))


def fmt_key(raw):
    if len(raw) == 4:
        return str(ipaddress.IPv4Address(raw))
    if len(raw) == 16:
        return str(ipaddress.IPv6Address(raw))
    if len(raw) in (7, 19):
        addr = ipaddress.ip_address(raw[:-3])
        port, proto = struct.unpack("!HB", raw[-3:])
        return "%s %s %d" % (addr, PROTO_NAME.get(proto, "proto%d" % proto), port)
    return "key " + raw.hex()


def fmt_value(raw, now):
    if len(raw) != 8:
        return raw.hex()
    expiry, = struct.unpack("=Q", raw)
    if expiry == 0:
        return "never"
    if expiry <= now:
        return "expired"
    return "+%ds" % round((expiry - now) / 1e9)


def dump(iface):
    print(xdp_line(iface))
    if not os.path.isdir(PIN_DIR):
        print("pins: none")
        return
    names = sorted(os.listdir(PIN_DIR))
    print("pins: " + (" ".join(names) if names else "(empty directory)"))
    for name in names:
        path = os.path.join(PIN_DIR, name)
        info = json.loads(bpftool("-j", "map", "show", "pinned", path))
        print("map %s: %s key %d value %d max_entries %d flags 0x%x" % (
            name, info["type"], info["bytes_key"], info["bytes_value"],
            info["max_entries"], info["flags"]))
        now = now_ns()
        entries = json.loads(bpftool("-j", "map", "dump", "pinned", path))
        print("  (%d entries)" % len(entries))
        if len(entries) > MAX_SHOWN:
            continue
        rows = []
        for e in entries:
            key = bytes(int(b, 16) for b in e["key"])
            val = bytes(int(b, 16) for b in e["value"])
            rows.append((key, "  %s = %s" % (fmt_key(key), fmt_value(val, now))))
        for _, line in sorted(rows):
            print(line)


# --- writes ---------------------------------------------------------------

def allow_key(fam, src, proto, port):
    raw = addr_bytes(src)
    if len(raw) != (4 if fam == "v4" else 16):
        sys.exit("grant: %s is not an IP%s address" % (src, fam))
    return raw + struct.pack("!HB", int(port), PROTO[proto])


def batch(lines):
    with tempfile.NamedTemporaryFile("w", suffix=".batch") as f:
        f.write("\n".join(lines) + "\n")
        f.flush()
        bpftool("batch", "file", f.name)


def grants():
    """All expiries are taken from one reading of the clock and written in one
    bpftool call, so `list` durations come out the same on every run."""
    now = now_ns()
    lines = []
    for spec in sys.stdin.read().splitlines():
        if not spec.strip():
            continue
        fam, src, proto, port, age = spec.split()
        expiry = 0 if age == "never" else now + int(age) * 1000000000
        lines.append("map update pinned %s/allow_%s key hex %s value hex %s" % (
            PIN_DIR, fam, " ".join(hexargs(allow_key(fam, src, proto, port))),
            " ".join(hexargs(struct.pack("=Q", expiry)))))
    batch(lines)


def protected_map(addr):
    return "%s/protected_v%d" % (PIN_DIR, ipaddress.ip_address(addr).version)


def protect(addr):
    bpftool("map", "update", "pinned", protected_map(addr),
            "key", "hex", *hexargs(addr_bytes(addr)), "value", "hex", "01")


def unprotect(addr):
    bpftool("map", "delete", "pinned", protected_map(addr),
            "key", "hex", *hexargs(addr_bytes(addr)))


def fill(name, count):
    """Made-up entries: 10.99.0.0/16 and fd00:99::/64 never collide with the
    addresses the scenarios use."""
    lines = []
    future = struct.pack("=Q", now_ns() + 86400 * 1000000000)
    for i in range(int(count)):
        v4 = bytes([10, 99, i >> 8 & 255, i & 255])
        v6 = ipaddress.IPv6Address("fd00:99::%x" % (i + 1)).packed
        key = {"protected_v4": v4, "protected_v6": v6,
               "allow_v4": v4 + struct.pack("!HB", 1000, 6),
               "allow_v6": v6 + struct.pack("!HB", 1000, 6)}[name]
        val = future if name.startswith("allow") else b"\x01"
        lines.append("map update pinned %s/%s key hex %s value hex %s" % (
            PIN_DIR, name, " ".join(hexargs(key)), " ".join(hexargs(val))))
    batch(lines)


def main(argv):
    cmds = {"dump": (dump, 1), "grants": (grants, 0), "protect": (protect, 1),
            "unprotect": (unprotect, 1), "fill": (fill, 2)}
    if len(argv) < 1 or argv[0] not in cmds or len(argv) - 1 != cmds[argv[0]][1]:
        sys.exit(__doc__)
    fn, _ = cmds[argv[0]]
    fn(*argv[1:])


if __name__ == "__main__":
    main(sys.argv[1:])
