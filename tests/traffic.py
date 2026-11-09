"""Traffic for the netns test: listeners on the gated side, probes on the client.

    traffic.py serve                     TCP 8080/9090 and UDP echo 5353/62159,
                                         IPv4 and IPv6; prints "ready" once bound
    traffic.py probe tcp|udp ADDR PORT   one connection or datagram
    traffic.py probe icmp ADDR           one echo request

A probe prints "pass" if the gated side answered and "drop" if it did not.
Standard library only, run with the system interpreter: /usr/bin/python3 -I.
"""
import os
import select
import socket
import struct
import sys
import threading

TIMEOUT = 0.5   # a veth answers in microseconds; silence this long is a drop
TCP_PORTS = (8080, 9090)
UDP_PORTS = (5353, 62159)


def dual_stack(kind):
    s = socket.socket(socket.AF_INET6, kind)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return s


def serve():
    def tcp(s):
        while True:
            c, _ = s.accept()
            c.close()

    def udp(s):
        while True:
            data, peer = s.recvfrom(512)
            s.sendto(data, peer)

    for port in TCP_PORTS:
        s = dual_stack(socket.SOCK_STREAM)
        s.bind(("::", port))
        s.listen(64)
        threading.Thread(target=tcp, args=(s,), daemon=True).start()
    for port in UDP_PORTS:
        s = dual_stack(socket.SOCK_DGRAM)
        s.bind(("::", port))
        threading.Thread(target=udp, args=(s,), daemon=True).start()
    print("ready", flush=True)
    threading.Event().wait()


def family(addr):
    return socket.AF_INET6 if ":" in addr else socket.AF_INET


def probe_tcp(addr, port):
    s = socket.socket(family(addr), socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    try:
        s.connect((addr, port))
    except ConnectionRefusedError:
        return True   # refused is still an answer from the gated side
    except OSError:
        return False
    finally:
        s.close()
    return True


def probe_udp(addr, port):
    s = socket.socket(family(addr), socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)
    token = os.urandom(8)
    try:
        s.sendto(token, (addr, port))
        while True:
            data, _ = s.recvfrom(512)
            if data == token:
                return True
    except OSError:
        return False
    finally:
        s.close()


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def probe_icmp(addr):
    v6 = ":" in addr
    if v6:
        s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
        request, reply = 128, 129   # the kernel fills in the ICMPv6 checksum
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        request, reply = 8, 0
    ident = os.getpid() & 0xFFFF
    body = struct.pack("!HH", ident, 1) + b"xdpgate"
    csum = 0 if v6 else checksum(struct.pack("!BBH", request, 0, 0) + body)
    s.sendto(struct.pack("!BBH", request, 0, csum) + body, (addr, 0))
    try:
        while select.select([s], [], [], TIMEOUT)[0]:
            data = s.recv(512)
            icmp = data if v6 else data[(data[0] & 0x0F) * 4:]
            if icmp[0] == reply and struct.unpack("!H", icmp[4:6])[0] == ident:
                return True
        return False
    finally:
        s.close()


def main(argv):
    if argv == ["serve"]:
        serve()
    elif len(argv) == 4 and argv[0] == "probe" and argv[1] in ("tcp", "udp"):
        ok = (probe_tcp if argv[1] == "tcp" else probe_udp)(argv[2], int(argv[3]))
        print("pass" if ok else "drop")
    elif len(argv) == 3 and argv[:2] == ["probe", "icmp"]:
        print("pass" if probe_icmp(argv[2]) else "drop")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
