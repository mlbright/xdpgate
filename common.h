/* common.h - shared definitions between the XDP program and userspace tools.
 *
 * The map key structs are read raw by the kernel hash maps, so the byte
 * layout MUST be identical on both sides. They are packed to eliminate
 * padding (otherwise uninitialised padding bytes would break key matching).
 */
#ifndef XDPGATE_COMMON_H
#define XDPGATE_COMMON_H

#include <linux/types.h>

#define XDPGATE_PIN_DIR "/sys/fs/bpf/xdpgate"

/* ---- always-allow carve-outs (see README for rationale) ---------------- */
#define SPA_PORT 62201   /* fwknopd default SPA UDP port - MUST pass-through  */
#define WG_PORT  41641   /* Tailscale / WireGuard default UDP listen port     */
#define SSH_PORT 22      /* management SSH - always reachable (break-glass)   */

/* Set to 1 to let ICMP/ICMPv6 reach protected destinations. Default 0 (strict
 * deny). Note: 0 will blackhole PMTUD ("frag needed" / "packet too big") to
 * protected service IPs - see README. NDP is link-local so unaffected. */
#define ALLOW_ICMP_TO_PROTECTED 0

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

/* allow-map keys. saddr and dport are stored in NETWORK byte order so they
 * compare directly against the on-wire header fields the XDP program reads. */
struct allow_v4_key {
	__u32 saddr;   /* network byte order (matches iphdr->saddr)  */
	__u16 dport;   /* network byte order (matches tcp/udp dest)  */
	__u8  proto;   /* IPPROTO_TCP (6) or IPPROTO_UDP (17)         */
} __attribute__((packed));

struct allow_v6_key {
	__u8  saddr[16];
	__u16 dport;   /* network byte order */
	__u8  proto;
} __attribute__((packed));

/* allow-map value: absolute CLOCK_MONOTONIC nanoseconds at which the grant
 * expires. The XDP program compares this against bpf_ktime_get_ns().
 * 0 means "no expiry" (rely solely on CMD_CYCLE_CLOSE) - avoid for a gate. */
struct allow_val {
	__u64 expiry_ns;
};

/* protected-destination set: v4 uses a bare __u32 key (network order). */
struct prot_v6_key {
	__u8 addr[16];
};

#endif /* XDPGATE_COMMON_H */
