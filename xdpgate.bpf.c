// SPDX-License-Identifier: GPL-2.0
/* xdpgate.bpf.c - default-deny gate for protected destination IPs.
 *
 * Decision order for every inbound packet:
 *   1. Non-IP (ARP, etc.)                    -> PASS (don't break the LAN)
 *   2. SPA port / Tailscale / SSH (any dest) -> PASS (unconditional carve-outs)
 *   3. Destination not in protected set      -> PASS (we only gate those IPs)
 *   4. Destination IS protected:
 *        - (src,proto,dport) in allow map and not expired -> PASS
 *        - otherwise                                      -> DROP
 *
 * The carve-outs are checked BEFORE the protected lookup, so the SPA packet,
 * Tailscale, and SSH survive even if they share an IP with a protected service.
 * This is also why fwknopd (which sniffs via AF_PACKET, downstream of XDP)
 * can still receive the SPA that authorises everything else.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} protected_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct prot_v6_key);
	__type(value, __u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} protected_v6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct allow_v4_key);
	__type(value, struct allow_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} allow_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct allow_v6_key);
	__type(value, struct allow_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} allow_v6 SEC(".maps");

static __always_inline int carve_out(__u8 proto, __u16 dport_be)
{
	if (proto == IPPROTO_UDP && dport_be == bpf_htons(SPA_PORT))
		return 1;
	if (proto == IPPROTO_UDP && dport_be == bpf_htons(WG_PORT))
		return 1;
	if (proto == IPPROTO_TCP && dport_be == bpf_htons(SSH_PORT))
		return 1;
	return 0;
}

static __always_inline int expired(struct allow_val *v)
{
	/* expiry_ns == 0 means "never". Otherwise fail-closed once we pass it. */
	return v->expiry_ns != 0 && bpf_ktime_get_ns() > v->expiry_ns;
}

static __always_inline int handle_v4(void *data, void *data_end,
				     struct ethhdr *eth)
{
	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;

	__u32 ihl = (__u32)iph->ihl * 4;
	if (ihl < sizeof(*iph) || (void *)iph + ihl > data_end)
		return XDP_PASS;

	__u8  proto = iph->protocol;
	__u32 daddr = iph->daddr;   /* network order */
	__u32 saddr = iph->saddr;
	void *l4 = (void *)iph + ihl;

	/* Non-first fragments carry no L4 header -> no port to match. */
	int is_frag_tail = (iph->frag_off & bpf_htons(0x1FFF)) != 0;

	__u16 dport = 0;
	int have_ports = 0;
	if (!is_frag_tail) {
		if (proto == IPPROTO_TCP) {
			struct tcphdr *th = l4;
			if ((void *)(th + 1) <= data_end) {
				dport = th->dest;
				have_ports = 1;
			}
		} else if (proto == IPPROTO_UDP) {
			struct udphdr *uh = l4;
			if ((void *)(uh + 1) <= data_end) {
				dport = uh->dest;
				have_ports = 1;
			}
		}
	}

	if (have_ports && carve_out(proto, dport))
		return XDP_PASS;

	if (!bpf_map_lookup_elem(&protected_v4, &daddr))
		return XDP_PASS;          /* not a gated destination */

	/* Destination is protected: default deny. */
	if (!have_ports) {
		if (proto == IPPROTO_ICMP && ALLOW_ICMP_TO_PROTECTED)
			return XDP_PASS;
		return XDP_DROP;          /* ICMP / frag-tail / unknown L4 */
	}

	struct allow_v4_key key = {};
	key.saddr = saddr;
	key.dport = dport;
	key.proto = proto;

	struct allow_val *v = bpf_map_lookup_elem(&allow_v4, &key);
	if (!v || expired(v))
		return XDP_DROP;
	return XDP_PASS;
}

static __always_inline int handle_v6(void *data, void *data_end,
				     struct ethhdr *eth)
{
	struct ipv6hdr *ip6h = (void *)(eth + 1);
	if ((void *)(ip6h + 1) > data_end)
		return XDP_PASS;

	__u8 proto = ip6h->nexthdr;   /* only the direct-L4 case is parsed */
	void *l4 = (void *)(ip6h + 1);

	__u16 dport = 0;
	int have_ports = 0;
	if (proto == IPPROTO_TCP) {
		struct tcphdr *th = l4;
		if ((void *)(th + 1) <= data_end) {
			dport = th->dest;
			have_ports = 1;
		}
	} else if (proto == IPPROTO_UDP) {
		struct udphdr *uh = l4;
		if ((void *)(uh + 1) <= data_end) {
			dport = uh->dest;
			have_ports = 1;
		}
	}

	if (have_ports && carve_out(proto, dport))
		return XDP_PASS;

	struct prot_v6_key pk = {};
	__builtin_memcpy(pk.addr, &ip6h->daddr, 16);
	if (!bpf_map_lookup_elem(&protected_v6, &pk))
		return XDP_PASS;

	if (!have_ports) {
		/* IPPROTO_ICMPV6 == 58. Extension headers also land here. */
		if (proto == 58 && ALLOW_ICMP_TO_PROTECTED)
			return XDP_PASS;
		return XDP_DROP;
	}

	struct allow_v6_key key = {};
	__builtin_memcpy(key.saddr, &ip6h->saddr, 16);
	key.dport = dport;
	key.proto = proto;

	struct allow_val *v = bpf_map_lookup_elem(&allow_v6, &key);
	if (!v || expired(v))
		return XDP_DROP;
	return XDP_PASS;
}

SEC("xdp")
int xdpgate(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	if (eth->h_proto == bpf_htons(ETH_P_IP))
		return handle_v4(data, data_end, eth);
	if (eth->h_proto == bpf_htons(ETH_P_IPV6))
		return handle_v6(data, data_end, eth);

	return XDP_PASS;   /* ARP and everything non-IP */
}
