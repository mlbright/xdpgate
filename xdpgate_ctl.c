// SPDX-License-Identifier: GPL-2.0
/* xdpgate-ctl - manage the pinned maps. Invoked per-SPA by fwknopd CMD_CYCLE,
 * and by an operator for the protected set / housekeeping.
 *
 *   xdpgate-ctl open  <ip> <tcp|udp> <port> [timeout_secs]
 *   xdpgate-ctl close <ip> <tcp|udp> <port>
 *   xdpgate-ctl add-protected <ip>
 *   xdpgate-ctl del-protected <ip>
 *   xdpgate-ctl reload
 *   xdpgate-ctl export
 *   xdpgate-ctl list
 *   xdpgate-ctl gc
 *
 * IP family is auto-detected (':' => IPv6). Ports and addresses are written to
 * the maps in network byte order to match what the XDP program reads on-wire.
 * Expiry is CLOCK_MONOTONIC nanoseconds, the same clock as bpf_ktime_get_ns().
 *
 * The protected set is owned by /etc/xdpgate/protected.conf, not by this tool:
 * `reload` makes the live maps equal that file, and add-protected/del-protected
 * are transient overrides that the next reload or reboot undoes.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>

#include "common.h"
#include "protected_conf.h"

#define DEFAULT_TIMEOUT_SECS 30   /* used when fwknop passes no $TIMEOUT */

static int map_fd(const char *name)
{
	char path[256];
	snprintf(path, sizeof(path), "%s/%s", XDPGATE_PIN_DIR, name);
	int fd = bpf_obj_get(path);
	if (fd < 0)
		fprintf(stderr, "cannot open pinned map %s: %s\n"
			"  (is xdpgate-load attached?)\n", path, strerror(errno));
	return fd;
}

static __u64 monotonic_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

static int parse_proto(const char *s, __u8 *out)
{
	if (!strcasecmp(s, "tcp")) { *out = IPPROTO_TCP; return 0; }
	if (!strcasecmp(s, "udp")) { *out = IPPROTO_UDP; return 0; }
	fprintf(stderr, "proto must be tcp or udp, got '%s'\n", s);
	return -1;
}

/* returns 4 or 6 on success, -1 on parse failure; fills v4/v6 buffers */
static int parse_ip(const char *s, __u32 *v4, __u8 v6[16])
{
	if (strchr(s, ':')) {
		if (inet_pton(AF_INET6, s, v6) == 1)
			return 6;
	} else {
		struct in_addr a;
		if (inet_pton(AF_INET, s, &a) == 1) {
			*v4 = a.s_addr;   /* already network order */
			return 4;
		}
	}
	fprintf(stderr, "bad IP address '%s'\n", s);
	return -1;
}

static int cmd_open_close(int argc, char **argv, int opening)
{
	if (argc < 5 || (opening && argc > 6)) {
		fprintf(stderr, "usage: %s %s <ip> <tcp|udp> <port>%s\n",
			argv[0], argv[1], opening ? " [timeout_secs]" : "");
		return 2;
	}
	__u32 v4 = 0; __u8 v6[16] = {0};
	int fam = parse_ip(argv[2], &v4, v6);
	if (fam < 0) return 2;

	__u8 proto;
	if (parse_proto(argv[3], &proto)) return 2;

	int port = atoi(argv[4]);
	if (port < 1 || port > 65535) {
		fprintf(stderr, "port out of range: %s\n", argv[4]);
		return 2;
	}
	__u16 dport_be = htons((__u16)port);

	__u64 expiry = 0;
	if (opening) {
		long t = (argc == 6) ? atol(argv[5]) : DEFAULT_TIMEOUT_SECS;
		if (t <= 0) t = DEFAULT_TIMEOUT_SECS;
		expiry = monotonic_ns() + (__u64)t * 1000000000ULL;
	}

	const char *mapname = (fam == 4) ? "allow_v4" : "allow_v6";
	int fd = map_fd(mapname);
	if (fd < 0) return 1;

	int err;
	if (fam == 4) {
		struct allow_v4_key k = {0};
		k.saddr = v4; k.dport = dport_be; k.proto = proto;
		if (opening) {
			struct allow_val val = { .expiry_ns = expiry };
			err = bpf_map_update_elem(fd, &k, &val, BPF_ANY);
		} else {
			err = bpf_map_delete_elem(fd, &k);
		}
	} else {
		struct allow_v6_key k = {0};
		memcpy(k.saddr, v6, 16); k.dport = dport_be; k.proto = proto;
		if (opening) {
			struct allow_val val = { .expiry_ns = expiry };
			err = bpf_map_update_elem(fd, &k, &val, BPF_ANY);
		} else {
			err = bpf_map_delete_elem(fd, &k);
		}
	}

	/* close on a missing key is fine (already expired/GC'd). */
	if (err && !(!opening && errno == ENOENT)) {
		fprintf(stderr, "%s failed: %s\n", argv[1], strerror(errno));
		return 1;
	}
	return 0;
}

static int cmd_protected(int argc, char **argv, int adding)
{
	if (argc != 3) {
		fprintf(stderr, "usage: %s %s <ip>\n", argv[0], argv[1]);
		return 2;
	}
	__u32 v4 = 0; __u8 v6[16] = {0};
	int fam = parse_ip(argv[2], &v4, v6);
	if (fam < 0) return 2;

	int fd = map_fd(fam == 4 ? "protected_v4" : "protected_v6");
	if (fd < 0) return 1;

	__u8 one = 1;
	int err;
	if (fam == 4) {
		err = adding ? bpf_map_update_elem(fd, &v4, &one, BPF_ANY)
			     : bpf_map_delete_elem(fd, &v4);
	} else {
		struct prot_v6_key k = {0};
		memcpy(k.addr, v6, 16);
		err = adding ? bpf_map_update_elem(fd, &k, &one, BPF_ANY)
			     : bpf_map_delete_elem(fd, &k);
	}
	if (err && !(!adding && errno == ENOENT)) {
		fprintf(stderr, "%s failed: %s\n", argv[1], strerror(errno));
		return 1;
	}

	/* The config file is the source of truth; this only moved the live map,
	 * and reconcile will move it back. Say so now rather than let it be a
	 * surprise the next time something reloads. */
	fprintf(stderr,
		"warning: runtime only - the next reload or reboot %s this.\n"
		"  %s %s %s %s to make it durable.\n",
		adding ? "reverts" : "restores",
		adding ? "Add" : "Remove", argv[2],
		adding ? "to" : "from", prot_conf_path());
	return 0;
}

static const char *proto_str(__u8 p)
{
	return p == IPPROTO_TCP ? "tcp" : p == IPPROTO_UDP ? "udp" : "?";
}

/* Expiries are stored on CLOCK_MONOTONIC, which has no meaning as a date, so
 * snapshot both clocks once per listing and convert relative to that pair. */
struct clocks {
	__u64  mono_ns;
	time_t wall;
};

static void clocks_now(struct clocks *c)
{
	c->mono_ns = monotonic_ns();
	c->wall = time(NULL);
}

/* "2d 23h 51m 31s", dropping leading zero units ("0s" for under a second). */
static void fmt_duration(long long secs, char *buf, size_t len)
{
	long long d = secs / 86400; secs %= 86400;
	long long h = secs / 3600;  secs %= 3600;
	long long m = secs / 60;    secs %= 60;
	size_t n = 0;

	if (d) n += snprintf(buf + n, len - n, "%lldd ", d);
	if (d || h) n += snprintf(buf + n, len - n, "%lldh ", h);
	if (d || h || m) n += snprintf(buf + n, len - n, "%lldm ", m);
	snprintf(buf + n, len - n, "%llds", secs);
}

/* The tail of a grant line: "expires <when> (in <dur>)" or a variant. */
static void print_expiry(__u64 expiry_ns, const struct clocks *c)
{
	if (!expiry_ns) {
		printf("no expiry\n");
		return;
	}

	long long left = ((long long)expiry_ns - (long long)c->mono_ns) / 1000000000LL;
	time_t when = c->wall + (time_t)left;

	char tbuf[64], dbuf[64];
	struct tm tm;
	if (localtime_r(&when, &tm))
		strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S %Z", &tm);
	else
		snprintf(tbuf, sizeof(tbuf), "?");

	fmt_duration(left < 0 ? -left : left, dbuf, sizeof(dbuf));
	if (left < 0)
		printf("expired %s (%s ago)\n", tbuf, dbuf);
	else
		printf("expires %s (in %s)\n", tbuf, dbuf);
}

/* Listing sort orders. Addresses compare as numbers: v4 after ntohl, v6
 * bytewise, since network order is big-endian and so memcmp is numeric. */
static int cmp_u32(__u32 a, __u32 b)
{
	return a < b ? -1 : a > b;
}

static int cmp_prot_v4(const void *a, const void *b)
{
	return cmp_u32(ntohl(*(const __u32 *)a), ntohl(*(const __u32 *)b));
}

static int cmp_prot_v6(const void *a, const void *b)
{
	return memcmp(a, b, sizeof(struct prot_v6_key));
}

/* Grants from one source address: tcp before udp, then by port. */
static int cmp_svc(__u8 pa, __u16 da, __u8 pb, __u16 db)
{
	return pa != pb ? cmp_u32(pa, pb) : cmp_u32(ntohs(da), ntohs(db));
}

static int cmp_allow_v4(const void *a, const void *b)
{
	const struct allow_v4_key *x = a, *y = b;
	int c = cmp_u32(ntohl(x->saddr), ntohl(y->saddr));
	return c ? c : cmp_svc(x->proto, x->dport, y->proto, y->dport);
}

static int cmp_allow_v6(const void *a, const void *b)
{
	const struct allow_v6_key *x = a, *y = b;
	int c = memcmp(x->saddr, y->saddr, 16);
	return c ? c : cmp_svc(x->proto, x->dport, y->proto, y->dport);
}

/* Every key of a hash map, sorted with cmp: iteration runs in hash order,
 * which reads as random. Returns the count; *out is malloc'd for the caller
 * to free. */
static size_t map_sorted_keys(int fd, size_t ksz,
			      int (*cmp)(const void *, const void *), void **out)
{
	unsigned char *keys = NULL;
	size_t n = 0, cap = 0;

	for (;;) {
		if (n == cap) {
			size_t ncap = cap ? cap * 2 : 64;
			unsigned char *p = realloc(keys, ncap * ksz);
			if (!p) {
				fprintf(stderr, "out of memory; listing is incomplete\n");
				break;
			}
			keys = p;
			cap = ncap;
		}
		/* Each key is the cursor for the next, so iterate in place. */
		if (bpf_map_get_next_key(fd, n ? keys + (n - 1) * ksz : NULL,
					 keys + n * ksz))
			break;
		n++;
	}
	if (n)
		qsort(keys, n, ksz, cmp);
	*out = keys;
	return n;
}

static void dump_allow_v4(const struct clocks *c)
{
	int fd = map_fd("allow_v4");
	if (fd < 0) return;
	struct allow_v4_key *keys;
	struct allow_val v;
	char ip[INET_ADDRSTRLEN];
	size_t n = map_sorted_keys(fd, sizeof(*keys), cmp_allow_v4,
				   (void **)&keys);
	for (size_t i = 0; i < n; i++) {
		if (bpf_map_lookup_elem(fd, &keys[i], &v)) continue;
		inet_ntop(AF_INET, &keys[i].saddr, ip, sizeof(ip));
		printf("v4 %s:%s/%u ", ip, proto_str(keys[i].proto),
		       ntohs(keys[i].dport));
		print_expiry(v.expiry_ns, c);
	}
	free(keys);
}

static void dump_allow_v6(const struct clocks *c)
{
	int fd = map_fd("allow_v6");
	if (fd < 0) return;
	struct allow_v6_key *keys;
	struct allow_val v;
	char ip[INET6_ADDRSTRLEN];
	size_t n = map_sorted_keys(fd, sizeof(*keys), cmp_allow_v6,
				   (void **)&keys);
	for (size_t i = 0; i < n; i++) {
		if (bpf_map_lookup_elem(fd, &keys[i], &v)) continue;
		inet_ntop(AF_INET6, keys[i].saddr, ip, sizeof(ip));
		printf("v6 [%s]:%s/%u ", ip, proto_str(keys[i].proto),
		       ntohs(keys[i].dport));
		print_expiry(v.expiry_ns, c);
	}
	free(keys);
}

/* Best-effort config load, for annotating `list` only. A box that has not been
 * migrated yet still has to be able to list its maps, so a missing or broken
 * config just means no annotations. Returns 1 if `out` is usable. */
static int load_cfg_quiet(struct prot_set *out)
{
	memset(out, 0, sizeof(*out));
	const char *path = prot_conf_path();
	if (access(path, R_OK))
		return 0;
	return prot_set_parse(path, out) ? 0 : 1;
}

/* Live protected entries, tagged with where they came from. Entries that are
 * in the config but NOT in the map print on a differently-prefixed line, so
 * tools scraping "^\s*protected v[46] <ip>" only ever see addresses that are
 * genuinely being gated right now. Sorts cfg in place. */
static void dump_protected(struct prot_set *cfg, int have_cfg)
{
	char ip[INET6_ADDRSTRLEN];
	__u8 v;

	int fd4 = map_fd("protected_v4");
	if (fd4 >= 0) {
		__u32 *keys;
		size_t n = map_sorted_keys(fd4, sizeof(*keys), cmp_prot_v4,
					   (void **)&keys);
		for (size_t i = 0; i < n; i++) {
			if (bpf_map_lookup_elem(fd4, &keys[i], &v)) continue;
			inet_ntop(AF_INET, &keys[i], ip, sizeof(ip));
			printf("protected v4 %s%s\n", ip,
			       (have_cfg && !prot_set_has_v4(cfg, keys[i]))
				       ? "   [runtime only]" : "");
		}
		free(keys);
	}

	int fd6 = map_fd("protected_v6");
	if (fd6 >= 0) {
		struct prot_v6_key *keys;
		size_t n = map_sorted_keys(fd6, sizeof(*keys), cmp_prot_v6,
					   (void **)&keys);
		for (size_t i = 0; i < n; i++) {
			if (bpf_map_lookup_elem(fd6, &keys[i], &v)) continue;
			inet_ntop(AF_INET6, keys[i].addr, ip, sizeof(ip));
			printf("protected v6 %s%s\n", ip,
			       (have_cfg && !prot_set_has_v6(cfg, keys[i].addr))
				       ? "   [runtime only]" : "");
		}
		free(keys);
	}

	if (!have_cfg)
		return;

	if (cfg->n_v4)
		qsort(cfg->v4, cfg->n_v4, sizeof(*cfg->v4), cmp_prot_v4);
	if (cfg->n_v6)
		qsort(cfg->v6, cfg->n_v6, sizeof(*cfg->v6), cmp_prot_v6);

	for (size_t i = 0; i < cfg->n_v4; i++) {
		if (fd4 < 0 || !bpf_map_lookup_elem(fd4, &cfg->v4[i], &v))
			continue;
		inet_ntop(AF_INET, &cfg->v4[i], ip, sizeof(ip));
		printf("missing   v4 %s   [in config, removed at runtime]\n", ip);
	}
	for (size_t i = 0; i < cfg->n_v6; i++) {
		if (fd6 < 0 || !bpf_map_lookup_elem(fd6, &cfg->v6[i], &v))
			continue;
		inet_ntop(AF_INET6, cfg->v6[i].addr, ip, sizeof(ip));
		printf("missing   v6 %s   [in config, removed at runtime]\n", ip);
	}
}

static int cmd_list(void)
{
	struct clocks c;
	clocks_now(&c);

	struct prot_set cfg;
	int have_cfg = load_cfg_quiet(&cfg);

	dump_protected(&cfg, have_cfg);
	dump_allow_v4(&c);
	dump_allow_v6(&c);

	if (have_cfg)
		prot_set_free(&cfg);
	return 0;
}

/* Make the live protected maps equal protected.conf. Only the protected maps
 * are touched - live SPA grants in allow_v4/allow_v6 are left alone, which is
 * the whole reason this exists instead of a service restart. */
static int cmd_reload(void)
{
	const char *path = prot_conf_path();
	struct prot_set set;

	if (prot_set_parse(path, &set))
		return 1;
	if (prot_set_check_hard(&set)) {
		prot_set_free(&set);
		fprintf(stderr, "reload aborted; the live protected set is unchanged\n");
		return 1;
	}
	prot_set_warn_nonlocal(&set);

	int fd4 = map_fd("protected_v4");
	int fd6 = map_fd("protected_v6");
	if (fd4 < 0 || fd6 < 0) {
		prot_set_free(&set);
		return 1;
	}

	int added = 0, removed = 0;
	int err = prot_set_reconcile(fd4, fd6, &set, &added, &removed);
	size_t n = set.n_v4 + set.n_v6;
	prot_set_free(&set);
	if (err)
		return 1;

	printf("reloaded %s: %zu address%s protected (+%d, -%d)\n",
	       path, n, n == 1 ? "" : "es", added, removed);
	return 0;
}

/* Dump the live protected set in protected.conf format, so a box whose set only
 * ever existed in the maps can capture it before its next boot needs the file. */
static int cmd_export(void)
{
	int fd4 = map_fd("protected_v4");
	int fd6 = map_fd("protected_v6");
	if (fd4 < 0 || fd6 < 0)
		return 1;

	char ip[INET6_ADDRSTRLEN];
	printf("# xdpgate protected set, exported from the live maps.\n");
	printf("# One address per line. '#' starts a comment; CIDR is not accepted.\n");

	__u32 k4, n4; __u8 v; int first = 1; k4 = 0;
	while (bpf_map_get_next_key(fd4, first ? NULL : &k4, &n4) == 0) {
		first = 0; k4 = n4;
		if (bpf_map_lookup_elem(fd4, &k4, &v)) continue;
		inet_ntop(AF_INET, &k4, ip, sizeof(ip));
		printf("%s\n", ip);
	}

	struct prot_v6_key k6, n6;
	first = 1;
	memset(&k6, 0, sizeof(k6));
	while (bpf_map_get_next_key(fd6, first ? NULL : &k6, &n6) == 0) {
		first = 0; k6 = n6;
		if (bpf_map_lookup_elem(fd6, &k6, &v)) continue;
		inet_ntop(AF_INET6, k6.addr, ip, sizeof(ip));
		printf("%s\n", ip);
	}
	return 0;
}

/* Reap expired allow entries. The kernel already DROPs them; this just frees
 * map slots for the missed-CMD_CYCLE_CLOSE case. Collect-then-delete to avoid
 * mutating the map mid-iteration. */
static int gc_one(const char *name, int v6)
{
	int fd = map_fd(name);
	if (fd < 0) return 0;
	__u64 now = monotonic_ns();

	/* Two passes: gather expired keys, then delete. */
	union { struct allow_v4_key k4; struct allow_v6_key k6; } cur, next;
	struct allow_val v;
	int first = 1, n = 0;
	memset(&cur, 0, sizeof(cur));

	/* simple bounded buffer */
	static unsigned char victims[4096][sizeof(struct allow_v6_key)];
	size_t ksz = v6 ? sizeof(struct allow_v6_key) : sizeof(struct allow_v4_key);

	while (n < 4096 &&
	       bpf_map_get_next_key(fd, first ? NULL : &cur, &next) == 0) {
		first = 0; memcpy(&cur, &next, ksz);
		if (bpf_map_lookup_elem(fd, &cur, &v)) continue;
		if (v.expiry_ns != 0 && now > v.expiry_ns)
			memcpy(victims[n++], &cur, ksz);
	}
	for (int i = 0; i < n; i++)
		bpf_map_delete_elem(fd, victims[i]);
	return n;
}

static int cmd_gc(void)
{
	int n = gc_one("allow_v4", 0) + gc_one("allow_v6", 1);
	printf("gc: reaped %d expired entr%s\n", n, n == 1 ? "y" : "ies");
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr,
			"usage: %s open  <ip> <tcp|udp> <port> [timeout_secs]\n"
			"       %s close <ip> <tcp|udp> <port>\n"
			"       %s add-protected <ip>      (transient - see reload)\n"
			"       %s del-protected <ip>      (transient - see reload)\n"
			"       %s reload                  apply %s\n"
			"       %s export                  dump the live set as config\n"
			"       %s list\n"
			"       %s gc\n",
			argv[0], argv[0], argv[0], argv[0], argv[0],
			prot_conf_path(), argv[0], argv[0], argv[0]);
		return 2;
	}
	if (!strcmp(argv[1], "open"))  return cmd_open_close(argc, argv, 1);
	if (!strcmp(argv[1], "close")) return cmd_open_close(argc, argv, 0);
	if (!strcmp(argv[1], "add-protected")) return cmd_protected(argc, argv, 1);
	if (!strcmp(argv[1], "del-protected")) return cmd_protected(argc, argv, 0);
	if (!strcmp(argv[1], "reload")) return cmd_reload();
	if (!strcmp(argv[1], "export")) return cmd_export();
	if (!strcmp(argv[1], "list")) return cmd_list();
	if (!strcmp(argv[1], "gc"))   return cmd_gc();

	fprintf(stderr, "unknown command '%s'\n", argv[1]);
	return 2;
}
