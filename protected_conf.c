// SPDX-License-Identifier: GPL-2.0
/* protected_conf.c - parse, validate and apply /etc/xdpgate/protected.conf. */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <bpf/bpf.h>

#include "protected_conf.h"

/* Probes used only as a route-lookup target; connect() on a UDP socket picks a
 * source address without putting anything on the wire. */
#define PROBE_V4 "1.1.1.1"
#define PROBE_V6 "2606:4700:4700::1111"

const char *prot_conf_path(void)
{
	const char *p = getenv(XDPGATE_CONF_ENV);
	return (p && *p) ? p : XDPGATE_CONF_DEFAULT;
}

void prot_set_free(struct prot_set *s)
{
	free(s->v4);
	free(s->v6);
	memset(s, 0, sizeof(*s));
}

int prot_set_has_v4(const struct prot_set *s, __u32 addr)
{
	for (size_t i = 0; i < s->n_v4; i++)
		if (s->v4[i] == addr)
			return 1;
	return 0;
}

int prot_set_has_v6(const struct prot_set *s, const __u8 addr[16])
{
	for (size_t i = 0; i < s->n_v6; i++)
		if (!memcmp(s->v6[i].addr, addr, 16))
			return 1;
	return 0;
}

/* 0 = appended, 1 = already present, -1 = out of memory */
static int push_v4(struct prot_set *s, __u32 addr)
{
	if (prot_set_has_v4(s, addr))
		return 1;
	if (s->n_v4 == s->cap_v4) {
		size_t cap = s->cap_v4 ? s->cap_v4 * 2 : 8;
		__u32 *p = realloc(s->v4, cap * sizeof(*p));
		if (!p)
			return -1;
		s->v4 = p;
		s->cap_v4 = cap;
	}
	s->v4[s->n_v4++] = addr;
	return 0;
}

static int push_v6(struct prot_set *s, const struct prot_v6_key *k)
{
	if (prot_set_has_v6(s, k->addr))
		return 1;
	if (s->n_v6 == s->cap_v6) {
		size_t cap = s->cap_v6 ? s->cap_v6 * 2 : 8;
		struct prot_v6_key *p = realloc(s->v6, cap * sizeof(*p));
		if (!p)
			return -1;
		s->v6 = p;
		s->cap_v6 = cap;
	}
	s->v6[s->n_v6++] = *k;
	return 0;
}

static char *trim(char *s)
{
	while (*s == ' ' || *s == '\t')
		s++;
	char *e = s + strlen(s);
	while (e > s && (e[-1] == ' ' || e[-1] == '\t' ||
			 e[-1] == '\r' || e[-1] == '\n'))
		*--e = '\0';
	return s;
}

static void explain_empty(const char *path)
{
	fprintf(stderr,
		"  An empty protected set gates nothing: every packet takes the\n"
		"  \"destination not protected -> PASS\" branch. There is no safe\n"
		"  default, so %s must name at least one address.\n"
		"  Copy protected.conf.example and list one address per line.\n",
		path);
}

int prot_set_parse(const char *path, struct prot_set *out)
{
	memset(out, 0, sizeof(*out));

	FILE *f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "%s: %s\n", path, strerror(errno));
		if (errno == ENOENT)
			explain_empty(path);
		return -1;
	}

	char *line = NULL;
	size_t cap = 0;
	ssize_t len;
	unsigned lineno = 0;
	int rc = -1;

	while ((len = getline(&line, &cap, f)) != -1) {
		lineno++;

		char *hash = strchr(line, '#');
		if (hash)
			*hash = '\0';
		char *p = trim(line);
		if (!*p)
			continue;

		if (strchr(p, '/')) {
			fprintf(stderr,
				"%s:%u: CIDR is not supported ('%s').\n"
				"  The protected maps are exact-match hashes; give each\n"
				"  address its own line.\n", path, lineno, p);
			goto out;
		}
		if (strpbrk(p, " \t")) {
			fprintf(stderr,
				"%s:%u: expected one address per line, got '%s'\n",
				path, lineno, p);
			goto out;
		}

		int r;
		if (strchr(p, ':')) {
			struct prot_v6_key k;
			memset(&k, 0, sizeof(k));
			if (inet_pton(AF_INET6, p, k.addr) != 1) {
				fprintf(stderr, "%s:%u: bad IPv6 address '%s'\n",
					path, lineno, p);
				goto out;
			}
			r = push_v6(out, &k);
		} else {
			struct in_addr a;
			if (inet_pton(AF_INET, p, &a) != 1) {
				fprintf(stderr, "%s:%u: bad IPv4 address '%s'\n",
					path, lineno, p);
				goto out;
			}
			r = push_v4(out, a.s_addr);   /* already network order */
		}

		if (r < 0) {
			fprintf(stderr, "%s:%u: out of memory\n", path, lineno);
			goto out;
		}
		if (r == 1)
			fprintf(stderr,
				"%s:%u: warning: duplicate address '%s', ignoring\n",
				path, lineno, p);
	}

	if (out->n_v4 + out->n_v6 == 0) {
		fprintf(stderr, "%s: no addresses configured.\n", path);
		explain_empty(path);
		goto out;
	}
	if (out->n_v4 > PROT_MAX_ENTRIES || out->n_v6 > PROT_MAX_ENTRIES) {
		fprintf(stderr,
			"%s: too many addresses (v4 %zu, v6 %zu; limit %d per family).\n"
			"  Raise max_entries on protected_v4/protected_v6 in\n"
			"  xdpgate.bpf.c and rebuild if you genuinely need more.\n",
			path, out->n_v4, out->n_v6, PROT_MAX_ENTRIES);
		goto out;
	}
	rc = 0;
out:
	free(line);
	fclose(f);
	if (rc)
		prot_set_free(out);
	return rc;
}

/* Ask the kernel which source address it would use to reach `probe`. connect()
 * on a datagram socket is a pure route lookup - no packet is transmitted. */
static int default_src_v4(__u32 *out)
{
	struct sockaddr_in probe = { .sin_family = AF_INET,
				     .sin_port = htons(53) };
	if (inet_pton(AF_INET, PROBE_V4, &probe.sin_addr) != 1)
		return -1;

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	int rc = -1;
	if (!connect(fd, (struct sockaddr *)&probe, sizeof(probe))) {
		struct sockaddr_in me;
		socklen_t l = sizeof(me);
		if (!getsockname(fd, (struct sockaddr *)&me, &l)) {
			*out = me.sin_addr.s_addr;
			rc = 0;
		}
	}
	close(fd);
	return rc;
}

static int default_src_v6(__u8 out[16])
{
	struct sockaddr_in6 probe = { .sin6_family = AF_INET6,
				      .sin6_port = htons(53) };
	if (inet_pton(AF_INET6, PROBE_V6, &probe.sin6_addr) != 1)
		return -1;

	int fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	int rc = -1;
	if (!connect(fd, (struct sockaddr *)&probe, sizeof(probe))) {
		struct sockaddr_in6 me;
		socklen_t l = sizeof(me);
		if (!getsockname(fd, (struct sockaddr *)&me, &l)) {
			memcpy(out, &me.sin6_addr, 16);
			rc = 0;
		}
	}
	close(fd);
	return rc;
}

static void explain_hard(const char *fam, const char *ip)
{
	fprintf(stderr,
		"refusing to apply: %s is this host's default %s source address.\n"
		"  The gate is stateless and ingress-only, so protecting it drops the\n"
		"  return path of every connection this host originates - including\n"
		"  the session you are reading this in.\n"
		"  Move the service to a dedicated address and put that in the config.\n",
		ip, fam);
}

int prot_set_check_hard(const struct prot_set *s)
{
	int bad = 0;
	char buf[INET6_ADDRSTRLEN];

	__u32 src4;
	if (!default_src_v4(&src4) && prot_set_has_v4(s, src4)) {
		inet_ntop(AF_INET, &src4, buf, sizeof(buf));
		explain_hard("IPv4", buf);
		bad = 1;
	}

	__u8 src6[16];
	if (!default_src_v6(src6) && prot_set_has_v6(s, src6)) {
		inet_ntop(AF_INET6, src6, buf, sizeof(buf));
		explain_hard("IPv6", buf);
		bad = 1;
	}

	/* A family with no default route just fails the probe; that is not an
	 * error, it only means there is no return path to break. */
	return bad ? -1 : 0;
}

void prot_set_warn_nonlocal(const struct prot_set *s)
{
	struct ifaddrs *ifa;
	if (getifaddrs(&ifa))
		return;   /* advisory only - never block on it */

	char buf[INET6_ADDRSTRLEN];

	for (size_t i = 0; i < s->n_v4; i++) {
		int found = 0;
		for (struct ifaddrs *a = ifa; a && !found; a = a->ifa_next) {
			if (!a->ifa_addr || a->ifa_addr->sa_family != AF_INET)
				continue;
			struct sockaddr_in *in = (struct sockaddr_in *)a->ifa_addr;
			found = (in->sin_addr.s_addr == s->v4[i]);
		}
		if (!found) {
			inet_ntop(AF_INET, &s->v4[i], buf, sizeof(buf));
			fprintf(stderr,
				"warning: %s is not currently assigned to this host "
				"(gating it is a no-op until it is)\n", buf);
		}
	}

	for (size_t i = 0; i < s->n_v6; i++) {
		int found = 0;
		for (struct ifaddrs *a = ifa; a && !found; a = a->ifa_next) {
			if (!a->ifa_addr || a->ifa_addr->sa_family != AF_INET6)
				continue;
			struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)a->ifa_addr;
			found = !memcmp(&in6->sin6_addr, s->v6[i].addr, 16);
		}
		if (!found) {
			inet_ntop(AF_INET6, s->v6[i].addr, buf, sizeof(buf));
			fprintf(stderr,
				"warning: %s is not currently assigned to this host "
				"(gating it is a no-op until it is)\n", buf);
		}
	}

	freeifaddrs(ifa);
}

static void report_update_failure(const char *map, const char *ip, int err)
{
	fprintf(stderr, "%s: cannot protect %s: %s\n", map, ip, strerror(err));
	if (err == E2BIG)
		fprintf(stderr,
			"  the map is full (max_entries %d); raise it in "
			"xdpgate.bpf.c and rebuild.\n", PROT_MAX_ENTRIES);
}

int prot_set_reconcile(int fd4, int fd6, const struct prot_set *s,
		       int *added, int *removed)
{
	__u8 one = 1, tmp;
	int add_n = 0, del_n = 0;
	char buf[INET6_ADDRSTRLEN];

	/* --- pass 1: add everything the file names ------------------------ */
	for (size_t i = 0; i < s->n_v4; i++) {
		if (!bpf_map_lookup_elem(fd4, &s->v4[i], &tmp))
			continue;
		if (bpf_map_update_elem(fd4, &s->v4[i], &one, BPF_ANY)) {
			inet_ntop(AF_INET, &s->v4[i], buf, sizeof(buf));
			report_update_failure("protected_v4", buf, errno);
			return -1;
		}
		add_n++;
	}
	for (size_t i = 0; i < s->n_v6; i++) {
		if (!bpf_map_lookup_elem(fd6, &s->v6[i], &tmp))
			continue;
		if (bpf_map_update_elem(fd6, &s->v6[i], &one, BPF_ANY)) {
			inet_ntop(AF_INET6, s->v6[i].addr, buf, sizeof(buf));
			report_update_failure("protected_v6", buf, errno);
			return -1;
		}
		add_n++;
	}

	/* --- pass 2: drop entries the file does not name ------------------
	 * Collect first, delete after: mutating a map mid-iteration is not
	 * defined for bpf_map_get_next_key(). */
	__u32 dead4[PROT_MAX_ENTRIES];
	struct prot_v6_key dead6[PROT_MAX_ENTRIES];
	size_t n4 = 0, n6 = 0;

	__u32 cur4, next4;
	int first = 1;
	memset(&cur4, 0, sizeof(cur4));
	while (n4 < PROT_MAX_ENTRIES &&
	       !bpf_map_get_next_key(fd4, first ? NULL : &cur4, &next4)) {
		first = 0;
		cur4 = next4;
		if (!prot_set_has_v4(s, cur4))
			dead4[n4++] = cur4;
	}

	struct prot_v6_key cur6, next6;
	first = 1;
	memset(&cur6, 0, sizeof(cur6));
	while (n6 < PROT_MAX_ENTRIES &&
	       !bpf_map_get_next_key(fd6, first ? NULL : &cur6, &next6)) {
		first = 0;
		cur6 = next6;
		if (!prot_set_has_v6(s, cur6.addr))
			dead6[n6++] = cur6;
	}

	for (size_t i = 0; i < n4; i++)
		if (!bpf_map_delete_elem(fd4, &dead4[i]))
			del_n++;
	for (size_t i = 0; i < n6; i++)
		if (!bpf_map_delete_elem(fd6, &dead6[i]))
			del_n++;

	if (added)
		*added = add_n;
	if (removed)
		*removed = del_n;
	return 0;
}
