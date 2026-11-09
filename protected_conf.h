/* SPDX-License-Identifier: GPL-2.0 */
/* protected_conf.h - the protected set as a declarative config file.
 *
 * The protected set is what makes the gate a gate: an empty set means every
 * packet takes the "dest not protected -> PASS" branch, so an attached program
 * with no entries is an elaborate no-op. Keeping that set only in the pinned
 * maps meant it vanished on every reboot and had to be retyped by hand, which
 * is why this file exists: /etc/xdpgate/protected.conf is the source of truth,
 * and both xdpgate-load (at attach) and xdpgate-ctl (at reload) apply it
 * through the same three calls - parse, check, reconcile.
 */
#ifndef XDPGATE_PROTECTED_CONF_H
#define XDPGATE_PROTECTED_CONF_H

#include <stddef.h>
#include <linux/types.h>

#include "common.h"

#define XDPGATE_CONF_DEFAULT "/etc/xdpgate/protected.conf"
#define XDPGATE_CONF_ENV     "XDPGATE_CONF"

/* Must match max_entries on protected_v4/protected_v6 in xdpgate.bpf.c. */
#define PROT_MAX_ENTRIES 256

/* Parsed contents of protected.conf. Addresses are stored in network byte
 * order so they drop straight into the map keys the XDP program reads. */
struct prot_set {
	__u32              *v4;
	size_t              n_v4;
	size_t              cap_v4;
	struct prot_v6_key *v6;
	size_t              n_v6;
	size_t              cap_v6;
};

/* $XDPGATE_CONF if set and non-empty, else XDPGATE_CONF_DEFAULT. */
const char *prot_conf_path(void);

void prot_set_free(struct prot_set *s);

/* Parse `path` into `out`. Returns 0 on success, -1 on any problem (missing
 * file, malformed line, zero addresses), having explained it on stderr. There
 * is deliberately no partial success: a typo'd address that silently drops a
 * service out of the protected set is the exact failure this file prevents. */
int prot_set_parse(const char *path, struct prot_set *out);

/* Refuse configurations that would cut the host off. XDP here is stateless and
 * ingress-only, so gating the source address the kernel picks for the default
 * route drops the return path of every host-originated flow - including the
 * SSH session of whoever is watching. Returns 0 if clear, -1 if it would.
 * This is the same overlap whats-on-ip grades HARD. */
int prot_set_check_hard(const struct prot_set *s);

/* Warn (never fail) about configured addresses not currently assigned to this
 * host: EC2 secondary and floating addresses are legitimately attached after
 * boot, so this cannot be an error. */
void prot_set_warn_nonlocal(const struct prot_set *s);

/* Make the maps equal the file: add what is missing, delete what the file does
 * not name. Idempotent. Adds run before deletes, so a reconcile that fails
 * part-way through can only ever leave more gated than configured, never less.
 * Returns 0 on success, -1 on failure; counts are optional. */
int prot_set_reconcile(int fd4, int fd6, const struct prot_set *s,
		       int *added, int *removed);

int prot_set_has_v4(const struct prot_set *s, __u32 addr);
int prot_set_has_v6(const struct prot_set *s, const __u8 addr[16]);

#endif /* XDPGATE_PROTECTED_CONF_H */
