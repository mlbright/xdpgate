// SPDX-License-Identifier: GPL-2.0
/* xdpgate-load - load + attach the XDP gate (generic/SKB mode) and pin maps.
 *
 *   xdpgate-load attach <iface> [obj.o]   # load, seed the protected set from
 *                                         #   /etc/xdpgate/protected.conf,
 *                                         #   attach, pin maps under
 *                                         #   /sys/fs/bpf/xdpgate
 *   xdpgate-load detach <iface>           # detach and remove pins
 *
 * Seeding happens between load and attach. libbpf creates and pins the maps
 * during bpf_object__load(), so they are writable before the program is wired
 * to the netdev: by the time the gate goes live it already knows what it is
 * gating. Any problem with the config aborts before the attach, so the gate is
 * either armed and correct or not armed at all - it can never be attached with
 * an empty protected set, which would pass every packet while looking healthy.
 *
 * Attachment persists after this process exits (the netdev holds the program;
 * the maps are pinned so xdpgate-ctl can reach them).
 */
#include <errno.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "common.h"
#include "protected_conf.h"

#define DEFAULT_OBJ "xdpgate.bpf.o"
#define XDP_GENERIC_FLAGS (XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST)

static void remove_pins(void)
{
	char path[256];
	const char *names[] = { "protected_v4", "protected_v6",
				"allow_v4", "allow_v6" };
	for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		snprintf(path, sizeof(path), "%s/%s", XDPGATE_PIN_DIR, names[i]);
		unlink(path);
	}
	rmdir(XDPGATE_PIN_DIR);
}

static int do_detach(int ifindex)
{
	int err = bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
	if (err) {
		fprintf(stderr, "detach failed: %s\n", strerror(-err));
		return 1;
	}
	remove_pins();   /* best-effort */
	printf("detached from ifindex %d and removed pins\n", ifindex);
	return 0;
}

/* Apply protected.conf to the freshly-loaded maps. Returns 0 to proceed with
 * the attach, -1 to abort it. */
static int seed_protected(struct bpf_object *obj)
{
	struct bpf_map *m4 = bpf_object__find_map_by_name(obj, "protected_v4");
	struct bpf_map *m6 = bpf_object__find_map_by_name(obj, "protected_v6");
	if (!m4 || !m6) {
		fprintf(stderr, "protected maps not found in object\n");
		return -1;
	}

	const char *path = prot_conf_path();
	struct prot_set set;
	if (prot_set_parse(path, &set))
		return -1;

	/* Validate before touching a map: a reconcile that has already started
	 * cannot be un-done, and this check exists to stop exactly that. */
	if (prot_set_check_hard(&set)) {
		prot_set_free(&set);
		return -1;
	}
	prot_set_warn_nonlocal(&set);

	int added = 0, removed = 0;
	int err = prot_set_reconcile(bpf_map__fd(m4), bpf_map__fd(m6), &set,
				     &added, &removed);
	size_t n = set.n_v4 + set.n_v6;
	prot_set_free(&set);
	if (err)
		return -1;

	printf("protected set seeded from %s: %zu address%s (+%d, -%d)\n",
	       path, n, n == 1 ? "" : "es", added, removed);
	return 0;
}

static int do_attach(int ifindex, const char *obj_path)
{
	int err;

	/* Remember whether the pin directory was ours, so a failed attach only
	 * cleans up pins it created and never tears down a live gate's maps. */
	int created_pindir = 0;
	if (mkdir(XDPGATE_PIN_DIR, 0700)) {
		if (errno != EEXIST) {
			fprintf(stderr, "mkdir %s: %s\n", XDPGATE_PIN_DIR,
				strerror(errno));
			fprintf(stderr, "is the bpf filesystem mounted at /sys/fs/bpf?\n");
			return 1;
		}
	} else {
		created_pindir = 1;
	}

	LIBBPF_OPTS(bpf_object_open_opts, opts,
		    .pin_root_path = XDPGATE_PIN_DIR);

	struct bpf_object *obj = bpf_object__open_file(obj_path, &opts);
	if (!obj) {
		fprintf(stderr, "open %s failed: %s\n", obj_path,
			strerror(errno));
		goto fail;
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "load failed: %s\n", strerror(-err));
		goto fail_close;
	}

	struct bpf_program *prog = bpf_object__find_program_by_name(obj,
								    "xdpgate");
	if (!prog) {
		fprintf(stderr, "program 'xdpgate' not found in object\n");
		goto fail_close;
	}

	/* Arm the maps before arming the datapath. */
	if (seed_protected(obj)) {
		fprintf(stderr, "refusing to attach: the protected set is unusable\n");
		goto fail_close;
	}

	err = bpf_xdp_attach(ifindex, bpf_program__fd(prog),
			     XDP_GENERIC_FLAGS, NULL);
	if (err) {
		fprintf(stderr, "xdp attach (generic) failed: %s\n",
			strerror(-err));
		goto fail_close;
	}

	/* Maps are auto-pinned by name via LIBBPF_PIN_BY_NAME + pin_root_path.
	 * Program stays attached to the netdev after we close the object. */
	bpf_object__close(obj);
	printf("attached xdpgate (generic mode) to ifindex %d; maps pinned at %s\n",
	       ifindex, XDPGATE_PIN_DIR);
	return 0;

fail_close:
	bpf_object__close(obj);
fail:
	if (created_pindir)
		remove_pins();
	return 1;
}

int main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr,
			"usage: %s attach <iface> [obj.o]\n"
			"       %s detach <iface>\n"
			"\n"
			"the protected set is read from %s\n"
			"(override with $%s)\n",
			argv[0], argv[0], prot_conf_path(), XDPGATE_CONF_ENV);
		return 2;
	}

	unsigned int ifindex = if_nametoindex(argv[2]);
	if (!ifindex) {
		fprintf(stderr, "unknown interface '%s'\n", argv[2]);
		return 2;
	}

	if (!strcmp(argv[1], "attach"))
		return do_attach(ifindex, argc > 3 ? argv[3] : DEFAULT_OBJ);
	if (!strcmp(argv[1], "detach"))
		return do_detach(ifindex);

	fprintf(stderr, "unknown command '%s'\n", argv[1]);
	return 2;
}
