// SPDX-License-Identifier: GPL-2.0
/* xdpgate-load - load + attach the XDP gate (generic/SKB mode) and pin maps.
 *
 *   xdpgate-load attach <iface> [obj.o]   # load, attach, pin maps under
 *                                         #   /sys/fs/bpf/xdpgate
 *   xdpgate-load detach <iface>           # detach and remove pins
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

#define DEFAULT_OBJ "xdpgate.bpf.o"
#define XDP_GENERIC_FLAGS (XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST)

static int do_detach(int ifindex)
{
	int err = bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
	if (err) {
		fprintf(stderr, "detach failed: %s\n", strerror(-err));
		return 1;
	}
	/* Best-effort removal of the pinned maps. */
	char path[256];
	const char *names[] = { "protected_v4", "protected_v6",
				"allow_v4", "allow_v6" };
	for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		snprintf(path, sizeof(path), "%s/%s", XDPGATE_PIN_DIR, names[i]);
		unlink(path);
	}
	rmdir(XDPGATE_PIN_DIR);
	printf("detached from ifindex %d and removed pins\n", ifindex);
	return 0;
}

static int do_attach(int ifindex, const char *obj_path)
{
	int err;

	if (mkdir(XDPGATE_PIN_DIR, 0700) && errno != EEXIST) {
		fprintf(stderr, "mkdir %s: %s\n", XDPGATE_PIN_DIR,
			strerror(errno));
		fprintf(stderr, "is the bpf filesystem mounted at /sys/fs/bpf?\n");
		return 1;
	}

	LIBBPF_OPTS(bpf_object_open_opts, opts,
		    .pin_root_path = XDPGATE_PIN_DIR);

	struct bpf_object *obj = bpf_object__open_file(obj_path, &opts);
	if (!obj) {
		fprintf(stderr, "open %s failed: %s\n", obj_path,
			strerror(errno));
		return 1;
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "load failed: %s\n", strerror(-err));
		bpf_object__close(obj);
		return 1;
	}

	struct bpf_program *prog = bpf_object__find_program_by_name(obj,
								    "xdpgate");
	if (!prog) {
		fprintf(stderr, "program 'xdpgate' not found in object\n");
		bpf_object__close(obj);
		return 1;
	}

	err = bpf_xdp_attach(ifindex, bpf_program__fd(prog),
			     XDP_GENERIC_FLAGS, NULL);
	if (err) {
		fprintf(stderr, "xdp attach (generic) failed: %s\n",
			strerror(-err));
		bpf_object__close(obj);
		return 1;
	}

	/* Maps are auto-pinned by name via LIBBPF_PIN_BY_NAME + pin_root_path.
	 * Program stays attached to the netdev after we close the object. */
	bpf_object__close(obj);
	printf("attached xdpgate (generic mode) to ifindex %d; maps pinned at %s\n",
	       ifindex, XDPGATE_PIN_DIR);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr,
			"usage: %s attach <iface> [obj.o]\n"
			"       %s detach <iface>\n",
			argv[0], argv[0]);
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
