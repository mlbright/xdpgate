/* The C half of the frozen map layout, checked against the same numbers that
 * src/layout.zig asserts. Compiled by `zig build test` while the C CLIs still
 * use common.h. */
#include <stddef.h>

#include "../common.h"
#include "../protected_conf.h"

_Static_assert(sizeof(struct prot_v6_key) == 16, "prot_v6_key");
_Static_assert(sizeof(struct allow_v4_key) == 7, "allow_v4_key");
_Static_assert(offsetof(struct allow_v4_key, dport) == 4, "allow_v4_key.dport");
_Static_assert(offsetof(struct allow_v4_key, proto) == 6, "allow_v4_key.proto");
_Static_assert(sizeof(struct allow_v6_key) == 19, "allow_v6_key");
_Static_assert(offsetof(struct allow_v6_key, dport) == 16, "allow_v6_key.dport");
_Static_assert(offsetof(struct allow_v6_key, proto) == 18, "allow_v6_key.proto");
_Static_assert(sizeof(struct allow_val) == 8, "allow_val");
_Static_assert(SPA_PORT == 62159, "SPA_PORT");
_Static_assert(PROT_MAX_ENTRIES == 256, "PROT_MAX_ENTRIES");
_Static_assert(ALLOW_ICMP_TO_PROTECTED == 0, "ALLOW_ICMP_TO_PROTECTED");
