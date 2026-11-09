#ifndef TRAFFICCOP_CONTRACT_H
#define TRAFFICCOP_CONTRACT_H
#include <linux/types.h>
#define TC_ABI_VERSION 1
/* Per-CPU cumulative counters. Never clear these during a reload. */
struct tc_counters {
    __u64 passed, dropped, bounced, honeypotted;
    __u64 malformed, other, jailed, default_hits;
};
_Static_assert(sizeof(struct tc_counters) == 64, "counter ABI changed");
/* Address bytes use network order; family is 4 or 6. Clear unused bytes. */
struct tc_address { __u8 bytes[16]; __u8 family; __u8 reserved[7]; };
_Static_assert(sizeof(struct tc_address) == 24, "address ABI changed");
#endif
