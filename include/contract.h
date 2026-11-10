#ifndef TRAFFICCOP_CONTRACT_H
#define TRAFFICCOP_CONTRACT_H
#include <linux/types.h>
#include <linux/bpf.h>
#define TC_ABI_VERSION 5
#define TC_MAX_RULES 64
#define TC_MAX_JAIL_SECONDS 3600
#define TC_MAX_SETS 16
#define TC_MAX_PREFIXES 10000
#define TC_BUCKET_SOURCES 65536
#define TC_STATE_SOURCES 1048576
#define TC_SCAN_SOURCES 65536
#define TC_VLAN_NONE 65535
/* Per-CPU cumulative counters. Never clear these during a reload. */
struct tc_counters {
    __u64 passed, dropped, bounced, honeypotted;
    __u64 malformed, other, jailed, default_hits;
};
_Static_assert(sizeof(struct tc_counters) == 64, "counter ABI changed");
/* Address bytes use network order; family is 4 or 6. Clear unused bytes. */
struct tc_address { __u8 bytes[16]; __u8 family; __u8 reserved[7]; };
_Static_assert(sizeof(struct tc_address) == 24, "address ABI changed");

/* Values 1..4 deliberately equal XDP_DROP/PASS/TX/REDIRECT. */
enum tc_action {
    TC_DROP = 1, TC_PASS = 2, TC_BOUNCE = 3, TC_HONEYPOT = 4,
    TC_LIMIT = 5, TC_JAIL = 6,
};
enum tc_match {
    TC_SRC_PREFIX = 1 << 0, TC_DST_PREFIX = 1 << 1,
    TC_SRC_SET = 1 << 2, TC_DST_SET = 1 << 3,
    TC_SPORT = 1 << 4, TC_DPORT = 1 << 5,
    TC_ICMP_TYPE = 1 << 6, TC_VLAN = 1 << 7,
};
struct tc_prefix {
    __u8 bytes[16];
    __u8 family, bits;
    __u8 reserved[2];
};
struct tc_rule {
    __u32 line, matches, action, rate, burst, jail_seconds;
    struct tc_prefix src, dst;
    __u16 sport_min, sport_max, dport_min, dport_max, vlan;
    __u8 family, proto, icmp_type, src_set, dst_set, log;
};
/* Immutable once attached. A new program/config map is built per generation.
 * Zero defaults support the bootstrap: default PASS, fragments DROP. */
struct tc_config {
    __u64 generation;
    __u32 rule_count, default_action, fragment_action, honeypot_ifindex;
    __u32 scan_ports, scan_window_seconds, scan_jail_seconds, reserved;
    struct tc_rule rules[TC_MAX_RULES];
};
/* LPM key: prefixlen = 32 + IP prefix bits; lookup uses 64 or 160.
 * The first four data bytes identify one set/family, even for /0. */
struct tc_set_key {
    __u32 prefixlen;
    __u8 set, family, reserved[2];
    __u8 bytes[16];
};
struct tc_rule_counters { __u64 hits, passed, dropped, bounced, honeypotted; };
struct tc_health {
    __u64 source_full, jail_full, scan_full, bucket_failed, event_lost, config_missing;
};
struct tc_event {
    __u64 time_ns, generation;
    __u32 line, verdict;
    struct tc_address src, dst;
    __u16 sport, dport;
    __u8 proto, has_ports, reserved[2];
};
/* Userspace reads use BPF_F_LOCK; release through unjail_command, never a
 * separately locked read/modify/write that could clear a retirement marker. */
struct tc_jail_value { struct bpf_spin_lock lock; __u32 retired; __u64 until_ns, cancelled_ns; };

enum tc_unjail_result { TC_UNJAIL_OK = 1, TC_UNJAIL_ABSENT = 2, TC_UNJAIL_RETRY = 3 };
struct tc_unjail_request { struct tc_address src; __u32 result, reserved; };
_Static_assert(sizeof(struct tc_unjail_request) == 32, "unjail request ABI changed");
struct tc_bucket_value {
    /* Atomic GCRA/token-bucket virtual finish time. LRU maps cannot contain
     * bpf_spin_lock on Linux 6.8; a 64-bit CAS serializes source consumption. */
    __u64 next_ns;
};
struct tc_scan_value {
    struct bpf_spin_lock lock;
    __u32 count;
    __u32 retired, reserved;
    __u64 generation, start_ns, pending_until_ns;
    __u64 ports[1024];
};
_Static_assert(sizeof(struct tc_prefix) == 20, "prefix ABI changed");
_Static_assert(sizeof(struct tc_rule) == 80, "rule ABI changed");
_Static_assert(sizeof(struct tc_config) == 5160, "config ABI changed");
_Static_assert(sizeof(struct tc_set_key) == 24, "set key ABI changed");
_Static_assert(sizeof(struct tc_rule_counters) == 40, "rule counters ABI changed");
_Static_assert(sizeof(struct tc_health) == 48, "health ABI changed");
_Static_assert(sizeof(struct tc_event) == 80, "event ABI changed");
_Static_assert(sizeof(struct tc_jail_value) == 24, "jail ABI changed");
_Static_assert(__builtin_offsetof(struct tc_jail_value, cancelled_ns) == 16, "cancel offset changed");
_Static_assert(sizeof(struct tc_bucket_value) == 8, "bucket ABI changed");
_Static_assert(sizeof(struct tc_scan_value) == 8232, "scan ABI changed");
_Static_assert(__builtin_offsetof(struct tc_rule, src) == 24, "rule src offset changed");
_Static_assert(__builtin_offsetof(struct tc_rule, family) == 74, "rule family offset changed");
_Static_assert(__builtin_offsetof(struct tc_config, rules) == 40, "rules offset changed");
_Static_assert(__builtin_offsetof(struct tc_event, src) == 24, "event src offset changed");
_Static_assert(__builtin_offsetof(struct tc_event, proto) == 76, "event protocol offset changed");
_Static_assert(__builtin_offsetof(struct tc_scan_value, ports) == 40, "scan bitmap offset changed");
#endif
