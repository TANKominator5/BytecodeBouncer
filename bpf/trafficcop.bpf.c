#include <linux/bpf.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include "contract.h"
#include "parse.h"

#define ARRAY_MAP(name, kind, count, value_type) \
    struct { \
        __uint(type, kind); __uint(max_entries, count); \
        __type(key, __u32); __type(value, value_type); \
    } name SEC(".maps")
#define SOURCE_MAP(name, count, value_type) \
    struct { \
        __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, count); \
        __uint(map_flags, BPF_F_NO_PREALLOC); \
        __type(key, struct tc_address); __type(value, value_type); \
    } name SEC(".maps")

ARRAY_MAP(counters, BPF_MAP_TYPE_PERCPU_ARRAY, 1, struct tc_counters);
ARRAY_MAP(health, BPF_MAP_TYPE_PERCPU_ARRAY, 1, struct tc_health);
/* Coalesced maintenance requests, shared with jail across replacements. */
ARRAY_MAP(maintenance, BPF_MAP_TYPE_ARRAY, 2, __u64);
ARRAY_MAP(unjail_request, BPF_MAP_TYPE_ARRAY, 1, struct tc_unjail_request);
ARRAY_MAP(config, BPF_MAP_TYPE_ARRAY, 1, struct tc_config);
ARRAY_MAP(rule_counters, BPF_MAP_TYPE_PERCPU_ARRAY, TC_MAX_RULES, struct tc_rule_counters);
SOURCE_MAP(sources, TC_STATE_SOURCES, __u64);
SOURCE_MAP(jail, TC_STATE_SOURCES, struct tc_jail_value);
SOURCE_MAP(scans, TC_SCAN_SOURCES, struct tc_scan_value);
/* Non-locking per-CPU seed avoids an 8 KiB stack allocation. Only the header
 * changes; the bitmap stays zero. Separate from the locked HASH value's BTF. */
struct scan_seed { __u32 lock, count, retired, reserved;
    __u64 generation, start_ns, pending_until_ns, ports[1024]; };
_Static_assert(sizeof(struct scan_seed) == sizeof(struct tc_scan_value), "scan seed ABI");
ARRAY_MAP(scan_seed, BPF_MAP_TYPE_PERCPU_ARRAY, 1, struct scan_seed);

struct bucket_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, TC_BUCKET_SOURCES);
    __type(key, struct tc_address);
    __type(value, struct tc_bucket_value);
};
/* A concrete instance keeps the inner value's full BTF (not a forward decl).
 * Userspace may reuse this map for the first limit rule. */
struct bucket_map bucket_template SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, TC_MAX_RULES);
    __type(key, __u32);
    __array(values, struct bucket_map);
} buckets SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, TC_MAX_PREFIXES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct tc_set_key);
    __type(value, __u32);
} sets SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

/* Retain the event schema in ELF BTF for consumers' layout checks. */
const struct tc_event event_abi = {};

/* The production loader specializes these immutable per-generation masks from
 * the validated rules. The generic object keeps every feature enabled for the
 * ABI/kernel fixtures. No rule or packet verdict moves into userspace. */
const volatile __u32 enabled_actions = ~0U;
const volatile __u32 enabled_matches = ~0U;

#include "match.h"
#include "state.h"
#include "actions.h"

SEC("xdp") int trafficcop(struct xdp_md *ctx)
{
    __u32 zero = 0;
    struct tc_counters *c = bpf_map_lookup_elem(&counters, &zero);
    struct tc_health *h = bpf_map_lookup_elem(&health, &zero);
    __u8 *data = (void *)(long)ctx->data;
    __u8 *end = (void *)(long)ctx->data_end;
    struct tc_packet packet = {};
    int parsed = parse_packet(data, end, &packet);
    if (parsed == TC_OTHER) {
        if (c) c->other++;
        return finish(c, TC_PASS);
    }
    if (parsed == TC_MALFORMED) {
        if (c) c->malformed++;
        return finish(c, TC_DROP);
    }
    count_source(&packet.src, h);
    __u64 now = bpf_ktime_get_ns();
    if (is_jailed(&packet.src, now)) {
        if (c) c->jailed++;
        return finish(c, TC_DROP);
    }
    /* This one immutable map belongs to this program generation. Never reread
     * a mutable global selector halfway through processing a frame. */
    struct tc_config *cfg = bpf_map_lookup_elem(&config, &zero);
    if (!cfg) {
        if (h) h->config_missing++;
        return finish(c, TC_DROP);
    }
    if (packet.has_ports && cfg->scan_ports) {
        int scan = scan_source(&packet, cfg, now, h);
        if (scan) {
            if (scan > 0 && c) c->jailed++;
            return finish(c, TC_DROP);
        }
    }
    struct match_context match = { .packet = &packet, .cfg = cfg, .index = -1 };
    bpf_loop(TC_MAX_RULES, match_rule, &match, 0);
    if (match.index >= 0 && match.index < TC_MAX_RULES) {
        __u32 index = match.index;
        struct tc_rule *rule = &cfg->rules[index];
        int verdict = rule->action;
        if ((enabled_actions & (1U << TC_LIMIT)) && verdict == TC_LIMIT)
            verdict = take_token(index, &packet.src, rule, now, h) ? TC_PASS : TC_DROP;
        else if ((enabled_actions & (1U << TC_JAIL)) && verdict == TC_JAIL) {
            jail_source(&packet.src, now, now + (__u64)rule->jail_seconds * 1000000000, h);
            verdict = TC_DROP;
        } else if ((enabled_actions & (1U << TC_BOUNCE)) && verdict == TC_BOUNCE) {
            /* Re-establish the writable packet bounds after helper calls. */
            data = (void *)(long)ctx->data;
            end = (void *)(long)ctx->data_end;
            if (data + 14 > end)
                verdict = TC_DROP;
            else {
#pragma unroll
                for (int i = 0; i < 6; i++) {
                    __u8 tmp = data[i];
                    data[i] = data[i + 6];
                    data[i + 6] = tmp;
                }
            }
        } else if ((enabled_actions & (1U << TC_HONEYPOT)) && verdict == TC_HONEYPOT) {
            /* Never silently fall back to PASS when redirect cannot be set up. */
            verdict = bpf_redirect(cfg->honeypot_ifindex, 0);
        }
        if (verdict < TC_DROP || verdict > TC_HONEYPOT)
            verdict = TC_DROP;
        count_rule(index, verdict);
        if (rule->log)
            log_decision(&packet, cfg->generation, rule->line, verdict, now, h);
        return finish(c, verdict);
    }
    if (packet.nonfirst)
        return finish(c, cfg->fragment_action == TC_PASS ? TC_PASS : TC_DROP);
    if (c) c->default_hits++;
    return finish(c, cfg->default_action == TC_DROP ? TC_DROP : TC_PASS);
}
char LICENSE[] SEC("license") = "GPL";

/* Never attach these programs. A daemon maintenance worker invokes them with
 * test-run, independent of packet processing and generation publication. All
 * expiry/retirement/delete decisions still execute in BPF with value locks. */
SEC("xdp") int reclaim_jail_command(struct xdp_md *ctx)
{
    (void)ctx;
    reclaim_state(0, bpf_ktime_get_ns(), 0);
    return XDP_PASS;
}
SEC("xdp") int reclaim_scan_command(struct xdp_md *ctx)
{
    (void)ctx;
    __u32 zero = 0;
    const struct tc_config *cfg = bpf_map_lookup_elem(&config, &zero);
    if (cfg) reclaim_state(1, bpf_ktime_get_ns(), cfg);
    return XDP_PASS;
}

/* Control-only program, invoked with BPF_PROG_TEST_RUN, never attached. The
 * daemon serializes requests on its private request map. Release and retirement
 * checks happen in one critical section, not two userspace map syscalls. */
SEC("xdp") int unjail_command(struct xdp_md *ctx)
{
    (void)ctx;
    __u32 zero = 0;
    struct tc_unjail_request *request = bpf_map_lookup_elem(&unjail_request, &zero);
    if (!request) return XDP_ABORTED;
    struct tc_jail_value *value = bpf_map_lookup_elem(&jail, &request->src);
    if (!value) { request->result = TC_UNJAIL_ABSENT; return XDP_PASS; }
    __u64 now = bpf_ktime_get_ns();
    bpf_spin_lock(&value->lock);
    __u32 result = TC_UNJAIL_ABSENT;
    if (value->retired) result = TC_UNJAIL_RETRY;
    else if (value->until_ns > now) {
        value->until_ns = 0;
        value->cancelled_ns = now;
        result = TC_UNJAIL_OK;
    }
    bpf_spin_unlock(&value->lock);
    request->result = result;
    return XDP_PASS;
}
