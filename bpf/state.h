#ifndef TRAFFICCOP_STATE_H
#define TRAFFICCOP_STATE_H
#define NS_PER_SECOND 1000000000ULL

/* Readers may hold an RCU-protected value pointer after deletion. Mark an
 * expired entry retired under its lock before deleting it; writers retry instead
 * of extending that detached value. Only one collector deletes from each map.
 * Userspace must use the same protocol, not independently delete state entries. */
struct reclaim_context { __u64 now, generation, window_ns; };
static long reclaim_jail(void *map, const void *key, void *raw, void *context)
{
    struct tc_jail_value *value = raw;
    struct reclaim_context *gc = context;
    bpf_spin_lock(&value->lock);
    /* Retain cancellation until every legal pre-release decision has expired.
     * Otherwise a captured old retry could recreate jail after reclamation. */
    int expired = !value->retired && value->until_ns <= gc->now &&
        (!value->cancelled_ns || (gc->now >= value->cancelled_ns &&
         gc->now - value->cancelled_ns >= TC_MAX_JAIL_SECONDS * NS_PER_SECOND));
    if (expired) value->retired = 1;
    bpf_spin_unlock(&value->lock);
    if (!expired) return 0;
    if (bpf_map_delete_elem(map, key)) {
        bpf_spin_lock(&value->lock);
        value->retired = 0;
        bpf_spin_unlock(&value->lock);
        return 0;
    }
    return 1;
}
static long reclaim_scan(void *map, const void *key, void *raw, void *context)
{
    struct tc_scan_value *value = raw;
    struct reclaim_context *gc = context;
    bpf_spin_lock(&value->lock);
    int expired = !value->retired && value->pending_until_ns <= gc->now &&
        (value->generation != gc->generation ||
         (gc->now >= value->start_ns && gc->now - value->start_ns >= gc->window_ns));
    if (expired) value->retired = 1;
    bpf_spin_unlock(&value->lock);
    if (!expired) return 0;
    if (bpf_map_delete_elem(map, key)) {
        bpf_spin_lock(&value->lock);
        value->retired = 0;
        bpf_spin_unlock(&value->lock);
        return 0;
    }
    return 1;
}
static __always_inline void reclaim_state(__u32 kind, __u64 now,
                                          const struct tc_config *cfg)
{
    __u64 *busy = bpf_map_lookup_elem(&maintenance, &kind);
    if (!busy || __sync_val_compare_and_swap(busy, 0, 1)) return;
    struct reclaim_context gc = { .now = now };
    if (kind == 0) {
        bpf_for_each_map_elem(&jail, reclaim_jail, &gc, 0);
    } else {
        gc.generation = cfg->generation;
        gc.window_ns = (__u64)cfg->scan_window_seconds * NS_PER_SECOND;
        bpf_for_each_map_elem(&scans, reclaim_scan, &gc, 0);
    }
    __sync_val_compare_and_swap(busy, 1, 0);
}

static __always_inline void count_source(const struct tc_address *src, struct tc_health *h)
{
    __u64 *count = bpf_map_lookup_elem(&sources, src);
    if (!count) {
        __u64 zero = 0;
        bpf_map_update_elem(&sources, src, &zero, BPF_NOEXIST);
        count = bpf_map_lookup_elem(&sources, src);
    }
    if (count)
        __sync_fetch_and_add(count, 1);
    else if (h)
        h->source_full++;
}
static __always_inline int is_jailed(const struct tc_address *src, __u64 now)
{
    struct tc_jail_value *value = bpf_map_lookup_elem(&jail, src);
    if (!value)
        return 0;
    bpf_spin_lock(&value->lock);
    int active = value->until_ns > now;
    bpf_spin_unlock(&value->lock);
    return active;
}
/* Keep retry/cancellation paths in a subprogram to limit verifier expansion. */
static __noinline int jail_source(const struct tc_address *src, __u64 decided, __u64 until,
                                        struct tc_health *h)
{
    if (until <= bpf_ktime_get_ns()) return -1;
    /* A simultaneous collector can retire the old pointer between lookup and
     * lock acquisition. Reinsert/relookup rather than updating orphaned state. */
#pragma clang loop unroll(disable)
    for (int attempt = 0; attempt < 4; attempt++) {
        struct tc_jail_value *value = bpf_map_lookup_elem(&jail, src);
        if (!value) {
            struct tc_jail_value initial = { .until_ns = until };
            long inserted = bpf_map_update_elem(&jail, src, &initial, BPF_NOEXIST);
            if (inserted && inserted != -EEXIST) {
                reclaim_state(0, bpf_ktime_get_ns(), 0);
                bpf_map_update_elem(&jail, src, &initial, BPF_NOEXIST);
            }
            value = bpf_map_lookup_elem(&jail, src);
        }
        if (!value) continue;
        bpf_spin_lock(&value->lock);
        int retired = value->retired;
        int cancelled = value->cancelled_ns && decided <= value->cancelled_ns;
        if (!retired && !cancelled && until > value->until_ns) value->until_ns = until;
        bpf_spin_unlock(&value->lock);
        if (!retired) return cancelled ? -1 : 1;
    }
    if (h) h->jail_full++;
    return 0;
}
static __always_inline int take_token(__u32 index, const struct tc_address *src,
                                      const struct tc_rule *rule, __u64 now,
                                      struct tc_health *h)
{
    void *map = bpf_map_lookup_elem(&buckets, &index);
    if (!map) {
        if (h) h->bucket_failed++;
        return 0;
    }
    struct tc_bucket_value *value = bpf_map_lookup_elem(map, src);
    if (!value) {
        struct tc_bucket_value initial = {};
        bpf_map_update_elem(map, src, &initial, BPF_NOEXIST);
        value = bpf_map_lookup_elem(map, src);
    }
    if (!value) {
        if (h) h->bucket_failed++;
        return 0;
    }
    if (!rule->rate || !rule->burst)
        return 0;
    /* Virtual finish time is a continuously refilling token bucket: each
     * accepted frame adds one interval, up to burst intervals ahead of now.
     * Ceil(interval) errs by at most 0.1% for rates <= 1,000,000/s. */
    __u64 interval = (NS_PER_SECOND + rule->rate - 1) / rule->rate;
    __u64 deadline = now + (__u64)rule->burst * interval;
    __u64 old = __sync_val_compare_and_swap(&value->next_ns, 0, 0);
#pragma clang loop unroll(disable)
    for (int i = 0; i < 64; i++) {
        __u64 next = (old > now ? old : now) + interval;
        if (next > deadline)
            return 0;
        __u64 actual = __sync_val_compare_and_swap(&value->next_ns, old, next);
        if (actual == old)
            return 1;
        old = actual;
    }
    if (h) h->bucket_failed++;
    return 0;
}
static __always_inline int scan_source(const struct tc_packet *p, const struct tc_config *cfg,
                                       __u64 now, struct tc_health *h)
{
    struct tc_scan_value *value = bpf_map_lookup_elem(&scans, &p->src);
    if (!value) {
        __u32 zero = 0;
        struct scan_seed *seed = bpf_map_lookup_elem(&scan_seed, &zero);
        if (!seed) { if (h) h->scan_full++; return -1; }
        seed->generation = cfg->generation;
        seed->start_ns = now;
        long inserted = bpf_map_update_elem(&scans, &p->src, seed, BPF_NOEXIST);
        if (inserted && inserted != -EEXIST) {
            reclaim_state(1, now, cfg);
            bpf_map_update_elem(&scans, &p->src, seed, BPF_NOEXIST);
        }
        value = bpf_map_lookup_elem(&scans, &p->src);
    }
    if (!value) {
        if (h) h->scan_full++;
        return -1;
    }
    __u64 pending = 0;
    bpf_spin_lock(&value->lock);
    if (value->retired) {
        bpf_spin_unlock(&value->lock);
        if (h) h->scan_full++;
        return -1;
    }
    if (value->generation != cfg->generation || !value->start_ns ||
        (now > value->start_ns && now - value->start_ns >= (__u64)cfg->scan_window_seconds * NS_PER_SECOND)) {
        volatile __u64 *ports = value->ports;
#pragma clang loop unroll(disable)
        for (int i = 0; i < 1024; i++)
            ports[i] = 0;
        value->count = 0;
        value->start_ns = now;
        value->generation = cfg->generation;
    }
    __u32 word = p->dport >> 6;
    __u64 mask = 1ULL << (p->dport & 63);
    if (!(value->ports[word] & mask)) {
        value->ports[word] |= mask;
        value->count++;
        if (value->count >= cfg->scan_ports && value->pending_until_ns <= now)
            value->pending_until_ns = now + (__u64)cfg->scan_jail_seconds * NS_PER_SECOND;
    }
    pending = value->pending_until_ns;
    bpf_spin_unlock(&value->lock);
    if (pending <= now) return 0;
    int installed = jail_source(&p->src,
        pending - (__u64)cfg->scan_jail_seconds * NS_PER_SECOND, pending, h);
    if (installed) {
        bpf_spin_lock(&value->lock);
        if (value->pending_until_ns == pending) value->pending_until_ns = 0;
        bpf_spin_unlock(&value->lock);
    }
    return installed < 0 ? 0 : 1;
}
#endif
