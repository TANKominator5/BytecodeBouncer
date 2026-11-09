#ifndef TRAFFICCOP_STATE_H
#define TRAFFICCOP_STATE_H
#define NS_PER_SECOND 1000000000ULL

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
static __always_inline void jail_source(const struct tc_address *src, __u64 until,
                                        struct tc_health *h)
{
    struct tc_jail_value *value = bpf_map_lookup_elem(&jail, src);
    if (!value) {
        struct tc_jail_value initial = {};
        bpf_map_update_elem(&jail, src, &initial, BPF_NOEXIST);
        value = bpf_map_lookup_elem(&jail, src);
    }
    if (!value) {
        if (h) h->jail_full++;
        return;
    }
    bpf_spin_lock(&value->lock);
    if (until > value->until_ns)
        value->until_ns = until;
    bpf_spin_unlock(&value->lock);
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
        bpf_map_update_elem(&scans, &p->src, &empty_scan, BPF_NOEXIST);
        value = bpf_map_lookup_elem(&scans, &p->src);
    }
    if (!value) {
        if (h) h->scan_full++;
        return 0;
    }
    int trigger = 0;
    bpf_spin_lock(&value->lock);
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
        trigger = value->count >= cfg->scan_ports;
    }
    bpf_spin_unlock(&value->lock);
    if (trigger)
        jail_source(&p->src, now + (__u64)cfg->scan_jail_seconds * NS_PER_SECOND, h);
    return trigger;
}
#endif
