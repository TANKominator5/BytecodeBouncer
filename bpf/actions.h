#ifndef TRAFFICCOP_ACTIONS_H
#define TRAFFICCOP_ACTIONS_H
static __always_inline int finish(struct tc_counters *c, int verdict)
{
    if (c) {
        if (verdict == TC_PASS) c->passed++;
        else if (verdict == TC_BOUNCE) c->bounced++;
        else if (verdict == TC_HONEYPOT) c->honeypotted++;
        else c->dropped++;
    }
    return verdict;
}
static __always_inline void count_rule(__u32 index, int verdict)
{
    struct tc_rule_counters *c = bpf_map_lookup_elem(&rule_counters, &index);
    if (!c)
        return;
    c->hits++;
    if (verdict == TC_PASS) c->passed++;
    else if (verdict == TC_BOUNCE) c->bounced++;
    else if (verdict == TC_HONEYPOT) c->honeypotted++;
    else c->dropped++;
}
static __always_inline void log_decision(const struct tc_packet *p, __u64 generation,
                                        __u32 line, int verdict, __u64 now,
                                        struct tc_health *h)
{
    struct tc_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        if (h) h->event_lost++;
        return;
    }
    *event = (struct tc_event) {
        .time_ns = now, .generation = generation, .line = line, .verdict = verdict,
        .src = p->src, .dst = p->dst, .sport = p->sport, .dport = p->dport,
        .proto = p->proto, .has_ports = p->has_ports,
    };
    bpf_ringbuf_submit(event, 0);
}
#endif
