#ifndef TRAFFICCOP_MATCH_H
#define TRAFFICCOP_MATCH_H
static __always_inline int prefix_matches(const struct tc_address *address,
                                          const struct tc_prefix *prefix)
{
    if (address->family != prefix->family || prefix->bits > 128 ||
        (prefix->family == 4 && prefix->bits > 32))
        return 0;
#pragma unroll
    for (int i = 0; i < 16; i++) {
        int remaining = (int)prefix->bits - i * 8;
        if (remaining <= 0)
            break;
        __u8 mask = remaining >= 8 ? 255 : (__u8)(255 << (8 - remaining));
        if ((address->bytes[i] & mask) != (prefix->bytes[i] & mask))
            return 0;
    }
    return 1;
}
static __always_inline int set_matches(const struct tc_address *address, __u8 set)
{
    struct tc_set_key key = { .prefixlen = address->family == 4 ? 64 : 160,
                             .set = set, .family = address->family };
    __builtin_memcpy(key.bytes, address->bytes, 16);
    return bpf_map_lookup_elem(&sets, &key) != 0;
}
struct match_context {
    struct tc_packet *packet;
    struct tc_config *cfg;
    int index;
};
/* bpf_loop prevents 64 copies of the rule's verifier paths from exploding. */
static long match_rule(__u32 index, void *context)
{
    struct match_context *m = context;
    if (index >= TC_MAX_RULES || index >= m->cfg->rule_count)
        return 1;
    /* Keep the bound on the actual 64-bit register used for pointer arithmetic;
     * clang can otherwise check one zero-extended copy and index with another. */
    __u64 slot = index;
    asm volatile("%0 &= 63" : "+r"(slot));
    const struct tc_rule *r = &m->cfg->rules[slot];
    const struct tc_packet *p = m->packet;
    __u32 matches = r->matches & enabled_matches;
    if ((r->family && r->family != p->src.family) || (r->proto && r->proto != p->proto))
        return 0;
    if ((matches & TC_SRC_PREFIX) && !prefix_matches(&p->src, &r->src))
        return 0;
    if ((matches & TC_DST_PREFIX) && !prefix_matches(&p->dst, &r->dst))
        return 0;
    if ((matches & TC_SRC_SET) && !set_matches(&p->src, r->src_set))
        return 0;
    if ((matches & TC_DST_SET) && !set_matches(&p->dst, r->dst_set))
        return 0;
    if ((matches & TC_SPORT) && (!p->has_ports || p->sport < r->sport_min || p->sport > r->sport_max))
        return 0;
    if ((matches & TC_DPORT) && (!p->has_ports || p->dport < r->dport_min || p->dport > r->dport_max))
        return 0;
    if ((matches & TC_ICMP_TYPE) && (!p->has_type || p->icmp_type != r->icmp_type))
        return 0;
    if ((matches & TC_VLAN) && p->vlan != r->vlan)
        return 0;
    m->index = slot;
    return 1;
}
#endif
