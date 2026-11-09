#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "contract.h"
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tc_counters);
} counters SEC(".maps");
/* Bootstrap only: no filtering until the rule-engine implementation lands. */
SEC("xdp") int trafficcop(struct xdp_md *ctx)
{
    __u32 key = 0;
    struct tc_counters *c = bpf_map_lookup_elem(&counters, &key);
    unsigned char *data = (void *)(long)ctx->data;
    unsigned char *end = (void *)(long)ctx->data_end;
    if (c) {
        c->passed++;
        /* Short/unknown Ethernet frames are explicitly counted as other. */
        if (data + 14 > end ||
            !((data[12] == 0x08 && data[13] == 0x00) ||
              (data[12] == 0x86 && data[13] == 0xdd)))
            c->other++;
        else
            c->default_hits++;
    }
    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
