/* Only attached to dedicated bench peers to receive XDP_TX/REDIRECT frames. */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
SEC("xdp") int bench_pass(struct xdp_md *ctx) { return XDP_PASS; }
char LICENSE[] SEC("license") = "GPL";
