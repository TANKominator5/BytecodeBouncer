/* Native tests for exact short lengths that BPF_PROG_TEST_RUN cannot submit. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "contract.h"
#include "parse.h"

int main(void)
{
    unsigned char data[256] = {};
    struct tc_packet p;
    for (int n = 0; n < 14; n++) {
        memset(&p, 0, sizeof(p));
        assert(parse_packet(data, data + n, &p) == TC_OTHER);
    }
    data[12] = 0x81;
    for (int n = 14; n < 18; n++) {
        memset(&p, 0, sizeof(p));
        assert(parse_packet(data, data + n, &p) == TC_OTHER);
    }
    data[12] = 8;
    data[14] = 0x45;
    data[23] = 17;
    for (int n = 14; n < 42; n++) {
        memset(&p, 0, sizeof(p));
        assert(parse_packet(data, data + n, &p) == TC_MALFORMED);
    }
    memset(&p, 0, sizeof(p));
    assert(parse_packet(data, data + 42, &p) == TC_IP);
    assert(p.has_ports && p.src.family == 4 && p.vlan == TC_VLAN_NONE);
    data[20] = 0;
    data[21] = 1;
    memset(&p, 0, sizeof(p));
    assert(parse_packet(data, data + 34, &p) == TC_IP);
    assert(p.nonfirst && !p.has_ports);
    puts("PASS: exact short Ethernet/VLAN/IP/UDP lengths and non-first fragments");
    return 0;
}
