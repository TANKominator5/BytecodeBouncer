#ifndef TRAFFICCOP_PARSE_H
#define TRAFFICCOP_PARSE_H

struct tc_packet {
    struct tc_address src, dst;
    __u16 sport, dport, vlan;
    __u8 proto, nonfirst, has_ports, has_type, icmp_type;
};
enum tc_parse_result { TC_IP, TC_OTHER, TC_MALFORMED };

static __always_inline __u16 read_be16(const __u8 *p)
{
    return ((__u16)p[0] << 8) | p[1];
}
static __always_inline int is_extension(__u8 proto)
{
    return proto == 0 || proto == 43 || proto == 44 || proto == 60;
}
/* All lengths/checksums supplied by the sender are deliberately ignored. */
static __always_inline int parse_packet(__u8 *data, __u8 *end, struct tc_packet *p)
{
    if (data + 14 > end)
        return TC_OTHER;
    __u16 ether = read_be16(data + 12);
    __u8 *ip = data + 14;
    p->vlan = TC_VLAN_NONE;
    if (ether == 0x8100) {
        if (data + 18 > end)
            return TC_OTHER;
        p->vlan = read_be16(data + 14) & 4095;
        ether = read_be16(data + 16);
        if (ether == 0x8100 || ether == 0x88a8)
            return TC_OTHER;
        ip = data + 18;
    }
    __u8 *transport;
    if (ether == 0x0800) {
        if (ip + 20 > end || ip[0] >> 4 != 4 || (ip[0] & 15) < 5)
            return TC_MALFORMED;
        __u32 ihl = (ip[0] & 15) * 4;
        if (ip + ihl > end)
            return TC_MALFORMED;
        p->src.family = p->dst.family = 4;
        __builtin_memcpy(p->src.bytes, ip + 12, 4);
        __builtin_memcpy(p->dst.bytes, ip + 16, 4);
        p->proto = ip[9];
        p->nonfirst = (read_be16(ip + 6) & 0x1fff) != 0;
        transport = ip + ihl;
    } else if (ether == 0x86dd) {
        if (ip + 40 > end || ip[0] >> 4 != 6)
            return TC_MALFORMED;
        p->src.family = p->dst.family = 6;
        __builtin_memcpy(p->src.bytes, ip + 8, 16);
        __builtin_memcpy(p->dst.bytes, ip + 24, 16);
        p->proto = ip[6];
        transport = ip + 40;
#pragma clang loop unroll(disable)
        for (int i = 0; i < 8; i++) {
            if (!is_extension(p->proto))
                break;
            if (transport + 8 > end)
                return TC_MALFORMED;
            __u32 length = 8;
            if (p->proto == 44) {
                p->nonfirst |= (read_be16(transport + 2) & 0xfff8) != 0;
            } else {
                length = ((__u32)transport[1] + 1) * 8;
            }
            if (transport + length > end)
                return TC_MALFORMED;
            p->proto = transport[0];
            transport += length;
        }
        if (is_extension(p->proto))
            return TC_MALFORMED;
    } else {
        return TC_OTHER;
    }
    if (p->nonfirst)
        return TC_IP;
    if (p->proto == 6 || p->proto == 17) {
        if (p->proto == 6) {
            if (transport + 20 > end)
                return TC_MALFORMED;
        } else if (transport + 8 > end) {
            return TC_MALFORMED;
        }
        /* Explicit bound for both port loads, independent of the branch above. */
        if (transport + 4 > end)
            return TC_MALFORMED;
        p->sport = read_be16(transport);
        p->dport = read_be16(transport + 2);
        p->has_ports = 1;
    } else if (p->proto == 1 || p->proto == 58) {
        if (transport + 8 > end)
            return TC_MALFORMED;
        p->icmp_type = transport[0];
        p->has_type = 1;
    }
    return TC_IP;
}
#endif
