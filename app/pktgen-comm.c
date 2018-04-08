/*******************************************************
 *
 *  Author        : Mr.Gao
 *  Email         : 729272771@qq.com
 *  Filename      : pktgen-comm.c
 *  Last modified : 2018-03-30 07:26
 *  Description   : 
 *
 * *****************************************************/

#include <pktgen-comm.h>

target_info t_info;
condition_info c_info;

/**************************************************************************//**
 *
 * get_rand_num - generate random num 
 *
 * DESCRIPTION
 * Generate random num with microsecond 
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static int 
get_rand_num(void)
{
    struct timeval tp;
    gettimeofday(&tp, NULL);
    srandom(tp.tv_usec + tp.tv_sec);

    return random();
}

/**************************************************************************//**
 *
 * show_pkt_content - display origin packet content 
 *
 * DESCRIPTION
 * Display origin packet content
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

void 
show_pkt_content(char* pkt_buff, int pkt_len)
{
    if (pkt_buff == NULL || pkt_len <= 0) {
        printf("Packet error\n");
        return;
    }

    int i = 0;
    for (; i < pkt_len; i += 2) {
        printf("%02hhx%02hhx ", pkt_buff[i], pkt_buff[i + 1]);
        if (i % 16 == 14) {
            printf("\n");
        }
    }
    printf("\n");
}

/**************************************************************************//**
 *
 * rand_ip_addr - generate random ip address 
 *
 * DESCRIPTION
 * Generate random ip address
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static uint32_t 
rand_ip_addr(uint32_t src_or_dst)
{
    if (src_or_dst == U_SRC)
        return IPv4(100, get_rand_num() % 256, get_rand_num() % 256, get_rand_num() % 255 + 1);
    else
        return IPv4(200, get_rand_num() % 256, get_rand_num() % 256, get_rand_num() % 255 + 1);
}

/**************************************************************************//**
 *
 * record_target_info - record target packet infomation 
 *
 * DESCRIPTION
 * Record target packet infomation that need to be modify
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static void 
record_target_info(uint32_t t_sip, uint32_t t_dip) 
{
    t_info.sip = t_sip;
    t_info.dip = t_dip;
}

/**************************************************************************//**
 *
 * init_condition_info - initialization of variables 
 *
 * DESCRIPTION
 * Initialization of variables that need to be modified
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static void 
init_condition_info(range_info_t *range)
{
    // src ip
    if (unlikely(range->src_ip_mode == U_INCR)) { 
        if (range->src_ip_inc == 0) 
            range->src_ip_inc ++;
        uint32_t p = htonl(c_info.sip);
        p += range->src_ip_inc;
        if (p < range->src_ip_min)
            p = range->src_ip_min;
        else if (p > range->src_ip_max)
            p = range->src_ip_max;
        c_info.sip = htonl(p);
    } else if (unlikely(range->src_ip_mode == U_RAND)) {
        c_info.sip = htonl(rand_ip_addr(U_SRC));
    } else if (unlikely(range->src_ip_mode == U_FIXD)) {
        c_info.sip = htonl(range->src_ip);
    }

    // dst ip
    if (unlikely(range->dst_ip_mode == U_INCR)) { 
        if (range->dst_ip_inc == 0)
            range->dst_ip_inc ++;
        uint32_t p = htonl(c_info.dip);
        p += range->dst_ip_inc;
        if (p < range->dst_ip_min)
            p = range->dst_ip_min;
        else if (p > range->dst_ip_max)
            p = range->dst_ip_max;
        c_info.dip = htonl(p);
    } else if (unlikely(range->dst_ip_mode == U_RAND)) {
        c_info.dip = htonl(rand_ip_addr(U_DST));
    } else if (unlikely(range->dst_ip_mode == U_FIXD)) {
        c_info.dip = htonl(range->dst_ip);
    }

    // src port
    if (unlikely(range->src_port_mode == U_INCR)) { 
        if (range->src_port_inc == 0) 
            range->src_port_inc ++;
        uint16_t sport = htons(c_info.sport);
        sport += range->src_port_inc;
        if (sport < range->src_port_min || sport > range->src_port_max)
            sport = range->src_port_min;
        c_info.sport = htons(sport);
    } else if (unlikely(range->src_port_mode == U_RAND)) {
        c_info.sport = htons(1024 + get_rand_num() % (65535 - 1024));
    } else if (unlikely(range->src_port_mode == U_FIXD)) {
        c_info.sport = htons(range->src_port);
    }

    // dst port
    if (unlikely(range->dst_port_mode == U_INCR)) { 
        if (range->dst_port_inc == 0)
            range->dst_port_inc = 1;
        uint16_t dport = htons(c_info.dport);
        dport += range->dst_port_inc;
        if (dport < range->dst_port_min || dport > range->dst_port_max)
            dport = range->dst_port_min;
        c_info.dport = htons(dport);
    } else if (unlikely(range->dst_port_mode == U_RAND)) {
        c_info.dport = htons(1024 + get_rand_num() % (65535 - 1024));
    } else if (unlikely(range->dst_port_mode == U_FIXD)) {
        c_info.dport = htons(range->dst_port);
    }

    // dst mac
    if (unlikely(range->dst_mac_mode == U_INCR)) {
        if (range->dst_mac_inc == 0)
            range->dst_mac_inc ++;
        c_info.dmac += range->dst_mac_inc;
        if (c_info.dmac < range->dst_mac_min || c_info.dmac > range->dst_mac_max)
            c_info.dmac = range->dst_mac_min;
    } else if (unlikely(range->dst_mac_mode == U_RAND)) {
        c_info.dmac = (uint64_t)get_rand_num();
    } else if (unlikely(range->dst_mac_mode) == U_FIXD) {
        c_info.dmac = range->dst_mac;
    }

    // src mac
    if (unlikely(range->src_mac_mode == U_INCR)) {
        if (range->src_mac_inc == 0)
            range->src_mac_inc ++;
        c_info.dmac += range->src_mac_inc;
        if (c_info.dmac < range->src_mac_min || c_info.dmac > range->src_mac_max)
            c_info.dmac = range->src_mac_min;
    } else if (unlikely(range->src_mac_mode == U_RAND)) {
        c_info.dmac = (uint64_t)get_rand_num();
    } else if (unlikely(range->src_mac_mode) == U_FIXD) {
        c_info.smac = range->src_mac;
    }
}

/**************************************************************************//**
 *
 * is_pkt_need_modify - choose packet needs to be modify.
 *
 * DESCRIPTION
 * Determine whether a packet needs to be modified
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static uint8_t 
is_pkt_need_modify(uint32_t sip, uint32_t dip)
{
    uint8_t ret = 0;
    if (sip == t_info.sip && dip == t_info.dip)
        ret = U_FORWARD;
    else if (sip == t_info.dip && dip == t_info.sip)
        ret = U_REVERSE;

    return ret;
}

/**************************************************************************//**
 *
 * modify_pkt_mac - modify packet mac address.
 *
 * DESCRIPTION
 * Analyse and modify packet mac address 
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static void 
modify_pkt_mac(pkt_hdr_t *hdr, uint8_t direction)
{
    if (direction == U_FORWARD) {
        if (c_info.smac)
            inet_h64tom(c_info.smac, &hdr->eth.s_addr);
        if (c_info.dmac)
            inet_h64tom(c_info.dmac, &hdr->eth.d_addr);
    } else if (direction == U_REVERSE) {
        if (c_info.dmac)
            inet_h64tom(c_info.dmac, &hdr->eth.s_addr);
        if (c_info.smac)
            inet_h64tom(c_info.smac, &hdr->eth.d_addr);
    }
}

/**************************************************************************//**
 *
 * modify_pkt_ip - modify packet ip address.
 *
 * DESCRIPTION
 * Analyse and modify packet ip address 
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static void 
modify_pkt_ip(pkt_hdr_t *hdr, uint8_t direction)
{
    if (direction == U_FORWARD) {
        if (c_info.sip)
            hdr->u.ipv4.src = c_info.sip;
        if (c_info.dip)
            hdr->u.ipv4.dst = c_info.dip;
    } else if (direction == U_REVERSE) {
        if (c_info.dip)
            hdr->u.ipv4.src = c_info.dip;
        if (c_info.sip)
            hdr->u.ipv4.dst = c_info.sip;
    }
}

/**************************************************************************//**
 *
 * modify_pkt_port - modify packet TCP of UDP port.
 *
 * DESCRIPTION
 * Analyse and modify packet TCP of UDP port 
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static void 
modify_pkt_port(pkt_hdr_t *hdr, uint8_t direction, uint8_t proto)
{
    if (direction == U_FORWARD) { 
        switch(proto) {
        case PG_IPPROTO_TCP:
            if (c_info.sport)
                hdr->u.tip.tcp.sport = c_info.sport;
            if (c_info.dport)
                hdr->u.tip.tcp.dport = c_info.dport;
            break;
        case PG_IPPROTO_UDP:
            if (c_info.sport)
                hdr->u.uip.udp.sport = c_info.sport;
            if (c_info.dport)
                hdr->u.uip.udp.dport = c_info.dport;
            break;
        }
    } else if (direction == U_REVERSE) {
        switch(proto) {
        case PG_IPPROTO_TCP:
            if (c_info.dport)
                hdr->u.tip.tcp.sport = c_info.dport;
            if (c_info.sport)
                hdr->u.tip.tcp.dport = c_info.sport;
            break;
        case PG_IPPROTO_UDP:
            if (c_info.dport)
                hdr->u.uip.udp.sport = c_info.dport;
            if (c_info.sport)
                hdr->u.uip.udp.dport = c_info.sport;
            break;
        }
    }
}

/**************************************************************************//**
 *
 * modify_pcap_data - analyse and modify pcap five tuples.
 *
 * DESCRIPTION
 * Analyse and modify pcap info
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

void 
modify_pcap_data(char* pkt_buff, uint16_t pid)
{
    pkt_hdr_t   *hdr;
    hdr = (pkt_hdr_t *)&pkt_buff[pid];

    port_info_t *info;
    info = &pktgen.info[pid];

    pcap_info_t *pcap;
    pcap = info->pcap;

    range_info_t *range;
    range = &info->range;

    static uint32_t pkt_idx = 0;
    static uint8_t record_flag = 1;

    if (hdr->eth.ether_type == ntohs(ETHER_TYPE_IPv4)) {
        uint8_t l4_proto = hdr->u.ipv4.proto;
        if (l4_proto == range->ip_proto) {
            if (pkt_idx % pcap->pkt_count == 0) {
                if (record_flag) {
                    record_target_info(hdr->u.ipv4.src, hdr->u.ipv4.dst); 
                    record_flag --;
                }
                init_condition_info(range);
            }

            uint8_t ret = is_pkt_need_modify(hdr->u.ipv4.src, hdr->u.ipv4.dst);
            if (ret > 0) {
                modify_pkt_mac(hdr, ret);
                modify_pkt_ip(hdr, ret);
                modify_pkt_port(hdr, ret, l4_proto);
            }
        }
    } else {
        printf("EXIT:NON-IPv4, Maybe IPv6\n");
    }
    pkt_idx ++ ;
}

