#ifndef __PKTGEN_COMM__
#define __PKTGEN_COMM__


#include <_pcap.h>
#include <pktgen.h>

#ifdef __cplusplus
extern "C" {
#endif

void show_pkt_content(char* pkt, int pkt_len);
void modify_pcap_data(char* pkt_buff, uint16_t pid);

typedef struct target_pkt_info{
    uint32_t sip;
    uint32_t dip;
}target_info;

typedef struct condition_pkt_info{
    /*
    struct ether_addr smac; 
    struct ether_addr dmac; 
    */
    uint64_t smac;
    uint64_t dmac;
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;
}condition_info;

enum {
    U_FIXD = 1,
    U_INCR,
    U_RAND
};

enum {
    U_SRC,
    U_DST
};

enum {
    U_FORWARD = 1,
    U_REVERSE
};

#ifdef __cplusplus
}
#endif

#endif
