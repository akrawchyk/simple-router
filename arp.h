/*******************************************************************************
 * file: arp.h
 * date: 10/13/10
 * Andrew Krawchyk
 *
 * Description:
 * contains headers for arp manipulation functions
 ******************************************************************************/

#ifndef ARP_H
#define ARP_H

#include <time.h>

#include "sr_protocol.h"

#define ARP_CACHE_SIZE 100
#define ARP_STALE_TIME 15   // in seconds

struct arp_cache_entry {
    uint32_t            ar_sip;                     // sender ip addr
    uint8_t             ar_sha[ETHER_ADDR_LEN];     // sender hardware addr
    time_t              timeCached;                 // timestamp
    int                 valid;                      // timeout
};


void handleArp(struct sr_instance*, uint8_t*, unsigned int, char* );
void arpSendReply(struct sr_instance*, uint8_t*, unsigned int, char*, struct sr_if* );
void arpSendRequest(struct sr_instance*, struct sr_if*, uint32_t );
void makearp(
        struct sr_arphdr* arpHdr,
        uint16_t    arp_hrd,
        uint16_t    arp_pro,
        uint8_t     arp_hln,
        uint8_t     arp_pln,
        uint16_t    arp_op,
        uint8_t*    arp_sha,
        uint32_t    arp_sip,
        uint8_t*    arp_tha,
        uint32_t    arp_tip );

void arpInitCache();
int arpSearchCache(uint32_t );
void arpCacheEntry(struct sr_arphdr* );
void arpUpdateCache();
uint8_t* arpReturnEntryMac(int );
void arpDumpCache();
void arpDumpHeader(struct sr_arphdr* );

#endif
