/******************************************************************************
 * file: forward.h
 * date: 10/13/10
 * Andrew Krawchyk
 *
 * contains headers for packet forwarding functions
 *****************************************************************************/

#ifndef FORWARD_H
#define FORWARD_H

#include <stdint.h>
#include <time.h>

#include "sr_if.h"
#include "sr_router.h"

#define PACKET_CACHE_SIZE 256

struct packet_cache_entry {
    uint8_t         packet[1514];                   // max expected size of packet
    struct sr_rt*   nexthop;                        // pointer to next hop entry
    uint32_t        tip;                            // target ip of packet
    unsigned int    len;                            // actual length of packet
    int             arps;                           // number of times requested info for mac
    time_t          timeCached;
};

void handleForward(struct sr_instance*, uint8_t*, unsigned int, char* );
void forwardPacket(struct sr_instance*, uint8_t*, unsigned int, char*, uint8_t* );
void cachePacket(struct sr_instance*, uint8_t*, unsigned int, struct sr_rt* );
void checkCachedPackets(struct sr_instance*, int );
void initPacketCache();

#endif
