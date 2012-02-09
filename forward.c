/******************************************************************************
 * file: forward.c
 * date: 10/13/10
 * Andrew Krawchyk
 *
 * contains implementation for packet forwarding functions
 *****************************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"
#include "ip.h"
#include "forward.h"

/* length of zero signifies empty spot in cache */
struct packet_cache_entry packetCache[PACKET_CACHE_SIZE];

/*-----------------------------------------------------------------------------
 * Method: void handleForward
 *
 * determines what interface to send a packet out of
 *---------------------------------------------------------------------------*/
void handleForward(
        struct sr_instance* sr,
        uint8_t* packet,
        unsigned int len,
        char* interface )
{
    struct ip* ipHdr = (struct ip*)(packet+14);
    struct sr_rt* rtptr = sr->routing_table;
    int cachedEntry;

    /* loop through rtable for the next hop with the packet's destination ip */
    while (rtptr) {
        if (rtptr->dest.s_addr == ipHdr->ip_dst.s_addr)
            break;
        else
            rtptr = rtptr->next;
    }

    /* if not in our rtable, send it out eth0 to the intarwebz */
    if (!rtptr) {
        rtptr = sr->routing_table;          // eth0
        if ((cachedEntry = arpSearchCache(rtptr->gw.s_addr)) > -1) {
            forwardPacket(sr, packet, len, rtptr->interface, arpReturnEntryMac(cachedEntry));
        } else {
            cachePacket(sr, packet, len, rtptr);
        }
    }
    
    /* look through arp cache for mac matching the ip destination. if we have it,
     * forward our packet. otherwise, cache the packet and wait for an arp reply
     * to tell us the correct mac address */
    if ((cachedEntry = arpSearchCache(rtptr->gw.s_addr)) > -1) {
        forwardPacket(sr, packet, len, rtptr->interface, arpReturnEntryMac(cachedEntry));       
    } else {
        cachePacket(sr, packet, len, rtptr);
    }
}

/*-----------------------------------------------------------------------------
 * Method: void forwardPacket
 *
 * builds the headers to forward the tcp/udp data
 *---------------------------------------------------------------------------*/
void forwardPacket(
        struct sr_instance* sr,
        uint8_t* packet,
        unsigned int len,
        char* interface,
        uint8_t* desthwaddr )
{
    struct sr_ethernet_hdr* ethernetHdr = (struct sr_ethernet_hdr*)packet;
    struct ip* ipHdr = (struct ip*)(packet+14);
    struct in_addr forwarded;
    int i;
    
    makeethernet(ethernetHdr, ntohs(ethernetHdr->ether_type),
            sr_get_interface(sr, interface)->addr, desthwaddr);

    sr_send_packet(sr, packet, len, interface);

    // log on send
    forwarded.s_addr = ipHdr->ip_dst.s_addr;
    printf("<- Forwarded packet with ip_dst %s to ", inet_ntoa(forwarded));
    for (i = 0; i < ETHER_ADDR_LEN; i++)
        printf("%2.2x", ethernetHdr->ether_dhost[i]);
    printf("\n");
}

/*-----------------------------------------------------------------------------
 * Method: void cachePacket(struct sr_instance* sr, uint8_t* packet,
 *                              unsigned int len, struct sr_rt* rtptr)
 *
 * sends a request for the hwaddr of the ipaddr we have, stores our packet
 * until we have an arp entry that matches the ip, then sends the packet
 *---------------------------------------------------------------------------*/
void cachePacket(
        struct sr_instance* sr,
        uint8_t* packet,
        unsigned int len,
        struct sr_rt* rtptr)
{
    struct ip* ipHdr = (struct ip*)(packet+14);
    int i;

    /* request arp for the unidentified packet */
    arpSendRequest(sr, sr_get_interface(sr, rtptr->interface), rtptr->gw.s_addr);

    /* look through packet cache for the first empty entry */
    for (i = 0; i < PACKET_CACHE_SIZE; i++) {
        if (packetCache[i].len == 0) 
            break;
    }

    /* copy packet data to cache */
    memcpy(&packetCache[i].packet, packet, len);
    packetCache[i].nexthop = rtptr;
    packetCache[i].tip = ipHdr->ip_dst.s_addr;
    packetCache[i].len = len;
    packetCache[i].arps = 1;
    packetCache[i].timeCached = time(NULL);

    /* dump cache
    uint8_t* ptr = packetCache[i].packet;
    printf("\nnexthop: %s\n", inet_ntoa(packetCache[i].nexthop->gw));
    printf("tip: %8.8x\n", packetCache[i].tip);
    printf("len: %d\n", packetCache[i].len);
    printf("arps: %d\n", packetCache[i].arps);
    for (i = 0; i < len; i++)
        printf("%2.2x", *ptr++);
    printf("\n");
    */
}

/*-----------------------------------------------------------------------------
 * Method: void checkCachedPackets(struct sr_instance* sr, int cachedArp)
 *
 * searches our packet cache for a matching ip in arpCache[cachedArp]. if we 
 * find a match, we forward the packet. if we do not find a match we need an
 * arp cache entry for it. make sure we have been waiting at least 3 seconds
 * before we send the src icmp unreachable packets. this does not drop the 
 * packet, it just looks every 3rd second to see if we have a response. every
 * time we look, we try to increment the arp counter
 *---------------------------------------------------------------------------*/
void checkCachedPackets(struct sr_instance* sr, int cachedArp)
{
    int i, arpMatch;
    for (i = 0; i < PACKET_CACHE_SIZE; i++) {
        if (packetCache[i].len > 0) {
            // if we have a packet waiting
            if (packetCache[i].arps <= 5) {
                // and we have not sent 5 arps for this packet yet
                if ((arpMatch = arpSearchCache(packetCache[i].tip)) > -1) {
                    // and we have an arp match for our packet's next hop
                    forwardPacket(sr, (uint8_t*)&packetCache[i].packet, packetCache[i].len,
                            // send it along
                            packetCache[i].nexthop->interface, arpReturnEntryMac(arpMatch));
                    packetCache[i].len = 0;
                } else {
                    /* wait three seconds between each arp request */
                    if ((int)(difftime(time(NULL), packetCache[i].timeCached))%3 < 1) {
                        arpSendRequest(sr, sr_get_interface(sr, packetCache[i].nexthop->interface),
                                packetCache[i].nexthop->gw.s_addr);
                        packetCache[i].arps++;
                    }
                }
            } else {
                /* then */
                icmpSendUnreachable(sr, (uint8_t*)&packetCache[i].packet, packetCache[i].len,
                        packetCache[i].nexthop->interface, ICMP_HOST_UNREACHABLE);
                packetCache[i].len = 0;
            }
        }
    }
}

/*-----------------------------------------------------------------------------
 * Method void initPacketCache()
 *
 * zero's the len field for all entries of our packet cache. if len is ever 
 * greater than zero that means there is a packet waiting to be forwarded
 *---------------------------------------------------------------------------*/
void initPacketCache()
{
    int i;
    for (i = 0; i < PACKET_CACHE_SIZE; i++)
        packetCache[i].len = 0;
}
