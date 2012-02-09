/*******************************************************************************
 * file: arp.c
 * date: 10/13/10
 * Andrew Krawchyk
 *
 * Description:
 * implements arp manipulation functions and data structures
 ******************************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sr_if.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "arp.h"
#include "ethernet.h"
#include "forward.h"

/*----------------------------------------------------------------------
 * ARP Cache data structure
 *
 * stores <protocol type, sender protocol address, sender hardware address>
 * triplet's along with valid/invalid flag based on timeout
 *---------------------------------------------------------------------*/
 struct arp_cache_entry arpCache[ARP_CACHE_SIZE];
 
/*--------------------------------------------------------------------- 
 * Method: void handleArp(struct sr_instance*, uint8_t*,
 *                          unsigned int, char* )
 *
 * decides what to do with an incoming ARP packet
 *---------------------------------------------------------------------*/
void handleArp(
        struct sr_instance* sr,
        uint8_t* packet,
        unsigned int len,
        char* interface)
{
    struct sr_arphdr * arpHdr = (struct sr_arphdr*)(packet+14);
    struct sr_if * ifptr = sr->if_list;
    struct in_addr requested, replied;
    int i;

    /* if we have an ARP request, loop over our list of interfaces to see if we
     have the hwaddr of the request ipaddr and send a reply if we do */
    if (ntohs(arpHdr->ar_op) == ARP_REQUEST) {
        requested.s_addr = arpHdr->ar_tip;
        fprintf(stdout, "-> ARP Request: who has %s?\n", inet_ntoa(requested));
        while (ifptr) {
            if (ifptr->ip == arpHdr->ar_tip) {
                arpSendReply(sr, packet, len, interface, ifptr);
                return;
            } else {
                ifptr = ifptr->next;
            }
        }

        if (!ifptr) {
            printf("-- ARP Request: we do not have %s\n", inet_ntoa(requested));
        }
    }
    /* if packet is an arp reply, cache it */
    if (ntohs(arpHdr->ar_op) == ARP_REPLY) {
        replied.s_addr = arpHdr->ar_sip;

        // log on receipt
        printf("-> ARP Reply: %s is at ", inet_ntoa(replied));
        for (i = 0; i < ETHER_ADDR_LEN; i++)
            printf("%2.2x", arpHdr->ar_sha[i]);
        printf("\n");

        /* cache the new arp entry */
        arpCacheEntry(arpHdr);

        /* loop through arp cache to find matching arps for cached packets */
        for (i = 0; i < ARP_CACHE_SIZE; i++) {
            if (arpCache[i].valid == 1)
                checkCachedPackets(sr, i);
        }
    }
}

/*---------------------------------------------------------------------
 * Method: void arpSendReply(struct sr_if*, struct sr_arphdr*,
 *                              struct sr_ethernet_hdr* ethernetHdr)
 *
 * Replies to incoming ARP request
 * -------------------------------------------------------------------*/
void arpSendReply(
        struct sr_instance* sr,
        uint8_t* packet,
        unsigned int len,
        char* interface,
        struct sr_if * ifptr)
{
    struct sr_ethernet_hdr * ethernetHdr = (struct sr_ethernet_hdr*)packet;
    struct sr_arphdr * arpHdr = (struct sr_arphdr*)(packet+14);
    struct in_addr replied;
    int i;

    makearp(arpHdr, arpHdr->ar_hrd, arpHdr->ar_pro, arpHdr->ar_hln, arpHdr->ar_pln, htons(ARP_REPLY),
            sr_get_interface(sr, interface)->addr, sr_get_interface(sr, interface)->ip,
            arpHdr->ar_sha, arpHdr->ar_sip);
    makeethernet(ethernetHdr, ETHERTYPE_ARP, ifptr->addr, ethernetHdr->ether_shost);

    // send our newly generated arp reply away!
    sr_send_packet(sr, packet, len, interface);

    // log on send
    replied.s_addr = arpHdr->ar_sip;
    fprintf(stdout, "<- ARP Reply: %s is at ", inet_ntoa(replied));
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%2.2x", arpHdr->ar_sha[i]);
    } printf ("\n");
}

/*-----------------------------------------------------------------------------
 * Method: void arpSendRequest(struct sr_instance* sr, struct sr_if* iface, uint32_t tip)
 *
 * broadcasts and arp request looking for the hwaddr matching tip on iface
 *---------------------------------------------------------------------------*/
void arpSendRequest(struct sr_instance* sr, struct sr_if* iface, uint32_t tip)
{
    /*make a packet that:
     * sha = eth0
     * sip = eth0
     * tha = ffffffffffff
     * tip = mac we want
     */

    struct in_addr requested;               // for logging
    uint8_t broadcast[ETHER_ADDR_LEN];      // 0xffffffffffff
    int i;

    /* allocate memory for new packet */
    uint8_t* requestPacket = malloc(42 * sizeof(uint8_t));
    if (requestPacket == NULL) {
        fprintf(stderr, "Error: malloc could not find memory for packet storage\n");
        return;
    }
    memset(requestPacket, 0, 42 * sizeof(uint8_t));

    /* organize our new packet */
    struct sr_ethernet_hdr* ethernetHdr = (struct sr_ethernet_hdr*)requestPacket;
    struct sr_arphdr* arpHdr = (struct sr_arphdr*)(requestPacket+14);

    /* fill in our broadcast array */
    for (i = 0; i < ETHER_ADDR_LEN; i++)
        broadcast[i] = 0xff;

    /* make the new arp request with our alloc'd packet */
    makearp(arpHdr, htons(ARPHDR_ETHER), htons(ETHERTYPE_IP), 6, 4, htons(ARP_REQUEST),
            iface->addr, iface->ip,
            broadcast, tip);
    makeethernet(ethernetHdr, ETHERTYPE_ARP, iface->addr, broadcast);

    /* send away */
    sr_send_packet(sr, requestPacket, 42, iface->name);

    // log on send
    requested.s_addr = tip;
    printf("<- ARP Request: who has %s?\n", inet_ntoa(requested));

    free(requestPacket);
}

/*-----------------------------------------------------------------------------
 * Method: void makearp(
 *      struct sr_arphdr* arpHdr,
 *      uint16_t    arp_hrd,
 *      uint16_t    arp_pro,
 *      uint8_t     arp_hln,
 *      uint8_t     arp_pln,
 *      uint16_t    arp_op,
 *      uint8_t*    arp_sha,
 *      uint32_t    arp_sip,
 *      uint8_t*    arp_tha,
 *      uint32_t    arp_tip )
 *
 * modifies an arp packet with the parameters passed
 * assuming everything is in network byte order
 *---------------------------------------------------------------------------*/
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
        uint32_t    arp_tip )
{
    uint32_t sbuf, tbuf;
    uint8_t shabuf[ETHER_ADDR_LEN], thabuf[ETHER_ADDR_LEN];
    int i;

    arpHdr->ar_hrd = arp_hrd;
    arpHdr->ar_pro = arp_pro;
    arpHdr->ar_hln = arp_hln;
    arpHdr->ar_pln = arp_pln;
    arpHdr->ar_op = arp_op;
    
    // read into buffer in case we are overwriting in place
    sbuf = arp_sip;
    tbuf = arp_tip;
    arpHdr->ar_sip = sbuf; 
    arpHdr->ar_tip = tbuf;

    // read into buffers in case we are overwriting in place
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        shabuf[i] = arp_sha[i];
        thabuf[i] = arp_tha[i];
    }

    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        arpHdr->ar_sha[i] = shabuf[i];
        arpHdr->ar_tha[i] = thabuf[i];
    }
}

/*---------------------------------------------------------------------
 * Method: void arpInitCache(struct arp_translation_table arpCache)
 *
 * zero's all valid fields in our ARP cache
 *--------------------------------------------------------------------*/
void arpInitCache()
{
    int i;
    for (i = 0; i < ARP_CACHE_SIZE; i++) {
        arpCache[i].valid = 0;
    }
}

/*-----------------------------------------------------------------------------
 * Method: void arpCacheEntry(struct sr_arphdr* arpHdr)
 *
 * stores new ARP info in network byte order in our cache
 *---------------------------------------------------------------------------*/
void arpCacheEntry(struct sr_arphdr* arpHdr)
{
    int i,j;

    /* find first empty slot in our cache */
    for (i = 0; i < ARP_CACHE_SIZE; i++) {
        if (arpCache[i].valid == 0) 
            break;
    }

    /* extract ARP info from arpHdr and cache it */
    arpCache[i].ar_sip = arpHdr->ar_sip;
    for (j = 0; j < ETHER_ADDR_LEN; j++)
        arpCache[i].ar_sha[j] = arpHdr->ar_sha[j];

    // timestamp and make valid
    arpCache[i].timeCached = time(NULL);
    arpCache[i].valid = 1;

    /* TODO
     *
     * LOOK THROUGH PACKET CACHE TO SEE IF WE CAN SEND SOMETHING WITH THE NEWLY
     * ADDED ARP ENTRY
     */
}

/*-----------------------------------------------------------------------------
 * Method: int arpSearchCache(struct ip* ipHdr)
 *
 * searches our arp cache to see if we have a valid hwaddr
 * that matches the target ipaddr we need to send to
 *---------------------------------------------------------------------------*/
int arpSearchCache(uint32_t ipaddr)
{
    /* look through cache for matching proto and sip with valid flag = 0 */
    /* returns index of that entry if found, otherwise returns -1 */
    int i;

    for (i = 0; i < ARP_CACHE_SIZE; i++) {
        if (arpCache[i].valid == 1) {
            if (arpCache[i].ar_sip == ipaddr) {
                return i;
            }
        }
    }
    
    return -1;
}

/*-----------------------------------------------------------------------------
 * Method: void arpUpdateCache()
 *
 * finds stale arp entries in our cache and invalidates them
 *---------------------------------------------------------------------------*/
void arpUpdateCache()
{
    /* find entries older than STALE_TIME seconds and set valid bit to 0 */
    int i;

    for (i = 0; i < ARP_CACHE_SIZE; i++) {
        /* if valid and timestamp is older than 15 seconds, mark invalid */
        if (arpCache[i].valid == 1) {
            if (difftime(time(NULL), arpCache[i].timeCached) > ARP_STALE_TIME) {
                printf("-- ARP: Marking ARP cache entry %d invalid\n", i);
                arpCache[i].valid = 0;
            }
        }
    }
}

/*-----------------------------------------------------------------------------
 * Method: uint8_t* arpReturnEntryMac(int entry)
 *
 * returns a pointer to the arpCache[entry] source hardware address
 *---------------------------------------------------------------------------*/
uint8_t* arpReturnEntryMac(int entry)
{
     return (uint8_t*)&arpCache[entry].ar_sha;
}

/*-----------------------------------------------------------------------------
 * Method: void armDumpCache()
 *
 * prints all of the cache entries to stdout
 *---------------------------------------------------------------------------*/
void arpDumpCache()
{
    int i,j;

    for (i = 0; i < ARP_CACHE_SIZE; i++) {
        if (arpCache[i].valid == 1) {
            printf("CACHE ENTRY: %d\n", i);
            printf("ar_sip: %8.8x\n", arpCache[i].ar_sip);
            printf("ar_sha: ");
            for (j = 0; j < ETHER_ADDR_LEN; j++)
                printf("%2.2x", arpCache[i].ar_sha[j]);
            printf("\n");
            printf("valid: %d\n", arpCache[i].valid);
            //printf("seconds: %S\n", arpCache[i].timeCached);
        }
    }
}

/*-----------------------------------------------------------------------------
 * Method: void arpDumpHeader(struct sr_arphdr* )
 *
 * Prints fields in the ARP header to stdout
 *---------------------------------------------------------------------------*/
 void arpDumpHeader(struct sr_arphdr* arpHdr)
 {
     struct in_addr ar_ip;
     int i;
    
     printf("==== ARP HEADER ====\n");
     fprintf(stdout, "Hardware Type: %4.4x\n", ntohs(arpHdr->ar_hrd));
     fprintf(stdout, "Protocol Type: %4.4x\n", ntohs(arpHdr->ar_pro));
     fprintf(stdout, "Hardware Address Length: %2.2x\n", arpHdr->ar_hln);
     fprintf(stdout, "Protocol Address Length: %2.2x\n", arpHdr->ar_pln);
     fprintf(stdout, "ARP operation: %4.4x\n", ntohs(arpHdr->ar_op));

    printf("Sender Hardware Address: ");
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        fprintf(stdout, "%2.2x", arpHdr->ar_sha[i]);
    } printf("\n");

    printf("Target Hardware Address: ");
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        fprintf(stdout, "%2.2x", arpHdr->ar_tha[i]);
    } printf("\n");

    ar_ip.s_addr = arpHdr->ar_sip;
    fprintf(stdout, "Sender IP Address: %s\n", inet_ntoa(ar_ip));
    ar_ip.s_addr = arpHdr->ar_tip;
    fprintf(stdout, "Target IP Address: %s\n", inet_ntoa(ar_ip));
    printf("====================\n");
}
