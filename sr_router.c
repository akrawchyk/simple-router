/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <unistd.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "ethernet.h"
#include "ip.h"
#include "arp.h"
#include "forward.h"
#include "checksum.h"

/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);


    /* Add initialization code here! */

    arpInitCache();
    initPacketCache();

} /* -- sr_init -- */



/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);

    struct sr_ethernet_hdr * ethernetHdr = (struct sr_ethernet_hdr *)packet;

    arpUpdateCache();

    if (dstIsBroadcast(ethernetHdr)) {
        if (ntohs(ethernetHdr->ether_type) == ETHERTYPE_ARP) {
            fprintf(stdout, "- Ethernet Type: %4.4x -> ARP\n", ntohs(ethernetHdr->ether_type));
            handleArp(sr, packet, len, interface);
        }
    } else if (weAreTarget(sr, packet, interface)) {
        if (ntohs(ethernetHdr->ether_type) == ETHERTYPE_IP) {
            fprintf(stdout, "- Ethernet Type: %4.4x -> IP\n", ntohs(ethernetHdr->ether_type));
            handleIp(sr, packet, len, interface);
        }

        if (ntohs(ethernetHdr->ether_type) == ETHERTYPE_ARP) {
            fprintf(stdout, "- Ethernet Type: %4.4x -> ARP\n", ntohs(ethernetHdr->ether_type));
            handleArp(sr, packet, len, interface);
        }
    } else {
        if (ntohs(ethernetHdr->ether_type) == ETHERTYPE_IP) {
            fprintf(stdout, "- Ethernet Type: %4.4x -> IP\n", ntohs(ethernetHdr->ether_type));
            handleForward(sr, packet, len, interface);
        }
    }

}/* end sr_ForwardPacket */

/*-----------------------------------------------------------------------------
 * Method: int weAreTarget(struct sr_instance* sr, struct sr_ethernet_hdr * ethernetHdr)
 *
 * determines if are the destination interface for our packet
 *---------------------------------------------------------------------------*/
int weAreTarget(struct sr_instance* sr, uint8_t* packet, const char* interface)
{
    struct sr_ethernet_hdr* ethernetHdr = (struct sr_ethernet_hdr*)packet;
    struct sr_if* incoming_if = sr_get_interface(sr, interface);

    if (ntohs(ethernetHdr->ether_type) == ETHERTYPE_ARP) {
        struct sr_arphdr* arpHdr = (struct sr_arphdr*)(packet+14);
        if (incoming_if->ip == arpHdr->ar_tip)
            return 1;
    } else if (ntohs(ethernetHdr->ether_type) == ETHERTYPE_IP) {
        struct ip* ipHdr = (struct ip*)(packet+14);
        if (incoming_if->ip == ipHdr->ip_dst.s_addr)
            return 1;
    }

    return 0;
}

/*-----------------------------------------------------------------------------
 * Method: int dstIsBroadcast(struct sr_ethernet_hdr* ethernetHdr)
 *
 * determines if the incoming packet is broadcast
 *---------------------------------------------------------------------------*/
int dstIsBroadcast(struct sr_ethernet_hdr* ethernetHdr)
{
    int i;

    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        if (ethernetHdr->ether_dhost[i] != 0xff)
            return 0;
    }

    return 1;
}
