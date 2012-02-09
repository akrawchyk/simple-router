/******************************************************************************
 * file: icmp.c
 * date: 10/13/10
 * Andrew Krawchyk
 *
 * Description:
 * implements icmp manipulation functions
 *****************************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "sr_if.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "ethernet.h"
#include "ip.h"
#include "icmp.h"
#include "checksum.h"

/*---------------------------------------------------------------------------------
* Method: void handleIcmp(struct sr_instance*, uint8_t*, unsigned int, char*);
*
* Determines what kind of ICMP packet we received and responds accordingly
*------------------------------------------------------------------------------------*/
void handleIcmp(struct sr_instance* sr,
          uint8_t* packet,
          unsigned int len,
          char* interface)
{
    struct icmp_hdr * icmpHdr = (struct icmp_hdr*)(packet+34);

    if (icmpHdr->icmp_type == ICMP_ECHO_REQUEST) {
        fprintf(stdout, "--> ICMP Type: %2.2x -> ECHO \n", icmpHdr->icmp_type);
        icmpSendEchoReply(sr, packet, len, interface);
    }
}

/*-----------------------------------------------------------------------------
 * Method: void icmpSendEchoReply(struct sr_instance* sr, uint8_t* packet,
 *                                  unsigned int len, char* interface )
 *
 * sends a reply to incoming icmp echo request
 *---------------------------------------------------------------------------*/
void icmpSendEchoReply(
        struct sr_instance* sr,
        uint8_t* packet, 
        unsigned int len,
        char* interface)
{
    /* organize our packet */
    struct sr_ethernet_hdr* ethernetHdr = (struct sr_ethernet_hdr*)packet;
    struct ip* ipHdr = (struct ip*)(packet+14);
    struct icmp_hdr* icmpHdr = (struct icmp_hdr*)(packet+34);

    /* modify packet in place to be sent back to pinger */
    makeicmp(icmpHdr, ICMP_ECHO_REPLY, 0, 64);
    makeip(ipHdr, len-14, IP_DF, 64, IPPROTO_ICMP, 
                sr_get_interface(sr, interface)->ip, ipHdr->ip_src.s_addr);
    makeethernet(ethernetHdr, ETHERTYPE_IP, 
                sr_get_interface(sr, interface)->addr, ethernetHdr->ether_shost);

    // send away
    sr_send_packet(sr, packet, len, interface);
    
    // log on send
    printf("<-- ICMP ECHO reply sent to %s\n", inet_ntoa(ipHdr->ip_dst));
}

/*-----------------------------------------------------------------------------
 * Method: void icmpSendEchoReply(struct sr_instance* sr, uint8_t* packet,
 *                                  unsigned int len, char* interface )
 *
 * sends a reply to incoming icmp echo request
 *---------------------------------------------------------------------------*/
void icmpSendUnreachable(
        struct sr_instance* sr,
        uint8_t* packet, 
        unsigned int len,
        char* interface,
        uint8_t type)
{
    /* allocate memory for our new packet */
    uint8_t* icmpPacket = malloc(70 * sizeof(uint8_t));
    if (icmpPacket == NULL) {
        fprintf(stderr, "Error: malloc could not find memory for packet storage\n");
        return;
    }
    memset(icmpPacket, 0, 70 * sizeof(uint8_t));

    /* organize our src packet */
    struct sr_ethernet_hdr* srcethernetHdr = (struct sr_ethernet_hdr*)packet;
    struct ip* srcipHdr = (struct ip*)(packet+14);

    /* organize pointers for our new packet */
    struct sr_ethernet_hdr* newEthHdr = (struct sr_ethernet_hdr*)icmpPacket;
    struct ip* newipHdr = (struct ip*)(icmpPacket+14);
    struct icmp_hdr* newicmpHdr = (struct icmp_hdr*)(icmpPacket+34);
    uint8_t* newicmpData = (uint8_t*)(icmpPacket+42);

    /* copy src ip header + tcp/udp ports to icmp data */
    memcpy(newicmpData, srcipHdr, 28);

    /* create icmp, ip and ethernet headers on our new packet */
    makeicmp(newicmpHdr, ICMP_DST_UNREACHABLE, type, 36);
    makeip(newipHdr, 70-14, IP_DF, 64, IPPROTO_ICMP,
            sr_get_interface(sr, interface)->ip, srcipHdr->ip_src.s_addr);
    makeethernet(newEthHdr, ETHERTYPE_IP,
            sr_get_interface(sr, interface)->addr, srcethernetHdr->ether_shost);
        
    /* send away */
    sr_send_packet(sr, icmpPacket, 70, interface);

    // log on send
    if (type == ICMP_PORT_UNREACHABLE)
        printf("<-- ICMP Destination Port Unreachable sent to %s\n", inet_ntoa(newipHdr->ip_dst));
    if (type == ICMP_HOST_UNREACHABLE)
        printf("<-- ICMP Destination Host Unreachable sent to %s\n", inet_ntoa(newipHdr->ip_dst));

    free(icmpPacket);
}

/*-----------------------------------------------------------------------------
 * Method void makeicmp(struct icmp_hdr* icmpHdr, uint8_t type, uint8_t code)
 *
 * assumes everything is in host byte order
 *---------------------------------------------------------------------------*/
void makeicmp(
        struct icmp_hdr * icmpHdr,
        uint8_t type,
        uint8_t code,
        int len)
{
    icmpHdr->icmp_type = type;
    icmpHdr->icmp_code = code;
    //icmpHdr->icmp_ident = htons(ident);
    //icmpHdr->icmp_seq = htons(seq);

    icmpHdr->icmp_checksum = 0x0000;
    icmpHdr->icmp_checksum = in_checksum((uint16_t*)icmpHdr, len);
}

/*-----------------------------------------------------------------------------
 * Method: void icmpDumpHeader(struct icmp_hdr * icmpHdr)
 *
 * Prints ICMP packet header information to stdout
 *---------------------------------------------------------------------------*/
void icmpDumpHeader(struct icmp_hdr * icmpHdr)
{
    printf("======== ICMP HEADER ========\n");
    fprintf(stdout, "ICMP Type: %2.2x\n", icmpHdr->icmp_type);
    fprintf(stdout, "ICMP Code: %2.2x\n", icmpHdr->icmp_code);
    fprintf(stdout, "ICMP Checksum: %4.4x\n", ntohs(icmpHdr->icmp_checksum));
    fprintf(stdout, "ICMP Identification: %4.4x\n", ntohs(icmpHdr->icmp_ident));
    fprintf(stdout, "ICMP Sequence Number: %4.4x\n", ntohs(icmpHdr->icmp_seq));
    printf("=============================\n");
}
