/***********************************************************************
 * file: ethernet.c
 * date: 10/13/10
 * Andrew Krawchyk
 *
 * Description:
 * contains functions to output and manipulate ethernet headers
 **********************************************************************/

#include <stdio.h>

#include "sr_protocol.h"

/* assumes everything is in host byte order */
void makeethernet(
        struct sr_ethernet_hdr* ethernetHdr,
        uint16_t type,
        uint8_t* src,
        uint8_t* dst )
{
    int i;
    uint8_t sbuf[ETHER_ADDR_LEN], dbuf[ETHER_ADDR_LEN];

    // read to buffer in case we are overwriting in place
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        sbuf[i] = src[i];
        dbuf[i] = dst[i];
    }

    ethernetHdr->ether_type = htons(type);
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        ethernetHdr->ether_shost[i] = sbuf[i];
        ethernetHdr->ether_dhost[i] = dbuf[i];
    }
}

/*----------------------------------------------------------------------
 * Method: void ethDumpHeader(struct sr_ethernet_hdr* )
 *
 * Prints fields in the ARP header to stdout
 *---------------------------------------------------------------------*/
 void ethDumpHeader(struct sr_ethernet_hdr* ethernetHdr)
 {
    int i;
    
    printf("==== ETHERNET HEADER ====\n");
    printf("Destination Ethernet Address: ");
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        fprintf(stdout, "%2.2x", ethernetHdr->ether_dhost[i]);
    } printf("\n");
    
    printf("Source Ethernet Address: ");
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        fprintf(stdout, "%2.2x", ethernetHdr->ether_shost[i]);
    } printf("\n");
    
    fprintf(stdout, "Packet Type ID: %4.4x\n", ntohs(ethernetHdr->ether_type));
    
    printf("=========================\n");
 }
