/*****************************************************************************
 * file: icmp.h
 * date: 10/13/10
 * Andrew Krawchyk
 *
 * Description:
 * Contains headers for ICMP protocol functions
 *****************************************************************************/
 
#ifndef ICMP_H
#define ICMP_H

#include <stdint.h>

#include "sr_protocol.h"

#define ICMP_ECHO_REPLY 0
#define ICMP_ECHO_REQUEST 8
#define ICMP_DST_UNREACHABLE 3
#define ICMP_HOST_UNREACHABLE 1
#define ICMP_PORT_UNREACHABLE 3

struct icmp_hdr
{
    uint8_t         icmp_type;
    uint8_t         icmp_code;
    uint16_t        icmp_checksum;
    uint16_t        icmp_ident;
    uint16_t        icmp_seq;
};

void handleIcmp(struct sr_instance*, uint8_t*, unsigned int, char* );
void icmpSendEchoReply(struct sr_instance*, uint8_t*, unsigned int, char*);
void icmpSendUnreachable(struct sr_instance*, uint8_t*, unsigned int, char*, uint8_t );
void makeicmp(struct icmp_hdr*, uint8_t, uint8_t, int );
void icmpDumpHeader(struct icmp_hdr* );

#endif
