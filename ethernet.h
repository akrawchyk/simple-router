/******************************************************************************
 * file: ethernet.h
 * date: 10/13/10
 * Andrew Krawchyk
 * 
 * contains headers for ethernet modification functions
 *****************************************************************************/

#ifndef ETHERNET_H
#define ETHERNET_H

#include "sr_protocol.h"

void makeethernet(struct sr_ethernet_hdr*, uint16_t, uint8_t*, uint8_t* );
void ethDumpHeader(struct sr_ethernet_hdr* );

#endif
