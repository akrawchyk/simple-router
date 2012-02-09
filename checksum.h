/*******************************************************************************
 * file: checksum.h
 * date: 10/13/10
 * Andrew Krawchyk
 * 
 * Description:
 * contains headers for internet checksum calculation algorithm
 ******************************************************************************/
 
#ifndef CHECKSUM_H
#define CHECKSUM_H
 
#include <stdint.h>
 
uint16_t in_checksum(uint16_t* addr, int count);

#endif
