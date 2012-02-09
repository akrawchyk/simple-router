/******************************************************************************
 * file: checksum.c
 * date: 10/13/10
 * Andrew Krawchyk
 * 
 * Description:
 * implements internet checksum algorithm defined by rfc1071
 *****************************************************************************/

#include <stdint.h>

uint16_t in_checksum(uint16_t* addr, int count)
{
    register uint32_t sum = 0;

    while (count > 1) {
        sum += *addr++;
        count -= 2;
    }

    if (count > 0)
        sum += *((uint8_t*)addr);

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return(~sum);
}
