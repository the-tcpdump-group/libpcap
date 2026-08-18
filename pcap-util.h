/*
 * Copyright (c) 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * pcap-util.h - common code for various files
 */

#ifndef pcap_util_h
#define pcap_util_h

#include <pcap/pcap-inttypes.h>
/*
 * We use the "receiver-makes-right" approach to byte order;
 * because time is at a premium when we are writing the file.
 * In other words, the pcap_file_header and pcap_pkthdr,
 * records are written in host byte order.
 * Note that the bytes of packet data are written out in the order in
 * which they were received, so multi-byte fields in packets are not
 * written in host byte order, they're written in whatever order the
 * sending machine put them in.
 *
 * We also use this for fixing up packet data headers from a remote
 * capture, where the server may have a different byte order from the
 * client.
 *
 * ntoh[ls] aren't sufficient because we might need to swap on a big-endian
 * machine (if the file was written in little-end order).
 *
 * These macros are used to generate case labels in switch statements,
 * so they can't be done as inline functions, and, when passed a
 * compile-time constant argument, must produce a compile-time constant
 * result.  This means that they must either use builtin functions that
 * are recognized by the compiler as producing constant results when
 * passed a constant argument, or must be done with expressions that
 * evaluate to compile-time constants when passed a compile-time
 * constant.
 *
 * Newer versions of GCC, Clang, Visual Studio C/C++, and possibly
 * some other compilers recognize the expressions as byte-swapping
 * idioms and generate optimized machine-specific code for architectures
 * that include instructions that can be used to swap bytes.
 */
#define PCAP_BSWAP_64(y) \
    ((uint64_t)(((((uint64_t)(y)) & UINT64_C(0xff00000000000000)) >> 56) | \
                ((((uint64_t)(y)) & UINT64_C(0x00ff000000000000)) >> 40) | \
                ((((uint64_t)(y)) & UINT64_C(0x0000ff0000000000)) >> 24) | \
                ((((uint64_t)(y)) & UINT64_C(0x000000ff00000000)) >> 8)  | \
                ((((uint64_t)(y)) & UINT64_C(0x00000000ff000000)) << 8)  | \
                ((((uint64_t)(y)) & UINT64_C(0x0000000000ff0000)) << 24) | \
                ((((uint64_t)(y)) & UINT64_C(0x000000000000ff00)) << 40) | \
                ((((uint64_t)(y)) & UINT64_C(0x00000000000000ff)) << 56)))
#define PCAP_BSWAP_32(y) \
    ((uint32_t)(((((uint32_t)(y)) & UINT32_C(0xff000000)) >> 24) | \
                ((((uint32_t)(y)) & UINT32_C(0x00ff0000)) >> 8)  | \
                ((((uint32_t)(y)) & UINT32_C(0x0000ff00)) << 8)  | \
                ((((uint32_t)(y)) & UINT32_C(0x000000ff)) << 24)))
#define PCAP_BSWAP_16(y) \
    ((uint16_t)(((((uint16_t)(y)) & UINT16_C(0x00ff)) << 8) | \
                ((((uint16_t)(y)) & UINT16_C(0xff00)) >> 8)))

/*
 * Byte-swap a pcap_4_byte_aligned_uint64;
 */
static inline pcap_4_byte_aligned_uint64 swap_4_byte_aligned_uint64(pcap_4_byte_aligned_uint64 val)
{
	return (pcap_4_byte_aligned_uint64){.halves[0] = PCAP_BSWAP_32(val.halves[1]), .halves[1] = PCAP_BSWAP_32(val.halves[0])};
}

/*
 * Byte-swap a pcap_4_byte_aligned_int64;
 */
static inline pcap_4_byte_aligned_int64 swap_4_byte_aligned_int64(pcap_4_byte_aligned_int64 val)
{
	return (pcap_4_byte_aligned_int64){.halves[0] = PCAP_BSWAP_32(val.halves[1]), .halves[1] = PCAP_BSWAP_32(val.halves[0])};
}

extern void pcapint_post_process(int linktype, int swapped,
    struct pcap_pkthdr *hdr, u_char *data);

#endif // pcap_util_h
