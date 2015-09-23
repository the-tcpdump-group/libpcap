/*
 * Copyright (c) 2002 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2009 CACE Technologies, Inc. Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef pcap_stdinc_h
#define pcap_stdinc_h

/*
 * Avoids a compiler warning in case this was already defined
 * (someone defined _WINSOCKAPI_ when including 'windows.h', in order
 * to prevent it from including 'winsock.h')
 */
#ifdef _WINSOCKAPI_
#undef _WINSOCKAPI_
#endif

#include <winsock2.h>
#include <fcntl.h>
#include <time.h>
#include <io.h>

#include "bittypes.h"

/*
 * A bunch of declarations for IPv6 from FreeBSD not present in Windows.
 */

#include <ws2tcpip.h>

#ifndef __MINGW32__
#define	IN_MULTICAST(a)		IN_CLASSD(a)
#endif

#define	IN_EXPERIMENTAL(a)	((((u_int32_t) (a)) & 0xf0000000) == 0xf0000000)

#define	IN_LOOPBACKNET		127

#if defined(__MINGW32__) && defined(DEFINE_ADDITIONAL_IPV6_STUFF)
/* IPv6 address */
struct in6_addr
  {
    union
      {
	u_int8_t		u6_addr8[16];
	u_int16_t	u6_addr16[8];
	u_int32_t	u6_addr32[4];
      } in6_u;
#define s6_addr			in6_u.u6_addr8
#define s6_addr16		in6_u.u6_addr16
#define s6_addr32		in6_u.u6_addr32
#define s6_addr64		in6_u.u6_addr64
  };

#define IN6ADDR_ANY_INIT { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }
#define IN6ADDR_LOOPBACK_INIT { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 }
#endif /* __MINGW32__ */

#if (defined _MSC_VER) || (defined(__MINGW32__) && defined(DEFINE_ADDITIONAL_IPV6_STUFF))
typedef unsigned short	sa_family_t;
#endif

#if defined(__MINGW32__) && defined(DEFINE_ADDITIONAL_IPV6_STUFF)

#define	__SOCKADDR_COMMON(sa_prefix) \
  sa_family_t sa_prefix##family

/* Ditto, for IPv6.  */
struct sockaddr_in6
  {
    __SOCKADDR_COMMON (sin6_);
    u_int16_t sin6_port;		/* Transport layer port # */
    u_int32_t sin6_flowinfo;	/* IPv6 flow information */
    struct in6_addr sin6_addr;	/* IPv6 address */
  };

#define IN6_IS_ADDR_V4MAPPED(a) \
	((((u_int32_t *) (a))[0] == 0) && (((u_int32_t *) (a))[1] == 0) && \
	 (((u_int32_t *) (a))[2] == htonl (0xffff)))

#define IN6_IS_ADDR_MULTICAST(a) (((u_int8_t *) (a))[0] == 0xff)

#define IN6_IS_ADDR_LINKLOCAL(a) \
	((((u_int32_t *) (a))[0] & htonl (0xffc00000)) == htonl (0xfe800000))

#define IN6_IS_ADDR_LOOPBACK(a) \
	(((u_int32_t *) (a))[0] == 0 && ((u_int32_t *) (a))[1] == 0 && \
	 ((u_int32_t *) (a))[2] == 0 && ((u_int32_t *) (a))[3] == htonl (1))
#endif /* __MINGW32__ */

#define ip6_vfc   ip6_ctlun.ip6_un2_vfc
#define ip6_flow  ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen  ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt   ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim  ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops  ip6_ctlun.ip6_un1.ip6_un1_hlim

#define nd_rd_type               nd_rd_hdr.icmp6_type
#define nd_rd_code               nd_rd_hdr.icmp6_code
#define nd_rd_cksum              nd_rd_hdr.icmp6_cksum
#define nd_rd_reserved           nd_rd_hdr.icmp6_data32[0]

/*
 *	IPV6 extension headers
 */
#define IPPROTO_HOPOPTS		0	/* IPv6 hop-by-hop options	*/
#define IPPROTO_IPV6		41  /* IPv6 header.  */
#define IPPROTO_ROUTING		43	/* IPv6 routing header		*/
#define IPPROTO_FRAGMENT	44	/* IPv6 fragmentation header	*/
#define IPPROTO_ESP		50	/* encapsulating security payload */
#define IPPROTO_AH		51	/* authentication header	*/
#define IPPROTO_ICMPV6		58	/* ICMPv6			*/
#define IPPROTO_NONE		59	/* IPv6 no next header		*/
#define IPPROTO_DSTOPTS		60	/* IPv6 destination options	*/
#define IPPROTO_PIM			103 /* Protocol Independent Multicast.  */

#define	 IPV6_RTHDR_TYPE_0 0

/* Option types and related macros */
#define IP6OPT_PAD1		0x00	/* 00 0 00000 */
#define IP6OPT_PADN		0x01	/* 00 0 00001 */
#define IP6OPT_JUMBO		0xC2	/* 11 0 00010 = 194 */
#define IP6OPT_JUMBO_LEN	6
#define IP6OPT_ROUTER_ALERT	0x05	/* 00 0 00101 */

#define IP6OPT_RTALERT_LEN	4
#define IP6OPT_RTALERT_MLD	0	/* Datagram contains an MLD message */
#define IP6OPT_RTALERT_RSVP	1	/* Datagram contains an RSVP message */
#define IP6OPT_RTALERT_ACTNET	2 	/* contains an Active Networks msg */
#define IP6OPT_MINLEN		2

#define IP6OPT_BINDING_UPDATE	0xc6	/* 11 0 00110 */
#define IP6OPT_BINDING_ACK	0x07	/* 00 0 00111 */
#define IP6OPT_BINDING_REQ	0x08	/* 00 0 01000 */
#define IP6OPT_HOME_ADDRESS	0xc9	/* 11 0 01001 */
#define IP6OPT_EID		0x8a	/* 10 0 01010 */

#define IP6OPT_TYPE(o)		((o) & 0xC0)
#define IP6OPT_TYPE_SKIP	0x00
#define IP6OPT_TYPE_DISCARD	0x40
#define IP6OPT_TYPE_FORCEICMP	0x80
#define IP6OPT_TYPE_ICMP	0xC0

#define IP6OPT_MUTABLE		0x20


#if defined(__MINGW32__) && defined(DEFINE_ADDITIONAL_IPV6_STUFF)
#ifndef EAI_ADDRFAMILY
struct addrinfo {
	int	ai_flags;	/* AI_PASSIVE, AI_CANONNAME */
	int	ai_family;	/* PF_xxx */
	int	ai_socktype;	/* SOCK_xxx */
	int	ai_protocol;	/* 0 or IPPROTO_xxx for IPv4 and IPv6 */
	size_t	ai_addrlen;	/* length of ai_addr */
	char	*ai_canonname;	/* canonical name for hostname */
	struct sockaddr *ai_addr;	/* binary address */
	struct addrinfo *ai_next;	/* next structure in linked list */
};
#endif
#endif /* __MINGW32__ */

#define caddr_t char*

#ifdef _MSC_VER
  #define snprintf  _snprintf
  #define vsnprintf _vsnprintf
  #define strdup    _strdup
#endif

#if !defined(__cplusplus)
  #define inline __inline
#endif

#ifdef __MINGW32__
  #include <stdint.h>
#else
  #ifndef _UINTPTR_T_DEFINED
    #ifdef  _WIN64
      typedef unsigned __int64    uintptr_t;
    #else
      typedef _W64 unsigned int   uintptr_t;
    #endif
    #define _UINTPTR_T_DEFINED
  #endif

  #ifndef _INTPTR_T_DEFINED
    #ifdef  _WIN64
      typedef __int64    intptr_t;
    #else
      typedef _W64 int   intptr_t;
    #endif
    #define _INTPTR_T_DEFINED
  #endif
#endif /*__MINGW32__*/

#endif /* pcap_stdinc_h */
