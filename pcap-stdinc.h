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
#endif /* __MINGW32__ */

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
