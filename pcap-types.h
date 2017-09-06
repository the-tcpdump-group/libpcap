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
#ifndef pcap_types_h
#define pcap_types_h

/*
 * Get the integer types we use defined, by hook or by crook.
 */
#ifdef _WIN32
/*
 * Avoids a compiler warning in case this was already defined
 * (someone defined _WINSOCKAPI_ when including 'windows.h', in order
 * to prevent it from including 'winsock.h')
 */
#ifdef _WINSOCKAPI_
#undef _WINSOCKAPI_
#endif

/*
 * This defines u_int.
 */
#include <winsock2.h>
#endif

#if defined(_MSC_VER)
  /*
   * Target is Windows, compiler is MSVC.
   */
  #if _MSC_VER >= 1800
    /*
     * VS 2013 or newer; we have <inttypes.h>.
     */
    #include <inttypes.h>

    #define u_int8_t uint8_t
    #define u_int16_t uint16_t
    #define u_int32_t uint32_t
    #define u_int64_t uint64_t
  #else
    /*
     * Earlier VS; we have to define this stuff ourselves.
     */
    #ifndef HAVE_U_INT8_T
      typedef unsigned char u_int8_t;
      typedef signed char int8_t;
    #endif

    #ifndef HAVE_U_INT16_T
      typedef unsigned short u_int16_t;
      typedef signed short int16_t;
    #endif

    #ifndef HAVE_U_INT32_T
      typedef unsigned int u_int32_t;
      typedef signed int int32_t;
    #endif

    #ifndef HAVE_U_INT64_T
      #ifdef _MSC_EXTENSIONS
        typedef unsigned _int64 u_int64_t;
        typedef _int64 int64_t;
      #else /* _MSC_EXTENSIONS */
        typedef unsigned long long u_int64_t;
        typedef long long int64_t;
      #endif
    #endif
  #endif

  /*
   * These may be defined by <inttypes.h>.
   *
   * XXX - for MSVC, we always want the _MSC_EXTENSIONS versions.
   * What about other compilers?  If, as the MinGW Web site says MinGW
   * does, the other compilers just use Microsoft's run-time library,
   * then they should probably use the _MSC_EXTENSIONS even if the
   * compiler doesn't define _MSC_EXTENSIONS.
   *
   * XXX - we currently aren't using any of these, but this allows
   * their use in the future.
   */
  #ifndef PRId64
    #ifdef _MSC_EXTENSIONS
      #define PRId64	"I64d"
    #else
      #define PRId64	"lld"
    #endif
  #endif /* PRId64 */

  #ifndef PRIo64
    #ifdef _MSC_EXTENSIONS
      #define PRIo64	"I64o"
    #else
      #define PRIo64	"llo"
    #endif
  #endif /* PRIo64 */

  #ifndef PRIx64
    #ifdef _MSC_EXTENSIONS
      #define PRIx64	"I64x"
    #else
      #define PRIx64	"llx"
    #endif
  #endif

  #ifndef PRIu64
    #ifdef _MSC_EXTENSIONS
      #define PRIu64	"I64u"
    #else
      #define PRIu64	"llu"
    #endif
  #endif
#elif defined(__MINGW32__)
  /*
   * Target is Windows, compiler is MinGW.
   */
  #include <stdint.h>
#elif !defined(_WIN32)
  /*
   * Target is UN*X or MS-DOS.
   */
  #if HAVE_INTTYPES_H
    #include <inttypes.h>
  #elif HAVE_STDINT_H
    #include <stdint.h>
  #endif
  #ifdef HAVE_SYS_BITYPES_H
    #include <sys/bitypes.h>
  #endif
  /*
   * This defines u_int, among other types.
   */
  #include <sys/types.h>
#endif

#endif /* pcap_types_h */
