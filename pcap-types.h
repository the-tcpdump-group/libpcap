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
  #include <sys/types.h>
#endif

#endif /* pcap_types_h */
