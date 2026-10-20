/*
 * Copyright (c) 1994, 1995, 1996
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the Computer Systems
 *	Engineering Group at Lawrence Berkeley Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef portability_h
#define	portability_h

#include <config.h> // HAVE_xxx

/*
 * Helpers for portability between Windows and UN*X and between different
 * flavors of UN*X.
 */
#include <stdarg.h>	/* this file declares varargs functions on some platforms */

#include "pcap/funcattrs.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_STRLCAT
  #define pcapint_strlcat	strlcat
#else
  #if defined(_MSC_VER) || defined(__MINGW32__)
    /*
     * strncat_s() is supported at least back to Visual
     * Studio 2005; we require Visual Studio 2015 or later.
     */
    #define pcapint_strlcat(x, y, z) \
	strncat_s((x), (z), (y), _TRUNCATE)
  #else
    /*
     * Define it ourselves.
     */
    extern size_t pcapint_strlcat(char * restrict dst, const char * restrict src, size_t dstsize);
  #endif
#endif

#ifdef HAVE_STRLCPY
  #define pcapint_strlcpy	strlcpy
#else
  #if defined(_MSC_VER) || defined(__MINGW32__)
    /*
     * strncpy_s() is supported at least back to Visual
     * Studio 2005; we require Visual Studio 2015 or later.
     */
    #define pcapint_strlcpy(x, y, z) \
	strncpy_s((x), (z), (y), _TRUNCATE)
  #else
    /*
     * Define it ourselves.
     */
    extern size_t pcapint_strlcpy(char * restrict dst, const char * restrict src, size_t dstsize);
  #endif
#endif

#ifdef _MSC_VER
  /*
   * If <crtdbg.h> has been included, and _DEBUG is defined, and
   * __STDC__ is zero, <crtdbg.h> will define strdup() to call
   * _strdup_dbg().  So if it's already defined, don't redefine
   * it.
   */
  #ifndef strdup
  #define strdup	_strdup
  #endif
#endif

/*
 * We want asprintf(), for some cases where we use it to construct
 * dynamically-allocated variable-length strings; it's present on
 * some, but not all, platforms.
 */
#ifdef HAVE_ASPRINTF
#define pcapint_asprintf asprintf
#else
extern int pcapint_asprintf(char **, PCAP_FORMAT_STRING(const char *), ...)
    PCAP_PRINTFLIKE(2, 3);
#endif

#ifdef HAVE_VASPRINTF
#define pcapint_vasprintf vasprintf
#else
extern int pcapint_vasprintf(char **, PCAP_FORMAT_STRING(const char *), va_list ap)
    PCAP_PRINTFLIKE(2, 0);
#endif

#ifdef HAVE_STRTOK_R
  #define pcapint_strtok_r	strtok_r
#else
  #ifdef _WIN32
    /*
     * Microsoft gives it a different name.
     */
    #define pcapint_strtok_r	strtok_s
  #else
    /*
     * Define it ourselves.
     */
    extern char *pcapint_strtok_r(char *, const char *, char **);
  #endif
#endif /* HAVE_STRTOK_R */

#ifdef _WIN32
  #if !defined(__cplusplus)
    #define inline __inline
  #endif
#include <winsock2.h>
#endif /* _WIN32 */

#ifdef HAVE_SYSEXITS_H
  // most OSes
  #include <sysexits.h>
#else
  // Windows and QNX
  #define EX_OK           0
  #define EX_USAGE       64
  #define EX_DATAERR     65
  #define EX_NOINPUT     66
  #define EX_NOUSER      67
  #define EX_NOHOST      68
  #define EX_UNAVAILABLE 69
  #define EX_SOFTWARE    70
  #define EX_OSERR       71
  #define EX_OSFILE      72
  #define EX_CANTCREAT   73
  #define EX_IOERR       74
  #define EX_TEMPFAIL    75
  #define EX_PROTOCOL    76
  #define EX_NOPERM      77
  #define EX_CONFIG      78
#endif // HAVE_SYSEXITS_H

#ifdef __cplusplus
}
#endif

#endif
