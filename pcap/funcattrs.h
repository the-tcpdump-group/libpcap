/* -*- Mode: c; tab-width: 8; indent-tabs-mode: 1; c-basic-offset: 8; -*- */
/*
 * Copyright (c) 1993, 1994, 1995, 1996, 1997
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

#ifndef lib_pcap_funcattrs_h
#define lib_pcap_funcattrs_h

/*
 * Attributes to apply to functions and their arguments, using various
 * compiler-specific extensions.
 */

/*
 * PCAP_API_DEF must be used when defining *data* exported from
 * libpcap.  It can be used when defining *functions* exported
 * from libpcap, but it doesn't have to be used there.  It
 * should not be used in declarations in headers.
 *
 * PCAP_API must be used when *declaring* data or functions
 * exported from libpcap; PCAP_API_DEF won't work on all platforms.
 */

/*
 * This was introduced by Clang:
 *
 *     http://clang.llvm.org/docs/LanguageExtensions.html#has-attribute
 *
 * in some version (which version?); it has been picked up by GCC 5.0.
 */
#ifndef __has_attribute
  /*
   * It's a macro, so you can check whether it's defined to check
   * whether it's supported.
   *
   * If it's not, define it to always return 0, so that we move on to
   * the fallback checks.
   */
  #define __has_attribute(x) 0
#endif

/*
 * Check whether this is GCC major.minor or a later release, or some
 * compiler that claims to be "just like GCC" of that version or a
 * later release.
 */
#define PCAP_IS_AT_LEAST_GNUC_VERSION(major, minor) \
	(defined(__GNUC__) && \
	    (__GNUC__ > (major) || \
	     (__GNUC__ == (major) && __GNUC_MINOR__ >= (minor))))

/*
 * Check wehether this is Sun C/SunPro C/Oracle Studio major.minor
 * or a later release.
 *
 * The version number in __SUNPRO_C is encoded in hex BCD, with the
 * uppermost hex digit being the major version number, the next
 * one or two hex digits being the minor version number, and
 * the last digit being the patch version.
 *
 * It represents the *compiler* version, not the product version;
 * see
 *
 *    https://sourceforge.net/p/predef/wiki/Compilers/
 *
 * for a partial mapping, which we assume continues for later
 * 12.x product releases.
 */
#define PCAP_SUNPRO_VERSION_TO_BCD(major, minor) \
	(((minor) >= 10) ? \
	    (((major) << 12) | (((minor)/10) << 8) | (((minor)%10) << 4)) : \
	    (((major) << 8) | ((minor) << 4)))
#define PCAP_IS_AT_LEAST_SUNC_VERSION(major, minor) \
	(defined(__SUNPRO_C) && \
	    (__SUNPRO_C >= PCAP_SUNPRO_VERSION_TO_BCD((major), (minor))))

/*
 * Check wehether this is IBM XL C major.minor or a later release.
 *
 * The version number in __xlC__ has the major version in the
 * upper 8 bits and the minor version in the lower 8 bits.
 */
#define PCAP_IS_AT_LEAST_XL_C_VERSION(major, minor) \
	(defined(__xlC__) && __xlC__ >= (((major) << 8) | (minor)))

/*
 * Check wehether this is Sun C/SunPro C/Oracle Studio major.minor
 * or a later release.
 *
 * The version number in __HP_aCC is encoded in zero-padded decimal BCD,
 * with the "A." stripped off, the uppermost two decimal digits being
 * the major version number, the next two decimal digits being the minor
 * version number, and the last two decimal digits being the patch version.
 * (Strip off the A., remove the . between the major and minor version
 * number, and add two digits of patch.)
 */
#define PCAP_IS_AT_LEAST_HP_C_VERSION(major, minor) \
	(defined(__HP_aCC) && \
	    (__HP_aCC >= ((major)*10000 + (minor)*100)))

#if defined(_WIN32)
  #ifdef BUILDING_PCAP
    /*
     * We're compiling libpcap, so we should export functions in our
     * API.
     */
    #define PCAP_API_DEF	__declspec(dllexport)
  #else
    #define PCAP_API_DEF	__declspec(dllimport)
  #endif
#elif defined(MSDOS)
  /* XXX - does this need special treatment? */
  #define PCAP_API_DEF
#else /* UN*X */
  #ifdef BUILDING_PCAP
    /*
     * We're compiling libpcap, so we should export functions in our API.
     * The compiler might be configured not to export functions from a
     * shared library by default, so we might have to explicitly mark
     * functions as exported.
     */
    #if PCAP_IS_AT_LEAST_GNUC_VERSION(3, 4) \
        || PCAP_IS_AT_LEAST_XL_C_VERSION(12, 0)
      /*
       * GCC 3.4 or later, or some compiler asserting compatibility with
       * GCC 3.4 or later, or XL C 13.0 or later, so we have
       * __attribute__((visibility()).
       */
      #define PCAP_API_DEF	__attribute__((visibility("default")))
    #elif PCAP_IS_AT_LEAST_SUNC_VERSION(5, 5)
      /*
       * Sun C 5.5 or later, so we have __global.
       * (Sun C 5.9 and later also have __attribute__((visibility()),
       * but there's no reason to prefer it with Sun C.)
       */
      #define PCAP_API_DEF	__global
    #else
      /*
       * We don't have anything to say.
       */
      #define PCAP_API_DEF
    #endif
  #else
    /*
     * We're not building libpcap.
     */
    #define PCAP_API_DEF
  #endif
#endif /* _WIN32/MSDOS/UN*X */

#define PCAP_API	PCAP_API_DEF extern

/*
 * PCAP_NORETURN, before a function declaration, means "this function
 * never returns".  (It must go before the function declaration, e.g.
 * "extern PCAP_NORETURN func(...)" rather than after the function
 * declaration, as the MSVC version has to go before the declaration.)
 */
#if __has_attribute(noreturn) \
    || PCAP_IS_AT_LEAST_GNUC_VERSION(2, 5) \
    || PCAP_IS_AT_LEAST_SUNC_VERSION(5, 9) \
    || PCAP_IS_AT_LEAST_XL_C_VERSION(10, 1) \
    || PCAP_IS_AT_LEAST_HP_C_VERSION(6, 10)
  /*
   * Compiler with support for __attribute((noreturn)), or GCC 2.5 and
   * later, or Solaris Studio 12 (Sun C 5.9) and later, or IBM XL C 10.1
   * and later (do any earlier versions of XL C support this?), or
   * HP aCC A.06.10 and later.
   */
  #define PCAP_NORETURN __attribute((noreturn))
#elif defined(_MSC_VER)
  /*
   * MSVC.
   */
  #define PCAP_NORETURN __declspec(noreturn)
#else
  #define PCAP_NORETURN
#endif

/*
 * PCAP_PRINTFLIKE(x,y), after a function declaration, means "this function
 * does printf-style formatting, with the xth argument being the format
 * string and the yth argument being the first argument for the format
 * string".
 */
#if __has_attribute(__format__) \
    || PCAP_IS_AT_LEAST_GNUC_VERSION(2, 3) \
    || PCAP_IS_AT_LEAST_XL_C_VERSION(10, 1) \
    || PCAP_IS_AT_LEAST_HP_C_VERSION(6, 10)
  /*
   * Compiler with support for it, or GCC 2.3 and later, or IBM XL C 10.1
   * and later (do any earlier versions of XL C support this?),
   * or HP aCC A.06.10 and later.
   */
  #define PCAP_PRINTFLIKE(x,y) __attribute__((__format__(__printf__,x,y)))
#else
  #define PCAP_PRINTFLIKE(x,y)
#endif

/*
 * PCAP_DEPRECATED(func, msg), after a function declaration, marks the
 * function as deprecated.
 *
 * The first argument is the name of the function; the second argument is
 * a string giving the warning message to use if the compiler supports that.
 *
 * (Thank you, Microsoft, for requiring the function name.)
 */
#if __has_attribute(deprecated) \
    || PCAP_IS_AT_LEAST_GNUC_VERSION(4, 5) \
    || PCAP_IS_AT_LEAST_SUNC_VERSION(5, 13)
  /*
   * Compiler that supports __has_attribute and __attribute__((deprecated)),
   * or GCC 4.5 and later, or Sun/Oracle C 12.4 (Sun C 5.13) or later.
   *
   * Those support __attribute__((deprecated(msg))) (we assume, perhaps
   * incorrectly, that anything that supports __has_attribute() is
   * recent enough to support __attribute__((deprecated(msg)))).
   */
  #define PCAP_DEPRECATED(func, msg)	__attribute__((deprecated(msg)))
#elif PCAP_IS_AT_LEAST_GNUC_VERSION(3, 1)
  /*
   * GCC 3.1 through 4.4.
   *
   * Those support __attribute__((deprecated)) but not
   * __attribute__((deprecated(msg))).
   */
  #define PCAP_DEPRECATED(func, msg)	__attribute__((deprecated))
#elif (defined(_MSC_VER) && (_MSC_VER >= 1500)) && !defined(BUILDING_PCAP)
  /*
   * MSVC from Visual Studio 2008 or later, and we're not building
   * libpcap itself.
   *
   * If we *are* building libpcap, we don't want this, as it'll warn
   * us even if we *define* the function.
   */
  #define PCAP_DEPRECATED(func, msg)	__pragma(deprecated(func))
#else
  #define PCAP_DEPRECATED(func, msg)
#endif

/*
 * For flagging arguments as format strings in MSVC.
 */
#if _MSC_VER >= 1400
 #include <sal.h>
 #if _MSC_VER > 1400
  #define PCAP_FORMAT_STRING(p) _Printf_format_string_ p
 #else
  #define PCAP_FORMAT_STRING(p) __format_string p
 #endif
#else
 #define PCAP_FORMAT_STRING(p) p
#endif

#endif /* lib_pcap_funcattrs_h */
