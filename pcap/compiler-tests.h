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

#ifndef lib_pcap_compiler_tests_h
#define lib_pcap_compiler_tests_h


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

#endif /* lib_pcap_funcattrs_h */
