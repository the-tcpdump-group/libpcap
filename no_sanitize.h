/*
 * Copyright (c) 2026
 *	The Tcpdump Group and contributors.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* \summary: macros to specify function attributes to suppress sanitizer checks */

#ifndef NO_SANITIZE_H
#define NO_SANITIZE_H

#include "pcap/compiler-tests.h"

/*
 * If we have a compiler that supports an __attribute__ to say "if we're
 * building with unsigned behavior sanitization, don't complain about
 * unsigned left shifts in this function", we label these functions with
 * that attribute - it's *not* undefined in the C standard, and we
 * *also* know it does what we want.
 *
 * We check for __attribute__((no_sanitize(XXX))) with __has_attribute,
 * as this check currently appears to be Clang-only, so we suppress it
 * with no_sanitize("unsigned-shift-base"). In addition, the
 * "-fsanitize=unsigned-shift-base" option, and thus
 * no_sanitize("unsigned-shift-base"),  is not supported before Clang 12,
 * so we check Clang 12 or later first.
 *
 * We define this here, rather than in pcap/funcattrs.h, because we
 * only want it used in selected places, and it doesn't apply to
 * function *declarations*, just function *definitions*.
 */
#if PCAP_IS_AT_LEAST_CLANG_VERSION(12, 0) && __has_attribute(no_sanitize)
#define UNSIGNED_SHIFT_OK	__attribute__((no_sanitize("unsigned-shift-base")))
#else
#define UNSIGNED_SHIFT_OK
#endif

#endif /* NO_SANITIZE_H */
