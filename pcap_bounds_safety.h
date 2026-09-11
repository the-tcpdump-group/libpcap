/* pcap_bounds_safety.h - portability macros for optional -fbounds-safety
 *
 * Copyright (c) 2026 Jeff Bindel
 *
 * License: BSD (same as libpcap; see LICENSE)
 *
 * When PCAP_SUPPORT_FBOUNDS_SAFETY is defined (typically via
 * -DPCAP_SUPPORT_FBOUNDS_SAFETY and a Clang toolchain that implements
 * -fbounds-safety), these macros expand to Clang bounds annotations.
 * Otherwise they expand to nothing so default builds are unchanged.
 *
 * Pattern matches libwebp / libpng / libjpeg-turbo / libtiff inert-macro
 * -fbounds-safety adoption: annotations are inert unless explicitly enabled.
 */

#ifndef PCAP_BOUNDS_SAFETY_H
#define PCAP_BOUNDS_SAFETY_H

#ifdef PCAP_SUPPORT_FBOUNDS_SAFETY

#  include <ptrcheck.h>
/* Non-ABI-breaking counted-by annotations for struct pointer members.
 * Prefer PCAP_COUNTED_BY_OR_NULL for pointers that may be NULL while the
 * companion size field is zero (pcap_t.buffer / bufsize pattern).
 */
#  define PCAP_COUNTED_BY(n) __counted_by(n)
#  define PCAP_COUNTED_BY_OR_NULL(n) __counted_by_or_null(n)

#else /* !PCAP_SUPPORT_FBOUNDS_SAFETY */

#  define PCAP_COUNTED_BY(n)
#  define PCAP_COUNTED_BY_OR_NULL(n)

#endif /* PCAP_SUPPORT_FBOUNDS_SAFETY */

#endif /* PCAP_BOUNDS_SAFETY_H */
