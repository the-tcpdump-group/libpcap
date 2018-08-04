/*-
 * Copyright (c) 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from the Stanford/CMU enet packet filter,
 * (net/enet.c) distributed as part of 4.3BSD, and code contributed
 * to Berkeley by Steven McCanne and Van Jacobson both of Lawrence
 * Berkeley Laboratory.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
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
 *
 *	@(#)bpf.c	7.5 (Berkeley) 7/15/91
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pcap/pcap-inttypes.h>
#include "pcap-types.h"

#ifndef _WIN32
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#endif /* _WIN32 */

#include <pcap/bpf.h>

#include <stdlib.h>

/*
 * If we have versions of GCC or Clang that support an __attribute__
 * to say "if we're building with unsigned behavior sanitization,
 * don't complain about undefined behavior in this function", we
 * label these functions with that attribute - we *know* it's undefined
 * in the C standard, but we *also* know it does what we want with
 * the ISA we're targeting and the compiler we're using.
 *
 * For GCC 4.9.0 and later, we use __attribute__((no_sanitize_undefined));
 * pre-5.0 GCC doesn't have __has_attribute, and I'm not sure whether
 * GCC or Clang first had __attribute__((no_sanitize(XXX)).
 *
 * For Clang, we check for __attribute__((no_sanitize(XXX)) with
 * __has_attribute, as there are versions of Clang that support
 * __attribute__((no_sanitize("undefined")) but don't support
 * __attribute__((no_sanitize_undefined)).
 *
 * We define this here, rather than in funcattrs.h, because we
 * only want it used here, we don't want it to be broadly used.
 * (Any printer will get this defined, but this should at least
 * make it harder for people to find.)
 */
#if defined(__GNUC__) && ((__GNUC__ * 100 + __GNUC_MINOR__) >= 409)
#define UNALIGNED_OK	__attribute__((no_sanitize_undefined))
#elif __has_attribute(no_sanitize)
#define UNALIGNED_OK	__attribute__((no_sanitize("undefined")))
#else
#define UNALIGNED_OK
#endif

#if (defined(__i386__) || defined(_M_IX86) || defined(__X86__) || defined(__x86_64__) || defined(_M_X64)) || \
    (defined(__arm__) || defined(_M_ARM) || defined(__aarch64__)) || \
    (defined(__m68k__) && (!defined(__mc68000__) && !defined(__mc68010__))) || \
    (defined(__ppc__) || defined(__ppc64__) || defined(_M_PPC) || defined(_ARCH_PPC) || defined(_ARCH_PPC64)) || \
    (defined(__s390__) || defined(__s390x__) || defined(__zarch__))
/*
 * The processor natively handles unaligned loads, so we can just
 * cast the pointer and fetch through it.
 *
 * XXX - are those all the x86 tests we need?
 * XXX - do we need to worry about ARMv1 through ARMv5, which didn't
 * support unaligned loads, and, if so, do we need to worry about all
 * of them, or just some of them, e.g. ARMv5?
 * XXX - are those the only 68k tests we need not to generated
 * unaligned accesses if the target is the 68000 or 68010?
 * XXX - are there any tests we don't need, because some definitions are for
 * compilers that also predefine the GCC symbols?
 * XXX - do we need to test for both 32-bit and 64-bit versions of those
 * architectures in all cases?
 */
UNALIGNED_OK static inline uint16_t
EXTRACT_SHORT(const void *p)
{
	return ((uint16_t)ntohs(*(const uint16_t *)(p)));
}

UNALIGNED_OK static inline uint32_t
EXTRACT_LONG(const void *p)
{
	return ((uint32_t)ntohl(*(const uint32_t *)(p)));
}

#elif PCAP_IS_AT_LEAST_GNUC_VERSION(2,0) && \
    (defined(__alpha) || defined(__alpha__) || \
     defined(__mips) || defined(__mips__))
/*
 * This is MIPS or Alpha, which don't natively handle unaligned loads,
 * but which have instructions that can help when doing unaligned
 * loads, and this is GCC 2.0 or later or a compiler that claims to
 * be GCC 2.0 or later, which we assume that mean we have
 * __attribute__((packed)), which we can use to convince the compiler
 * to generate those instructions.
 *
 * Declare packed structures containing a uint16_t and a uint32_t,
 * cast the pointer to point to one of those, and fetch through it;
 * the GCC manual doesn't appear to explicitly say that
 * __attribute__((packed)) causes the compiler to generate unaligned-safe
 * code, but it apppears to do so.
 *
 * We do this in case the compiler can generate code using those
 * instructions to do an unaligned load and pass stuff to "ntohs()" or
 * "ntohl()", which might be better than than the code to fetch the
 * bytes one at a time and assemble them.  (That might not be the
 * case on a little-endian platform, such as DEC's MIPS machines and
 * Alpha machines, where "ntohs()" and "ntohl()" might not be done
 * inline.)
 *
 * We do this only for specific architectures because, for example,
 * at least some versions of GCC, when compiling for 64-bit SPARC,
 * generate code that assumes alignment if we do this.
 *
 * XXX - add other architectures and compilers as possible and
 * appropriate.
 *
 * HP's C compiler, indicated by __HP_cc being defined, supports
 * "#pragma unaligned N" in version A.05.50 and later, where "N"
 * specifies a number of bytes at which the typedef on the next
 * line is aligned, e.g.
 *
 *	#pragma unalign 1
 *	typedef uint16_t unaligned_uint16_t;
 *
 * to define unaligned_uint16_t as a 16-bit unaligned data type.
 * This could be presumably used, in sufficiently recent versions of
 * the compiler, with macros similar to those below.  This would be
 * useful only if that compiler could generate better code for PA-RISC
 * or Itanium than would be generated by a bunch of shifts-and-ORs.
 *
 * DEC C, indicated by __DECC being defined, has, at least on Alpha,
 * an __unaligned qualifier that can be applied to pointers to get the
 * compiler to generate code that does unaligned loads and stores when
 * dereferencing the pointer in question.
 *
 * XXX - what if the native C compiler doesn't support
 * __attribute__((packed))?  How can we get it to generate unaligned
 * accesses for *specific* items?
 */
typedef struct {
	uint16_t	val;
} __attribute__((packed)) unaligned_uint16_t;

typedef struct {
	uint32_t	val;
} __attribute__((packed)) unaligned_uint32_t;

UNALIGNED_OK static inline uint16_t
EXTRACT_SHORT(const void *p)
{
	return ((uint16_t)ntohs(((const unaligned_uint16_t *)(p))->val));
}

UNALIGNED_OK static inline uint32_t
EXTRACT_LONG(const void *p)
{
	return ((uint32_t)ntohl(((const unaligned_uint32_t *)(p))->val));
}
#else
/*
 * This architecture doesn't natively support unaligned loads, and either
 * this isn't a GCC-compatible compiler, we don't have __attribute__,
 * or we do but we don't know of any better way with this instruction
 * set to do unaligned loads, so do unaligned loads of big-endian
 * quantities the hard way - fetch the bytes one at a time and
 * assemble them.
 */
#define EXTRACT_SHORT(p) \
	((uint16_t)(((uint16_t)(*((const uint8_t *)(p) + 0)) << 8) | \
	            ((uint16_t)(*((const uint8_t *)(p) + 1)) << 0)))
#define EXTRACT_LONG(p) \
	((uint32_t)(((uint32_t)(*((const uint8_t *)(p) + 0)) << 24) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 1)) << 16) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 2)) << 8) | \
	            ((uint32_t)(*((const uint8_t *)(p) + 3)) << 0)))
#endif /* unaligned access checks */

#ifdef __linux__
#include <linux/types.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#endif

enum {
        BPF_S_ANC_NONE,
        BPF_S_ANC_VLAN_TAG,
        BPF_S_ANC_VLAN_TAG_PRESENT,
};

/*
 * Execute the filter program starting at pc on the packet p
 * wirelen is the length of the original packet
 * buflen is the amount of data present
 * aux_data is auxiliary data, currently used only when interpreting
 * filters intended for the Linux kernel in cases where the kernel
 * rejects the filter; it contains VLAN tag information
 * For the kernel, p is assumed to be a pointer to an mbuf if buflen is 0,
 * in all other cases, p is a pointer to a buffer and buflen is its size.
 *
 * Thanks to Ani Sinha <ani@arista.com> for providing initial implementation
 */
u_int
bpf_filter_with_aux_data(const struct bpf_insn *pc, const u_char *p,
    u_int wirelen, u_int buflen, const struct bpf_aux_data *aux_data)
{
	register u_int32_t A, X;
	register bpf_u_int32 k;
	u_int32_t mem[BPF_MEMWORDS];

	if (pc == 0)
		/*
		 * No filter means accept all.
		 */
		return (u_int)-1;
	A = 0;
	X = 0;
	--pc;
	for (;;) {
		++pc;
		switch (pc->code) {

		default:
			abort();
		case BPF_RET|BPF_K:
			return (u_int)pc->k;

		case BPF_RET|BPF_A:
			return (u_int)A;

		case BPF_LD|BPF_W|BPF_ABS:
			k = pc->k;
			if (k > buflen || sizeof(int32_t) > buflen - k) {
				return 0;
			}
			A = EXTRACT_LONG(&p[k]);
			continue;

		case BPF_LD|BPF_H|BPF_ABS:
			k = pc->k;
			if (k > buflen || sizeof(int16_t) > buflen - k) {
				return 0;
			}
			A = EXTRACT_SHORT(&p[k]);
			continue;

		case BPF_LD|BPF_B|BPF_ABS:
			switch (pc->k) {

#if defined(SKF_AD_VLAN_TAG_PRESENT)
			case SKF_AD_OFF + SKF_AD_VLAN_TAG:
				if (!aux_data)
					return 0;
				A = aux_data->vlan_tag;
				break;

			case SKF_AD_OFF + SKF_AD_VLAN_TAG_PRESENT:
				if (!aux_data)
					return 0;
				A = aux_data->vlan_tag_present;
				break;
#endif
			default:
				k = pc->k;
				if (k >= buflen) {
					return 0;
				}
				A = p[k];
				break;
			}
			continue;

		case BPF_LD|BPF_W|BPF_LEN:
			A = wirelen;
			continue;

		case BPF_LDX|BPF_W|BPF_LEN:
			X = wirelen;
			continue;

		case BPF_LD|BPF_W|BPF_IND:
			k = X + pc->k;
			if (pc->k > buflen || X > buflen - pc->k ||
			    sizeof(int32_t) > buflen - k) {
				return 0;
			}
			A = EXTRACT_LONG(&p[k]);
			continue;

		case BPF_LD|BPF_H|BPF_IND:
			k = X + pc->k;
			if (X > buflen || pc->k > buflen - X ||
			    sizeof(int16_t) > buflen - k) {
				return 0;
			}
			A = EXTRACT_SHORT(&p[k]);
			continue;

		case BPF_LD|BPF_B|BPF_IND:
			k = X + pc->k;
			if (pc->k >= buflen || X >= buflen - pc->k) {
				return 0;
			}
			A = p[k];
			continue;

		case BPF_LDX|BPF_MSH|BPF_B:
			k = pc->k;
			if (k >= buflen) {
				return 0;
			}
			X = (p[pc->k] & 0xf) << 2;
			continue;

		case BPF_LD|BPF_IMM:
			A = pc->k;
			continue;

		case BPF_LDX|BPF_IMM:
			X = pc->k;
			continue;

		case BPF_LD|BPF_MEM:
			A = mem[pc->k];
			continue;

		case BPF_LDX|BPF_MEM:
			X = mem[pc->k];
			continue;

		case BPF_ST:
			mem[pc->k] = A;
			continue;

		case BPF_STX:
			mem[pc->k] = X;
			continue;

		case BPF_JMP|BPF_JA:
			/*
			 * XXX - we currently implement "ip6 protochain"
			 * with backward jumps, so sign-extend pc->k.
			 */
			pc += (bpf_int32)pc->k;
			continue;

		case BPF_JMP|BPF_JGT|BPF_K:
			pc += (A > pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JGE|BPF_K:
			pc += (A >= pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JEQ|BPF_K:
			pc += (A == pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JSET|BPF_K:
			pc += (A & pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JGT|BPF_X:
			pc += (A > X) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JGE|BPF_X:
			pc += (A >= X) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JEQ|BPF_X:
			pc += (A == X) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JSET|BPF_X:
			pc += (A & X) ? pc->jt : pc->jf;
			continue;

		case BPF_ALU|BPF_ADD|BPF_X:
			A += X;
			continue;

		case BPF_ALU|BPF_SUB|BPF_X:
			A -= X;
			continue;

		case BPF_ALU|BPF_MUL|BPF_X:
			A *= X;
			continue;

		case BPF_ALU|BPF_DIV|BPF_X:
			if (X == 0)
				return 0;
			A /= X;
			continue;

		case BPF_ALU|BPF_MOD|BPF_X:
			if (X == 0)
				return 0;
			A %= X;
			continue;

		case BPF_ALU|BPF_AND|BPF_X:
			A &= X;
			continue;

		case BPF_ALU|BPF_OR|BPF_X:
			A |= X;
			continue;

		case BPF_ALU|BPF_XOR|BPF_X:
			A ^= X;
			continue;

		case BPF_ALU|BPF_LSH|BPF_X:
			A <<= X;
			continue;

		case BPF_ALU|BPF_RSH|BPF_X:
			A >>= X;
			continue;

		case BPF_ALU|BPF_ADD|BPF_K:
			A += pc->k;
			continue;

		case BPF_ALU|BPF_SUB|BPF_K:
			A -= pc->k;
			continue;

		case BPF_ALU|BPF_MUL|BPF_K:
			A *= pc->k;
			continue;

		case BPF_ALU|BPF_DIV|BPF_K:
			A /= pc->k;
			continue;

		case BPF_ALU|BPF_MOD|BPF_K:
			A %= pc->k;
			continue;

		case BPF_ALU|BPF_AND|BPF_K:
			A &= pc->k;
			continue;

		case BPF_ALU|BPF_OR|BPF_K:
			A |= pc->k;
			continue;

		case BPF_ALU|BPF_XOR|BPF_K:
			A ^= pc->k;
			continue;

		case BPF_ALU|BPF_LSH|BPF_K:
			A <<= pc->k;
			continue;

		case BPF_ALU|BPF_RSH|BPF_K:
			A >>= pc->k;
			continue;

		case BPF_ALU|BPF_NEG:
			/*
			 * Most BPF arithmetic is unsigned, but negation
			 * can't be unsigned; throw some casts to
			 * specify what we're trying to do.
			 */
			A = (u_int32_t)(-(int32_t)A);
			continue;

		case BPF_MISC|BPF_TAX:
			X = A;
			continue;

		case BPF_MISC|BPF_TXA:
			A = X;
			continue;
		}
	}
}

u_int
bpf_filter(const struct bpf_insn *pc, const u_char *p, u_int wirelen,
    u_int buflen)
{
	return bpf_filter_with_aux_data(pc, p, wirelen, buflen, NULL);
}


/*
 * Return true if the 'fcode' is a valid filter program.
 * The constraints are that each jump be forward and to a valid
 * code, that memory accesses are within valid ranges (to the
 * extent that this can be checked statically; loads of packet
 * data have to be, and are, also checked at run time), and that
 * the code terminates with either an accept or reject.
 *
 * The kernel needs to be able to verify an application's filter code.
 * Otherwise, a bogus program could easily crash the system.
 */
int
bpf_validate(const struct bpf_insn *f, int len)
{
	u_int i, from;
	const struct bpf_insn *p;

	if (len < 1)
		return 0;

	for (i = 0; i < (u_int)len; ++i) {
		p = &f[i];
		switch (BPF_CLASS(p->code)) {
		/*
		 * Check that memory operations use valid addresses.
		 */
		case BPF_LD:
		case BPF_LDX:
			switch (BPF_MODE(p->code)) {
			case BPF_IMM:
				break;
			case BPF_ABS:
			case BPF_IND:
			case BPF_MSH:
				/*
				 * There's no maximum packet data size
				 * in userland.  The runtime packet length
				 * check suffices.
				 */
				break;
			case BPF_MEM:
				if (p->k >= BPF_MEMWORDS)
					return 0;
				break;
			case BPF_LEN:
				break;
			default:
				return 0;
			}
			break;
		case BPF_ST:
		case BPF_STX:
			if (p->k >= BPF_MEMWORDS)
				return 0;
			break;
		case BPF_ALU:
			switch (BPF_OP(p->code)) {
			case BPF_ADD:
			case BPF_SUB:
			case BPF_MUL:
			case BPF_OR:
			case BPF_AND:
			case BPF_XOR:
			case BPF_LSH:
			case BPF_RSH:
			case BPF_NEG:
				break;
			case BPF_DIV:
			case BPF_MOD:
				/*
				 * Check for constant division or modulus
				 * by 0.
				 */
				if (BPF_SRC(p->code) == BPF_K && p->k == 0)
					return 0;
				break;
			default:
				return 0;
			}
			break;
		case BPF_JMP:
			/*
			 * Check that jumps are within the code block,
			 * and that unconditional branches don't go
			 * backwards as a result of an overflow.
			 * Unconditional branches have a 32-bit offset,
			 * so they could overflow; we check to make
			 * sure they don't.  Conditional branches have
			 * an 8-bit offset, and the from address is <=
			 * BPF_MAXINSNS, and we assume that BPF_MAXINSNS
			 * is sufficiently small that adding 255 to it
			 * won't overflow.
			 *
			 * We know that len is <= BPF_MAXINSNS, and we
			 * assume that BPF_MAXINSNS is < the maximum size
			 * of a u_int, so that i + 1 doesn't overflow.
			 *
			 * For userland, we don't know that the from
			 * or len are <= BPF_MAXINSNS, but we know that
			 * from <= len, and, except on a 64-bit system,
			 * it's unlikely that len, if it truly reflects
			 * the size of the program we've been handed,
			 * will be anywhere near the maximum size of
			 * a u_int.  We also don't check for backward
			 * branches, as we currently support them in
			 * userland for the protochain operation.
			 */
			from = i + 1;
			switch (BPF_OP(p->code)) {
			case BPF_JA:
				if (from + p->k >= (u_int)len)
					return 0;
				break;
			case BPF_JEQ:
			case BPF_JGT:
			case BPF_JGE:
			case BPF_JSET:
				if (from + p->jt >= (u_int)len || from + p->jf >= (u_int)len)
					return 0;
				break;
			default:
				return 0;
			}
			break;
		case BPF_RET:
			break;
		case BPF_MISC:
			break;
		default:
			return 0;
		}
	}
	return BPF_CLASS(f[len - 1].code) == BPF_RET;
}
