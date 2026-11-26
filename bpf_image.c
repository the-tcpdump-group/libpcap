/*
 * Copyright (c) 1990, 1991, 1992, 1994, 1995, 1996
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <config.h>

#include <pcap-types.h>

#include <stdio.h>
#include <string.h>

#ifdef __linux__
#include <linux/types.h>
#include <linux/if_packet.h>
#include <linux/filter.h>

/*
 * We want our versions of these #defines, not Linux's version.
 * (The two should be the same; if not, we have a problem; all BPF
 * implementations *should* be source-compatible supersets of ours.)
 */
#undef BPF_STMT
#undef BPF_JUMP
#endif

#include "pcap-int.h"

#include "thread-local.h"
#include "bpf_opcodes.h"

#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#ifdef SKF_AD_OFF
/*
 * Symbolic names for offsets that refer to the special Linux BPF locations.
 */
static const char *offsets[SKF_AD_MAX] = {
#ifdef SKF_AD_PROTOCOL
	[SKF_AD_PROTOCOL] = "proto",
#endif
#ifdef SKF_AD_PKTTYPE
	[SKF_AD_PKTTYPE] = "type",
#endif
#ifdef SKF_AD_IFINDEX
	[SKF_AD_IFINDEX] = "ifidx",
#endif
#ifdef SKF_AD_NLATTR
	[SKF_AD_NLATTR] = "nla",
#endif
#ifdef SKF_AD_NLATTR_NEST
	[SKF_AD_NLATTR_NEST] = "nlan",
#endif
#ifdef SKF_AD_MARK
	[SKF_AD_MARK] = "mark",
#endif
#ifdef SKF_AD_QUEUE
	[SKF_AD_QUEUE] = "queue",
#endif
#ifdef SKF_AD_HATYPE
	[SKF_AD_HATYPE] = "hatype",
#endif
#ifdef SKF_AD_RXHASH
	[SKF_AD_RXHASH] = "rxhash",
#endif
#ifdef SKF_AD_CPU
	[SKF_AD_CPU] = "cpu",
#endif
#ifdef SKF_AD_ALU_XOR_X
	[SKF_AD_ALU_XOR_X] = "xor_x",
#endif
#ifdef SKF_AD_VLAN_TAG
	[SKF_AD_VLAN_TAG] = "vlan_tci",
#endif
#ifdef SKF_AD_VLAN_TAG_PRESENT
	[SKF_AD_VLAN_TAG_PRESENT] = "vlanp",
#endif
#ifdef SKF_AD_PAY_OFFSET
	[SKF_AD_PAY_OFFSET] = "poff",
#endif
#ifdef SKF_AD_RANDOM
	[SKF_AD_RANDOM] = "random",
#endif
#ifdef SKF_AD_VLAN_TPID
	[SKF_AD_VLAN_TPID] = "vlan_tpid"
#endif
};
#endif

static void
bpf_print_abs_load_operand(char *buf, size_t bufsize, const struct bpf_insn *p)
{
#ifdef SKF_AD_OFF
	const char *sym;

	/*
	 * It's an absolute load.
	 * Is the offset a special Linux offset that we know about?
	 */
	if (p->k >= (bpf_u_int32)SKF_AD_OFF &&
	    p->k < (bpf_u_int32)(SKF_AD_OFF + SKF_AD_MAX) &&
	    (sym = offsets[p->k - (bpf_u_int32)SKF_AD_OFF]) != NULL) {
		/*
		 * Yes.  Print the offset symbolically.
		 */
		(void)snprintf(buf, bufsize, "[%s]", sym);
	} else
#endif
		(void)snprintf(buf, bufsize, "[%d]", p->k);
}

char *
bpf_image(const struct bpf_insn *p, int n)
{
	const char *op;
	static thread_local char image[256];
	char operand_buf[64];
	const char *operand;

	switch (p->code) {

	default:
		op = "unimp";
		(void)snprintf(operand_buf, sizeof operand_buf, "0x%x", p->code);
		operand = operand_buf;
		break;

	case OPCODE_RET(BPF_K):
		op = "ret";
		(void)snprintf(operand_buf, sizeof operand_buf, "#%d", p->k);
		operand = operand_buf;
		break;

	case OPCODE_RET(BPF_A):
		op = "ret";
		operand = "";
		break;

	case OPCODE_LOAD(BPF_W, BPF_ABS):
		op = "ld";
		bpf_print_abs_load_operand(operand_buf, sizeof operand_buf, p);
		operand = operand_buf;
		break;

	case OPCODE_LOAD(BPF_H, BPF_ABS):
		op = "ldh";
		bpf_print_abs_load_operand(operand_buf, sizeof operand_buf, p);
		operand = operand_buf;
		break;

	case OPCODE_LOAD(BPF_B, BPF_ABS):
		op = "ldb";
		bpf_print_abs_load_operand(operand_buf, sizeof operand_buf, p);
		operand = operand_buf;
		break;

	case OPCODE_LOAD(BPF_W, BPF_LEN):
		op = "ld";
		operand = "#pktlen";
		break;

	case OPCODE_LOADX(BPF_W, BPF_LEN):
		op = "ldx";
		operand = "#pktlen";
		break;

	case OPCODE_LOAD(BPF_W, BPF_IND):
		op = "ld";
		(void)snprintf(operand_buf, sizeof operand_buf, "[x + %d]", p->k);
		operand = operand_buf;
		break;

	case OPCODE_LOAD(BPF_H, BPF_IND):
		op = "ldh";
		(void)snprintf(operand_buf, sizeof operand_buf, "[x + %d]", p->k);
		operand = operand_buf;
		break;

	case OPCODE_LOAD(BPF_B, BPF_IND):
		op = "ldb";
		(void)snprintf(operand_buf, sizeof operand_buf, "[x + %d]", p->k);
		operand = operand_buf;
		break;

	case OPCODE_LOAD(BPF_W, BPF_IMM):
		op = "ld";
		(void)snprintf(operand_buf, sizeof operand_buf, "#0x%x", p->k);
		operand = operand_buf;
		break;

	case OPCODE_LOADX(BPF_W, BPF_IMM):
		op = "ldx";
		(void)snprintf(operand_buf, sizeof operand_buf, "#0x%x", p->k);
		operand = operand_buf;
		break;

	case OPCODE_LOADX(BPF_B, BPF_MSH):
		op = "ldxb";
		(void)snprintf(operand_buf, sizeof operand_buf, "4*([%d]&0xf)", p->k);
		operand = operand_buf;
		break;

	case OPCODE_LOAD(BPF_W, BPF_MEM):
		op = "ld";
		(void)snprintf(operand_buf, sizeof operand_buf, "M[%d]", p->k);
		operand = operand_buf;
		break;

	case OPCODE_LOADX(BPF_W, BPF_MEM):
		op = "ldx";
		(void)snprintf(operand_buf, sizeof operand_buf, "M[%d]", p->k);
		operand = operand_buf;
		break;

	case OPCODE_ST_M:
		op = "st";
		(void)snprintf(operand_buf, sizeof operand_buf, "M[%d]", p->k);
		operand = operand_buf;
		break;

	case OPCODE_STX_M:
		op = "stx";
		(void)snprintf(operand_buf, sizeof operand_buf, "M[%d]", p->k);
		operand = operand_buf;
		break;

	case OPCODE_JA:
		op = "ja";
		(void)snprintf(operand_buf, sizeof operand_buf, "%d", n + 1 + p->k);
		operand = operand_buf;
		break;

	case OPCODE_BRANCH_K(BPF_JGT):
		op = "jgt";
		(void)snprintf(operand_buf, sizeof operand_buf, "#0x%x", p->k);
		operand = operand_buf;
		break;

	case OPCODE_BRANCH_K(BPF_JGE):
		op = "jge";
		(void)snprintf(operand_buf, sizeof operand_buf, "#0x%x", p->k);
		operand = operand_buf;
		break;

	case OPCODE_BRANCH_K(BPF_JEQ):
		op = "jeq";
		(void)snprintf(operand_buf, sizeof operand_buf, "#0x%x", p->k);
		operand = operand_buf;
		break;

	case OPCODE_BRANCH_K(BPF_JSET):
		op = "jset";
		(void)snprintf(operand_buf, sizeof operand_buf, "#0x%x", p->k);
		operand = operand_buf;
		break;

	case OPCODE_BRANCH_X(BPF_JGT):
		op = "jgt";
		operand = "x";
		break;

	case OPCODE_BRANCH_X(BPF_JGE):
		op = "jge";
		operand = "x";
		break;

	case OPCODE_BRANCH_X(BPF_JEQ):
		op = "jeq";
		operand = "x";
		break;

	case OPCODE_BRANCH_X(BPF_JSET):
		op = "jset";
		operand = "x";
		break;

	case OPCODE_ALU_X(BPF_ADD):
		op = "add";
		operand = "x";
		break;

	case OPCODE_ALU_X(BPF_SUB):
		op = "sub";
		operand = "x";
		break;

	case OPCODE_ALU_X(BPF_MUL):
		op = "mul";
		operand = "x";
		break;

	case OPCODE_ALU_X(BPF_DIV):
		op = "div";
		operand = "x";
		break;

	case OPCODE_ALU_X(BPF_MOD):
		op = "mod";
		operand = "x";
		break;

	case OPCODE_ALU_X(BPF_AND):
		op = "and";
		operand = "x";
		break;

	case OPCODE_ALU_X(BPF_OR):
		op = "or";
		operand = "x";
		break;

	case OPCODE_ALU_X(BPF_XOR):
		op = "xor";
		operand = "x";
		break;

	case OPCODE_ALU_X(BPF_LSH):
		op = "lsh";
		operand = "x";
		break;

	case OPCODE_ALU_X(BPF_RSH):
		op = "rsh";
		operand = "x";
		break;

	case OPCODE_ALU_K(BPF_ADD):
		op = "add";
		(void)snprintf(operand_buf, sizeof operand_buf, "#%d", p->k);
		operand = operand_buf;
		break;

	case OPCODE_ALU_K(BPF_SUB):
		op = "sub";
		(void)snprintf(operand_buf, sizeof operand_buf, "#%d", p->k);
		operand = operand_buf;
		break;

	case OPCODE_ALU_K(BPF_MUL):
		op = "mul";
		(void)snprintf(operand_buf, sizeof operand_buf, "#%d", p->k);
		operand = operand_buf;
		break;

	case OPCODE_ALU_K(BPF_DIV):
		op = "div";
		(void)snprintf(operand_buf, sizeof operand_buf, "#%d", p->k);
		operand = operand_buf;
		break;

	case OPCODE_ALU_K(BPF_MOD):
		op = "mod";
		(void)snprintf(operand_buf, sizeof operand_buf, "#%d", p->k);
		operand = operand_buf;
		break;

	case OPCODE_ALU_K(BPF_AND):
		op = "and";
		(void)snprintf(operand_buf, sizeof operand_buf, "#0x%x", p->k);
		operand = operand_buf;
		break;

	case OPCODE_ALU_K(BPF_OR):
		op = "or";
		(void)snprintf(operand_buf, sizeof operand_buf, "#0x%x", p->k);
		operand = operand_buf;
		break;

	case OPCODE_ALU_K(BPF_XOR):
		op = "xor";
		(void)snprintf(operand_buf, sizeof operand_buf, "#0x%x", p->k);
		operand = operand_buf;
		break;

	case OPCODE_ALU_K(BPF_LSH):
		op = "lsh";
		(void)snprintf(operand_buf, sizeof operand_buf, "#%d", p->k);
		operand = operand_buf;
		break;

	case OPCODE_ALU_K(BPF_RSH):
		op = "rsh";
		(void)snprintf(operand_buf, sizeof operand_buf, "#%d", p->k);
		operand = operand_buf;
		break;

	case OPCODE_NEG:
		op = "neg";
		operand = "";
		break;

	case OPCODE_MISC(BPF_TAX):
		op = "tax";
		operand = "";
		break;

	case OPCODE_MISC(BPF_TXA):
		op = "txa";
		operand = "";
		break;
	}
	if (BPF_CLASS(p->code) == BPF_JMP && BPF_OP(p->code) != BPF_JA) {
		(void)snprintf(image, sizeof image,
			      "(%03d) %-8s %-16s jt %d\tjf %d",
			      n, op, operand, n + 1 + p->jt, n + 1 + p->jf);
	} else if (! *operand) {
		(void)snprintf(image, sizeof image,
			      "(%03d) %-s",
			      n, op);
	} else {
		(void)snprintf(image, sizeof image,
			      "(%03d) %-8s %s",
			      n, op, operand);
	}
	return image;
}
