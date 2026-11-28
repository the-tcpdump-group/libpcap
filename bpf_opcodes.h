/*
 * Copyright (c) 2026
 *	The Tcpdump Group and contributors.  All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef BPF_OPCODES_H
#define BPF_OPCODES_H

#include "pcap/bpf.h"

/*
 * Valid BPF opcodes comprise one (e.g. BPF_ST), two (e.g. BPF_RET|BPF_K) or
 * three (e.g. BPF_ALU|BPF_ADD|BPF_X) constants.  Even constants that are only
 * nominally specified because they are defined to zero (e.g. BPF_K) have
 * meaning in the source code and the ISA.  Instead of ORing the constants in
 * place use the following two macros: so long as the code uses a correct
 * macro, not specifying the correct number of constants will be a compile-time
 * error.  Groups of related BPF opcodes can wrap these with their own macros
 * to factor common parts out.
 */
#define OPCODE_2ARY(x1, x2) ((x1) | (x2))
#define OPCODE_3ARY(x1, x2, x3) ((x1) | (x2) | (x3))

/*
 * Load instruction opcodes comprise three constants.
 */
#define OPCODE_LOAD(size, mode) OPCODE_3ARY(BPF_LD, (size), (mode))
#define OPCODE_LOADX(size, mode) OPCODE_3ARY(BPF_LDX, (size), (mode))

/*
 * Store instruction opcodes are single constants.
 */
#define OPCODE_ST_M BPF_ST
#define OPCODE_STX_M BPF_STX

/*
 * Branch instruction opcodes comprise two (for "ja L") or three (for
 * everything else) constants.
 */
#define OPCODE_JA OPCODE_2ARY(BPF_JMP, BPF_JA)
#define OPCODE_BRANCH_X(jtype) OPCODE_3ARY(BPF_JMP, (jtype), BPF_X)
#define OPCODE_BRANCH_K(jtype) OPCODE_3ARY(BPF_JMP, (jtype), BPF_K)

/*
 * ALU instruction opcodes comprise two (for "neg") or three (for everything
 * else) constants.
 */
#define OPCODE_NEG OPCODE_2ARY(BPF_ALU, BPF_NEG)
#define OPCODE_ALU_X(op) OPCODE_3ARY(BPF_ALU, (op), BPF_X)
#define OPCODE_ALU_K(op) OPCODE_3ARY(BPF_ALU, (op), BPF_K)

/*
 * Return instruction opcodes always comprise two constants.
 */
#define OPCODE_RET(rval) OPCODE_2ARY(BPF_RET, (rval))

/*
 * Miscellaneous instruction opcodes always comprise two constants.
 */
#define OPCODE_MISC(op) OPCODE_2ARY(BPF_MISC, (op))

#endif // BPF_OPCODES_H
