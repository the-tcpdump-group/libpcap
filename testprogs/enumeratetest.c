/*
 * Copyright (c) 2026
 *	The Tcpdump Group and contributors.  All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#ifdef _WIN32
  #include "getopt.h"
#else
  #include <unistd.h>
#endif

#if defined(_WIN32) || defined(__QNX__)
  #include "unix.h"
#else
  #include <sysexits.h>
#endif

#include "pcap/pcap.h"
#include "pcap/bpf.h"

static const char *program_name;

#define BPF_IMAGE_FORMAT "%-50s; 0x%04x\n"
static int
enumerate_bpf_space(bool (*is_valid)(const struct bpf_insn *))
{
	struct bpf_insn insn = {
		.code = 0x0000,
		/*
		 * Use small offsets to keep the resulting jump labels within
		 * the resulting mock program.
		 */
		.jt = 1,
		.jf = 0,
		/*
		 * Use a value of k that for lsh/rsh is a valid number of bits
		 * and for ld/ldx/st/stx is a valid scratch memory register
		 * number.
		 */
		.k = 15,
	};
	uint16_t found = 0;
	do {
		if (BPF_CLASS(insn.code) != BPF_RET && is_valid(&insn))
			printf(BPF_IMAGE_FORMAT, bpf_image(&insn, found++),
			       insn.code);
	} while (insn.code++ != UINT16_MAX);
	do {
		if (BPF_CLASS(insn.code) == BPF_RET && is_valid(&insn))
			printf(BPF_IMAGE_FORMAT, bpf_image(&insn, found++),
			       insn.code);
	} while (insn.code++ != UINT16_MAX);
	return EX_OK;
}

#define BPF_IMAGE_UNIMPL "(000) unimp "
static bool
valid_bpf_image(const struct bpf_insn *insn)
{
	return !! strncmp(bpf_image(insn, 0), BPF_IMAGE_UNIMPL,
	                  sizeof(BPF_IMAGE_UNIMPL) - 1);
}

static int
enumerate_bpf_image(void)
{
	return enumerate_bpf_space(valid_bpf_image);
}

static const struct enumfunc {
	const char *name;
	int (*runner)(void);
} enumfuncs[] = {
	{
		"bpf_image",
		enumerate_bpf_image,
	},
	{NULL, NULL}
};

static void
usage_short(FILE *f)
{
	fprintf(f, "%s, with %s\n", program_name, pcap_lib_version());
	fprintf(f, "Usage: %s <name>\n", program_name);
	fprintf(f, "       (print all elements of an enumeration)\n");
	fprintf(f, "   or: %s -h\n", program_name);
	fprintf(f, "       (print the detailed help screen)\n");
}

static void
usage_long(FILE *f)
{
	usage_short(f);
	fprintf(f, "\nSupported valid invocations:\n");
	for (const struct enumfunc *ef = enumfuncs; ef->runner; ef++)
		printf("       %s %s\n", program_name, ef->name);
	fprintf(f, "\nExit status codes:\n");
	fprintf(f, "  %3u: Success.\n", EX_OK);
	fprintf(f, "  %3u: Invalid command-line argument(s).\n", EX_USAGE);
}

int
main(int argc, char **argv)
{
	{
		const char *cp = strrchr(argv[0], '/');
		program_name = cp ? cp + 1 : argv[0];
	}

	{
		int op;
		opterr = 0;

		// Use "if", same as in translatetest.c.
		if ((op = getopt(argc, argv, "h")) != -1) {
			switch (op) {
			case 'h':
				usage_long(stdout);
				exit(EX_OK);
			default:
				usage_short(stderr);
				exit(EX_USAGE);
			}
		}
	}

	argc -= optind;
	argv += optind;
	if (argc == 1)
		for (const struct enumfunc *ef = enumfuncs; ef->runner; ef++)
			if (! strcmp(ef->name, argv[0]))
				exit(ef->runner());
	usage_short(stderr);
	exit(EX_USAGE);
}
