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

#include <config.h> // for "pcap-int.h"
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
#include "pcap-int.h" // PCAP_ISDIGIT() etc.

/*
 * For functions that take an int it is not practicable to test every possible
 * value, so use a smaller interval.
 */
#define ENUMERATE_INT_MIN INT16_MIN
#define ENUMERATE_INT_MAX INT16_MAX

static const char *program_name;

#define BPF_IMAGE_FORMAT "%-50s; 0x%04x\n"
static int
enumerate_bpf_space(bool (*is_valid)(const struct bpf_insn *))
{
	struct bpf_insn insn = {
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
	for (insn.code = 0; ; insn.code++) {
		if (BPF_CLASS(insn.code) != BPF_RET && is_valid(&insn))
			printf(BPF_IMAGE_FORMAT, bpf_image(&insn, found++),
			       insn.code);
		if (insn.code == UINT16_MAX)
			break;
	}
	for (insn.code = 0; ; insn.code++) {
		if (BPF_CLASS(insn.code) == BPF_RET && is_valid(&insn))
			printf(BPF_IMAGE_FORMAT, bpf_image(&insn, found++),
			       insn.code);
		if (insn.code == UINT16_MAX)
			break;
	}
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

static bool
insn_without_k(const struct bpf_insn *insn)
{
	return pcapint_opcode_without_k(insn->code);
}

static int
enumerate_pcapint_opcode_without_k(void)
{
	return enumerate_bpf_space(insn_without_k);
}

/*
 * pcap_statustostr() returns a string for any argument, so the results must
 * be filtered.
 */
#define UNKNOWN_ERROR "Unknown error: -"
#define UNKNOWN_WARNING "Unknown warning: "
static int
enumerate_pcap_statustostr(void)
{
	for (int i = ENUMERATE_INT_MIN; i <= ENUMERATE_INT_MAX; i++) {
		const char *errstr = pcap_statustostr(i);
		if ((i < 0 && strncmp(errstr, UNKNOWN_ERROR, sizeof(UNKNOWN_ERROR) - 1)) ||
		     i == 0 ||
		    (i > 0 && strncmp(errstr, UNKNOWN_WARNING, sizeof(UNKNOWN_WARNING) - 1)))
			printf("%d: %s\n", i, errstr);
	}
	return EX_OK;
}

/*
 * Enumerate by attempting a number-to-string translation, for every successful
 * (i.e. the string is not NULL) translation require a successful (i.e. the
 * number is not PCAP_ERROR) string-to-number translation and the two numbers
 * to be equal.  This does not prove a one-to-one correspondence, even in the
 * case-insensitive string comparison sense -- if a string translates to a
 * number, but the number does not translate to the string (e.g. "USER2" -> 149
 * -> "PKTAP" on macOS), finding any such strings would be out of scope of a
 * quick test.  Also -1 cannot be a valid number.
 */
static int
enumerate_and_verify(const char *(*tostr)(int), int (*fromstr)(const char *))
{
	int ret = EX_OK;
	for (int i = ENUMERATE_INT_MIN; i <= ENUMERATE_INT_MAX; i++) {
		const char *str = tostr(i);
		if (! str)
			continue;
		printf("%d: %s\n", i, str);
		const int inverse = fromstr(str);
		if (inverse == PCAP_ERROR) {
			fprintf(stderr,
			        "ERROR: \"%s\" failed to translate\n", str);
			ret = EX_SOFTWARE;
		} else if (inverse != i) {
			fprintf(stderr,
			        "ERROR: \"%s\" translated to %d, not %d\n",
			        str, inverse, i);
			ret = EX_SOFTWARE;
		}
	}
	return ret;
}

static int
enumerate_pcap_datalink_val_to_name(void)
{
	return enumerate_and_verify(pcap_datalink_val_to_name,
	                            pcap_datalink_name_to_val);
}

static int
enumerate_pcap_tstamp_type_val_to_name(void)
{
	return enumerate_and_verify(pcap_tstamp_type_val_to_name,
	                            pcap_tstamp_type_name_to_val);
}

static void
print_int_as_char(const int i)
{
	if (0 <= i && i <= INT8_MAX)
		printf("%d: '%c'\n", i, (char)i);
	else
		printf("%d: ???\n", i);
}

static int
enumerate_PCAP_ISDIGIT(void)
{
	for (int i = ENUMERATE_INT_MIN; i <= ENUMERATE_INT_MAX; i++)
		if (PCAP_ISDIGIT(i))
			print_int_as_char(i);
	return EX_OK;
}

static int
enumerate_PCAP_ISXDIGIT(void)
{
	for (int i = ENUMERATE_INT_MIN; i <= ENUMERATE_INT_MAX; i++)
		if (PCAP_ISXDIGIT(i))
			print_int_as_char(i);
	return EX_OK;
}

static int
enumerate_PCAP_ISUPPER(void)
{
	for (int i = ENUMERATE_INT_MIN; i <= ENUMERATE_INT_MAX; i++)
		if (PCAP_ISUPPER(i))
			print_int_as_char(i);
	return EX_OK;
}

static int
enumerate_PCAP_ISLOWER(void)
{
	for (int i = ENUMERATE_INT_MIN; i <= ENUMERATE_INT_MAX; i++)
		if (PCAP_ISLOWER(i))
			print_int_as_char(i);
	return EX_OK;
}

static int
enumerate_PCAP_ISALPHA(void)
{
	for (int i = ENUMERATE_INT_MIN; i <= ENUMERATE_INT_MAX; i++)
		if (PCAP_ISALPHA(i))
			print_int_as_char(i);
	return EX_OK;
}

static int
enumerate_PCAP_ISALNUM(void)
{
	for (int i = ENUMERATE_INT_MIN; i <= ENUMERATE_INT_MAX; i++)
		if (PCAP_ISALNUM(i))
			print_int_as_char(i);
	return EX_OK;
}

static const struct enumfunc {
	const char *name;
	int (*runner)(void);
} enumfuncs[] = {
	{
		"bpf_image",
		enumerate_bpf_image,
	},
	{
		"pcap_statustostr",
		enumerate_pcap_statustostr,
	},
	{
		"pcapint_opcode_without_k",
		enumerate_pcapint_opcode_without_k,
	},
	{
		"pcap_datalink_val_to_name",
		enumerate_pcap_datalink_val_to_name,
	},
	{
		"pcap_tstamp_type_val_to_name",
		enumerate_pcap_tstamp_type_val_to_name,
	},
	{
		"PCAP_ISDIGIT",
		enumerate_PCAP_ISDIGIT,
	},
	{
		"PCAP_ISXDIGIT",
		enumerate_PCAP_ISXDIGIT,
	},
	{
		"PCAP_ISUPPER",
		enumerate_PCAP_ISUPPER,
	},
	{
		"PCAP_ISLOWER",
		enumerate_PCAP_ISLOWER,
	},
	{
		"PCAP_ISALPHA",
		enumerate_PCAP_ISALPHA,
	},
	{
		"PCAP_ISALNUM",
		enumerate_PCAP_ISALNUM,
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
	fprintf(f, "  %3u: Unexpected error in the results.\n", EX_SOFTWARE);
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
