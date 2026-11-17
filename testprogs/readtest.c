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

#include <config.h>

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>

#ifdef _WIN32
  #include "getopt.h"
#else
  #include <unistd.h>
#endif

#include <errno.h>

#include "varattrs.h"

#include "pcap/funcattrs.h"

#include "test-util.h"
#include "portability.h"

static const char *program_name;

/* Forwards */
static void PCAP_NORETURN usage(FILE *);

static pcap_t *pd;

static void
cleanup(void)
{
	if (pd)
		pcap_close(pd);
}

struct callback_info {
	int	nsec_precision;	/* time stamps have nanosecond precision */
};

/*
 * Print packet metadata and data.
 */
static void
print_packet(u_char *user _U_, const struct pcap_pkthdr *h, const u_char *p)
{
	/*
	 * Print the header info.
	 */
	printf("secs %" PRId64 ", frac %ld, caplen %u, len %u:\n",
	    (int64_t)h->ts.tv_sec, (long)h->ts.tv_usec, h->caplen, h->len);

	/*
	 * Print the packet data.
	 */
	bpf_u_int32 i = 0;
	while (i < h->caplen) {
		for (bpf_u_int32 j = 0; j < 16 && i < h->caplen; i++, j++)
			printf(" %02x", p[i]);
		printf("\n");
	}
}

/*
 * Test the code that reads savefiles.
 *
 * Writes out information about the file, followed by the timestamp,
 * captured length, on-the-network length, and raw hex data of each
 * packet.
 *
 * Future possibilities:
 *
 *  print only the packet metadata by default, and print the data
 *  with -v;
 *
 *  have an option to request microsecond or nanosecond time stamps;
 *
 *  if we add APIs to fully support pcapng, an option to request
 *  that it use that API and that it print the details of each
 *  block that it reads, including options.
 */
int
main(int argc, char **argv)
{
	int op;
	int status;
	union {
		uint32_t uint;
		uint8_t bytes[4];
	} byte_order_magic = { .bytes = { 0xa1, 0xb2, 0xc3, 0xd4 } };
	const char *our_byte_order, *swapped_byte_order;

	if (atexit(cleanup))
		error(EX_OSERR, "atexit() failed: %s", pcap_strerror(errno));

	program_name = set_program_name(argv[0]);

	opterr = 0;
	while ((op = getopt(argc, argv, "h")) != -1) {
		switch (op) {

		case 'h':
			usage(stdout);
			/* NOTREACHED */

		default:
			usage(stderr);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;
	if (argc == 0) {
		usage(stderr);
		/* NOTREACHED */
	}

	/*
	 * Determine our byte order, so we can report the byte order of
	 * the file, which is independent of the host reading it,
	 * rather than whether it's byte-swapped, which depends on the
	 * host reading it.
	 *
	 * That way, both big-endian and little-endian hosts will display
	 * the byte order of a given file the same.
	 */
	if (byte_order_magic.uint == 0xa1b2c3d4) {
		our_byte_order = "big-endian";
		swapped_byte_order = "little-endian";
	} else {
		our_byte_order = "little-endian";
		swapped_byte_order = "big-endian";
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	pd = pcap_open_offline(argv[0], errbuf);
	if (pd == NULL)
		error(EX_NOINPUT, "Failed opening: %s", errbuf);

	printf("pcap version %d.%d, %s, linktype %s, snaplen %d\n",
	    pcap_major_version(pd), pcap_minor_version(pd),
	    pcap_is_swapped(pd) ? swapped_byte_order : our_byte_order,
	    pcap_datalink_val_to_name(pcap_datalink(pd)),
	    pcap_snapshot(pd));
	struct callback_info cb_info = { .nsec_precision = 0 };
	status = pcap_loop(pd, -1, print_packet, (u_char *)&cb_info);
	if (status == PCAP_ERROR)
		error(EX_DATAERR, "failed reading: %s", pcap_geterr(pd));
	exit(EX_OK);
}

static void
usage(FILE *f)
{
	(void)fprintf(f, "%s, with %s\n", program_name,
	    pcap_lib_version());
	(void)fprintf(f, "Usage: %s <capture file>\n",
	    program_name);
	(void)fprintf(f, "  or:  %s -h\n", program_name);
	(void)fprintf(f, "       (print the detailed help screen)\n");
	if (f != stdout)
		exit(EX_USAGE);
	exit(EX_OK);
}
