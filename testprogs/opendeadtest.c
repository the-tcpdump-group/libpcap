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

#include "varattrs.h"

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
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

#include <errno.h>

#include "pcap/funcattrs.h"

#ifdef _WIN32
  #include "portability.h"
#endif

#define MAXIMUM_SNAPLEN		262144

static const char *program_name;

/* Forwards */
static void PCAP_NORETURN usage(void);
static void PCAP_NORETURN error(const int, const char *, ...) PCAP_PRINTFLIKE(2, 3);

int
main(int argc, char **argv)
{
	char *cp;
	int op;
	int snaplen;
	char *p;
	pcap_t *pd;

	snaplen = MAXIMUM_SNAPLEN;
	if ((cp = strrchr(argv[0], '/')) != NULL)
		program_name = cp + 1;
	else
		program_name = argv[0];

	opterr = 0;
	while ((op = getopt(argc, argv, "s:")) != -1) {
		switch (op) {

		case 's': {
			char *end;
			long long_snaplen;

			long_snaplen = strtol(optarg, &end, 0);
			if (optarg == end || *end != '\0'
			    || long_snaplen < 0
			    || long_snaplen > MAXIMUM_SNAPLEN)
				error(EX_USAGE, "invalid snaplen %s", optarg);
			else {
				if (snaplen == 0)
					snaplen = MAXIMUM_SNAPLEN;
				else
					snaplen = (int)long_snaplen;
			}
			break;
		}

		default:
			usage();
			/* NOTREACHED */
		}
	}

	if (optind >= argc) {
		/* No link-layer type specified. */
		usage();
		/* NOTREACHED */
	}
	int dlt = pcap_datalink_name_to_val(argv[optind]);
	if (dlt < 0) {
		dlt = (int)strtol(argv[optind], &p, 10);
		if (p == argv[optind] || *p != '\0')
			error(EX_USAGE, "invalid data link type %s", argv[optind]);
	}

	pd = pcap_open_dead(dlt, snaplen);
	if (pd == NULL)
		error(EX_SOFTWARE, "Can't open fake pcap_t");

	/*
	 * Make sure the file descriptors we get for this are -1.
	 */
	int fileno = pcap_fileno(pd);
	if (fileno != -1) {
		pcap_close(pd);
		error(EX_SOFTWARE, "pcap_fileno() returns %d, not -1",
		    fileno);
	}
	int selectable_fd = pcap_get_selectable_fd(pd);
	if (selectable_fd != -1) {
		pcap_close(pd);
		error(EX_SOFTWARE, "pcap_get_selectable_fd() returns %d, not -1",
		    selectable_fd);
	}
	pcap_close(pd);
	return 0;
}

static void
usage(void)
{
	(void)fprintf(stderr,
	    "Usage: %s [ -s snaplen ] <DLT>\n",
	    program_name);
	exit(1);
}

/* VARARGS */
static void
error(const int status, const char *fmt, ...)
{
	va_list ap;

	(void)fprintf(stderr, "%s: ", program_name);
	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
	exit(status);
	/* NOTREACHED */
}
