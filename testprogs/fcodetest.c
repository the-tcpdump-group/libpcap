/*
 * Copyright (c) 2026
 *	The Tcpdump Group and contributors.  All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <config.h>

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>

#ifdef _WIN32
  #include "getopt.h"
#else
  #include <unistd.h>
#endif

#include "pcap/funcattrs.h"
#include "portability.h"
#include "test-util.h"

static const char *program_name;
static struct bpf_program fcode;
static pcap_t *pd;

static void
cleanup(void)
{
	pcap_freecode(&fcode);
	if (pd)
		pcap_close(pd);
}

static void
PCAP_NORETURN_DEF
usage(FILE *f)
{
	fprintf(f, "%s, with %s\n", program_name, pcap_lib_version());
	fprintf(f, "Usage: %s [-dq] -i <progfile>\n", program_name);
	fprintf(f, "	   (load, validate and print a filter program)\n");
	fprintf(f, "  or:  %s -r <pcapfile> -i <progfile>\n", program_name);
	fprintf(f, "	   (load a filter program, do not validate it and print the filtering\n");
	fprintf(f, "	   result for each packet in the specified savefile)\n");
	fprintf(f, "  or:  %s -h\n", program_name);
	fprintf(f, "	   (print the detailed help screen)\n");
	if (f != stdout)
		exit(EX_USAGE);
	fprintf(f, "\nOptions specific to %s:\n", program_name);
	fprintf(f, "  -i <progfile>   a filter program in cbpf-savefile(5) format (\"-\" means stdin)\n");
	fprintf(f, "  -q              do not print the filter program\n");
	fprintf(f, "\n");
	fprintf(f, "Options common with tcpdump:\n");
	fprintf(f, "  -d              change output format (accumulates, one -d is implicit)\n");
	fprintf(f, "  -r <pcapfile>   read the packets from this savefile\n");
	fprintf(f, "\nExit status codes:\n");
	fprintf(f, "  %3u: All input has been successfully processed.\n", EX_OK);
	fprintf(f, "  %3u: libpcap has orderly rejected the filter.\n", EX_DATAERR);
	fprintf(f, "  %3u: libpcap has orderly rejected the savefile.\n", EX_NOINPUT);
	fprintf(f, "  %3u: Unexpected OS error.\n", EX_OSERR);
	fprintf(f, "  %3u: Unexpected I/O or file format error.\n", EX_IOERR);
	fprintf(f, "  %3u: This executable has been invoked incorrectly.\n", EX_USAGE);
	exit(EX_OK);
}

int
main(int argc, char **argv)
{
	program_name = set_program_name(argv[0]);
	if (atexit(cleanup))
		error(EX_OSERR, "atexit() failed: %s", pcap_strerror(errno));

	int dflag = 1;
	bool qflag = false;
	char *progfile = NULL;
	char *pcapfile = NULL;

	opterr = 0;
	int op;
	while ((op = getopt(argc, argv, "dhi:nqr:")) != -1) {
		switch (op) {
		case 'd':
			++dflag;
			break;
		case 'h':
			usage(stdout);
			/* NOTREACHED */
		case 'i':
			progfile = optarg;
			break;
		case 'q':
			qflag = true;
			break;
		case 'r':
			pcapfile = optarg;
			break;
		default:
			usage(stderr);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;
	if (argc || ! progfile)
		usage(stderr);
	if (pcapfile) {
		if (dflag > 1)
			error(EX_USAGE, "-r is not compatible with -d");
		if (qflag)
			error(EX_USAGE, "-r is not compatible with -q");
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	{
		int ret = read_cbpffile(progfile, &fcode, errbuf);
		if (ret != EX_OK)
			error(ret, "read_cbpffile(): %s", errbuf);
	}
	if (pcapfile) {
		/*
		 * To enable testing of error handling in the interpreter, do
		 * not validate the filter program.
		 */
		if (NULL == (pd = pcap_open_offline(pcapfile, errbuf)))
			error(EX_NOINPUT, "Failed opening: %s", errbuf);
		print_filtering_results(pd, &fcode);
	} else {
		if (! bpf_validate(fcode.bf_insns, fcode.bf_len))
			error(EX_DATAERR, "Filter doesn't pass validation");
		if (! qflag)
			bpf_dump(&fcode, dflag);
	}
	exit(EX_OK);
}
