/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 2000
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

#include "varattrs.h"

#ifndef lint
static const char copyright[] _U_ =
    "@(#) Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 2000\n\
The Regents of the University of California.  All rights reserved.\n";
#endif

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#ifdef _WIN32
  #include "getopt.h"
#else
  #include <unistd.h>
#endif

#include <errno.h>
#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <sys/socket.h>
  #include <arpa/inet.h>
#endif
#include <sys/types.h>

#include "pcap/funcattrs.h"
#include "portability.h"
#include "test-util.h"

#define MAXIMUM_SNAPLEN		262144

#ifdef BDEBUG
/*
 * We have pcap_set_optimizer_debug() and pcap_set_print_dot_graph() in
 * libpcap; declare them (they're not declared by any libpcap header,
 * because they're special hacks, only available if libpcap was configured
 * to include them, and only intended for use by libpcap developers trying
 * to debug the optimizer for filter expressions).
 */
PCAP_API void pcap_set_optimizer_debug(int);
PCAP_API void pcap_set_print_dot_graph(int);
#endif

#ifdef __linux__
#include <linux/filter.h> // SKF_AD_VLAN_TAG_PRESENT
#endif // __linux__

/*
 * pcap-int.h is a private header and should not be included by programs that
 * use libpcap.  This test program uses a special hack because it is the
 * simplest way to test internal code paths that otherwise would require
 * elevated privileges or that cannot be exercised otherwise.  Do not
 * do this in normal code.
 */
#include <pcap-int.h>

static const char *program_name;

/* Forwards */
static void PCAP_NORETURN usage(FILE *);

static char *cmdbuf;
static pcap_t *pd;
static struct bpf_program fcode;

static void
cleanup(void)
{
	if (cmdbuf)
		free(cmdbuf);
	pcap_freecode (&fcode);
	if (pd)
		pcap_close(pd);
}

int
main(int argc, char **argv)
{
	int op;
	int dflag = 1;
#ifdef BDEBUG
	int gflag = 0;
#endif
	char *infile = NULL;
	char *insavefile = NULL;
	int Oflag = 1;
#ifdef __linux__
	bool lflag = false;
#endif
	bool qflag = false;
	int snaplen = MAXIMUM_SNAPLEN;
	enum {
		NOT_SAVEFILE_FILTER,
		UNSWAPPED_SAVEFILE_FILTER,
		SWAPPED_SAVEFILE_FILTER
	} Sflag = NOT_SAVEFILE_FILTER;
	char *p;
	bpf_u_int32 netmask = PCAP_NETMASK_UNKNOWN;

	if (atexit(cleanup))
		error(EX_OSERR, "atexit() failed: %s", pcap_strerror(errno));
#ifdef _WIN32
	WSADATA wsaData;
	if (0 != WSAStartup(MAKEWORD(2, 2), &wsaData))
		return 1;
#endif /* _WIN32 */

	program_name = set_program_name(argv[0]);

	opterr = 0;
	while ((op = getopt(argc, argv, "hdF:gm:Os:S:lqr:")) != -1) {
		switch (op) {

		case 'h':
			usage(stdout);
			/* NOTREACHED */

		case 'd':
			++dflag;
			break;

		case 'g':
#ifdef BDEBUG
			++gflag;
			break;
#else
			error(EX_USAGE, "libpcap and filtertest not built with optimizer debugging enabled");
#endif

		case 'F':
			infile = optarg;
			break;

		case 'r':
			insavefile = optarg;
			break;

		case 'O':
			Oflag = 0;
			break;

		case 'm': {
			bpf_u_int32 addr;

			switch (inet_pton(AF_INET, optarg, &addr)) {

			case 0:
				error(EX_USAGE, "invalid netmask %s", optarg);

			case -1:
				error(EX_USAGE, "invalid netmask %s: %s", optarg,
				    pcap_strerror(errno));

			case 1:
				// inet_pton(): network byte order, pcap_compile(): host byte order.
				netmask = ntohl(addr);
				break;
			}
			break;
		}

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

		case 'l':
#ifdef __linux__
			// Enable Linux BPF extensions.
			lflag = true;
			break;
#else
			error(EX_USAGE, "libpcap and filtertest built without Linux BPF extensions");
#endif

		case 'q':
			qflag = true;
			break;

		case 'S':
			if (strcmp(optarg, "unswapped") == 0)
				Sflag = UNSWAPPED_SAVEFILE_FILTER;
			else if (strcmp(optarg, "swapped") == 0)
				Sflag = SWAPPED_SAVEFILE_FILTER;
			else
				error(EX_USAGE, "invalid -S value \"%s\"", optarg);
			break;

		default:
			usage(stderr);
			/* NOTREACHED */
		}
	}

	if (insavefile) {
		if (dflag > 1)
			error(EX_USAGE, "-r is not compatible with -d");
#ifdef BDEBUG
		if (gflag)
			error(EX_USAGE, "-r is not compatible with -g");
#endif
#ifdef __linux__
		if (lflag)
			error(EX_USAGE, "-r is not compatible with -l");
#endif
		if (qflag)
			error(EX_USAGE, "-r is not compatible with -q");
		if (Sflag != NOT_SAVEFILE_FILTER)
			error(EX_USAGE, "-r is not compatible with -S");
		if (snaplen != MAXIMUM_SNAPLEN)
			error(EX_USAGE, "-r is not compatible with -s");

		char errbuf[PCAP_ERRBUF_SIZE];
		if (NULL == (pd = pcap_open_offline(insavefile, errbuf)))
			error(EX_NOINPUT, "Failed opening: %s", errbuf);
	} else {
		// Must have at least one command-line argument for the DLT.
		if (optind >= argc) {
			usage(stderr);
			/* NOTREACHED */
		}
		if (dflag > 1 && qflag)
			error(EX_USAGE, "-d is not compatible with -q");
		int dlt = pcap_datalink_name_to_val(argv[optind]);
		if (dlt < 0) {
			dlt = (int)strtol(argv[optind], &p, 10);
			if (p == argv[optind] || *p != '\0')
				error(EX_USAGE, "invalid data link type %s", argv[optind]);
		}
		optind++;

		pd = pcap_open_dead(dlt, snaplen);
		if (pd == NULL)
			error(EX_SOFTWARE, "Can't open fake pcap_t");
#ifdef __linux__
		if (lflag) {
#ifdef SKF_AD_VLAN_TAG_PRESENT
			/*
			 * Generally speaking, the fact the header defines the
			 * symbol does not necessarily mean the running kernel
			 * supports what is known as [vlanp] and everything
			 * before it, but in this use case the filter program
			 * is not meant for the kernel.
			 */
			pd->bpf_codegen_flags |= BPF_SPECIAL_VLAN_HANDLING;
#endif // SKF_AD_VLAN_TAG_PRESENT
			pd->bpf_codegen_flags |= BPF_SPECIAL_BASIC_HANDLING;
		}
#endif // __linux__
#ifdef BDEBUG
		pcap_set_optimizer_debug(dflag);
		pcap_set_print_dot_graph(gflag);
#endif
		if (Sflag != NOT_SAVEFILE_FILTER) {
			/*
			 * Make pcap_compile() generate code for a savefile
			 * rather than a live capture.
			 */
			pd->bpf_codegen_flags |= BPF_OFFLINE_AF_HANDLING;
			pd->swapped = (Sflag == SWAPPED_SAVEFILE_FILTER);
		}
	}

	cmdbuf = infile == NULL ? copy_argv(&argv[optind]) :
	    strcmp(infile, "-") == 0 ? read_stdin() :
	    read_infile(infile);
	// cmdbuf may still be NULL.

	/*
	 * If pcap_compile() has rejected the filter expression, it is a user
	 * input problem.
	 */
	if (pcap_compile(pd, &fcode, cmdbuf, Oflag, netmask) < 0) // cmdbuf == NULL is valid.
		error(EX_DATAERR, "%s", pcap_geterr(pd));
	/*
	 * If pcap_compile() has accepted the filter expression and produced a
	 * filter program that fails to validate (which is supposed never to be
	 * the case because the function validates its result), this is a bug
	 * in libpcap.
	 */
	if (! bpf_validate(fcode.bf_insns, fcode.bf_len))
		error(EX_SOFTWARE, "Filter doesn't pass validation");

	if (insavefile) {
		print_filtering_results(pd, &fcode);
	} else {
#ifdef BDEBUG
		// only show machine code if BDEBUG defined, since dflag > 3
		printf("machine codes for filter: ");
		if (! cmdbuf)
			printf("NULL");
		else {
			// replace line feed with space
			for (char *cp = cmdbuf; *cp != '\0'; ++cp)
				if (*cp == '\r' || *cp == '\n')
					*cp = ' ';
			printf("'%s'", cmdbuf);
		}
		printf("\n");
#endif
		if (! qflag)
			bpf_dump(&fcode, dflag);
	}
#ifdef _WIN32
	WSACleanup();
#endif
	exit(EX_OK);
}

static void
usage(FILE *f)
{
	(void)fprintf(f, "%s, with %s\n", program_name,
	    pcap_lib_version());
	(void)fprintf(f,
	    "Usage: %s [-d"
#ifdef BDEBUG
	    "g"
#endif
#ifdef __linux__
	    "l"
#endif
	    "Oq] [-S {unswapped|swapped}] [-F <file>] [-m <netmask>]\n"
	    "       [-s <snaplen>] <DLT> [<expression>]\n",
	    program_name);
	(void)fprintf(f, "       (compile a filter expression, validate and print the program)\n");
	(void)fprintf(f, "  or:  %s [-O] [-F <file>] [-m <netmask>] -r <file> [<expression>]\n",
	    program_name);
	(void)fprintf(f, "       (compile a filter expression, validate the program and print the\n");
	(void)fprintf(f, "       filtering result for each packet in the specified savefile)\n");
	(void)fprintf(f, "  or:  %s -h\n", program_name);
	(void)fprintf(f, "       (print the detailed help screen)\n");
	if (f != stdout)
		exit(EX_USAGE);
	(void)fprintf(f, "\nOptions specific to %s:\n", program_name);
	(void)fprintf(f, "  <DLT>           a valid DLT name, e.g. 'EN10MB'\n");
	(void)fprintf(f, "  <expression>    a valid filter expression, e.g. 'tcp port 80'\n");
#ifdef BDEBUG
	(void)fprintf(f, "  -g              print Graphviz dot graphs for the optimizer steps\n");
#endif
#ifdef __linux__
	(void)fprintf(f, "  -l              allow the use of Linux BPF extensions\n");
#endif
	(void)fprintf(f, "  -m <netmask>    use this IPv4 netmask for pcap_compile(3PCAP),\n");
	(void)fprintf(f, "                  e.g. 255.255.255.0\n");
	(void)fprintf(f, "  -q              do not print the filter program\n");
	(void)fprintf(f, "  -S {unswapped|swapped} generate filter code for a savefile\n");
	(void)fprintf(f, "\n");
	(void)fprintf(f, "Options common with tcpdump:\n");
	(void)fprintf(f, "  -d              change output format (accumulates, one -d is implicit)\n");
	(void)fprintf(f, "  -F <file>       read the filter expression from the specified file\n");
	(void)fprintf(f, "                  (\"-\" means stdin and allows at most %u characters)\n", MAX_STDIN);
	(void)fprintf(f, "  -O              do not optimize the filter program\n");
	(void)fprintf(f, "  -r <file>       read the packets from this savefile\n");
	(void)fprintf(f, "  -s <snaplen>    set the snapshot length (<= %u)\n", MAXIMUM_SNAPLEN);
	(void)fprintf(f, "\nIf no filter expression is specified, it defaults to an empty string, which\n");
	(void)fprintf(f, "accepts all packets.  If the -F option is in use, it replaces any filter\n");
	(void)fprintf(f, "expression specified as a command-line argument.\n");
	(void)fprintf(f, "\nExit status codes:\n");
	(void)fprintf(f, "  %3u: All input has been successfully processed.\n", EX_OK);
	(void)fprintf(f, "  %3u: libpcap has orderly rejected the filter.\n", EX_DATAERR);
	(void)fprintf(f, "  %3u: libpcap has orderly rejected the savefile.\n", EX_NOINPUT);
	(void)fprintf(f, "  %3u: Unexpected libpcap error.\n", EX_SOFTWARE);
	(void)fprintf(f, "  %3u: Unexpected OS error.\n", EX_OSERR);
	(void)fprintf(f, "  %3u: Unexpected I/O or file format error.\n", EX_IOERR);
	(void)fprintf(f, "  %3u: This executable has been invoked incorrectly.\n", EX_USAGE);
	exit(EX_OK);
}
