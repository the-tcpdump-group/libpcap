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

#include "varattrs.h"

#ifndef lint
static const char copyright[] _U_ =
    "@(#) Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 2000\n\
The Regents of the University of California.  All rights reserved.\n";
#endif

#include <config.h>

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
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

#include <fcntl.h>
#include <errno.h>
#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <sys/socket.h>
  #include <arpa/inet.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>

#include "pcap/funcattrs.h"
#include "extract.h"

#define MAXIMUM_SNAPLEN		262144
#define MAX_STDIN		(64 * 1024)

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
static void PCAP_NORETURN error(const int, const char *, ...) PCAP_PRINTFLIKE(2, 3);
static void warn(const char *, ...) PCAP_PRINTFLIKE(1, 2);

/*
 * On Windows, we need to open the file in binary mode, so that
 * we get all the bytes specified by the size we get from "fstat()".
 * On UNIX, that's not necessary.  O_BINARY is defined on Windows;
 * we define it as 0 if it's not defined, so it does nothing.
 */
#ifndef O_BINARY
#define O_BINARY	0
#endif

static char *cmdbuf;
static pcap_t *pd;
static struct bpf_program fcode;

/*
 * atexit() is broken on Linux/ARMv7 with TinyCC, work around by calling this
 * function explicitly just before exit() if there is a possibility any of
 * these resources have been allocated.
 */
static void
cleanup(void)
{
	if (cmdbuf)
		free(cmdbuf);
	pcap_freecode (&fcode);
	if (pd)
		pcap_close(pd);
}

// Replace "# comment" with spaces.
static void
blank_comments(char *cp, const size_t size)
{
	for (size_t i = 0; i < size; i++) {
		if (cp[i] == '#')
			while (i < size && cp[i] != '\n')
				cp[i++] = ' ';
	}
}

static void
read_infile(char *fname)
{
	int fd, cc;
	char *cp;
	struct stat buf;

	fd = open(fname, O_RDONLY|O_BINARY);
	if (fd < 0)
		error(EX_IOERR, "can't open %s: %s", fname, pcap_strerror(errno));

	if (fstat(fd, &buf) < 0)
		error(EX_IOERR, "can't stat %s: %s", fname, pcap_strerror(errno));

	/*
	 * _read(), on Windows, has an unsigned int byte count and an
	 * int return value, so we can't handle a file bigger than
	 * INT_MAX - 1 bytes (and have no reason to do so; a filter *that*
	 * big will take forever to compile).  (The -1 is for the '\0' at
	 * the end of the string.)
	 */
	if (buf.st_size > INT_MAX - 1)
		error(EX_IOERR, "%s is larger than %d bytes; that's too large", fname,
		    INT_MAX - 1);
	cp = malloc((u_int)buf.st_size + 1);
	cmdbuf = cp;
	if (cp == NULL)
		error(EX_OSERR, "malloc(%d) for %s: %s", (u_int)buf.st_size + 1,
			fname, pcap_strerror(errno));
	cc = (int)read(fd, cp, (u_int)buf.st_size);
	if (cc < 0)
		error(EX_IOERR, "read %s: %s", fname, pcap_strerror(errno));
	if (cc != buf.st_size)
		error(EX_IOERR, "short read %s (%d != %d)", fname, cc, (int)buf.st_size);

	close(fd);
	blank_comments(cp, (size_t)cc);
	cp[cc] = '\0';
}

// Copy stdin into a size-limited buffer.
static void
read_stdin(void)
{
	char *buf = calloc(1, MAX_STDIN + 1);
	cmdbuf = buf;
	if (buf == NULL)
		error(EX_OSERR, "%s: calloc", __func__);
	size_t readsize = fread(buf, 1, MAX_STDIN, stdin);
	if (! feof(stdin))
		error(EX_IOERR, "received more than %u bytes on stdin", MAX_STDIN);
	if (ferror(stdin))
		error(EX_IOERR, "failed reading from stdin after %zd bytes", readsize);
	fclose(stdin);
	// No error, all data is within the buffer and NUL-terminated.
	blank_comments(buf, readsize);
}

#define CBPFSF_HEADER_SIZE 20
static void
read_cbpffile(const char *fname)
{
	FILE *f = strcmp("-", fname) ? fopen(fname, "rb") : stdin;
	if (! f)
		error(EX_IOERR, "can't open '%s': %s",
		    fname, pcap_strerror(errno));

	uint8_t readbuf[CBPFSF_HEADER_SIZE];
	if (1 != fread(readbuf, sizeof(readbuf), 1, f))
		error(EX_IOERR,
		    "failed to read cbpf-savefile header from '%s': %s",
		    fname, pcap_strerror(errno));
	const uint8_t cbpfhdrstart[] = {
		0xa1, 0xb2, 0xc3, 0xcb, // binary signature
		'c', 'B', 'P', 'F', // ASCII hint
		1, // MajorVer
		// Ignore: MinorVer, Flags, SnapLen, and LinkTypeValue.
	};
	if (memcmp(readbuf, cbpfhdrstart, sizeof(cbpfhdrstart)))
		error(EX_IOERR, "invalid cbpf-savefile header in '%s'", fname);

	fcode.bf_len = EXTRACT_BE_U_2(readbuf + 18);
	fcode.bf_insns = fcode.bf_len ?
		calloc(fcode.bf_len, sizeof(struct bpf_insn)) : NULL;
	for (uint16_t i = 0; i < fcode.bf_len; i++) {
		if (1 != fread(readbuf, sizeof(struct bpf_insn), 1, f))
			error(EX_IOERR,
			    "failed to read the next instruction from '%s': %s",
			    fname, pcap_strerror(errno));
		fcode.bf_insns[i].code = EXTRACT_BE_U_2(readbuf);
		fcode.bf_insns[i].jt = readbuf[2];
		fcode.bf_insns[i].jf = readbuf[3];
		fcode.bf_insns[i].k = EXTRACT_BE_U_4(readbuf + 4);
	}
	// Ignore any TLVs after the instructions.
	if (fclose(f))
		error(EX_IOERR, "failed closing '%s'", fname);
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
	cleanup();
	exit(status);
	/* NOTREACHED */
}

/* VARARGS */
_U_
static void
warn(const char *fmt, ...)
{
	va_list ap;

	(void)fprintf(stderr, "%s: WARNING: ", program_name);
	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
}

/*
 * Copy arg vector into a new buffer, concatenating arguments with spaces.
 */
static void
copy_argv(char **argv)
{
	char **p;
	size_t len = 0;
	char *buf;
	char *src, *dst;

	p = argv;
	if (*p == 0)
		return;

	while (*p)
		len += strlen(*p++) + 1;

	buf = (char *)malloc(len);
	cmdbuf = buf;
	if (buf == NULL)
		error(EX_OSERR, "%s: malloc", __func__);

	p = argv;
	dst = buf;
	while ((src = *p++) != NULL) {
		while ((*dst++ = *src++) != '\0')
			;
		dst[-1] = ' ';
	}
	dst[-1] = '\0';
}

int
main(int argc, char **argv)
{
	char *cp;
	int op;
	int dflag = 1;
#ifdef BDEBUG
	int gflag = 0;
#endif
	char *infile = NULL;
	char *insavefile = NULL;
	char *cbpfsavefile = NULL;
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
	/*
	 * This program exits with EX_DATAERR iff the user input has a problem.
	 * By default the user input is a filter expression, in which case the
	 * filter program is an output of pcap_compile(), so if the latter has
	 * accepted the expression, but produced a program that fails to
	 * validate, this is a problem in libpcap, not in the user input.  If
	 * the user input is a compiled filter program, a failure to validate
	 * it means a problem in the user input.
	 */
	int validation_error = EX_SOFTWARE;

#ifdef _WIN32
	WSADATA wsaData;
	if (0 != WSAStartup(MAKEWORD(2, 2), &wsaData))
		return 1;
#endif /* _WIN32 */

	if ((cp = strrchr(argv[0], '/')) != NULL)
		program_name = cp + 1;
	else
		program_name = argv[0];

	opterr = 0;
	while ((op = getopt(argc, argv, "hi:dF:gm:Os:S:lqr:")) != -1) {
		switch (op) {

		case 'h':
			usage(stdout);
			/* NOTREACHED */

		case 'i':
			cbpfsavefile = optarg;
			validation_error = EX_DATAERR;
			break;

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
	} else if (cbpfsavefile) {
		if (dflag > 1 && qflag)
			error(EX_USAGE, "-d is not compatible with -q");
		if (infile)
			error(EX_USAGE, "-i is not compatible with -F");
#ifdef BDEBUG
		if (gflag)
			error(EX_USAGE, "-i is not compatible with -g");
#endif
#ifdef __linux__
		if (lflag)
			error(EX_USAGE, "-i is not compatible with -l");
#endif
		if (netmask != PCAP_NETMASK_UNKNOWN)
			error(EX_USAGE, "-i is not compatible with -m");
		if (! Oflag)
			error(EX_USAGE, "-i is not compatible with -O");
		if (snaplen != MAXIMUM_SNAPLEN)
			error(EX_USAGE, "-i is not compatible with -s");
		if (Sflag != NOT_SAVEFILE_FILTER)
			error(EX_USAGE, "-i is not compatible with -S");
		// Must not have any non-option arguments.
		if (optind < argc)
			usage(stderr);
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

	if (cbpfsavefile)
		read_cbpffile(cbpfsavefile);
	else {
		if (! infile)
			copy_argv(&argv[optind]);
		else if (strcmp(infile, "-"))
			read_infile(infile);
		else
			read_stdin();
		// cmdbuf may still be NULL.

		if (pcap_compile(pd, &fcode, cmdbuf, Oflag, netmask) < 0) // cmdbuf == NULL is valid.
			error(EX_DATAERR, "%s", pcap_geterr(pd));
	}

	/*
	 * Skip the validation step when using a cbpf-savefile to filter a
	 * savefile: this way a filter program can be fed into the interpreter
	 * regardless of whether it would pass the validator.
	 */
	if (! (cbpfsavefile && insavefile) &&
	    ! bpf_validate(fcode.bf_insns, fcode.bf_len))
		error(validation_error, "Filter doesn't pass validation");

	if (! insavefile) {
#ifdef BDEBUG
		// only show machine code if BDEBUG defined, since dflag > 3
		printf("machine codes for filter: ");
		if (! cmdbuf)
			printf("NULL");
		else {
			// replace line feed with space
			for (cp = cmdbuf; *cp != '\0'; ++cp)
				if (*cp == '\r' || *cp == '\n')
					*cp = ' ';
			printf("'%s'", cmdbuf);
		}
		printf("\n");
#endif
		if (! qflag)
			bpf_dump(&fcode, dflag);
	} else {
		struct pcap_pkthdr *h;
		const u_char *d;
		int ret;
		while (PCAP_ERROR_BREAK != (ret = pcap_next_ex(pd, &h, &d))) {
			if (ret == PCAP_ERROR)
				error(EX_IOERR, "pcap_next_ex() failed: %s", pcap_geterr(pd));
			if (ret == 1)
				printf("%d\n", pcap_offline_filter(&fcode, h, d));
			else
				error(EX_IOERR, "pcap_next_ex() failed: %d", ret);
		}
	}
	cleanup();
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
	(void)fprintf(f, "  or:  %s [-dq] -i <file>\n", program_name);
	(void)fprintf(f, "       (load, validate and print a filter program)\n");
	(void)fprintf(f, "  or:  %s -i <file> -r <file>\n", program_name);
	(void)fprintf(f, "       (load a filter program and print the filtering result for each packet\n");
	(void)fprintf(f, "       in the specified savefile)\n");
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
	(void)fprintf(f, "  -i <file>       a compiled filter program in cbpf-savefile(5) format\n");
	(void)fprintf(f, "                  (\"-\" means stdin)\n");
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
