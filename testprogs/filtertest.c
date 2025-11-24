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
#ifdef _WIN32
  #include "getopt.h"
  #include "unix.h"
#else
  #include <unistd.h>
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

#define MAXIMUM_SNAPLEN		262144
#define MAX_STDIN		(64 * 1024)
#define BPF_IMAGE_UNIMPL	"(000) unimp"
#define BPF_IMAGE_ARGV		"_enumerate_bpf_image"

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
/*
 * pcap-int.h is a private header and should not be included by programs that
 * use libpcap.  This test program uses a special hack because it is the
 * simplest way to test internal code paths that otherwise would require
 * elevated privileges.  Do not do this in normal code.
 */
#include <pcap-int.h>
#endif // __linux__

static char *program_name;

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
		error(EX_NOINPUT, "can't open %s: %s", fname, pcap_strerror(errno));

	if (fstat(fd, &buf) < 0)
		error(EX_NOINPUT, "can't stat %s: %s", fname, pcap_strerror(errno));

	/*
	 * _read(), on Windows, has an unsigned int byte count and an
	 * int return value, so we can't handle a file bigger than
	 * INT_MAX - 1 bytes (and have no reason to do so; a filter *that*
	 * big will take forever to compile).  (The -1 is for the '\0' at
	 * the end of the string.)
	 */
	if (buf.st_size > INT_MAX - 1)
		error(EX_DATAERR, "%s is larger than %d bytes; that's too large", fname,
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
		error(EX_DATAERR, "received more than %u bytes on stdin", MAX_STDIN);
	if (ferror(stdin))
		error(EX_IOERR, "failed reading from stdin after %zd bytes", readsize);
	fclose(stdin);
	// No error, all data is within the buffer and NUL-terminated.
	blank_comments(buf, readsize);
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

static void
enumerate_bpf_image(void)
{
	struct bpf_insn insn = {
		.code = 0x0000,
		.jt = 0xab,
		.jf = 0xcd,
		.k = 0xabcd,
	};
	do {
		const char *image = bpf_image(&insn, 0);
		if (strncmp(image, BPF_IMAGE_UNIMPL, sizeof(BPF_IMAGE_UNIMPL) - 1))
			printf("%-50s; 0x%04x\n", image, insn.code);
	} while (insn.code++ != UINT16_MAX);
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
	int Oflag = 1;
#ifdef __linux__
	int lflag = 0;
#endif
	int snaplen = MAXIMUM_SNAPLEN;
	char *p;
	bpf_u_int32 netmask = PCAP_NETMASK_UNKNOWN;

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
	while ((op = getopt(argc, argv, "hdF:gm:Os:lr:")) != -1) {
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
				error(EX_DATAERR, "invalid netmask %s", optarg);

			case -1:
				error(EX_DATAERR, "invalid netmask %s: %s", optarg,
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
				error(EX_DATAERR, "invalid snaplen %s", optarg);
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
			lflag = 1;
			break;
#else
			error(EX_USAGE, "libpcap and filtertest built without Linux BPF extensions");
#endif

		default:
			usage(stderr);
			/* NOTREACHED */
		}
	}

	if (insavefile) {
		if (dflag > 1)
			warn("-d is a no-op with -r");
#ifdef BDEBUG
		if (gflag)
			warn("-g is a no-op with -r");
#endif
#ifdef __linux__
		if (lflag)
			warn("-l is a no-op with -r");
#endif

		char errbuf[PCAP_ERRBUF_SIZE];
		if (NULL == (pd = pcap_open_offline(insavefile, errbuf)))
			error(EX_NOINPUT, "Failed opening: %s", errbuf);
	} else {
		// Must have at least one command-line argument for the DLT.
		if (optind >= argc) {
			usage(stderr);
			/* NOTREACHED */
		}
		int dlt = pcap_datalink_name_to_val(argv[optind]);
		if (dlt < 0) {
			dlt = (int)strtol(argv[optind], &p, 10);
			if (p == argv[optind] || *p != '\0')
				error(EX_DATAERR, "invalid data link type %s", argv[optind]);
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
	}

	if (! infile)
		copy_argv(&argv[optind]);
	else if (strcmp(infile, "-"))
		read_infile(infile);
	else
		read_stdin();
	// cmdbuf may still be NULL.

	if (cmdbuf && ! strcmp(BPF_IMAGE_ARGV, cmdbuf)) {
		enumerate_bpf_image();
		cleanup();
		exit(EX_OK);
	}

	if (pcap_compile(pd, &fcode, cmdbuf, Oflag, netmask) < 0) // cmdbuf == NULL is valid.
		error(EX_DATAERR, "%s", pcap_geterr(pd));

	if (!bpf_validate(fcode.bf_insns, fcode.bf_len))
		warn("Filter doesn't pass validation");

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
	    "O"
#ifdef __linux__
	    "l"
#endif
	    "] [ -F file ] [ -m netmask] [ -s snaplen ] dlt [ expr ]\n",
	    program_name);
	(void)fprintf(f, "       (print the filter program bytecode)\n");
	(void)fprintf(f,
	    "  or:  %s [-O] [ -F file ] [ -m netmask] -r file [ expression ]\n",
	    program_name);
	(void)fprintf(f, "       (print the filter program result for each packet)\n");
	(void)fprintf(f, "  or:  %s -h\n", program_name);
	(void)fprintf(f, "       (print the detailed help screen)\n");
	if (f != stdout)
		exit(EX_USAGE);
	(void)fprintf(f, "\nOptions specific to %s:\n", program_name);
	(void)fprintf(f, "  <dlt>           a valid DLT name, e.g. 'EN10MB'\n");
	(void)fprintf(f, "  <expr>          a valid filter expression, e.g. 'tcp port 80'\n");
#ifdef __linux__
	(void)fprintf(f, "  -l              allow the use of Linux BPF extensions\n");
#endif
#ifdef BDEBUG
	(void)fprintf(f, "  -g              print Graphviz dot graphs for the optimizer steps\n");
#endif
	(void)fprintf(f, "  -m <netmask>    use this netmask for pcap_compile(), e.g. 255.255.255.0\n");
	(void)fprintf(f, "\n");
	(void)fprintf(f, "Options common with tcpdump:\n");
	(void)fprintf(f, "  -d              change output format (accumulates, one -d is implicit)\n");
	(void)fprintf(f, "  -O              do not optimize the filter program\n");
	(void)fprintf(f, "  -F <file>       read the filter expression from the specified file\n");
	(void)fprintf(f, "                  (\"-\" means stdin and allows at most %u characters)\n", MAX_STDIN);
	(void)fprintf(f, "  -s <snaplen>    set the snapshot length\n");
	(void)fprintf(f, "  -r <file>       read the packets from this savefile\n");
	(void)fprintf(f, "\nIf no filter expression is specified, it defaults to an empty string, which\n");
	(void)fprintf(f, "accepts all packets.  If the -F option is in use, it replaces any filter\n");
	(void)fprintf(f, "expression specified as a command-line argument.\n");
	exit(EX_OK);
}
