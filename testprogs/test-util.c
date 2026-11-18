/*
 * Copyright (c) 2005
 *	The Tcpdump Group and contributors.  All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <pcap.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

// read() and close()
#ifdef _WIN32
  #include "unix.h"
#else
  #include <unistd.h>
#endif

#include "test-util.h"
#include "portability.h"
#include "extract.h"

/*
 * On Windows, we need to open the file in binary mode, so that
 * we get all the bytes specified by the size we get from "fstat()".
 * On UNIX, that's not necessary.  O_BINARY is defined on Windows;
 * we define it as 0 if it's not defined, so it does nothing.
 */
#ifndef O_BINARY
#define O_BINARY	0
#endif

static const char *program_name = "unknown";

const char *
set_program_name(const char *argv0)
{
	const char *cp = strrchr(argv0, '/');
	program_name = cp ? cp + 1 : argv0;
	return program_name;
}

/* VARARGS */
void
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

/* VARARGS */
void
warning(const char *fmt, ...)
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
char *
copy_argv(char **argv)
{
	if (*argv == NULL)
		return NULL;

	char **p = argv;
	size_t len = 0;
	while (*p)
		len += strlen(*p++) + 1;

	char *buf = malloc(len);
	if (buf == NULL)
		error(EX_OSERR, "%s: malloc", __func__);

	p = argv;
	char *src, *dst = buf;
	while ((src = *p++) != NULL) {
		while ((*dst++ = *src++) != '\0')
			;
		dst[-1] = ' ';
	}
	dst[-1] = '\0';

	return buf;
}

// Replace "# comment" with spaces.
void
blank_comments(char *cp, const size_t size)
{
	for (size_t i = 0; i < size; i++) {
		if (cp[i] == '#')
			while (i < size && cp[i] != '\n')
				cp[i++] = ' ';
	}
}

char *
read_infile(const char *fname)
{
	int fd = open(fname, O_RDONLY|O_BINARY);
	if (fd < 0)
		error(EX_IOERR, "can't open %s: %s", fname, pcap_strerror(errno));

	struct stat buf;
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
	char *cp = malloc((u_int)buf.st_size + 1);
	if (cp == NULL)
		error(EX_OSERR, "malloc(%d) for %s: %s", (u_int)buf.st_size + 1,
			fname, pcap_strerror(errno));
	int cc = (int)read(fd, cp, (u_int)buf.st_size);
	if (cc < 0) {
		free(cp);
		error(EX_IOERR, "read %s: %s", fname, pcap_strerror(errno));
	}
	if (cc != buf.st_size) {
		free(cp);
		error(EX_IOERR, "short read %s (%d != %d)", fname, cc, (int)buf.st_size);
	}

	close(fd);
	blank_comments(cp, (size_t)cc);
	cp[cc] = '\0';
	return cp;
}

// Copy stdin into a size-limited buffer.
char *
read_stdin(void)
{
	char *buf = calloc(1, MAX_STDIN + 1);
	if (buf == NULL)
		error(EX_OSERR, "%s: calloc", __func__);
	size_t readsize = fread(buf, 1, MAX_STDIN, stdin);
	if (! feof(stdin)) {
		free(buf);
		error(EX_IOERR, "received more than %u bytes on stdin", MAX_STDIN);
	}
	if (ferror(stdin)) {
		free(buf);
		error(EX_IOERR, "failed reading from stdin after %zd bytes", readsize);
	}
	fclose(stdin);
	// No error, all data is within the buffer and NUL-terminated.
	blank_comments(buf, readsize);
	return buf;
}

#define CBPFSF_HEADER_SIZE 20
int
read_cbpffile(const char *fname, struct bpf_program *fcode, char *errbuf)
{
	int ret = EX_IOERR;
	fcode->bf_insns = NULL;
	FILE *f = strcmp("-", fname) ? fopen(fname, "rb") : stdin;
	if (! f) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE,
		    "can't open '%s': %s", fname, pcap_strerror(errno));
		goto fail;
	}

	uint8_t readbuf[CBPFSF_HEADER_SIZE];
	if (1 != fread(readbuf, sizeof(readbuf), 1, f)) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE,
		    "failed to read cbpf-savefile header from '%s': %s",
		    fname, pcap_strerror(errno));
		goto fail;
	}
	const uint8_t cbpfhdrstart[] = {
		0xa1, 0xb2, 0xc3, 0xcb, // binary signature
		'c', 'B', 'P', 'F', // ASCII hint
		1, // MajorVer
		// Ignore: MinorVer, Flags, SnapLen, and LinkTypeValue.
	};
	if (memcmp(readbuf, cbpfhdrstart, sizeof(cbpfhdrstart))) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE,
		    "invalid cbpf-savefile header in '%s'", fname);
		goto fail;
	}

	fcode->bf_len = EXTRACT_BE_U_2(readbuf + 18);
	if (fcode->bf_len) {
		fcode->bf_insns = calloc(fcode->bf_len, sizeof(struct bpf_insn));
		if (! fcode->bf_insns) {
			snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "calloc(): %s", pcap_strerror(errno));
			ret = EX_OSERR;
			goto fail;
		}
	}
	for (uint16_t i = 0; i < fcode->bf_len; i++) {
		if (1 != fread(readbuf, sizeof(struct bpf_insn), 1, f)) {
			snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "failed to read the next instruction from '%s': %s",
			    fname, pcap_strerror(errno));
			goto fail;
		}
		fcode->bf_insns[i].code = EXTRACT_BE_U_2(readbuf);
		fcode->bf_insns[i].jt = readbuf[2];
		fcode->bf_insns[i].jf = readbuf[3];
		fcode->bf_insns[i].k = EXTRACT_BE_U_4(readbuf + 4);
	}
	// Ignore any TLVs after the instructions.
	if (fclose(f)) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE,
		    "failed closing '%s'", fname);
		goto fail;
	}
	return EX_OK;

fail:
	if (f)
		fclose(f);
	fcode->bf_len = 0;
	if (fcode->bf_insns) {
		free(fcode->bf_insns);
		fcode->bf_insns = NULL;
	}
	return ret;
}

void
print_filtering_results(pcap_t *p, const struct bpf_program *fcode)
{
	struct pcap_pkthdr *h;
	const u_char *d;
	int ret;
	while (PCAP_ERROR_BREAK != (ret = pcap_next_ex(p, &h, &d))) {
		if (ret == PCAP_ERROR)
			error(EX_IOERR, "pcap_next_ex() failed: %s", pcap_geterr(p));
		if (ret == 1)
			printf("%d\n", pcap_offline_filter(fcode, h, d));
		else
			error(EX_IOERR, "pcap_next_ex() failed: %d", ret);
	}
}
