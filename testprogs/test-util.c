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
	char **p;
	size_t len = 0;
	char *buf;
	char *src, *dst;

	p = argv;
	if (*p == 0)
		return NULL;

	while (*p)
		len += strlen(*p++) + 1;

	buf = (char *)malloc(len);
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
	if (cp == NULL)
		error(EX_OSERR, "malloc(%d) for %s: %s", (u_int)buf.st_size + 1,
			fname, pcap_strerror(errno));
	cc = (int)read(fd, cp, (u_int)buf.st_size);
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
