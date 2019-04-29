/*
 * Copyright (c) 2017
 *	Internet Systems Consortium, Inc.  All rights reserved.
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
 *
 * pcap-ioplugin.c - supports dynamic loading of compression modules
 *	Created by Ray Bellis, ISC.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ftmacros.h"

#ifdef _WIN32
#include <pcap-stdinc.h>
#else /* _WIN32 */
#if HAVE_INTTYPES_H
#include <inttypes.h>
#elif HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_SYS_BITYPES_H
#include <sys/bitypes.h>
#endif
#include <sys/types.h>
#endif /* _WIN32 */

#include <errno.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "pcap-int.h"

#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif

#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

/*
 * Setting O_BINARY on DOS/Windows is a bit tricky
 */
#if defined(_WIN32)
  #define SET_BINMODE(f)  _setmode(_fileno(f), _O_BINARY)
#elif defined(MSDOS)
  #if defined(__HIGHC__)
  #define SET_BINMODE(f)  setmode(f, O_BINARY)
  #else
  #define SET_BINMODE(f)  setmode(fileno(f), O_BINARY)
  #endif
#else
  #define SET_BINMODE(f)  (void)f
#endif

/*
 * fopen's safe version on Windows.
 */
#ifdef _MSC_VER
FILE *fopen_safe(const char *filename, const char* mode)
{
	FILE *fp = NULL;
	errno_t errno;
	errno = fopen_s(&fp, filename, mode);
	if (errno == 0)
		return fp;
	else
		return NULL;
}
#endif

static FILE*
stdio_open_read(const char *fname, char *errbuf)
{
	FILE *fp = NULL;

	if (strcmp(fname, "-") == 0) {
		fp = stdin;
		SET_BINMODE(fp);
	} else {
		/*
		 * "b" is supported as of C90, so *all* UN*Xes should
		 * support it, even though it does nothing.  It's
		 * required on Windows, as the file is a binary file
		 * and must be written in binary mode.
		 */
		fp = fopen(fname, "rb");
		if (fp == NULL) {
			pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: fopen: %s", fname,
				pcap_strerror(errno));
			return (NULL);
		}
	}

	return fp;
}

static FILE*
stdio_open_write(const char *fname, char *errbuf)
{
	FILE *fp = NULL;

	if (strcmp(fname, "-") == 0) {
		fp = stdout;
		SET_BINMODE(fp);
	} else {
		/*
		 * "b" is supported as of C90, so *all* UN*Xes should
		 * support it, even though it does nothing.  It's
		 * required on Windows, as the file is a binary file
		 * and must be written in binary mode.
		 */
		fp = fopen(fname, "wb");
		if (fp == NULL) {
			pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: fopen: %s", fname,
				pcap_strerror(errno));
			return (NULL);
		}
	}

	return fp;
}

static const pcap_ioplugin_t* pcap_ioplugin_stdio() {
	static pcap_ioplugin_t plugin = {
		.open_read = stdio_open_read,
		.open_write = stdio_open_write
	};

	return &plugin;
}

/*
 * loads an I/O plugin with the given name
 * (on UNIX, a .so shared library)
 *
 * NB: fails silently and falls back to existing uncompressed
 *     stdio-based output if the plugin fails to load
 */

const pcap_ioplugin_t* pcap_ioplugin_init(const char *name)
{
	void *lib = NULL;
	if (name == NULL) {
		goto fail;
	}

#if HAVE_DLOPEN
	lib = dlopen(name, RTLD_NOW);
	if (lib != NULL) {
		pcap_ioplugin_init_fn ioplugin_init = dlsym(lib, "ioplugin_init");
		if (ioplugin_init == NULL) {
			dlclose(lib);
			goto fail;
		} else {
			return ioplugin_init();
		}
	}
#endif /* HAVE_DLOPEN */

fail:
	return pcap_ioplugin_stdio();
}

static int invoked_atexit = 0;

struct file_entry {
	FILE					*fp;
	const void				*cookie;
	TAILQ_ENTRY(file_entry)	 next;
};

static TAILQ_HEAD(, file_entry) file_list;

static void pcap_ioplugin_closeall()
{
	struct file_entry *entry = NULL;

	TAILQ_FOREACH(entry, &file_list, next) {
		fclose(entry->fp);
	}
}

void pcap_ioplugin_register_fp_cookie(FILE *fp, const void *cookie)
{
	struct file_entry *entry = (struct file_entry *)malloc(sizeof *entry);
	if (!entry) {
		return;
	}
	entry->fp = fp;
	entry->cookie = cookie;

	if (!invoked_atexit) {
		invoked_atexit = 1;
		TAILQ_INIT(&file_list);
		atexit(pcap_ioplugin_closeall);
	}

	TAILQ_INSERT_TAIL(&file_list, entry, next);
}

void pcap_ioplugin_unregister_fp_cookie(const void *cookie)
{
	struct file_entry *entry = NULL, *tmp = NULL;

	for (entry = TAILQ_FIRST(&file_list); entry != NULL; entry = tmp) {
		tmp = TAILQ_NEXT(entry, next);
		if (entry->cookie == cookie) {
			TAILQ_REMOVE(&file_list, entry, next);
			free(entry);
			break;
		}
	}
}
