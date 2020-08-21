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

#include "pcap-int.h"

#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif

#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

static FILE*
stdio_open_read(const char *fname, char *errbuf)
{
	FILE *fp = NULL;

	if (fname == NULL) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE,
		    "A null pointer was supplied as the file name");
		return (NULL);
	}

        if (fname[0] == '-' && fname[1] == '\0')
        {
                fp = stdin;
                if (stdin == NULL) {
                        snprintf(errbuf, PCAP_ERRBUF_SIZE,
                                 "The standard input is not open");
                        return (NULL);
                }
		SET_BINMODE(fp);
	} else {
		/*
		 * "b" is supported as of C90, so *all* UN*Xes should
		 * support it, even though it does nothing.  It's
		 * required on Windows, as the file is a binary file
		 * and must be written in binary mode.
                 *
                 * Use charset_fopen(); on Windows, it tests whether we're
                 * in "local code page" or "UTF-8" mode, and treats the
                 * pathname appropriately, and on other platforms, it just
                 * wraps fopen().
                 *
                 */
                fp = charset_fopen(fname, "rb");
		if (fp == NULL) {
			snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: fopen: %s", fname,
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
                if (stdout == NULL) {
                        snprintf(errbuf, PCAP_ERRBUF_SIZE,
                                 "The standard input is not open");
                        return (NULL);
                }

		SET_BINMODE(fp);
	} else {
		/*
		 * "b" is supported as of C90, so *all* UN*Xes should
		 * support it, even though it does nothing.  It's
		 * required on Windows, as the file is a binary file
		 * and must be written in binary mode.
		 */
                fp = charset_fopen(fname, "rb");
		if (fp == NULL) {
			snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: fopen: %s", fname,
				pcap_strerror(errno));
			return (NULL);
		}
	}

	return fp;
}

static const pcap_ioplugin_t*
pcap_ioplugin_stdio(void) {
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

const pcap_ioplugin_t*
pcap_ioplugin_init(const char *name)
{
	void *lib = NULL;
	if (name == NULL) {
		goto fail;
	}

#if HAVE_DLOPEN && WANT_IOPLUGIN
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

struct file_entry {
	FILE					*fp;
	const void				*cookie;
	struct file_entry		*next;
};

static struct {
	struct file_entry		*head;
} file_list = { NULL };

static int registered_atexit = 0;
static int running_atexit = 0;

static void
pcap_ioplugin_closeall(void)
{
	struct file_entry *entry = file_list.head;

	running_atexit = 1;

	while (entry) {
		struct file_entry *tmp = entry;
		entry = entry->next;
		fclose(tmp->fp);
		free(tmp);
	}

	file_list.head = NULL;
}

void
pcap_ioplugin_register_fp_cookie(FILE *fp, const void *cookie)
{
	struct file_entry *entry = malloc(sizeof *entry);
	if (!entry) {
		return;
	}
	entry->fp = fp;
	entry->cookie = cookie;

	if (!registered_atexit) {
		registered_atexit = 1;
		atexit(pcap_ioplugin_closeall);
	}

	/* O(1) insertion to front of list */
	entry->next = file_list.head;
	file_list.head = entry;
}

void
pcap_ioplugin_unregister_fp_cookie(const void *cookie)
{
	struct file_entry *entry = file_list.head;

	/* atexit handler does its own list traversal */
	if (running_atexit) {
		return;
	}

	/* check head of list */
	if (entry && entry->cookie == cookie) {
		file_list.head = entry->next;
		free(entry);
		return;
	}

	/* otherwise check following nodes */
	while (entry) {
		struct file_entry *next = entry->next;
		if (next && next->cookie == cookie) {
			/* remove following node */
			entry->next = next->next;
			free(next);
			return;
		}
		entry = next;
	}
}
