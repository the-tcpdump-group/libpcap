/*
 * Copyright (c) 1993, 1994, 1995, 1996, 1997, 1998
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the Computer Systems
 *	Engineering Group at Lawrence Berkeley Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef lint
static const char rcsid[] =
    "@(#) $Header: /tcpdump/master/libpcap/pcap.c,v 1.41 2002-08-02 03:44:21 guy Exp $ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef WIN32
#include <pcap-stdinc.h>
#else /* WIN32 */
#include <sys/types.h>
#endif /* WIN32 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include <fcntl.h>
#include <errno.h>

#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#include "pcap-int.h"

int
pcap_dispatch(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{

	if (p->sf.rfile != NULL)
		return (pcap_offline_read(p, cnt, callback, user));
	return (pcap_read(p, cnt, callback, user));
}

int
pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
	register int n;

	for (;;) {
		if (p->sf.rfile != NULL)
			n = pcap_offline_read(p, cnt, callback, user);
		else {
			/*
			 * XXX keep reading until we get something
			 * (or an error occurs)
			 */
			do {
				n = pcap_read(p, cnt, callback, user);
			} while (n == 0);
		}
		if (n <= 0)
			return (n);
		if (cnt > 0) {
			cnt -= n;
			if (cnt <= 0)
				return (0);
		}
	}
}

struct singleton {
	struct pcap_pkthdr *hdr;
	const u_char *pkt;
};


static void
pcap_oneshot(u_char *userData, const struct pcap_pkthdr *h, const u_char *pkt)
{
	struct singleton *sp = (struct singleton *)userData;
	*sp->hdr = *h;
	sp->pkt = pkt;
}

const u_char *
pcap_next(pcap_t *p, struct pcap_pkthdr *h)
{
	struct singleton s;

	s.hdr = h;
	if (pcap_dispatch(p, 1, pcap_oneshot, (u_char*)&s) <= 0)
		return (0);
	return (s.pkt);
}

int
pcap_datalink(pcap_t *p)
{
	return (p->linktype);
}

int
pcap_snapshot(pcap_t *p)
{
	return (p->snapshot);
}

int
pcap_is_swapped(pcap_t *p)
{
	return (p->sf.swapped);
}

int
pcap_major_version(pcap_t *p)
{
	return (p->sf.version_major);
}

int
pcap_minor_version(pcap_t *p)
{
	return (p->sf.version_minor);
}

FILE *
pcap_file(pcap_t *p)
{
	return (p->sf.rfile);
}

int
pcap_fileno(pcap_t *p)
{
#ifndef WIN32
	return (p->fd);
#else
	if (p->adapter != NULL)
		return ((int)(DWORD)p->adapter->hFile);
	else
		return (-1);
#endif
}

void
pcap_perror(pcap_t *p, char *prefix)
{
	fprintf(stderr, "%s: %s\n", prefix, p->errbuf);
}

char *
pcap_geterr(pcap_t *p)
{
	return (p->errbuf);
}

/*
 * NOTE: in the future, these may need to call platform-dependent routines,
 * e.g. on platforms with memory-mapped packet-capture mechanisms where
 * "pcap_read()" uses "select()" or "poll()" to wait for packets to arrive.
 */
int
pcap_getnonblock(pcap_t *p, char *errbuf)
{
#ifndef WIN32
	int fdflags;
#endif

	if (p->sf.rfile != NULL) {
		/*
		 * This is a savefile, not a live capture file, so
		 * never say it's in non-blocking mode.
		 */
		return (0);
	}
#ifndef WIN32
	fdflags = fcntl(p->fd, F_GETFL, 0);
	if (fdflags == -1) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "F_GETFL: %s",
		    pcap_strerror(errno));
		return (-1);
	}
	if (fdflags & O_NONBLOCK)
		return (1);
	else
		return (0);
#else
	return (p->nonblock);
#endif
}

int
pcap_setnonblock(pcap_t *p, int nonblock, char *errbuf)
{
#ifndef WIN32
	int fdflags;
#else
	int newtimeout;
#endif

	if (p->sf.rfile != NULL) {
		/*
		 * This is a savefile, not a live capture file, so
		 * ignore requests to put it in non-blocking mode.
		 */
		return (0);
	}
#ifndef WIN32
	fdflags = fcntl(p->fd, F_GETFL, 0);
	if (fdflags == -1) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "F_GETFL: %s",
		    pcap_strerror(errno));
		return (-1);
	}
	if (nonblock)
		fdflags |= O_NONBLOCK;
	else
		fdflags &= ~O_NONBLOCK;
	if (fcntl(p->fd, F_SETFL, fdflags) == -1) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "F_SETFL: %s",
		    pcap_strerror(errno));
		return (-1);
	}
#else
	if (nonblock) {
		/*
		 * Set the read timeout to -1 for non-blocking mode.
		 */
		newtimeout = -1;
	} else {
		/*
		 * Restore the timeout set when the device was opened.
		 * (Note that this may be -1, in which case we're not
		 * really leaving non-blocking mode.)
		 */
		newtimeout = p->timeout;
	}
	if (!PacketSetReadTimeout(p->adapter, newtimeout)) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "PacketSetReadTimeout: %s", pcap_win32strerror());
		return (-1);
	}
	p->nonblock = (newtimeout == -1);
#endif
	return (0);
}

#ifdef WIN32
/*
 * Generate a string for the last Win32-specific error (i.e. an error generated when 
 * calling a Win32 API).
 * For errors occurred during standard C calls, we still use pcap_strerror()
 */
char *
pcap_win32strerror(void)
{
	DWORD error;
	static char errbuf[PCAP_ERRBUF_SIZE+1];
	int errlen;

	error = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, error, 0, errbuf,
	    PCAP_ERRBUF_SIZE, NULL);

	/*
	 * "FormatMessage()" "helpfully" sticks CR/LF at the end of the
	 * message.  Get rid of it.
	 */
	errlen = strlen(errbuf);
	if (errlen >= 2) {
		errbuf[errlen - 1] = '\0';
		errbuf[errlen - 2] = '\0';
	}
	return (errbuf);
}
#endif

/*
 * Not all systems have strerror().
 */
char *
pcap_strerror(int errnum)
{
#ifdef HAVE_STRERROR
	return (strerror(errnum));
#else
	extern int sys_nerr;
	extern const char *const sys_errlist[];
	static char ebuf[20];

	if ((unsigned int)errnum < sys_nerr)
		return ((char *)sys_errlist[errnum]);
	(void)snprintf(ebuf, sizeof ebuf, "Unknown error: %d", errnum);
	return(ebuf);
#endif
}

pcap_t *
pcap_open_dead(int linktype, int snaplen)
{
	pcap_t *p;

	p = malloc(sizeof(*p));
	if (p == NULL)
		return NULL;
	memset (p, 0, sizeof(*p));
#ifndef WIN32
	p->fd = -1;
#else
	p->adapter = NULL;
#endif /* WIN32 */
	p->snapshot = snaplen;
	p->linktype = linktype;
	return p;
}

void
pcap_close(pcap_t *p)
{
	/*XXX*/
#ifndef WIN32
	if (p->fd >= 0) {
#ifdef linux
		pcap_close_linux(p);
#endif
		close(p->fd);
	}
#else /* WIN32 */
	if (p->adapter != NULL) {
		PacketCloseAdapter(p->adapter);
		p->adapter = NULL;
	}
#endif /* WIN32 */
	if (p->sf.rfile != NULL) {
		if (p->sf.rfile != stdin)
			(void)fclose(p->sf.rfile);
		if (p->sf.base != NULL)
			free(p->sf.base);
	} else if (p->buffer != NULL)
		free(p->buffer);

	pcap_freecode(&p->fcode);
	free(p);
}
