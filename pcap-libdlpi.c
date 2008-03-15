/*
 * Copyright (c) 1993, 1994, 1995, 1996, 1997
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
 *
 * This code contributed by Sagun Shakya (sagun.shakya@sun.com)
 */
/*
 * Packet capture routines for DLPI using libdlpi under SunOS 5.11.
 */

#ifndef lint
static const char rcsid[] _U_ =
	"@(#) $Header: /tcpdump/master/libpcap/pcap-libdlpi.c,v 1.1.2.3 2008-03-15 04:26:29 guy Exp $ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/bufmod.h>
#include <sys/stream.h>
#include <libdlpi.h>
#include <errno.h>
#include <memory.h>
#include <stropts.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pcap-int.h"
#include "dlpisubs.h"

/* Forwards. */
static int pcap_read_libdlpi(pcap_t *, int, pcap_handler, u_char *);
static int pcap_inject_libdlpi(pcap_t *, const void *, size_t);
static void pcap_close_libdlpi(pcap_t *);
static void pcap_libdlpi_err(const char *, const char *, int, char *);

/*
 * list_interfaces() will list all the network links that are
 * available on a system.
 */
static boolean_t list_interfaces(const char *, void *);

typedef struct linknamelist {
	char	linkname[DLPI_LINKNAME_MAX];
	struct linknamelist *lnl_next;
} linknamelist_t;

typedef struct linkwalk {
	linknamelist_t	*lw_list;
	int		lw_err;
} linkwalk_t;

/*
 * The caller of this function should free the memory allocated
 * for each linknamelist_t "entry" allocated.
 */
static boolean_t
list_interfaces(const char *linkname, void *arg)
{
	linkwalk_t	*lwp = arg;
	linknamelist_t	*entry;

	if ((entry = calloc(1, sizeof(linknamelist_t))) == NULL) {
		lwp->lw_err = ENOMEM;
		return (B_TRUE);
	}
	(void) strlcpy(entry->linkname, linkname, DLPI_LINKNAME_MAX);

	if (lwp->lw_list == NULL) {
		lwp->lw_list = entry;
	} else {
		entry->lnl_next = lwp->lw_list;
		lwp->lw_list = entry;
	}

	return (B_FALSE);
}

pcap_t *
pcap_open_live(const char *device, int snaplen, int promisc, int to_ms,
    char *ebuf)
{
	int retv;
	pcap_t *p;
	dlpi_handle_t dh;
	dlpi_info_t dlinfo;

	if ((p = (pcap_t *)malloc(sizeof(*p))) == NULL) {
		strlcpy(ebuf, pcap_strerror(errno), PCAP_ERRBUF_SIZE);
		return (NULL);
	}
	memset(p, 0, sizeof(*p));
	p->fd = -1;	/* indicate that it hasn't been opened yet */
	p->send_fd = -1;

	/*
	 * Enable Solaris raw and passive DLPI extensions;
	 * dlpi_open() will not fail if the underlying link does not support
	 * passive mode. See dlpi(7P) for details.
	 */
	retv = dlpi_open(device, &dh, DLPI_RAW|DLPI_PASSIVE);
	if (retv != DLPI_SUCCESS) {
		pcap_libdlpi_err(device, "dlpi_open", retv, ebuf);
		goto bad;
	}
	p->dlpi_hd = dh;

	p->snapshot = snaplen;

	/* Bind with DLPI_ANY_SAP. */
	if ((retv = dlpi_bind(p->dlpi_hd, DLPI_ANY_SAP, 0)) != DLPI_SUCCESS) {
		pcap_libdlpi_err(device, "dlpi_bind", retv, ebuf);
		goto bad;
	}

	/* Enable promiscuous mode. */
	if (promisc) {
		retv = dlpi_promiscon(p->dlpi_hd, DL_PROMISC_PHYS);
		if (retv != DLPI_SUCCESS) {
			pcap_libdlpi_err(device, "dlpi_promisc(PHYSICAL)",
			    retv, ebuf);
			goto bad;
		}
	} else {
		/* Try to enable multicast. */
		retv = dlpi_promiscon(p->dlpi_hd, DL_PROMISC_MULTI);
		if (retv != DLPI_SUCCESS) {
			pcap_libdlpi_err(device, "dlpi_promisc(MULTI)",
			    retv, ebuf);
			goto bad;
		}
	}

	/* Try to enable SAP promiscuity. */
	if ((retv = dlpi_promiscon(p->dlpi_hd, DL_PROMISC_SAP)) != DLPI_SUCCESS) {
		if (!promisc) {
			pcap_libdlpi_err(device, "dlpi_promisc(SAP)",
			    retv, ebuf);
			goto bad;
		}

		/* Not fatal, since the DL_PROMISC_PHYS mode worked. */
		fprintf(stderr, "WARNING: dlpi_promisc(SAP) failed on"
		    " %s:(%s)\n", device, dlpi_strerror(retv));
	}

	/* Determine link type.  */
	if ((retv = dlpi_info(p->dlpi_hd, &dlinfo, 0)) != DLPI_SUCCESS) {
		pcap_libdlpi_err(device, "dlpi_info", retv, ebuf);
		goto bad;
	}

	if (pcap_process_mactype(p, dlinfo.di_mactype, ebuf) != 0)
		goto bad;

	p->fd = dlpi_fd(p->dlpi_hd);

	/* Push and configure bufmod. */
	if (pcap_conf_bufmod(p, snaplen, to_ms, ebuf) != 0)
		goto bad;

	/*
	 * Flush the read side.
	 */
	if (ioctl(p->fd, I_FLUSH, FLUSHR) != 0) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "FLUSHR: %s",
		    pcap_strerror(errno));
		goto bad;
	}

	/* Allocate data buffer. */
	if (pcap_alloc_databuf(p, ebuf) != 0)
		goto bad;

	/*
	 * "p->fd" is a FD for a STREAMS device, so "select()" and
	 * "poll()" should work on it.
	 */
	p->selectable_fd = p->fd;

	p->read_op = pcap_read_libdlpi;
	p->inject_op = pcap_inject_libdlpi;
	p->setfilter_op = install_bpf_program;	/* No kernel filtering */
	p->setdirection_op = NULL;	/* Not implemented */
	p->set_datalink_op = NULL;	/* Can't change data link type */
	p->getnonblock_op = pcap_getnonblock_fd;
	p->setnonblock_op = pcap_setnonblock_fd;
	p->stats_op = pcap_stats_dlpi;
	p->close_op = pcap_close_libdlpi;

	return (p);
bad:
	/* Get rid of any link-layer type list we allocated. */
	if (p->dlt_list != NULL)
		free(p->dlt_list);
	pcap_close_libdlpi(p);
	free(p);
	return (NULL);
}

/*
 * In Solaris, the "standard" mechanism" i.e SIOCGLIFCONF will only find
 * network links that are plumbed and are up. dlpi_walk(3DLPI) will find
 * additional network links present in the system.
 */
int
pcap_platform_finddevs(pcap_if_t **alldevsp, char *errbuf)
{
	int retv = 0;

	linknamelist_t	*entry, *next;
	linkwalk_t	lw = {NULL, 0};
	int 		save_errno;

	/* dlpi_walk() for loopback will be added here. */

	dlpi_walk(list_interfaces, &lw, 0);

	if (lw.lw_err != 0) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE,
		    "dlpi_walk: %s", pcap_strerror(lw.lw_err));
		retv = -1;
		goto done;
	}

	/* Add linkname if it does not exist on the list. */
	for (entry = lw.lw_list; entry != NULL; entry = entry->lnl_next) {
		if (pcap_add_if(alldevsp, entry->linkname, 0, NULL, errbuf) < 0)
			retv = -1;
	}
done:
	save_errno = errno;
	for (entry = lw.lw_list; entry != NULL; entry = next) {
		next = entry->lnl_next;
		free(entry);
	}
	errno = save_errno;

	return (retv);
}

/*
 * Read data received on DLPI handle. Returns -2 if told to terminate, else
 * returns the number of packets read.
 */
static int
pcap_read_libdlpi(pcap_t *p, int count, pcap_handler callback, u_char *user)
{
	int len;
	u_char *bufp;
	size_t msglen;
	int retv;

	len = p->cc;
	if (len != 0) {
		bufp = p->bp;
		goto process_pkts;
	}
	do {
		/* Has "pcap_breakloop()" been called? */
		if (p->break_loop) {
			/*
			 * Yes - clear the flag that indicates that it has,
			 * and return -2 to indicate that we were told to
			 * break out of the loop.
			 */
			p->break_loop = 0;
			return (-2);
		}

		msglen = p->bufsize;
		bufp = p->buffer + p->offset;

		retv = dlpi_recv(p->dlpi_hd, NULL, NULL, bufp,
		    &msglen, -1, NULL);
		if (retv != DLPI_SUCCESS) {
			/*
			 * This is most likely a call to terminate out of the
			 * loop. So, do not return an error message, instead
			 * check if "pcap_breakloop()" has been called above.
			 */
			if (retv == DL_SYSERR && errno == EINTR) {
				len = 0;
				continue;
			}
			pcap_libdlpi_err(dlpi_linkname(p->dlpi_hd),
			    "dlpi_recv", retv, p->errbuf);
			return (-1);
		}
		len = msglen;
	} while (len == 0);

process_pkts:
	return (pcap_process_pkts(p, callback, user, count, bufp, len));
}

static int
pcap_inject_libdlpi(pcap_t *p, const void *buf, size_t size)
{
	int retv;

	retv = dlpi_send(p->dlpi_hd, NULL, 0, buf, size, NULL);
	if (retv != DLPI_SUCCESS) {
		pcap_libdlpi_err(dlpi_linkname(p->dlpi_hd), "dlpi_send", retv,
		    p->errbuf);
		return (-1);
	}
	/*
	 * dlpi_send(3DLPI) does not provide a way to return the number of
	 * bytes sent on the wire. Based on the fact that DLPI_SUCCESS was
	 * returned we are assuming 'size' bytes were sent.
	 */
	return (size);
}

/*
 * Close dlpi handle and deallocate data buffer.
 */
static void
pcap_close_libdlpi(pcap_t *p)
{
	dlpi_close(p->dlpi_hd);
	free(p->buffer);
}

/*
 * Write error message to buffer.
 */
static void
pcap_libdlpi_err(const char *linkname, const char *func, int err, char *errbuf)
{
	snprintf(errbuf, PCAP_ERRBUF_SIZE, "libpcap: %s failed on %s: %s",
	    func, linkname, dlpi_strerror(err));
}
