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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>

#include "portability.h"
#include "test-util.h"

static const char *program_name;

int
main(int argc, char **argv)
{
	pcap_t *pd;
	char ebuf[PCAP_ERRBUF_SIZE];
	int status;

	program_name = set_program_name(argv[0]);

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <device>\n", program_name);
		exit(EX_USAGE);
	}

	pd = pcap_create(argv[1], ebuf);
	if (pd == NULL)
		error(EX_OSERR, "%s", ebuf);
	status = pcap_can_set_rfmon(pd);
	if (status < 0) {
		if (status == PCAP_ERROR)
			error(EX_OSERR, "%s: pcap_can_set_rfmon failed: %s",
			    argv[1], pcap_geterr(pd));
		else
			error(EX_OSERR, "%s: pcap_can_set_rfmon failed: %s",
			    argv[1], pcap_statustostr(status));
	}
	printf("%s: Monitor mode %s be set\n", argv[1], status ? "can" : "cannot");
	exit(EX_OK);
}
