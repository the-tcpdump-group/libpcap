/*
 * Copyright (c) 1993, 1994, 1995, 1996, 1998
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pcap-int.h"

/*
 * Private data for storing sets of options.
 * This is to be used by functions which seem to grow additional options
 * This is avoid ABI explosion of do_thing, and do_thing_with_opt_bar(),
 * and then do_thing_with_opt_bar_baz(...). Instead a "pcap_option" should be
 * created to which get/set shall be done.
 *
 * each option shall have an element in enum pcap_option_name {}.
 */
struct pcap_options {
        int   tstamp_precision;
        const char *io_read_plugin;
        const char *io_write_plugin;
};

pcap_options *pcap_alloc_option(void)
{
        pcap_options *po = malloc(sizeof(struct pcap_options));
        memset(po, 0, sizeof(struct pcap_options));
        return po;  // caller has to check for NULL anyway.
}

void pcap_free_option(pcap_options *po)
{
        if(po != NULL) {
                if(po->io_read_plugin) free((void *)po->io_read_plugin);
                if(po->io_write_plugin) free((void *)po->io_write_plugin);
                free((void *)po);
        }
}

/* Return 0 on success, -1 on failure invalid option, -2 on type mismatch */
int pcap_set_option_string(pcap_options *po,
                           enum   pcap_option_name pon,
                           const char *value)
{
        const char *saved = strdup(value);
        switch(pon) {
        case PON_TSTAMP_PRECISION:
                free((void *)saved);
                return -2;

        case PON_IO_READ_PLUGIN:
                po->io_read_plugin = saved;
                break;
        case PON_IO_WRITE_PLUGIN:
                po->io_write_plugin= saved;
                break;
        default:
                free((void *)saved);
                return -1;
        }
        return 0;
}

/* Return 0 on success, -1 on failure invalid option, -2 on type mismatch */
int pcap_set_option_int(pcap_options *po,
                        enum   pcap_option_name pon,
                        const int value)
{
        switch(pon) {
        case PON_TSTAMP_PRECISION:
                po->tstamp_precision = value;
                break;

        case PON_IO_READ_PLUGIN:
        case PON_IO_WRITE_PLUGIN:
                return -2;
        default:
                return -1;
        }
        return 0;
}

const char *pcap_get_option_string(pcap_options *po,
                                   enum   pcap_option_name pon)
{
        switch(pon) {
        case PON_TSTAMP_PRECISION:
                return NULL;

        case PON_IO_READ_PLUGIN:
                return po->io_read_plugin;
        case PON_IO_WRITE_PLUGIN:
                return po->io_write_plugin;
        }
        return NULL;
}


/* return int value, or zero for not-found, mis-type */
int pcap_get_option_int(pcap_options *po,
                        enum   pcap_option_name pon)
{
        switch(pon) {
        case PON_TSTAMP_PRECISION:
                return po->tstamp_precision;
                break;

        case PON_IO_READ_PLUGIN:
        case PON_IO_WRITE_PLUGIN:
                return 0;
        }
        return 0;
}

