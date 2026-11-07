/*
 * Copyright (c) 2005
 *	The Tcpdump Group and contributors.  All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef TEST_UTIL_H
#define TEST_UTIL_H

#include <sys/types.h>
#include "pcap/funcattrs.h"

const char *set_program_name(const char *) PCAP_NONNULL(1);
void PCAP_NORETURN error(const int, PCAP_FORMAT_STRING(const char *), ...) PCAP_PRINTFLIKE(2, 3);
void warning(const char *, ...) PCAP_PRINTFLIKE(1, 2);
char *copy_argv(char **) PCAP_NONNULL(1);
void blank_comments(char *, const size_t) PCAP_NONNULL(1);
char *read_infile(const char *) PCAP_NONNULL(1);

#endif // TEST_UTIL_H
