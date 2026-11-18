/*
 * Copyright (c) 2005
 *	The Tcpdump Group and contributors.  All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef TEST_UTIL_H
#define TEST_UTIL_H

#include <pcap.h>
#include <sys/types.h>
#include "pcap/funcattrs.h"

#define MAX_STDIN		(64 * 1024)

const char *set_program_name(const char *) PCAP_NONNULL(1);
void PCAP_NORETURN error(const int, PCAP_FORMAT_STRING(const char *), ...) PCAP_PRINTFLIKE(2, 3);
void warning(PCAP_FORMAT_STRING(const char *), ...) PCAP_PRINTFLIKE(1, 2);
char *copy_argv(char **) PCAP_NONNULL(1) PCAP_WARN_UNUSED_RESULT;
void blank_comments(char *, const size_t) PCAP_NONNULL(1);
char *read_infile(const char *) PCAP_NONNULL(1) PCAP_WARN_UNUSED_RESULT;
char *read_stdin(void) PCAP_WARN_UNUSED_RESULT;
int read_cbpffile(const char *, struct bpf_program *, char *) PCAP_NONNULL(1, 2, 3) PCAP_WARN_UNUSED_RESULT;
void print_filtering_results(pcap_t *, const struct bpf_program *) PCAP_NONNULL(1, 2);

#endif // TEST_UTIL_H
