/*
 * Copyright (c) 2026
 *	The Tcpdump Group and contributors.  All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Allocation-failure test for pcap_compile().
 *
 * This program replaces malloc(), calloc(), realloc(), free() and strdup()
 * with an allocator over a private arena that can fail any chosen allocation
 * on demand.  Because the test is linked with the static libpcap library,
 * every allocation libpcap makes goes through these functions, so each
 * allocation failure point of pcap_compile() can be tested in turn without
 * any special build options.
 *
 * For every allocation failure point the test checks that pcap_compile():
 *
 *  - does not terminate the process (the Flex scanner used to call exit()
 *    on internal allocation failures) and does not crash;
 *
 *  - either succeeds or fails with PCAP_ERROR and a non-empty error message;
 *
 *  - leaves no allocated memory behind (error paths used to leak the scanner
 *    input buffer state and the copy of the filter string).
 *
 * The test also checks that pcap_compile() succeeds when no allocation
 * fails, and that the resulting program can be run.
 */

#include <config.h> // for feature-test macros

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
  #include "getopt.h"
#else
  #include <unistd.h>
#endif

#if defined(_WIN32) || defined(__QNX__)
  #include "unix.h"
#else
  #include <sysexits.h>
#endif

#include "pcap/pcap.h"
#include "pcap-int.h" // struct pcap, for p->errbuf

static const char *program_name;

/*
 * A simple free-list allocator over a static arena with coalescing.  It
 * needs no allocation of its own and can serve any number of allocations
 * and frees in any order, so it is safe to use from the replacement
 * allocation functions themselves and from the C library.
 *
 * Every block has a header immediately before its payload; the payload is
 * aligned to the strictest fundamental alignment.  Each block also records
 * whether it was allocated while a test iteration was running ("scoped");
 * only scoped blocks take part in the leak check, so one-time lazy
 * allocations made by the C library outside pcap_compile() do not matter.
 */
#define ARENA_SIZE (8U * 1024U * 1024U)

union max_align {
	long double ld;
	void *p;
	long long ll;
};

struct blk {
	struct blk *prev;	/* previous block in the arena */
	struct blk *next;	/* next block in the arena */
	size_t size;		/* payload size in bytes */
	int is_free;
	int scoped;
	unsigned int magic;
};

#define BLK_MAGIC 0x70637031U
#define ALIGN_SIZE (sizeof(union max_align))
#define HDR_SIZE \
	(((sizeof(struct blk) + ALIGN_SIZE - 1U) / ALIGN_SIZE) * ALIGN_SIZE)

static union max_align arena[ARENA_SIZE / sizeof(union max_align)];
#define ARENA_BYTES (sizeof(arena))

static struct blk *first_blk;
static struct blk *last_blk;
static size_t arena_used;
static long scoped_live;	/* live scoped blocks */
static int arena_error;		/* arena exhaustion or corruption */

/* Allocation failure injection state. */
static int inject_active;	/* nonzero while pcap_compile() runs */
static long inject_count;	/* allocations seen in this iteration */
static long inject_fail_at;	/* fail this allocation; 0 = fail none */

/*
 * Round an allocation size up to the arena alignment; returns nonzero on
 * overflow.
 */
static int
round_up_size(size_t n, size_t *out)
{
	if (n == 0)
		n = 1;
	if (n > SIZE_MAX - (ALIGN_SIZE - 1U))
		return 1;
	*out = ((n + ALIGN_SIZE - 1U) / ALIGN_SIZE) * ALIGN_SIZE;
	return 0;
}

static void *
arena_alloc(size_t n, int scoped)
{
	struct blk *b;
	size_t need;

	if (round_up_size(n, &need)) {
		arena_error = 1;
		errno = ENOMEM;
		return NULL;
	}

	/* First fit among the free blocks. */
	for (b = first_blk; b != NULL; b = b->next) {
		if (! b->is_free || b->size < need)
			continue;
		/* Split the block if the remainder can hold a block. */
		if (b->size >= need + HDR_SIZE + ALIGN_SIZE) {
			struct blk *nb;

			nb = (struct blk *)((char *)b + HDR_SIZE + need);
			nb->prev = b;
			nb->next = b->next;
			nb->size = b->size - need - HDR_SIZE;
			nb->is_free = 1;
			nb->scoped = 0;
			nb->magic = 0;
			if (nb->next != NULL)
				nb->next->prev = nb;
			else
				last_blk = nb;
			b->next = nb;
			b->size = need;
		}
		b->is_free = 0;
		b->scoped = scoped;
		b->magic = BLK_MAGIC;
		if (scoped)
			scoped_live++;
		return (char *)b + HDR_SIZE;
	}

	/* Allocate a fresh block at the tail of the arena. */
	if (arena_used + HDR_SIZE + need > ARENA_BYTES) {
		arena_error = 1;
		errno = ENOMEM;
		return NULL;
	}
	b = (struct blk *)((char *)arena + arena_used);
	arena_used += HDR_SIZE + need;
	b->prev = last_blk;
	b->next = NULL;
	b->size = need;
	b->is_free = 0;
	b->scoped = scoped;
	b->magic = BLK_MAGIC;
	if (last_blk != NULL)
		last_blk->next = b;
	else
		first_blk = b;
	last_blk = b;
	if (scoped)
		scoped_live++;
	return (char *)b + HDR_SIZE;
}

/*
 * Release a block and coalesce it with its free neighbours.  A pointer that
 * is not in the arena at all was allocated by some other allocator (parts
 * of the C library allocate internally with symbols this test does not
 * replace); there is no portable way to release such a block here, so it is
 * left alone.
 */
static void
arena_free(void *p)
{
	struct blk *b;

	if (p == NULL)
		return;
	if ((char *)p < (char *)arena + HDR_SIZE ||
	    (char *)p >= (char *)arena + ARENA_BYTES)
		return;
	b = (struct blk *)((char *)p - HDR_SIZE);
	if (b->magic != BLK_MAGIC) {
		/* Double free or corruption. */
		arena_error = 1;
		return;
	}
	b->magic = 0;
	b->is_free = 1;
	if (b->scoped)
		scoped_live--;

	if (b->next != NULL && b->next->is_free) {
		b->size += HDR_SIZE + b->next->size;
		b->next = b->next->next;
		if (b->next != NULL)
			b->next->prev = b;
		else
			last_blk = b;
	}
	if (b->prev != NULL && b->prev->is_free) {
		b->prev->size += HDR_SIZE + b->size;
		b->prev->next = b->next;
		if (b->next != NULL)
			b->next->prev = b->prev;
		else
			last_blk = b->prev;
	}
}

static void *
arena_realloc(void *p, size_t n, int scoped)
{
	struct blk *b;
	size_t need;
	void *q;

	if (p == NULL)
		return arena_alloc(n, scoped);
	if (n == 0) {
		arena_free(p);
		return NULL;
	}
	b = (struct blk *)((char *)p - HDR_SIZE);
	if (b->magic != BLK_MAGIC) {
		arena_error = 1;
		return NULL;
	}
	if (round_up_size(n, &need)) {
		arena_error = 1;
		errno = ENOMEM;
		return NULL;
	}
	if (b->size >= need)
		return p;
	/*
	 * Allocate before releasing, so that on failure the original block
	 * remains valid and unchanged, as realloc() requires.  The copy
	 * inherits the scope of the original block.
	 */
	q = arena_alloc(n, b->scoped);
	if (q == NULL)
		return NULL;
	memcpy(q, p, b->size);
	arena_free(p);
	return q;
}

/*
 * Decide whether this allocation attempt should fail.  The injection
 * counter runs only while pcap_compile() is executing, so allocations made
 * by the C library on behalf of this program never fail.
 */
static int
fail_now(void)
{
	if (! inject_active)
		return 0;
	inject_count++;
	if (inject_fail_at != 0 && inject_count == inject_fail_at) {
		errno = ENOMEM;
		return 1;
	}
	return 0;
}

void *
malloc(size_t n)
{
	if (fail_now())
		return NULL;
	return arena_alloc(n, inject_active);
}

void *
calloc(size_t m, size_t n)
{
	void *p;
	size_t total;

	if (fail_now())
		return NULL;
	if (m != 0 && n > SIZE_MAX / m) {
		errno = ENOMEM;
		return NULL;
	}
	total = m * n;
	p = arena_alloc(total, inject_active);
	if (p != NULL)
		memset(p, 0, total);
	return p;
}

void *
realloc(void *p, size_t n)
{
	if (fail_now())
		return NULL;
	return arena_realloc(p, n, inject_active);
}

void
free(void *p)
{
	arena_free(p);
}

char *
strdup(const char *s)
{
	size_t n;
	char *p;

	if (fail_now())
		return NULL;
	n = strlen(s) + 1;
	p = arena_alloc(n, inject_active);
	if (p != NULL)
		memcpy(p, s, n);
	return p;
}

/*
 * Run pcap_compile() once with allocation number fail_at injected
 * (0 = inject nothing).  On success runs the resulting program and frees
 * it.  Returns nonzero on a test failure, with a message printed.
 */
static int
check_compile(pcap_t *p, const char *filter, int optimize, long fail_at,
    long *count_out)
{
	struct bpf_program f;
	int rc;

	/*
	 * The error buffer must start out empty, otherwise a stale error
	 * message from a previous run could mask a missing one.
	 */
	p->errbuf[0] = '\0';
	inject_count = 0;
	inject_fail_at = fail_at;
	inject_active = 1;
	rc = pcap_compile(p, &f, filter, optimize, 0xFFFFFF);
	inject_active = 0;
	if (count_out != NULL)
		*count_out = inject_count;

	if (rc == 0) {
		struct pcap_pkthdr h;
		unsigned char pkt[128];

		memset(&h, 0, sizeof(h));
		memset(pkt, 0x45, sizeof(pkt));
		h.caplen = h.len = (bpf_u_int32)sizeof(pkt);
		(void)pcap_offline_filter(&f, &h, pkt);
		pcap_freecode(&f);
		/*
		 * A successful compile with a failure injected is fine:
		 * the failed allocation may have been made by the C library
		 * on behalf of an operation whose failure libpcap tolerates.
		 */
		return 0;
	}
	if (fail_at == 0) {
		fprintf(stderr, "%s: pcap_compile(\"%s\") failed without an "
		    "injected failure: %s\n", program_name, filter,
		    p->errbuf[0] != '\0' ? p->errbuf : "no error message");
		return 1;
	}
	if (rc != PCAP_ERROR) {
		fprintf(stderr, "%s: pcap_compile(\"%s\") with allocation %ld "
		    "failing returned %d, expected %d\n", program_name, filter,
		    fail_at, rc, PCAP_ERROR);
		return 1;
	}
	if (p->errbuf[0] == '\0') {
		fprintf(stderr, "%s: pcap_compile(\"%s\") with allocation %ld "
		    "failing set no error message\n", program_name, filter,
		    fail_at);
		return 1;
	}
	return 0;
}

static const char *const test_filters[] = {
	"tcp port 80",
	"host 1.2.3.4 and udp",
	"ether proto \\ip and ip[0] & 0xf != 5",
	"ip6 protochain 17",
	"vlan and (tcp or udp)",
	"tcp[tcpflags] & (tcp-syn|tcp-fin) != 0",
	"not broadcast and not multicast",
};

/*
 * For every test filter and both optimisation settings, fail every
 * allocation of pcap_compile() in turn and check the results.
 */
static int
run_compile_suite(void)
{
	pcap_t *p;
	unsigned int i;
	int failures = 0;

	p = pcap_open_dead(DLT_EN10MB, 65535);
	if (p == NULL) {
		fprintf(stderr, "%s: pcap_open_dead() failed\n", program_name);
		return EX_SOFTWARE;
	}

	for (i = 0; i < sizeof(test_filters) / sizeof(test_filters[0]); i++) {
		for (int optimize = 0; optimize <= 1; optimize++) {
			long n;

			/*
			 * The first run must succeed and counts the
			 * allocations made by one pcap_compile() call.
			 */
			if (check_compile(p, test_filters[i], optimize, 0,
			    &n)) {
				failures++;
				continue;
			}
			if (n == 0) {
				fprintf(stderr, "%s: no allocations seen for "
				    "\"%s\"; the allocation replacements are "
				    "not being used\n", program_name,
				    test_filters[i]);
				failures++;
				continue;
			}
			if (scoped_live != 0) {
				fprintf(stderr, "%s: \"%s\" leaked %ld block(s)"
				    "\n", program_name, test_filters[i],
				    scoped_live);
				failures++;
				continue;
			}

			for (long fail_at = 1; fail_at <= n; fail_at++) {
				long used;

				if (check_compile(p, test_filters[i],
				    optimize, fail_at, &used)) {
					failures++;
					break;
				}
				if (scoped_live != 0) {
					fprintf(stderr, "%s: \"%s\" with "
					    "allocation %ld failing leaked "
					    "%ld block(s)\n", program_name,
					    test_filters[i], fail_at,
					    scoped_live);
					failures++;
					break;
				}
				if (arena_error) {
					fprintf(stderr, "%s: \"%s\" with "
					    "allocation %ld failing hit an "
					    "arena error (double free or "
					    "corruption)\n", program_name,
					    test_filters[i], fail_at);
					failures++;
					break;
				}
			}
		}
	}

	pcap_close(p);
	if (failures != 0)
		return EX_SOFTWARE;
	printf("OK\n");
	return EX_OK;
}

static void
usage_short(FILE *f)
{
	fprintf(f, "%s, with %s\n", program_name, pcap_lib_version());
	fprintf(f, "Usage: %s <name>\n", program_name);
	fprintf(f, "       (run an allocation-failure test)\n");
	fprintf(f, "   or: %s -h\n", program_name);
	fprintf(f, "       (print the detailed help screen)\n");
}

static void
usage_long(FILE *f)
{
	usage_short(f);
	fprintf(f, "\nSupported valid invocations:\n");
	fprintf(f, "       %s compile\n", program_name);
	fprintf(f, "\nExit status codes:\n");
	fprintf(f, "  %3u: Success.\n", EX_OK);
	fprintf(f, "  %3u: Unexpected error in the results.\n", EX_SOFTWARE);
	fprintf(f, "  %3u: Invalid command-line argument(s).\n", EX_USAGE);
}

int
main(int argc, char **argv)
{
	{
		const char *cp = strrchr(argv[0], '/');
		program_name = cp ? cp + 1 : argv[0];
	}

	{
		int op;
		opterr = 0;

		// Use "if", same as in translatetest.c.
		if ((op = getopt(argc, argv, "h")) != -1) {
			switch (op) {
			case 'h':
				usage_long(stdout);
				exit(EX_OK);
			default:
				usage_short(stderr);
				exit(EX_USAGE);
			}
		}
	}

	argc -= optind;
	argv += optind;
	if (argc == 1 && ! strcmp(argv[0], "compile"))
		exit(run_compile_suite());
	usage_short(stderr);
	exit(EX_USAGE);
}
