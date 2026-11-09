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

#include <config.h>

#include <stdio.h>
#include <string.h>

#include "sockutils.h"

/*
 * Zero-length data is legitimate in the rpcap protocol, and the source
 * pointer may be NULL in that case (for example, an interface without a
 * description).  sock_bufferize() must not pass a NULL source to memcpy()
 * even when the length is zero.
 */
int
main(void)
{
	char buf[16];
	char src[4] = { 1, 2, 3, 4 };
	int offset;
	int i;

	memset(buf, 0xAA, sizeof(buf));

	offset = 0;
	if (sock_bufferize(NULL, 0, buf, &offset, (int)sizeof(buf),
	    SOCKBUF_BUFFERIZE, NULL, 0) != 0) {
		fprintf(stderr, "zero-length copy failed\n");
		return 1;
	}
	if (offset != 0) {
		fprintf(stderr, "zero-length copy advanced offset to %d\n",
		    offset);
		return 1;
	}
	for (i = 0; i < (int)sizeof(buf); i++) {
		if ((unsigned char)buf[i] != 0xAA) {
			fprintf(stderr,
			    "zero-length copy modified buffer at %d\n", i);
			return 1;
		}
	}

	/*
	 * The same call in check-only mode, where both the source and the
	 * destination are allowed to be NULL.
	 */
	offset = 0;
	if (sock_bufferize(NULL, 0, NULL, &offset, 0, SOCKBUF_CHECKONLY,
	    NULL, 0) != 0) {
		fprintf(stderr, "zero-length check-only copy failed\n");
		return 1;
	}
	if (offset != 0) {
		fprintf(stderr,
		    "zero-length check-only copy advanced offset to %d\n",
		    offset);
		return 1;
	}

	/* And a non-empty copy must still copy the bytes. */
	offset = 0;
	if (sock_bufferize(src, (int)sizeof(src), buf, &offset,
	    (int)sizeof(buf), SOCKBUF_BUFFERIZE, NULL, 0) != 0) {
		fprintf(stderr, "non-empty copy failed\n");
		return 1;
	}
	if (offset != (int)sizeof(src) ||
	    memcmp(buf, src, sizeof(src)) != 0) {
		fprintf(stderr, "non-empty copy produced wrong result\n");
		return 1;
	}

	printf("sock_bufferize zero-length and normal copies are OK\n");
	return 0;
}
