/* libpcap 31.01.2015 can-helper.h Kai Renken */
/*
 * lib.h - library include for command line tools
 *
 * Copyright (c) 2002-2007 Volkswagen Group Electronic Research
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Volkswagen nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * Alternatively, provided that this notice is retained in full, this
 * software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2, in which case the provisions of the
 * GPL apply INSTEAD OF those given above.
 *
 * The provided data structures and external interfaces from this code
 * are not restricted to be used by modules with a GPL compatible license.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * Send feedback to <linux-can@vger.kernel.org>
 *
 */

/* buffer sizes for CAN frame string representations */

#define CL_ID (sizeof("12345678##1"))
#define CL_DATA sizeof(".AA")
#define CL_BINDATA sizeof(".10101010")

 /* CAN FD ASCII hex short representation with DATA_SEPERATORs */
#define CL_CFSZ (2*CL_ID + 64*CL_DATA)

/* CAN FD ASCII hex long representation with binary output */
#define CL_LONGCFSZ (2*CL_ID + sizeof("   [255]  ") + (64*CL_BINDATA))

/* CAN DLC to real data length conversion helpers especially for CAN FD */

/* get data length from can_dlc with sanitized can_dlc */
unsigned char can_dlc2len(unsigned char can_dlc);

/* map the sanitized data length to an appropriate data length code */
unsigned char can_len2dlc(unsigned char len);

unsigned char asc2nibble(char c);
/*
 * Returns the decimal value of a given ASCII hex character.
 *
 * While 0..9, a..f, A..F are valid ASCII hex characters.
 * On invalid characters the value 16 is returned for error handling.
 */

int hexstring2data(char *arg, unsigned char *data, int maxdlen);
/*
 * Converts a given ASCII hex string to a (binary) byte string.
 *
 * A valid ASCII hex string consists of an even number of up to 16 chars.
 * Leading zeros '00' in the ASCII hex string are interpreted.
 *
 * Examples:
 *
 * "1234"   => data[0] = 0x12, data[1] = 0x34
 * "001234" => data[0] = 0x00, data[1] = 0x12, data[2] = 0x34
 *
 * Return values:
 * 0 = success
 * 1 = error (in length or the given characters are no ASCII hex characters)
 *
 * Remark: The not written data[] elements are initialized with zero.
 *
 */

int parse_canframe(char *cs, struct canfd_frame *cf);
/*
 * Transfers a valid ASCII string decribing a CAN frame into struct canfd_frame.
 *
 * CAN 2.0 frames
 * - string layout <can_id>#{R{len}|data}
 * - {data} has 0 to 8 hex-values that can (optionally) be separated by '.'
 * - {len} can take values from 0 to 8 and can be omitted if zero
 * - return value on successful parsing: CAN_MTU
 *
 * CAN FD frames
 * - string layout <can_id>##<flags>{data}
 * - <flags> a single ASCII Hex value (0 .. F) which defines canfd_frame.flags
 * - {data} has 0 to 64 hex-values that can (optionally) be separated by '.'
 * - return value on successful parsing: CANFD_MTU
 *
 * Return value on detected problems: 0
 *
 * <can_id> can have 3 (standard frame format) or 8 (extended frame format)
 * hexadecimal chars
 *
 *
 * Examples:
 *
 * 123# -> standard CAN-Id = 0x123, len = 0
 * 12345678# -> extended CAN-Id = 0x12345678, len = 0
 * 123#R -> standard CAN-Id = 0x123, len = 0, RTR-frame
 * 123#R0 -> standard CAN-Id = 0x123, len = 0, RTR-frame
 * 123#R7 -> standard CAN-Id = 0x123, len = 7, RTR-frame
 * 7A1#r -> standard CAN-Id = 0x7A1, len = 0, RTR-frame
 *
 * 123#00 -> standard CAN-Id = 0x123, len = 1, data[0] = 0x00
 * 123#1122334455667788 -> standard CAN-Id = 0x123, len = 8
 * 123#11.22.33.44.55.66.77.88 -> standard CAN-Id = 0x123, len = 8
 * 123#11.2233.44556677.88 -> standard CAN-Id = 0x123, len = 8
 * 32345678#112233 -> error frame with CAN_ERR_FLAG (0x2000000) set
 *
 * 123##0112233 -> CAN FD frame standard CAN-Id = 0x123, flags = 0, len = 3
 * 123##1112233 -> CAN FD frame, flags = CANFD_BRS, len = 3
 * 123##2112233 -> CAN FD frame, flags = CANFD_ESI, len = 3
 * 123##3 -> CAN FD frame, flags = (CANFD_ESI | CANFD_BRS), len = 0
 *     ^^
 *     CAN FD extension to handle the canfd_frame.flags content
 *
 * Simple facts on this compact ASCII CAN frame representation:
 *
 * - 3 digits: standard frame format
 * - 8 digits: extendend frame format OR error frame
 * - 8 digits with CAN_ERR_FLAG (0x2000000) set: error frame
 * - an error frame is never a RTR frame
 * - CAN FD frames do not have a RTR bit
 */

void fprint_canframe(FILE *stream , struct canfd_frame *cf, char *eol, int sep, int maxdlen);
void sprint_canframe(char *buf , struct canfd_frame *cf, int sep, int maxdlen);
/*
 * Creates a CAN frame hexadecimal output in compact format.
 * The CAN data[] is separated by '.' when sep != 0.
 *
 * The type of the CAN frame (CAN 2.0 / CAN FD) is specified by maxdlen:
 * maxdlen = 8 -> CAN2.0 frame
 * maxdlen = 64 -> CAN FD frame
 *
 * 12345678#112233 -> extended CAN-Id = 0x12345678, len = 3, data, sep = 0
 * 12345678#R -> extended CAN-Id = 0x12345678, RTR, len = 0
 * 12345678#R5 -> extended CAN-Id = 0x12345678, RTR, len = 5
 * 123#11.22.33.44.55.66.77.88 -> standard CAN-Id = 0x123, dlc = 8, sep = 1
 * 32345678#112233 -> error frame with CAN_ERR_FLAG (0x2000000) set
 * 123##0112233 -> CAN FD frame standard CAN-Id = 0x123, flags = 0, len = 3
 * 123##2112233 -> CAN FD frame, flags = CANFD_ESI, len = 3
 *
 * Examples:
 *
 * fprint_canframe(stdout, &frame, "\n", 0); // with eol to STDOUT
 * fprint_canframe(stderr, &frame, NULL, 0); // no eol to STDERR
 *
 */

#define CANLIB_VIEW_ASCII	0x1
#define CANLIB_VIEW_BINARY	0x2
#define CANLIB_VIEW_SWAP	0x4
#define CANLIB_VIEW_ERROR	0x8
#define CANLIB_VIEW_INDENT_SFF	0x10

#define SWAP_DELIMITER '`'

void fprint_long_canframe(FILE *stream , struct canfd_frame *cf, char *eol, int view, int maxdlen);
void sprint_long_canframe(char *buf , struct canfd_frame *cf, int view, int maxdlen);
/*
 * Creates a CAN frame hexadecimal output in user readable format.
 *
 * The type of the CAN frame (CAN 2.0 / CAN FD) is specified by maxdlen:
 * maxdlen = 8 -> CAN2.0 frame
 * maxdlen = 64 -> CAN FD frame
 *
 * 12345678   [3]  11 22 33 -> extended CAN-Id = 0x12345678, dlc = 3, data
 * 12345678   [0]  remote request -> extended CAN-Id = 0x12345678, RTR
 * 14B0DC51   [8]  4A 94 E8 2A EC 58 55 62   'J..*.XUb' -> (with ASCII output)
 * 20001111   [7]  C6 23 7B 32 69 98 3C      ERRORFRAME -> (CAN_ERR_FLAG set)
 * 12345678  [03]  11 22 33 -> CAN FD with extended CAN-Id = 0x12345678, dlc = 3
 *
 * 123   [3]  11 22 33         -> CANLIB_VIEW_INDENT_SFF == 0
 *      123   [3]  11 22 33    -> CANLIB_VIEW_INDENT_SFF == set
 *
 * Examples:
 *
 * // CAN FD frame with eol to STDOUT
 * fprint_long_canframe(stdout, &frame, "\n", 0, CANFD_MAX_DLEN);
 *
 * // CAN 2.0 frame without eol to STDERR
 * fprint_long_canframe(stderr, &frame, NULL, 0, CAN_MAX_DLEN);
 *
 */

void snprintf_can_error_frame(char *buf, size_t len, struct canfd_frame *cf,
			      char *sep);
/*
 * Creates a CAN error frame output in user readable format.
 */
