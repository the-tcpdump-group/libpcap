/*
 * Check array-size bounds and normal pcapng interface growth.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <config.h>

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pcap-util.h"

static int
check_array_size(void)
{
	static const size_t element_sizes[] = { 2, 3, 7, 16, 31, 32, 40 };
	size_t i, limit;

	if (pcapint_check_array_size(SIZE_MAX, 0) != 0 ||
	    pcapint_check_array_size(SIZE_MAX, 1) != 0) {
		fprintf(stderr, "valid zero- and one-byte sizes rejected\n");
		return (-1);
	}
	for (i = 0; i < sizeof(element_sizes) / sizeof(element_sizes[0]); i++) {
		limit = SIZE_MAX / element_sizes[i];
		if (pcapint_check_array_size(0, element_sizes[i]) != 0 ||
		    pcapint_check_array_size(limit - 1, element_sizes[i]) != 0 ||
		    pcapint_check_array_size(limit, element_sizes[i]) != 0) {
			fprintf(stderr, "valid array size rejected\n");
			return (-1);
		}
		if (pcapint_check_array_size(limit + 1, element_sizes[i]) != -1 ||
		    pcapint_check_array_size(SIZE_MAX, element_sizes[i]) != -1) {
			fprintf(stderr, "overflow array size accepted\n");
			return (-1);
		}
	}
	puts("PASS: valid array sizes accepted; overflow array sizes rejected");
	return (0);
}

/* Write little-endian fields without depending on structure padding. */
static void
put32(FILE *fp, uint32_t value)
{
	u_char bytes[4];

	bytes[0] = (u_char)value;
	bytes[1] = (u_char)(value >> 8);
	bytes[2] = (u_char)(value >> 16);
	bytes[3] = (u_char)(value >> 24);
	(void)fwrite(bytes, sizeof(bytes), 1, fp);
}

#define INTERFACE_COUNT 17

static int
write_capture(const char *filename)
{
	FILE *fp;
	uint32_t i;
	int failed;

	fp = fopen(filename, "wb");
	if (fp == NULL) {
		perror(filename);
		return (-1);
	}
	put32(fp, 0x0a0d0d0a); /* Section Header Block. */
	put32(fp, 28);
	put32(fp, 0x1a2b3c4d);
	put32(fp, 1); /* Version 1.0. */
	put32(fp, 0xffffffff);
	put32(fp, 0xffffffff);
	put32(fp, 28);
	for (i = 0; i < INTERFACE_COUNT; i++) {
		put32(fp, 1); /* Interface Description Block. */
		put32(fp, 20);
		put32(fp, 1); /* Ethernet, reserved field zero. */
		put32(fp, 64);
		put32(fp, 20);
	}
	for (i = 0; i < INTERFACE_COUNT; i++) {
		put32(fp, 6); /* Enhanced Packet Block. */
		put32(fp, 36);
		put32(fp, i);
		put32(fp, 0);
		put32(fp, (i + 1) * 1000000);
		put32(fp, 4);
		put32(fp, 4);
		put32(fp, i);
		put32(fp, 36);
	}
	failed = ferror(fp);
	if (fclose(fp) != 0)
		failed = 1;
	if (failed) {
		fprintf(stderr, "failed to write capture\n");
		return (-1);
	}
	return (0);
}

static int
read_capture(const char *filename)
{
	pcap_t *p;
	struct pcap_pkthdr *header;
	const u_char *data;
	char errbuf[PCAP_ERRBUF_SIZE];
	int i, status;

	p = pcap_open_offline(filename, errbuf);
	if (p == NULL) {
		fprintf(stderr, "%s\n", errbuf);
		return (-1);
	}
	if (pcap_datalink(p) != DLT_EN10MB || pcap_snapshot(p) != 64) {
		fprintf(stderr, "unexpected capture properties\n");
		pcap_close(p);
		return (-1);
	}
	for (i = 0; i < INTERFACE_COUNT; i++) {
		status = pcap_next_ex(p, &header, &data);
		if (status != 1) {
			fprintf(stderr, "packet %d: status %d: %s\n",
			    i, status, pcap_geterr(p));
			pcap_close(p);
			return (-1);
		}
		if (header->caplen != 4 || header->len != 4 ||
		    header->ts.tv_sec != i + 1 || header->ts.tv_usec != 0 ||
		    data[0] != i || data[1] != 0 || data[2] != 0 || data[3] != 0) {
			fprintf(stderr, "packet %d: unexpected contents\n", i);
			pcap_close(p);
			return (-1);
		}
	}
	status = pcap_next_ex(p, &header, &data);
	pcap_close(p);
	if (status != PCAP_ERROR_BREAK) {
		fprintf(stderr, "expected end of capture, got %d\n", status);
		return (-1);
	}
	puts("PASS: valid pcapng capture with 17 interfaces and 17 packets");
	return (0);
}

int
main(int argc, char **argv)
{
	int status;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <capture filename>|--arithmetic-only\n",
		    argv[0]);
		return (EXIT_FAILURE);
	}
	if (check_array_size() == -1)
		return (EXIT_FAILURE);
	if (strcmp(argv[1], "--arithmetic-only") == 0)
		return (EXIT_SUCCESS);
	status = write_capture(argv[1]);
	if (status == 0)
		status = read_capture(argv[1]);
	if (remove(argv[1]) != 0) {
		perror(argv[1]);
		status = -1;
	}
	return (status == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
