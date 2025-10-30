// for "pcap-int.h"
#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
  #include "getopt.h"
  #include "unix.h"
#else
  #include <unistd.h>
  #include <sysexits.h>
#endif

#include "pcap/pcap.h"
// pcap_nametoeproto(), pcap_nametollc() and pcapint_xdtoi()
#include "pcap/namedb.h"
// pcapint_atodn() and pcapint_atoan()
#include "nametoaddr.h"
// pcapint_parsesrcstr_ex() and pcapint_createsrcstr_ex()
#include "pcap-int.h"

static const char *program_name;

/*
 * pcap_nametoeproto() does not implement a notion of invalid input: any string
 * that is not one of the known protocols is considered an "unspecified"
 * protocol.
 */
static int
test_pcap_nametoeproto(const char *arg)
{
	int result = pcap_nametoeproto(arg);
	printf("OK: ");
	if (result == PROTO_UNDEF)
		printf("PROTO_UNDEF\n");
	else
		printf("0x%04x\n", (uint16_t)result);
	return EX_OK;
}

// Same as the above.
static int
test_pcap_nametollc(const char *arg)
{
	int result = pcap_nametollc(arg);
	printf("OK: ");
	if (result == PROTO_UNDEF)
		printf("PROTO_UNDEF\n");
	else
		printf("0x%02x\n", (uint8_t)result);
	return EX_OK;
}

// pcapint_xdtoi() always returns a value.
static int
test_pcapint_xdtoi(const char *arg)
{
	char *endptr = NULL;
	errno = 0;
	unsigned long parsed = strtoul(arg, &endptr, 10);
	if (endptr == arg) {
		fprintf(stderr, "ERROR: no digits\n");
		return EX_USAGE;
	}
	if (*endptr) {
		fprintf(stderr, "ERROR: invalid character '%c'\n", *endptr);
		return EX_USAGE;
	}
	if (errno) {
		fprintf(stderr, "ERROR: errno %d\n", errno);
		return EX_USAGE;
	}
	char printed[PCAP_BUF_SIZE];
	snprintf(printed, sizeof(printed), "%lu", parsed);
	if (strcmp(arg, printed)) {
		fprintf(stderr, "ERROR: there is other input besides the integer\n");
		return EX_USAGE;
	}
	if (parsed > UINT8_MAX) {
		fprintf(stderr, "ERROR: the integer must be within the valid range\n");
		return EX_USAGE;
	}
	// Now ready to run the actual function.
	printf("OK: 0x%02x\n", pcapint_xdtoi((u_char)parsed));
	return EX_OK;
}

// 0: rejected, 1: accepted.
static int
test_pcapint_atodn(const char *arg)
{
	uint16_t dnaddr;
	if (! pcapint_atodn(arg, &dnaddr)) {
		fprintf(stderr, "ERROR: 0\n");
		return EX_DATAERR;
	}
	printf("OK: %u.%u\n", dnaddr >> 10, dnaddr & 0x03ff);
	return EX_OK;
}

// Same as the above.
static int
test_pcapint_atoan(const char *arg)
{
	uint8_t output;
	if (! pcapint_atoan(arg, &output)) {
		fprintf(stderr, "ERROR: 0\n");
		return EX_DATAERR;
	}
	printf("OK: $%02x\n", output);
	return EX_OK;
}

static int
test_pcap_ether_aton(const char *arg)
{
	u_char *result = pcap_ether_aton(arg);
	if (! result) {
		fprintf(stderr, "ERROR: NULL\n");
		return EX_DATAERR;
	}
	printf("OK: %02x:%02x:%02x:%02x:%02x:%02x\n", result[0], result[1],
	       result[2], result[3], result[4], result[5]);
	free(result);
	return EX_OK;
}

/*
 * pcapint_parsesrcstr_ex() is always available, the implementation is stub
 * when ENABLE_REMOTE is not defined.  0: accepted, PCAP_ERROR: rejected.
 */
static int
test_pcapint_parsesrcstr_ex(const char *arg)
{
	int type;
	char userinfo[PCAP_BUF_SIZE] = {0}, host[PCAP_BUF_SIZE] = {0},
	    port[PCAP_BUF_SIZE] = {0}, name[PCAP_BUF_SIZE] = {0};
	u_char uses_ssl;
	char errbuf[PCAP_ERRBUF_SIZE] = {0};
	if (pcapint_parsesrcstr_ex(arg, &type, userinfo, host, port, name, &uses_ssl, errbuf)) {
		fprintf(stderr, "ERROR: %s\n", errbuf);
		return EX_DATAERR;
	}

	char source[PCAP_BUF_SIZE] = {0};
	if (pcapint_createsrcstr_ex(source, type, userinfo, host, port, name, uses_ssl, errbuf)) {
		fprintf(stderr, "ERROR: %s\n", errbuf);
		return EX_DATAERR;
	}
	printf("OK: %s\n", source);
	return EX_OK;
}

static const struct {
	const char *name;
	u_char null_ok;
	int (*runner)(const char *);
	const char *arg_descr;
} testfunc[] = {
	{"pcap_nametoeproto", 0, test_pcap_nametoeproto, "Ethernet protocol name"},
	{"pcap_nametollc", 0, test_pcap_nametollc, "LLC protocol name"},
	{"pcapint_xdtoi", 0, test_pcapint_xdtoi, "0..255"},
	{"pcapint_atodn", 0, test_pcapint_atodn, "DECnet address"},
	{"pcapint_atoan", 0, test_pcapint_atoan, "ARCnet address"},
	{"pcap_ether_aton", 0, test_pcap_ether_aton, "MAC-48 address"},
	{"pcapint_parsesrcstr_ex", 1, test_pcapint_parsesrcstr_ex, "source string"},
};
#define NUM_FUNCS (sizeof(testfunc) / sizeof(testfunc[0]))

static void
usage_short(FILE *f)
{
	fprintf(f, "%s, with %s\n", program_name, pcap_lib_version());
	fprintf(f, "Usage: %s <function name> [<argument>]\n", program_name);
	fprintf(f, "       (invoke the function using the specified argument or NULL if applicable)\n");
	fprintf(f, "   or: %s -h\n", program_name);
	fprintf(f, "       (print the detailed help screen)\n");
}

static void
usage_long(FILE *f)
{
	usage_short(f);
	fprintf(f, "\nSupported valid invocations:\n");
	for (unsigned i = 0; i < NUM_FUNCS; i++)
		printf("       %s %s %s<%s>%s\n", program_name,
		       testfunc[i].name, testfunc[i].null_ok ? "[" : "",
		       testfunc[i].arg_descr, testfunc[i].null_ok ? "]" : "");
	fprintf(f, "\nExit status codes:\n");
	fprintf(f, "  %3u: The function has accepted the input, any details are on the standard\n", EX_OK);
	fprintf(f, "       output prefixed with \"OK: \".\n");
	fprintf(f, "  %3u: The function has rejected the input, any details are on the standard\n", EX_DATAERR);
	fprintf(f, "       error prefixed with \"ERROR: \".\n");
	fprintf(f, "  %3u: This executable has been invoked incorrectly.\n", EX_USAGE);
}

int
main(const int argc, char **argv)
{
	{
		const char *cp = strrchr(argv[0], '/');
		program_name = cp ? cp + 1 : argv[0];
	}

	{
		int op;
		opterr = 0;
		while ((op = getopt(argc, argv, "h")) != -1) {
			switch (op) {
			case 'h':
				usage_long(stdout);
				exit(EX_OK);
			default:
				usage_short(stderr);
				exit(EX_USAGE);
			}
		}
		// At least the function name must be present.
		if (argc < 2) {
			usage_short(stderr);
			exit(EX_USAGE);
		}
	}

	char *funcname = argv[1];
	for (unsigned i = 0; i < NUM_FUNCS; i++) {
		if (strcmp(testfunc[i].name, funcname))
			continue;
		const char *arg;
		switch (argc) {
		case 2:
			// The argument is absent.
			if (! testfunc[i].null_ok) {
				fprintf(stderr, "Function %s requires a non-NULL argument.\n", funcname);
				usage_long(stderr);
				exit(EX_USAGE);
			}
			arg = NULL;
			break;
		case 3:
			// The argument is present (can be an empty string).
			arg = argv[2];
			break;
		default:
			usage_short(stderr);
			exit(EX_USAGE);
		}
		exit(testfunc[i].runner(arg));
	}
	fprintf(stderr, "Unknown function '%s'\n", funcname);
	usage_long(stderr);
	exit(EX_USAGE);
}
