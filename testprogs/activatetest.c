#include <stdio.h>
#include <pcap.h>

#define CAPTURE_DEVICE "nosuchdevice"

int main(void)
{
	/*
	 * When trying to use libpcap on a device that does not exist, the
	 * expected behaviour is that pcap_create() does not return an error,
	 * and pcap_activate() does return an error, and the error code
	 * specifically tells that the interface does not exist.  tcpdump
	 * depends on this semantics to accept integer indices instead of
	 * device names.  This test provides means to verify the actual
	 * behaviour, which is specific to each libpcap module.
	 */
	char errbuf[PCAP_ERRBUF_SIZE];
	printf("Trying to use capture device \"%s\"...\n", CAPTURE_DEVICE);
	pcap_t *p = pcap_create(CAPTURE_DEVICE, errbuf);
	if (! p) {
		fprintf(stderr,
		        "FAIL: Unexpected error from pcap_create() (%s).\n",
		        errbuf);
		return 1;
	}
	int ret = 1, err = pcap_activate(p);
	switch (err) {
	case 0:
		fprintf(stderr, "FAIL: No error from pcap_activate().\n");
		break;
	case PCAP_ERROR:
		fprintf(stderr, "FAIL: Generic error from pcap_activate().\n");
		break;
	case PCAP_ERROR_PERM_DENIED:
		fprintf(stderr, "FAIL: Permission denied from pcap_activate(), "
		        "retry with higher privileges.\n");
		break;
	case PCAP_ERROR_NO_SUCH_DEVICE:
		printf("PASS: Correct specific error from pcap_activate().\n");
		ret = 0;
		break;
	default:
		fprintf(stderr,
		        "FAIL: Unexpected error %d from pcap_activate().\n",
		        err);
	}
	pcap_close(p);
	return ret;
}
