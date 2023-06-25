#define _GNU_SOURCE

/* XXX Hack not to include the Mach BPF interface */
#define _DEVICE_BPF_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <fcntl.h>
#include <hurd.h>
#include <mach.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <device/device.h>
#include <device/device_types.h>
#include <device/net_status.h>
#include <net/if_ether.h>

#include "pcap-int.h"

struct pcap_hurd {
	struct pcap_stat stat;
	device_t mach_dev;
	mach_port_t rcv_port;
};

static struct bpf_insn filter[] = {
	{ NETF_IN | NETF_OUT | NETF_BPF, 0, 0, 0 },
	{ BPF_RET | BPF_K, 0, 0, MAXIMUM_SNAPLEN },
};

#define FILTER_COUNT (sizeof(filter) / sizeof(short))

static int
pcap_read_hurd(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
	struct net_rcv_msg *msg;
	struct pcap_hurd *ph;
	struct pcap_pkthdr h;
	struct timespec ts;
	int ret, wirelen, caplen;
	u_char *pkt;
	kern_return_t kr;

	ph = p->priv;
	msg = (struct net_rcv_msg *)p->buffer;

retry:
	if (p->break_loop) {
		p->break_loop = 0;
		return PCAP_ERROR_BREAK;
	}

	kr = mach_msg(&msg->msg_hdr, MACH_RCV_MSG | MACH_RCV_INTERRUPT, 0,
		      p->bufsize, ph->rcv_port, MACH_MSG_TIMEOUT_NONE,
		      MACH_PORT_NULL);

	if (kr) {
		if (kr == MACH_RCV_INTERRUPTED)
			goto retry;

		snprintf(p->errbuf, sizeof(p->errbuf), "mach_msg: %s",
			 pcap_strerror(kr));
		return PCAP_ERROR;
	}

	ph->stat.ps_recv++;

	/* XXX Ethernet support only */
	wirelen = ETH_HLEN + msg->net_rcv_msg_packet_count
		  - sizeof(struct packet_header);
	pkt = p->buffer + offsetof(struct net_rcv_msg, packet)
	      + sizeof(struct packet_header) - ETH_HLEN;
	memmove(pkt, p->buffer + offsetof(struct net_rcv_msg, header),
		ETH_HLEN);

	caplen = (wirelen > p->snapshot) ? p->snapshot : wirelen;
	ret = bpf_filter(p->fcode.bf_insns, pkt, wirelen, caplen);

	if (!ret)
		goto out;

	clock_gettime(CLOCK_REALTIME, &ts);
	h.ts.tv_sec = ts.tv_sec;
	h.ts.tv_usec = ts.tv_nsec / 1000;
	h.len = wirelen;
	h.caplen = caplen;
	callback(user, &h, pkt);

out:
	return 1;
}

static int
pcap_inject_hurd(pcap_t *p, const void *buf, int size)
{
	struct pcap_hurd *ph;
	kern_return_t kr;
	int count;

	ph = p->priv;
	kr = device_write(ph->mach_dev, D_NOWAIT, 0,
			  (io_buf_ptr_t)buf, size, &count);

	if (kr) {
		snprintf(p->errbuf, sizeof(p->errbuf), "device_write: %s",
			 pcap_strerror(kr));
		return -1;
	}

	return count;
}

static int
pcap_stats_hurd(pcap_t *p, struct pcap_stat *ps)
{
	struct pcap_hurd *ph;

	ph = p->priv;
	*ps = ph->stat;
	return 0;
}

static void
pcap_cleanup_hurd(pcap_t *p)
{
	struct pcap_hurd *ph;

	ph = p->priv;

	if (ph->rcv_port != MACH_PORT_NULL) {
		mach_port_deallocate(mach_task_self(), ph->rcv_port);
		ph->rcv_port = MACH_PORT_NULL;
	}

	if (ph->mach_dev != MACH_PORT_NULL) {
		device_close(ph->mach_dev);
		ph->mach_dev = MACH_PORT_NULL;
	}

	pcap_cleanup_live_common(p);
}

static int
pcap_activate_hurd(pcap_t *p)
{
	struct pcap_hurd *ph;
	mach_port_t master;
	kern_return_t kr;

	ph = p->priv;

	/* Try devnode first */
	master = file_name_lookup(p->opt.device, O_READ | O_WRITE, 0);

	if (master != MACH_PORT_NULL)
		kr = device_open(master, D_WRITE | D_READ, "eth", &ph->mach_dev);
	else {
		/* If unsuccessful, try Mach device */
		kr = get_privileged_ports(NULL, &master);

		if (kr) {
			snprintf(p->errbuf, sizeof(p->errbuf),
				 "get_privileged_ports: %s", pcap_strerror(kr));
			goto error;
		}

		kr = device_open(master, D_READ | D_WRITE, p->opt.device,
				 &ph->mach_dev);
	}

	mach_port_deallocate(mach_task_self(), master);

	if (kr) {
		snprintf(p->errbuf, sizeof(p->errbuf), "device_open: %s",
			 pcap_strerror(kr));
		goto error;
	}

	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
				&ph->rcv_port);

	if (kr) {
		snprintf(p->errbuf, sizeof(p->errbuf), "mach_port_allocate: %s",
			 pcap_strerror(kr));
		goto error;
	}

	kr = device_set_filter(ph->mach_dev, ph->rcv_port,
			       MACH_MSG_TYPE_MAKE_SEND, 0,
			       (filter_array_t)filter, FILTER_COUNT);

	if (kr) {
		snprintf(p->errbuf, sizeof(p->errbuf), "device_set_filter: %s",
			 pcap_strerror(kr));
		goto error;
	}

	p->bufsize = sizeof(struct net_rcv_msg);
	p->buffer = malloc(p->bufsize);

	if (p->buffer == NULL) {
		snprintf(p->errbuf, sizeof(p->errbuf), "malloc: %s",
			 pcap_strerror(errno));
		goto error;
	}

	/*
	 * XXX Ethernet only currently
	 *
	 * XXX - does "Ethernet only currently" mean "the only devices
	 * on which the Hurd supports packet capture are Ethernet
	 * devices", or "it supports other devices but makes them
	 * all provide Ethernet headers"?
	 *
	 * If the latter, is there a way to determine whether the
	 * device is a real Ethernet, so that we could offer DLT_DOCSIS,
	 * in case you're capturing DOCSIS traffic that a Cisco Cable
	 * Modem Termination System is putting out onto an Ethernet
	 * (it doesn't put an Ethernet header onto the wire, it puts
	 * raw DOCSIS frames out on the wire inside the low-level
	 * Ethernet framing)?
	 */
	p->linktype = DLT_EN10MB;

	p->read_op = pcap_read_hurd;
	p->inject_op = pcap_inject_hurd;
	p->setfilter_op = pcap_install_bpf_program;
	p->stats_op = pcap_stats_hurd;

	return 0;

error:
	pcap_cleanup_hurd(p);
	return PCAP_ERROR;
}

pcap_t *
pcap_create_interface(const char *device _U_, char *ebuf)
{
	struct pcap_hurd *ph;
	pcap_t *p;

	p = PCAP_CREATE_COMMON(ebuf, struct pcap_hurd);
	if (p == NULL)
		return NULL;

	ph = p->priv;
	ph->mach_dev = MACH_PORT_NULL;
	ph->rcv_port = MACH_PORT_NULL;
	p->activate_op = pcap_activate_hurd;
	return p;
}

int
pcap_platform_finddevs(pcap_if_list_t *alldevsp, char *errbuf)
{
	return 0;
}

/*
 * Libpcap version string.
 */
const char *
pcap_lib_version(void)
{
	return PCAP_VERSION_STRING;
}
