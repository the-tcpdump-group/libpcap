/*
 * pcap-odp.c based on pcap-linux.c: Packet capture interface to OpenDataPlane.org
 * Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/mman.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>
#include <poll.h>
#include <dirent.h>

#include <sys/time.h>
#define SHM_PKT_POOL_SIZE      (512*2048)
#define SHM_PKT_POOL_BUF_SIZE  1856

#include "pcap-int.h"
#include "pcap/sll.h"
#include "pcap/vlan.h"

#ifdef SO_ATTACH_FILTER
#include <linux/types.h>
#include <linux/filter.h>
#endif

#ifdef HAVE_LINUX_NET_TSTAMP_H
#include <linux/net_tstamp.h>
#endif

/*
 * Got libnl?
 */
#ifdef HAVE_LIBNL
#include <linux/nl80211.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#endif /* HAVE_LIBNL */

/*
 * Got ethtool support?
 */
#ifdef HAVE_LINUX_ETHTOOL_H
#include <linux/ethtool.h>
#endif

#ifndef HAVE_SOCKLEN_T
typedef int		socklen_t;
#endif

#ifndef MSG_TRUNC
/*
 * This is being compiled on a system that lacks MSG_TRUNC; define it
 * with the value it has in the 2.2 and later kernels, so that, on
 * those kernels, when we pass it in the flags argument to "recvfrom()"
 * we're passing the right value and thus get the MSG_TRUNC behavior
 * we want.  (We don't get that behavior on 2.0[.x] kernels, because
 * they didn't support MSG_TRUNC.)
 */
#define MSG_TRUNC	0x20
#endif

#ifndef SOL_PACKET
/*
 * This is being compiled on a system that lacks SOL_PACKET; define it
 * with the value it has in the 2.2 and later kernels, so that we can
 * set promiscuous mode in the good modern way rather than the old
 * 2.0-kernel crappy way.
 */
#define SOL_PACKET	263
#endif

#define MAX_LINKHEADER_SIZE	256

/*
 * When capturing on all interfaces we use this as the buffer size.
 * Should be bigger then all MTUs that occur in real life.
 * 64kB should be enough for now.
 */
#define BIGGER_THAN_ALL_MTUS	(64*1024)

/*
 * Private data for capturing on Linux SOCK_PACKET or PF_PACKET sockets.
 */
struct pcap_linux {
	u_int	packets_read;	/* count of packets read with recvfrom() */
	long	proc_dropped;	/* packets reported dropped by /proc/net/dev */
	struct pcap_stat stat;

	char	*device;	/* device name */
	int	filter_in_userland; /* must filter in userland */
	int	blocks_to_filter_in_userland;
	int	must_do_on_close; /* stuff we must do when we close */
	int	timeout;	/* timeout for buffering */
	int	sock_packet;	/* using Linux 2.0 compatible interface */
	int	cooked;		/* using SOCK_DGRAM rather than SOCK_RAW */
	int	ifindex;	/* interface index of device we're bound to */
	int	lo_ifindex;	/* interface index of the loopback device */
	bpf_u_int32 oldmode;	/* mode to restore when turning monitor mode off */
	char	*mondevice;	/* mac80211 monitor device we created */
	u_char	*mmapbuf;	/* memory-mapped region pointer */
	size_t	mmapbuflen;	/* size of region */
	int	vlan_offset;	/* offset at which to insert vlan tags; if -1, don't insert */
	u_int	tp_version;	/* version of tpacket_hdr for mmaped ring */
	u_int	tp_hdrlen;	/* hdrlen of tpacket_hdr for mmaped ring */
	u_char	*oneshot_buffer; /* buffer for copy of packet */
#ifdef HAVE_TPACKET3
	unsigned char *current_packet; /* Current packet within the TPACKET_V3 block. Move to next block if NULL. */
	int packets_left; /* Unhandled packets left within the block from previous call to pcap_read_linux_mmap_v3 in case of TPACKET_V3. */
#endif
};

/*
 * Stuff to do when we close.
 */
#define MUST_CLEAR_PROMISC	0x00000001	/* clear promiscuous mode */
#define MUST_CLEAR_RFMON	0x00000002	/* clear rfmon (monitor) mode */
#define MUST_DELETE_MONIF	0x00000004	/* delete monitor-mode interface */

/*
 * Prototypes for internal functions and methods.
 */
static int pcap_inject_linux_odp(pcap_t *, const void *, size_t);
static int pcap_stats_linux_odp(pcap_t *, struct pcap_stat *);
static int pcap_setfilter_linux_odp(pcap_t *, struct bpf_program *);
static int pcap_setdirection_linux_odp(pcap_t *, pcap_direction_t);
static int pcap_set_datalink_linux_odp(pcap_t *, int);
static void pcap_cleanup_linux_odp(pcap_t *);

static void pcap_odp_init(pcap_t *);
static int pcap_activate_odp(pcap_t *);
static int pcap_read_odp(pcap_t *, int, pcap_handler, u_char *);
static void pcap_cleanup_odp(pcap_t *);

/*
 * Grabs the number of dropped packets by the interface from /proc/net/dev.
 *
 * XXX - what about /sys/class/net/{interface name}/rx_*?  There are
 * individual devices giving, in ASCII, various rx_ and tx_ statistics.
 *
 * Or can we get them in binary form from netlink?
 */
static long int
linux_if_drops(const char * if_name)
{
	char buffer[512];
	char * bufptr;
	FILE * file;
	int field_to_convert = 3, if_name_sz = strlen(if_name);
	long int dropped_pkts = 0;
	
	file = fopen("/proc/net/dev", "r");
	if (!file)
		return 0;

	while (!dropped_pkts && fgets( buffer, sizeof(buffer), file ))
	{
		/* 	search for 'bytes' -- if its in there, then
			that means we need to grab the fourth field. otherwise
			grab the third field. */
		if (field_to_convert != 4 && strstr(buffer, "bytes"))
		{
			field_to_convert = 4;
			continue;
		}
	
		/* find iface and make sure it actually matches -- space before the name and : after it */
		if ((bufptr = strstr(buffer, if_name)) &&
			(bufptr == buffer || *(bufptr-1) == ' ') &&
			*(bufptr + if_name_sz) == ':')
		{
			bufptr = bufptr + if_name_sz + 1;

			/* grab the nth field from it */
			while( --field_to_convert && *bufptr != '\0')
			{
				while (*bufptr != '\0' && *(bufptr++) == ' ');
				while (*bufptr != '\0' && *(bufptr++) != ' ');
			}
			
			/* get rid of any final spaces */
			while (*bufptr != '\0' && *bufptr == ' ') bufptr++;
			
			if (*bufptr != '\0')
				dropped_pkts = strtol(bufptr, NULL, 10);

			break;
		}
	}
	
	fclose(file);
	return dropped_pkts;
} 


/*
 * With older kernels promiscuous mode is kind of interesting because we
 * have to reset the interface before exiting. The problem can't really
 * be solved without some daemon taking care of managing usage counts.
 * If we put the interface into promiscuous mode, we set a flag indicating
 * that we must take it out of that mode when the interface is closed,
 * and, when closing the interface, if that flag is set we take it out
 * of promiscuous mode.
 *
 * Even with newer kernels, we have the same issue with rfmon mode.
 */

static void pcap_cleanup_linux_odp( pcap_t *handle )
{
	struct pcap_linux *handlep = handle->priv;
	struct ifreq	ifr;
#ifdef IW_MODE_MONITOR
	int oldflags;
	struct iwreq ireq;
#endif /* IW_MODE_MONITOR */

	if (handlep->must_do_on_close != 0) {
		/*
		 * There's something we have to do when closing this
		 * pcap_t.
		 */
		if (handlep->must_do_on_close & MUST_CLEAR_PROMISC) {
			/*
			 * We put the interface into promiscuous mode;
			 * take it out of promiscuous mode.
			 *
			 * XXX - if somebody else wants it in promiscuous
			 * mode, this code cannot know that, so it'll take
			 * it out of promiscuous mode.  That's not fixable
			 * in 2.0[.x] kernels.
			 */
			memset(&ifr, 0, sizeof(ifr));
			strlcpy(ifr.ifr_name, handlep->device,
			    sizeof(ifr.ifr_name));
			if (ioctl(handle->fd, SIOCGIFFLAGS, &ifr) == -1) {
				fprintf(stderr,
				    "Can't restore interface %s flags (SIOCGIFFLAGS failed: %s).\n"
				    "Please adjust manually.\n"
				    "Hint: This can't happen with Linux >= 2.2.0.\n",
				    handlep->device, strerror(errno));
			} else {
				if (ifr.ifr_flags & IFF_PROMISC) {
					/*
					 * Promiscuous mode is currently on;
					 * turn it off.
					 */
					ifr.ifr_flags &= ~IFF_PROMISC;
					if (ioctl(handle->fd, SIOCSIFFLAGS,
					    &ifr) == -1) {
						fprintf(stderr,
						    "Can't restore interface %s flags (SIOCSIFFLAGS failed: %s).\n"
						    "Please adjust manually.\n"
						    "Hint: This can't happen with Linux >= 2.2.0.\n",
						    handlep->device,
						    strerror(errno));
					}
				}
			}
		}


#ifdef IW_MODE_MONITOR
		if (handlep->must_do_on_close & MUST_CLEAR_RFMON) {
			/*
			 * We put the interface into rfmon mode;
			 * take it out of rfmon mode.
			 *
			 * XXX - if somebody else wants it in rfmon
			 * mode, this code cannot know that, so it'll take
			 * it out of rfmon mode.
			 */

			/*
			 * First, take the interface down if it's up;
			 * otherwise, we might get EBUSY.
			 * If we get errors, just drive on and print
			 * a warning if we can't restore the mode.
			 */
			oldflags = 0;
			memset(&ifr, 0, sizeof(ifr));
			strlcpy(ifr.ifr_name, handlep->device,
			    sizeof(ifr.ifr_name));
			if (ioctl(handle->fd, SIOCGIFFLAGS, &ifr) != -1) {
				if (ifr.ifr_flags & IFF_UP) {
					oldflags = ifr.ifr_flags;
					ifr.ifr_flags &= ~IFF_UP;
					if (ioctl(handle->fd, SIOCSIFFLAGS, &ifr) == -1)
						oldflags = 0;	/* didn't set, don't restore */
				}
			}

			/*
			 * Now restore the mode.
			 */
			strlcpy(ireq.ifr_ifrn.ifrn_name, handlep->device,
			    sizeof ireq.ifr_ifrn.ifrn_name);
			ireq.u.mode = handlep->oldmode;
			if (ioctl(handle->fd, SIOCSIWMODE, &ireq) == -1) {
				/*
				 * Scientist, you've failed.
				 */
				fprintf(stderr,
				    "Can't restore interface %s wireless mode (SIOCSIWMODE failed: %s).\n"
				    "Please adjust manually.\n",
				    handlep->device, strerror(errno));
			}

			/*
			 * Now bring the interface back up if we brought
			 * it down.
			 */
			if (oldflags != 0) {
				ifr.ifr_flags = oldflags;
				if (ioctl(handle->fd, SIOCSIFFLAGS, &ifr) == -1) {
					fprintf(stderr,
					    "Can't bring interface %s back up (SIOCSIFFLAGS failed: %s).\n"
					    "Please adjust manually.\n",
					    handlep->device, strerror(errno));
				}
			}
		}
#endif /* IW_MODE_MONITOR */

		/*
		 * Take this pcap out of the list of pcaps for which we
		 * have to take the interface out of some mode.
		 */
		pcap_remove_from_pcaps_to_close(handle);
	}

	if (handlep->mondevice != NULL) {
		free(handlep->mondevice);
		handlep->mondevice = NULL;
	}
	if (handlep->device != NULL) {
		free(handlep->device);
		handlep->device = NULL;
	}
	pcap_cleanup_live_common(handle);
}

static int
pcap_set_datalink_linux_odp(pcap_t *handle, int dlt)
{
	handle->linktype = dlt;
	return 0;
}

static int
pcap_inject_linux_odp(pcap_t *handle, const void *buf, size_t size)
{
	struct pcap_linux *handlep = handle->priv;
	int ret = 0;

	/* ODP inject is not implemented yet */

	return ret;
}

static int
pcap_stats_linux_odp(pcap_t *handle, struct pcap_stat *stats)
{
	/* ODP stats interface is not defined yet. Will be implemented once defined.*/
	return 0;
}

/*
 * Description string for the "any" device.
 */
static const char any_descr[] = "Pseudo-device that captures on all interfaces";

static int
pcap_setfilter_linux_odp(pcap_t *handle, struct bpf_program *filter)
{
	/* ODP filtering is TBD*/

	return 0;
}

/*
 * Set direction flag: Which packets do we accept on a forwarding
 * single device? IN, OUT or both?
 */
static int
pcap_setdirection_linux_odp(pcap_t *handle, pcap_direction_t d)
{
#ifdef HAVE_PF_PACKET_SOCKETS
	struct pcap_linux *handlep = handle->priv;

	if (!handlep->sock_packet) {
		handle->direction = d;
		return 0;
	}
#endif
	/*
	 * We're not using PF_PACKET sockets, so we can't determine
	 * the direction of the packet.
	 */
	snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
	    "Setting direction is not supported on SOCK_PACKET sockets");
	return -1;
}

pcap_t *
odp_create(const char *device, char *ebuf, int *is_ours)
{
	pcap_t *handle;
	struct pcap_odp *podp;

	*is_ours = (!strncmp(device, "odp:", 4)
		    || !strncmp(device, "netmap:", 7)
		    || !strncmp(device, "vale", 4));
	if (! *is_ours)
		return NULL;
	if (!strncmp(device, "odp:", 4)) {
		handle = pcap_create_common((device + 4), ebuf, sizeof(struct pcap_linux));
		handle->selectable_fd = -1;
		podp = handle->priv;
		podp->is_netmap = false;
	} else {
		handle = pcap_create_common(device, ebuf, sizeof(struct pcap_linux));
		handle->selectable_fd = -1;
		podp = handle->priv;
		podp->is_netmap = false;
	}
	if (handle == NULL)
		return NULL;

	handle->activate_op = pcap_activate_odp;
	return (handle);
}

static void
pcap_odp_init(pcap_t *handle)
{
	odp_buffer_pool_t pool;
	odp_pktio_t pktio;
	void *pool_base;
	char inq_name[ODP_QUEUE_NAME_LEN];
	odp_queue_t inq_def;
	odp_queue_param_t qparam;
	int fd;
	int ret;
	struct pcap_odp *podp;
	odp_shm_t shm;

	/* Init ODP before calling anything else */
	if (odp_init_global()) {
		fprintf(stderr, "Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Create thread structure for ODP */
	if (odp_init_local()) {
		ODP_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Is pool have been created in another theard ? */
	pool = odp_buffer_pool_lookup("packet_pool");
	if (pool == ODP_BUFFER_POOL_INVALID) {
		/* Create packet pool */
		shm = odp_shm_reserve("shm_packet_pool",
				SHM_PKT_POOL_SIZE, ODP_CACHE_LINE_SIZE, 0);
		pool_base = odp_shm_addr(shm);
		if (pool_base == NULL) {
			fprintf(stderr,
				"Error: packet pool mem alloc failed.\n");
			exit(EXIT_FAILURE);
		}

		pool = odp_buffer_pool_create("packet_pool", pool_base,
				SHM_PKT_POOL_SIZE,
				SHM_PKT_POOL_BUF_SIZE,
				ODP_CACHE_LINE_SIZE,
				ODP_BUFFER_TYPE_PACKET);
		if (pool == ODP_BUFFER_POOL_INVALID) {
			fprintf(stderr, "Error: packet pool create failed.\n");
			exit(EXIT_FAILURE);
		}
		odp_buffer_pool_print(pool);
	} else {
		fprintf(stdout, "packet pool have been created.\n");
	}

	/* Open a packet IO instance for this thread */
	/* if any device, need ODP support */

	podp = handle->priv;

	podp->pktio = odp_pktio_open(handle->opt.source, pool);
	if (podp->pktio == ODP_QUEUE_INVALID) {
		fprintf(stderr, "  Error: pktio create failed %s\n", handle->opt.source);
		return;
	}

	/*
	 * Create and set the default INPUT queue associated with the 'pktio'
	 * resource
	 */
	qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	qparam.sched.group = ODP_SCHED_GROUP_DEFAULT;
	snprintf(inq_name, sizeof(inq_name), "%i-pktio_inq_def",
		 (int)podp->pktio);
	inq_name[ODP_QUEUE_NAME_LEN - 1] = '\0';

	inq_def = odp_queue_create(inq_name, ODP_QUEUE_TYPE_PKTIN, &qparam);
	if (inq_def == ODP_QUEUE_INVALID) {
		fprintf(stderr, "  Error: pktio queue creation failed\n");
		return;
	}

	ret = odp_pktio_inq_setdef(podp->pktio, inq_def);
	if (ret != 0) {
		fprintf(stderr, "  Error: default input-Q setup\n");
		return;
	}

	printf("  created pktio:%02i, queue mode\n"
		"  default pktio%02i-INPUT queue:%u\n",
		podp->pktio, podp->pktio, inq_def);

}

static int
pcap_activate_odp(pcap_t *handle)
{
	struct pcap_linux *handlep = handle->priv;
	const char	*device;
	int		status = 0;
	int		arptype;
	struct ifreq	ifr;

	/* initial ODP stuff */
	pcap_odp_init(handle);

	device = handle->opt.source;

	handle->inject_op = pcap_inject_linux_odp;
	handle->setdirection_op = pcap_setdirection_linux_odp;
	handle->set_datalink_op = pcap_set_datalink_linux_odp;
	handle->setnonblock_op = pcap_setnonblock_fd; /* Not ODP function */
	handle->getnonblock_op = pcap_getnonblock_fd; /* Not ODP function */
	handle->cleanup_op = pcap_cleanup_odp;
	handle->read_op = pcap_read_odp;
	handle->setfilter_op = pcap_setfilter_linux_odp;
	handle->stats_op = pcap_stats_linux_odp;

	/*
	 * The "any" device is a special device which causes us not
	 * to bind to a particular device and thus to look at all
	 * devices.
	 */
	if (strcmp(device, "any") == 0) {
		if (handle->opt.promisc) {
			handle->opt.promisc = 0;
			/* Just a warning. */
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
				 "Promiscuous mode not supported on the \"any\" device");
			status = PCAP_WARNING_PROMISC_NOTSUP;
		}
	}

	handlep->device = strdup(device);
	if (handlep->device == NULL) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "strdup: %s",
			 pcap_strerror(errno));
		return PCAP_ERROR;
	}

	/* copy timeout value */
	handlep->timeout = handle->opt.timeout;

	/*
	 * If we're in promiscuous mode, then we probably want
	 * to see when the interface drops packets too, so get an
	 * initial count from /proc/net/dev
	 */
	if (handle->opt.promisc)
		handlep->proc_dropped = linux_if_drops(handlep->device);

	/* + activate_new */
	/* Will create a sock_fd just for setting */
	status = activate_new(handle);
	if (status < 0)
		goto fail;

	/* Allocate the buffer */
	status = 0;
	if (handle->opt.buffer_size != 0) {
		/*
		 * Set the socket buffer size to the specified value.
		 */
		if (setsockopt(handle->fd, SOL_SOCKET, SO_RCVBUF,
			       &handle->opt.buffer_size,
		    sizeof(handle->opt.buffer_size)) == -1) {
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
				 "SO_RCVBUF: %s", pcap_strerror(errno));
			status = PCAP_ERROR;
			goto fail;
		}
	}

	handle->buffer = malloc(handle->bufsize + handle->offset);
	if (!handle->buffer) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			 "malloc: %s", pcap_strerror(errno));
		status = PCAP_ERROR;
		goto fail;
	}

	handle->selectable_fd = handle->fd;
	/* - activate_new */

	return status;

fail:
	pcap_cleanup_linux_odp(handle);
	return status;
}

static int
pcap_read_odp(pcap_t *handle, int max_packets, pcap_handler callback,
	      u_char *userdata)
{
	odp_packet_t pkt;
	odp_buffer_t buf;
	u_char *bp;
	struct pcap_linux *handlep = handle->priv;
	struct pcap_pkthdr pcap_header;
	struct timeval ts;
	long n = 1;
	struct pcap_odp *podp = handle->priv;

	for (n = 1; (n <= max_packets) || (max_packets < 0); n++) {
		/* Use schedule to get buf from any input queue */
		buf = odp_schedule(NULL, ODP_SCHED_WAIT);

		pkt = odp_packet_from_buffer(buf);
		if (odp_unlikely(odp_packet_error(pkt)))
			goto clean_buf; /* Drop */

		/* fill out pcap_header */
		gettimeofday(&ts, NULL);
		pcap_header.ts = ts;
		bp = odp_packet_l2(pkt);
		pcap_header.len	= odp_packet_get_len(pkt);
		pcap_header.caplen = pcap_header.len;

		/* ODP not yet support filtering_in_kernel */
		if (handlep->filter_in_userland && handle->fcode.bf_insns) {
			if (bpf_filter(handle->fcode.bf_insns, bp,
				       pcap_header.len,
				       pcap_header.caplen) == 0) {
				/* rejected by filter */
				n--;
				goto clean_buf;
			}
		}

		callback(userdata, &pcap_header, bp);

clean_buf:
		handlep->packets_read++;
		odp_buffer_free(buf);

		if (handle->break_loop) {
			handle->break_loop = 0;
			return PCAP_ERROR_BREAK;
		}
	}

	return max_packets;
}

static void
pcap_cleanup_odp(pcap_t *handle)
{
	struct pcap_odp *podp = handle->priv;

	odp_pktio_close(podp->pktio);
	pcap_cleanup_linux_odp(handle);
}
