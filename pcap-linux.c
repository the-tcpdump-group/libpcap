/*
 *  pcap-linux.c: Packet capture interface to the Linux kernel
 *
 *  Copyright (c) 2000 Torsten Landschoff <torsten@debian.org>
 *  		       Sebastian Krahmer  <krahmer@cs.uni-potsdam.de>
 *  
 *  License: BSD
 *  
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *  
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *  3. The names of the authors may not be used to endorse or promote
 *     products derived from this software without specific prior
 *     written permission.
 *  
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 *  IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */
#ifndef lint
static const char rcsid[] =
    "@(#) $Header: /tcpdump/master/libpcap/pcap-linux.c,v 1.42 2000-12-16 10:43:29 guy Exp $ (LBL)";
#endif

/*
 * Known problems with 2.0[.x] kernels:
 *
 *   - The loopback device gives every packet twice; on 2.2[.x] kernels,
 *     if we use PF_PACKET, we can filter out the transmitted version
 *     of the packet by using data in the "sockaddr_ll" returned by
 *     "recvfrom()", but, on 2.0[.x] kernels, we have to use
 *     PF_INET/SOCK_PACKET, which means "recvfrom()" supplies a
 *     "sockaddr_pkt" which doesn't give us enough information to let
 *     us do that.
 *
 *   - We have to set the interface's IFF_PROMISC flag ourselves, if
 *     we're to run in promiscuous mode, which means we have to turn
 *     it off ourselves when we're done; the kernel doesn't keep track
 *     of how many sockets are listening promiscuously, which means
 *     it won't get turned off automatically when no sockets are
 *     listening promiscuously.  We catch "pcap_close()" and, for
 *     interfaces we put into promiscuous mode, take them out of
 *     promiscuous mode - which isn't necessarily the right thing to
 *     do, if another socket also requested promiscuous mode between
 *     the time when we opened the socket and the time when we close
 *     the socket.
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pcap-int.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <netinet/if_ether.h>

#ifdef HAVE_NETPACKET_PACKET_H
#include <netpacket/packet.h>
#endif
#ifdef SO_ATTACH_FILTER
#include <linux/types.h>
#include <linux/filter.h>
#endif

#ifndef __GLIBC__
typedef int		socklen_t;
#endif

#ifndef MSG_TRUNC
#define MSG_TRUNC	0
#endif

#define MAX_LINKHEADER_SIZE	256

/* 
 * When capturing on all interfaces we use this as the buffer size. 
 * Should be bigger then all MTUs that occur in real life.
 * 64kB should be enough for now.
 */
#define BIGGER_THAN_ALL_MTUS	(64*1024)

/*
 * Prototypes for internal functions
 */
static int map_arphrd_to_dlt(int arptype );
static int live_open_old(pcap_t *, char *, int, int, char *);
static int live_open_new(pcap_t *, char *, int, int, char *);
static int pcap_read_packet(pcap_t *, pcap_handler, u_char *);

/*
 * Wrap some ioctl calls
 */
#ifdef HAVE_NETPACKET_PACKET_H
static int	iface_get_id(int fd, const char *device, char *ebuf);
#endif
static int	iface_get_mtu(int fd, const char *device, char *ebuf);
static int 	iface_get_arptype(int fd, const char *device, char *ebuf);
#ifdef HAVE_NETPACKET_PACKET_H
static int 	iface_bind(int fd, int ifindex, char *ebuf);
#endif
static int 	iface_bind_old(int fd, const char *device, char *ebuf);

/*
 *  Get a handle for a live capture from the given device. You can 
 *  pass NULL as device to get all packages (without link level 
 *  information of course). If you pass 1 as promisc the interface
 *  will be set to promiscous mode (XXX: I think this usage should 
 *  be deprecated and functions be added to select that later allow
 *  modification of that values -- Torsten).
 *  
 *  See also pcap(3).
 */
pcap_t *
pcap_open_live(char *device, int snaplen, int promisc, int to_ms, char *ebuf)
{
        /* Allocate a handle for this session. */

	pcap_t	*handle = malloc(sizeof(*handle));
	if (handle == NULL) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "malloc: %s",
			 pcap_strerror(errno));
		return NULL;
	}

	/* Initialize some components of the pcap structure. */

	memset(handle, 0, sizeof(*handle));
	handle->snapshot	= snaplen;
	handle->md.timeout	= to_ms;

	/*
	 * NULL and "any" are special devices which give us the hint to 
	 * monitor all devices.
	 */
	if (!device || strcmp(device, "any") == 0) {
		device			= NULL;
		handle->md.device	= strdup("any");
	} else
		handle->md.device	= strdup(device);

	if (handle->md.device == NULL) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "strdup: %s",
			 pcap_strerror(errno) );
		free(handle);
		return NULL;
	}

	/* 
	 * Current Linux kernels use the protocol family PF_PACKET to 
	 * allow direct access to all packets on the network while 
	 * older kernels had a special socket type SOCK_PACKET to 
	 * implement this feature.
	 * While this old implementation is kind of obsolete we need
	 * to be compatible with older kernels for a while so we are 
	 * trying both methods with the newer method preferred.
	 */

	if (! (live_open_new(handle, device, promisc, to_ms, ebuf) ||
	       live_open_old(handle, device, promisc, to_ms, ebuf)) )
	{
		/* 
		 * Both methods to open the packet socket failed. Tidy
		 * up and report our failure (ebuf is expected to be
		 * set by the functions above). 
		 */

		free(handle->md.device);
		free(handle);
		return NULL;
	}

	/* 
	 * Okay, now we have a packet stream open. Maybe we need to handle 
	 * a timeout? In that case we set the filehandle to nonblocking 
	 * so pcap_read can try reading the fd and call select if no data
	 * is available at first. 
	 */

	if (to_ms > 0) {
		int	flags = fcntl(handle->fd, F_GETFL);
		if (flags != -1) {
			flags |= O_NONBLOCK;
			flags = fcntl(handle->fd, F_SETFL, flags);
		}
		if (flags == -1) {
			snprintf(ebuf, PCAP_ERRBUF_SIZE, "fcntl: %s",
				 pcap_strerror(errno));
			pcap_close(handle);
			return NULL;
		}
	}

	return handle;
}

/*
 *  Read at most max_packets from the capture stream and call the callback
 *  for each of them. Returns the number of packets handled or -1 if an
 *  error occured. 
 *  
 *  XXX: Can I rely on the Linux-specified behaviour of select (returning
 *  the time left in the timeval structure)? I really don't want to query
 *  the system time before each select call...
 *  
 *  pcap_read currently gets not only a packet from the kernel but also
 *  the sockaddr_ll returned as source of the packet. This way we can at
 *  some time extend tcpdump and libpcap to sniff on all devices at a time
 *  and find the right printing routine by using the information in the
 *  sockaddr_ll structure.
 */
int
pcap_read(pcap_t *handle, int max_packets, pcap_handler callback, u_char *user)
{
	int		status, packets;
	fd_set		read_fds;
	struct timeval	tv;

	/*
	 * Fill in a timeval structure for select if we need to obeye a
	 * timeout.
	 */
	if (handle->md.timeout > 0) {
		tv.tv_usec	= (handle->md.timeout % 1000) * 1000;
		tv.tv_sec	= (handle->md.timeout / 1000);
	}

	/*
	 * Read packets until the packet limit has been reached or 
	 * an error occured while reading. Call the user function 
	 * for each received packet.
	 */
	for (packets = 0; max_packets == -1 || packets < max_packets;)
	{
		status = pcap_read_packet(handle, callback, user);

		if (status > 0) {
			packets += status;
			continue;
		} else if (status == -1)
			return -1;

		/* 
		 * If no packet is available we go to sleep. FIXME: This
		 * might be better implemented using poll(?)
		 */
		FD_ZERO(&read_fds);
		FD_SET(handle->fd, &read_fds);
		status = select(handle->fd + 1, 
				&read_fds, NULL, NULL, &tv);

		if (status == -1) {
			if (errno == EINTR)
				return packets;
			snprintf(handle->errbuf, sizeof(handle->errbuf),
				 "select: %s", pcap_strerror(errno));
			return -1;
		} 
		else if (status == 0 || 
			   (tv.tv_usec == 0 && tv.tv_sec == 0))
			return packets;
	}

	return packets;
}

/*
 *  Read a packet from the socket calling the handler provided by 
 *  the user. Returns the number of packets received or -1 if an
 *  error occured.
 */
static int
pcap_read_packet(pcap_t *handle, pcap_handler callback, u_char *userdata)
{
#ifdef HAVE_NETPACKET_PACKET_H
	struct sockaddr_ll	from;
#else
	struct sockaddr		from;
#endif
	socklen_t		fromlen;
	int			packet_len, caplen;
	struct pcap_pkthdr	pcap_header;

	/*
	 * We don't currently use the from return value of recvfrom but
	 * this will probably be implemented in the future.
	 */

	/* Receive a single packet from the kernel */

	do {
		fromlen = sizeof(from);
		packet_len = recvfrom( 
			handle->fd, handle->buffer + handle->offset,
			handle->md.readlen, MSG_TRUNC, 
			(struct sockaddr *) &from, &fromlen);
	} while (packet_len == -1 && errno == EINTR);

	/* Check if an error occured */

	if (packet_len == -1) {
		if (errno == EAGAIN)
			return 0;	/* no packet there */
		else {
			snprintf(handle->errbuf, sizeof(handle->errbuf),
				 "recvfrom: %s", pcap_strerror(errno));
			return -1;
		}
	}

#ifdef HAVE_NETPACKET_PACKET_H
	/*
	 * If this is from the loopback device, reject outgoing packets;
	 * we'll see the packet as an incoming packet as well, and
	 * we don't want to see it twice.
	 *
	 * We can only do this if we're using PF_PACKET; the address
	 * returned for SOCK_PACKET is a "sockaddr_pkt" which lacks
	 * the relevant packet type information.
	 */
	if (!handle->md.sock_packet &&
	    from.sll_ifindex == handle->md.lo_ifindex &&
	    from.sll_pkttype == PACKET_OUTGOING)
		return 0;
#endif

	/*
	 * XXX: According to the kernel source we should get the real 
	 * packet len if calling recvfrom with MSG_TRUNC set. It does 
	 * not seem to work here :(, but it is supported by this code
	 * anyway. 
	 * To be honest the code RELIES on that feature so this is really
	 * broken with 2.2.x kernels.
	 * I spend a day to figure out what's going on and I found out
	 * that the following is happening: 
	 *
	 * The packet comes from a random interface and the packet_rcv 
	 * hook is called with a clone of the packet. That code inserts
	 * the packet into the receive queue of the packet socket.
	 * If a filter is attached to that socket that filter is run
	 * first - and there lies the problem. The default filter always
	 * cuts the packet at the snaplen:
	 *
	 * # tcpdump -d
	 * (000) ret      #68
	 *
	 * So the packet filter cuts down the packet. The recvfrom call 
	 * says "hey, it's only 68 bytes, it fits into the buffer" with
	 * the result that we don't get the real packet length. This 
	 * is valid at least until kernel 2.2.17pre6. 
	 *
	 * tcpdump is currently fixed by changing the BPF code generator
	 * to not truncate the received packet. 
	 */

	caplen = packet_len;
	if (caplen > handle->snapshot)
		caplen = handle->snapshot;

	/* Run the packet filter if not using kernel filter */
	if (!handle->md.use_bpf && handle->fcode.bf_insns) {
		if (bpf_filter(handle->fcode.bf_insns, handle->buffer, 
		                packet_len, caplen) == 0)
		{
			/* rejected by filter */
			return 0;
		}
	}

	/* Fill in our own header data */

	if (ioctl(handle->fd, SIOCGSTAMP, &pcap_header.ts) == -1) {
		snprintf(handle->errbuf, sizeof(handle->errbuf),
			 "ioctl: %s", pcap_strerror(errno));
		return -1;
	}
	pcap_header.caplen	= caplen;
	pcap_header.len		= packet_len;

	/* Call the user supplied callback function */
	handle->md.stat.ps_recv++;
	callback(userdata, &pcap_header, handle->buffer + handle->offset);

	return 1;
}

/*
 *  Get the statistics for the given packet capture handle.
 *  FIXME: Currently does not report the number of dropped packets.
 */
int
pcap_stats(pcap_t *handle, struct pcap_stat *stats)
{
	*stats = handle->md.stat;
	return 0;
}

/*
 *  Attach the given BPF code to the packet capture device. 
 */
int
pcap_setfilter(pcap_t *handle, struct bpf_program *filter)
{
#ifdef SO_ATTACH_FILTER
	struct sock_fprog	fcode;
#endif

	if (!handle)
		return -1;
	if (!filter) {
	        strncpy(handle->errbuf, "setfilter: No filter specified",
			sizeof(handle->errbuf));
		return -1;
	}

	/* Make our private copy of the filter */

	if (install_bpf_program(handle, filter) < 0) {
		snprintf(handle->errbuf, sizeof(handle->errbuf),
			 "malloc: %s", pcap_strerror(errno));
		return -1;
	}

	/* 
	 * Run user level packet filter by default. Will be overriden if 
	 * installing a kernel filter succeeds. 
	 */
	handle->md.use_bpf = 0;

	/*
	 * If we're reading from a savefile, don't try to install
	 * a kernel filter.
	 */
	if (handle->sf.rfile != NULL)
		return 0;

	/* Install kernel level filter if possible */

#ifdef SO_ATTACH_FILTER
	/*
	 * Oh joy, the Linux kernel uses struct sock_fprog instead of 
	 * struct bpf_program and of course the length field is of 
	 * different size. Pointed out by Sebastian
	 */

	fcode.filter	= (struct sock_filter *) handle->fcode.bf_insns;
	fcode.len	= filter->bf_len;
#ifdef USHRT_MAX
	if (filter->bf_len > USHRT_MAX) {
		/*
		 * fcode.len is an unsigned short for current kernel. 
		 * I have yet to see BPF-Code with that much instructions
		 * but still it is possible. So for the sake of 
		 * correctness I added this check.
		 */
		fprintf(stderr, "Warning: Filter to complex for kernel\n");
	} 
	else
#endif
        if (setsockopt(handle->fd, SOL_SOCKET, SO_ATTACH_FILTER, 
		       &fcode, sizeof(fcode)) == 0)
	{
		/* Installation succeded - using kernel filter. */
		handle->md.use_bpf = 1;
	} 
	else
	{
		/* 
		 * Print a warning if kernel filter available but a problem
		 * occured using it. 
		 */
		if (errno != ENOPROTOOPT && errno != EOPNOTSUPP) {
			fprintf(stderr, "Warning: Kernel filter failed: %s\n", 
				pcap_strerror(errno));
		}
	}
#endif

	return 0;
}

/*
 *  Linux uses the ARP hardware type to identify the type of an 
 *  interface. pcap uses the DLT_xxx constants for this. This 
 *  function maps the ARPHRD_xxx constant to an appropriate
 *  DLT_xxx constant.
 *  
 *  Returns -1 if unable to map the type.
 */
static int map_arphrd_to_dlt(int arptype)
{
	switch (arptype) {
	case ARPHRD_ETHER:
	case ARPHRD_METRICOM:
	case ARPHRD_LOOPBACK:	return DLT_EN10MB;
	case ARPHRD_EETHER:	return DLT_EN3MB;
	case ARPHRD_AX25:	return DLT_AX25;
	case ARPHRD_PRONET:	return DLT_PRONET;
	case ARPHRD_CHAOS:	return DLT_CHAOS;
#ifndef ARPHRD_IEEE802_TR
#define ARPHRD_IEEE802_TR 800	/* From Linux 2.4 */
#endif
	case ARPHRD_IEEE802_TR:
	case ARPHRD_IEEE802:	return DLT_IEEE802;
	case ARPHRD_ARCNET:	return DLT_ARCNET;
	case ARPHRD_FDDI:	return DLT_FDDI;

#ifndef ARPHRD_ATM  /* FIXME: How to #include this? */
#define ARPHRD_ATM 19
#endif
	case ARPHRD_ATM:	return DLT_ATM_CLIP;

	case ARPHRD_SIT:
	case ARPHRD_PPP:
	case ARPHRD_CSLIP:
	case ARPHRD_SLIP6:
	case ARPHRD_CSLIP6:
	case ARPHRD_SLIP:	return DLT_RAW;
	}

	return -1;
}

/* ===== Functions to interface to the newer kernels ================== */

/*
 *  Try to open a packet socket using the new kernel interface.
 *  Returns 0 on failure.
 *  FIXME: 0 uses to mean success (Sebastian)
 */
static int
live_open_new(pcap_t *handle, char *device, int promisc, 
	      int to_ms, char *ebuf)
{
#ifdef HAVE_NETPACKET_PACKET_H
	int			sock_fd = -1, device_id, mtu, arptype;
	struct packet_mreq	mr;

	/* One shot loop used for error handling - bail out with break */

	do {
		/*
		 * Open a socket with protocol family packet. If a device is
		 * given we try to open it in raw mode otherwise we use 
		 * the cooked interface. 
		 */
		sock_fd = device ? 
			socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
		      : socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));

		if (sock_fd == -1) {
			snprintf(ebuf, PCAP_ERRBUF_SIZE, "socket: %s",
				 pcap_strerror(errno) );
			break;
		}

		/* It seems the kernel supports the new interface. */
		handle->md.sock_packet = 0;

		/*
		 * Get the interface index of the loopback device.
		 * If the attempt fails, don't fail, just set the
		 * "md.lo_ifindex" to -1.
		 *
		 * XXX - can there be more than one device that loops
		 * packets back, i.e. devices other than "lo"?  If so,
		 * we'd need to find them all, and have an array of
		 * indices for them, and check all of them in
		 * "pcap_read_packet()".
		 */
		handle->md.lo_ifindex = iface_get_id(sock_fd, "lo", ebuf);

		/*
		 * What kind of frames do we have to deal with? Fall back 
		 * to cooked mode if we have an unknown interface type. 
		 */

		if (device) {
			arptype	= iface_get_arptype(sock_fd, device, ebuf);
			if (arptype == -1) 
				break;
			handle->linktype = map_arphrd_to_dlt(arptype);
			if (handle->linktype == -1) {
				/*
				 * Unknown interface type - reopen in cooked
				 * mode.
				 */
				if (close(sock_fd) == -1) {
					snprintf(ebuf, PCAP_ERRBUF_SIZE,
						 "close: %s", pcap_strerror(errno));
					break;
				}
				sock_fd = socket(PF_PACKET, SOCK_DGRAM, 
						 htons(ETH_P_ALL));
				if (sock_fd == -1) {
					snprintf(ebuf, PCAP_ERRBUF_SIZE,
						 "socket: %s", pcap_strerror(errno));
					break;
				}

				fprintf(stderr, 
					"Warning: arptype %d not supported by "
					"libpcap - falling back to cooked "
					"socket\n",
					arptype);
				handle->linktype = DLT_RAW;
			}

			device_id = iface_get_id(sock_fd, device, ebuf);
			if (device_id == -1)
				break;

			if (iface_bind(sock_fd, device_id, ebuf) == -1)
				break;
		} else {
			handle->linktype = DLT_RAW;

			/*
			 * XXX - squelch GCC complaints about
			 * uninitialized variables; if we can't
			 * select promiscuous mode on all interfaces,
			 * we should move the code below into the
			 * "if (device)" branch of the "if" and
			 * get rid of the next statement.
			 */
			device_id = -1;
		}

		/* Select promiscuous mode on/off */

#ifdef SOL_PACKET
		/* 
		 * Hmm, how can we set promiscuous mode on all interfaces?
		 * I am not sure if that is possible at all.
		 */

		if (device) {
			memset(&mr, 0, sizeof(mr));
			mr.mr_ifindex = device_id;
			mr.mr_type    = promisc ? 
				PACKET_MR_PROMISC : PACKET_MR_ALLMULTI;
			if (setsockopt(sock_fd, SOL_PACKET, 
				PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) == -1)
			{
				snprintf(ebuf, PCAP_ERRBUF_SIZE, 
					"setsockopt: %s", pcap_strerror(errno));
				break;
			}
		}
#endif

		/* Compute the buffersize */

		mtu	= iface_get_mtu(sock_fd, device, ebuf);
		if (mtu == -1)
			break;
		handle->bufsize	 = MAX_LINKHEADER_SIZE + mtu;

		/* Fill in the pcap structure */

		handle->fd 	 = sock_fd;
		handle->offset	 = 0;

		handle->buffer	 = malloc(handle->bufsize);
		if (!handle->buffer) {
			snprintf(ebuf, PCAP_ERRBUF_SIZE,
				 "malloc: %s", pcap_strerror(errno));
			break;
		}

		/*
		 * This is a 2.2 or later kernel, as it has PF_PACKET;
		 * "recvfrom()", when passed the MSG_TRUNC flag, will
		 * return the actual length of the packet, not the
		 * number of bytes from the packet copied to userland,
		 * so we can safely pass it a byte count based on the
		 * snapshot length.
		 */
		handle->md.readlen = handle->snapshot;
		return 1;

	} while(0);

	if (sock_fd != -1)
		close(sock_fd);
	return 0;
#else
	strncpy(ebuf, 
		"New packet capturing interface not supported by build " 
		"environment", PCAP_ERRBUF_SIZE);
	return 0;
#endif
}

#ifdef HAVE_NETPACKET_PACKET_H
/*
 *  Return the index of the given device name. Fill ebuf and return 
 *  -1 on failure.
 */
static int
iface_get_id(int fd, const char *device, char *ebuf)
{
	struct ifreq	ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

	if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE,
			 "ioctl: %s", pcap_strerror(errno));
		return -1;
	}

	return ifr.ifr_ifindex;
}

/*
 *  Bind the socket associated with FD to the given device. 
 */
static int
iface_bind(int fd, int ifindex, char *ebuf)
{
	struct sockaddr_ll	sll;

	memset(&sll, 0, sizeof(sll));
	sll.sll_family		= AF_PACKET;
	sll.sll_ifindex		= ifindex;
	sll.sll_protocol	= htons(ETH_P_ALL);

	if (bind(fd, (struct sockaddr *) &sll, sizeof(sll)) == -1) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE,
			 "bind: %s", pcap_strerror(errno));
		return -1;
	}

	return 0;
}

#endif


/* ===== Functions to interface to the older kernels ================== */

/*
 * With older kernels promiscuous mode is kind of interesting because we
 * have to reset the interface before exiting. The problem can't really
 * be solved without some daemon taking care of managing usage counts. 
 * If we put the interface into promiscuous mode, we set a flag indicating
 * that we must take it out of that mode when the interface is closed,
 * and, when closing the interface, if that flag is set we take it out
 * of promiscuous mode.
 */

/*
 * List of pcaps for which we turned promiscuous mode on by hand.
 * If there are any such pcaps, we arrange to call "pcap_close_all()"
 * when we exit, and have it close all of them to turn promiscuous mode
 * off.
 */
static struct pcap *pcaps_to_close;

/*
 * TRUE if we've already called "atexit()" to cause "pcap_close_all()" to
 * be called on exit.
 */
static int did_atexit;

static void	pcap_close_all(void)
{
	struct pcap *handle;

	while ((handle = pcaps_to_close) != NULL)
		pcap_close(handle);
}

void	pcap_close_linux( pcap_t *handle )
{
	struct pcap	*p, *prevp;
	struct ifreq	ifr;

	if (handle->md.clear_promisc) {
		/*
		 * We put the interface into promiscuous mode; take
		 * it out of promiscuous mode.
		 *
		 * XXX - if somebody else wants it in promiscuous mode,
		 * this code cannot know that, so it'll take it out
		 * of promiscuous mode.  That's not fixable in 2.0[.x]
		 * kernels.
		 */
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, handle->md.device, sizeof(ifr.ifr_name));
		if (ioctl(handle->fd, SIOCGIFFLAGS, &ifr) == -1) {
			fprintf(stderr, 
			    "Can't restore interface flags (SIOCGIFFLAGS failed: %s).\n"
			    "Please adjust manually.\n"
			    "Hint: This can't happen with Linux >= 2.2.0.\n",
			    strerror(errno));
		} else {
			if (ifr.ifr_flags & IFF_PROMISC) {
				/*
				 * Promiscuous mode is currently on; turn it
				 * off.
				 */
				ifr.ifr_flags &= ~IFF_PROMISC;
				if (ioctl(handle->fd, SIOCSIFFLAGS, &ifr) == -1) {
					fprintf(stderr, 
					    "Can't restore interface flags (SIOCSIFFLAGS failed: %s).\n"
					    "Please adjust manually.\n"
					    "Hint: This can't happen with Linux >= 2.2.0.\n",
					    strerror(errno));
				}
			}
		}

		/*
		 * Take this pcap out of the list of pcaps for which we
		 * have to take the interface out of promiscuous mode.
		 */
		for (p = pcaps_to_close, prevp = NULL; p != NULL;
		    prevp = p, p = p->md.next) {
			if (p == handle) {
				/*
				 * Found it.  Remove it from the list.
				 */
				if (prevp == NULL) {
					/*
					 * It was at the head of the list.
					 */
					pcaps_to_close = p->md.next;
				} else {
					/*
					 * It was in the middle of the list.
					 */
					prevp->md.next = p->md.next;
				}
				break;
			}
		}
	}
	if (handle->md.device != NULL)
		free(handle->md.device);
}

/*
 *  Try to open a packet socket using the old kernel interface.
 *  Returns 0 on failure.
 *  FIXME: 0 uses to mean success (Sebastian)
 */
static int
live_open_old(pcap_t *handle, char *device, int promisc, 
	      int to_ms, char *ebuf)
{
	int		sock_fd = -1, mtu, arptype;
	struct utsname	utsname;
	struct ifreq	ifr;

	do {
		/* Open the socket */

		sock_fd = socket(PF_INET, SOCK_PACKET, htons(ETH_P_ALL));
		if (sock_fd == -1) {
			snprintf(ebuf, PCAP_ERRBUF_SIZE,
				 "socket: %s", pcap_strerror(errno));
			break;
		}

		/* It worked - we are using the old interface */
		handle->md.sock_packet = 1;

		/* Bind to the given device */

		if (!device) {
		        strncpy(ebuf, "pcap_open_live: No interface given",
				PCAP_ERRBUF_SIZE);
			break;
		}
		if (iface_bind_old(sock_fd, device, ebuf) == -1)
			break;

		/* Go to promisc mode */
		if (promisc) {
			memset(&ifr, 0, sizeof(ifr));
			strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
			if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr) == -1) {
				snprintf(ebuf, PCAP_ERRBUF_SIZE,
					 "ioctl: %s", pcap_strerror(errno));
				break;
			}
			if ((ifr.ifr_flags & IFF_PROMISC) == 0) {
				/*
				 * Promiscuous mode isn't currently on,
				 * so turn it on, and remember that
				 * we should turn it off when the
				 * pcap_t is closed.
				 */

				/*
				 * If we haven't already done so, arrange
				 * to have "pcap_close_all()" called when
				 * we exit.
				 */
				if (!did_atexit) {
					if (atexit(pcap_close_all) == -1) {
						/*
						 * "atexit()" failed; don't
						 * put the interface in
						 * promiscuous mode, just
						 * give up.
						 */
						strncpy(ebuf, "atexit failed",
							PCAP_ERRBUF_SIZE);
						break;
					}
				}

				ifr.ifr_flags |= IFF_PROMISC;
				if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr) == -1) {
				        snprintf(ebuf, PCAP_ERRBUF_SIZE,
						 "ioctl: %s",
						 pcap_strerror(errno));
					break;
				}
				handle->md.clear_promisc = 1;

				/*
				 * Add this to the list of pcaps
				 * to close when we exit.
				 */
				handle->md.next = pcaps_to_close;
				pcaps_to_close = handle;
			}
		}

		/* Compute the buffersize */

		mtu	= iface_get_mtu(sock_fd, device, ebuf);
		if (mtu == -1)
			break;
		handle->bufsize	 = MAX_LINKHEADER_SIZE + mtu;
		if (handle->bufsize < handle->snapshot)
			handle->bufsize = handle->snapshot;

		/* All done - fill in the pcap handle */

		arptype = iface_get_arptype(sock_fd, device, ebuf);
		if (arptype == -1)
			break;

		handle->fd 	 = sock_fd;
		handle->offset	 = 0;
		handle->linktype = map_arphrd_to_dlt(arptype);
		if (handle->linktype == -1) {
			snprintf(ebuf, PCAP_ERRBUF_SIZE,
				 "interface type of %s not supported", device);
			break;
		}
		handle->buffer	 = malloc(handle->bufsize);
		if (!handle->buffer) {
		        snprintf(ebuf, PCAP_ERRBUF_SIZE,
				 "malloc: %s", pcap_strerror(errno));
			break;
		}

		/*
		 * This might be a 2.0[.x] kernel - check.
		 */
		if (uname(&utsname) < 0 ||
		    strncmp(utsname.release, "2.0", 3) == 0) {
			/*
			 * Either we couldn't find out what kernel release
			 * this is, or it's a 2.0[.x] kernel.
			 *
			 * In the 2.0[.x] kernel, a "recvfrom()" on
			 * a SOCK_PACKET socket, with MSG_TRUNC set, will
			 * return the number of bytes read, so if we pass
			 * a length based on the snapshot length, it'll
			 * return the number of bytes from the packet
			 * copied to userland, not the actual length
			 * of the packet.
			 *
			 * This means that, for example, the IP dissector
			 * in tcpdump will get handed a packet length less
			 * than the length in the IP header, and will
			 * complain about "truncated-ip".
			 *
			 * So we don't bother trying to copy from the
			 * kernel only the bytes in which we're interested,
			 * but instead copy them all, just as the older
			 * versions of libpcap for Linux did.
			 *
			 * Just one of many problems with packet capture
			 * on 2.0[.x] kernels; you really want a 2.2[.x]
			 * or later kernel if you want packet capture to
			 * work well.
			 */
			handle->md.readlen = handle->bufsize;
		} else {
			/*
			 * This is a 2.2[.x] or later kernel (although
			 * why we're using SOCK_PACKET on such a system
			 * is unknown to me).
			 *
			 * We can safely pass "recvfrom()" a byte count
			 * based on the snapshot length.
			 */
			handle->md.readlen = handle->snapshot;
		}
		return 1;

	} while (0);

	if (sock_fd != -1)
		close(sock_fd);
	return 0;
}

/*
 *  Bind the socket associated with FD to the given device using the 
 *  interface of the old kernels.
 */
static int
iface_bind_old(int fd, const char *device, char *ebuf)
{
	struct sockaddr	saddr;

	memset(&saddr, 0, sizeof(saddr));
	strncpy(saddr.sa_data, device, sizeof(saddr.sa_data));
	if (bind(fd, &saddr, sizeof(saddr)) == -1) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE,
			 "bind: %s", pcap_strerror(errno));
		return -1;
	}

	return 0;
}


/* ===== System calls available on all supported kernels ============== */

/*
 *  Query the kernel for the MTU of the given interface. 
 */
static int
iface_get_mtu(int fd, const char *device, char *ebuf)
{
	struct ifreq	ifr;

	if (!device)
		return BIGGER_THAN_ALL_MTUS;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

	if (ioctl(fd, SIOCGIFMTU, &ifr) == -1) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE,
			 "ioctl: %s", pcap_strerror(errno));
		return -1;
	}

	return ifr.ifr_mtu;
}

/*
 *  Get the hardware type of the given interface as ARPHRD_xxx constant.
 */
static int
iface_get_arptype(int fd, const char *device, char *ebuf)
{
	struct ifreq	ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE,
			 "ioctl: %s", pcap_strerror(errno));
		return -1;
	}

	return ifr.ifr_hwaddr.sa_family;
}
