/*
	pcap-linux.c: Packet capture interface to the Linux kernel
	Copyright (c) 2000 Torsten Landschoff <torsten@debian.org>
			   Sebastian Krahmer  <krahmer@cs.uni-potsdam.de>

	License: BSD

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions
	are met:

	1. Redistributions of source code must retain the above copyright
	   notice, this list of conditions and the following disclaimer.
	2. Redistributions in binary form must reproduce the above copyright
	   notice, this list of conditions and the following disclaimer in
	   the documentation and/or other materials provided with the
	   distribution.
	3. The names of the authors may not be used to endorse or promote
	   products derived from this software without specific prior
	   written permission.

	THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
	IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
*/

/*
    TODO:

    - Make it compatible with older Linux installations (at compilation time)

    BUGS: 

    - setting promiscuous on loopback for example gives every packet
      twice
*/


/*
    FYI:

    pcap_read currently reads not only a packet from the kernel but also
    the sockaddr_ll returned as source of the packet. This way we can at 
    some time extend tcpdump and libpcap to sniff on all devices at a time
    and find the right printing routine by using the information in the
    sockaddr_ll structure.
*/


#include "pcap-int.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
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
#define MSG_TRUNC	0
#endif

#define MAX_LINKHEADER_SIZE	256

/* Prototypes for internal functions */
static int map_arphrd_to_dlt( int arptype );
static int live_open_old( pcap_t *, char *, int, int, char * );
static int live_open_new( pcap_t *, char *, int, int, char * );
static int pcap_read_packet( pcap_t *, pcap_handler, u_char * );

/* Wrap some ioctl calls */
static int	iface_get_id( int fd, const char *device, char *ebuf );
static int	iface_get_mtu( int fd, const char *device, char *ebuf );
static int 	iface_get_arptype( int fd, const char *device, char *ebuf );
static int 	iface_bind( int fd, int ifindex, char *ebuf );
static int 	iface_bind_old( int fd, const char *device, char *ebuf );

/*
	pcap_open_live:

	Get a handle for a live capture from the given device. You can 
	pass NULL as device to get all packages (without link level 
	information of course). If you pass 1 as promisc the interface
	will be set to promiscous mode (XXX: I think this usage should 
	be deprecated and functions be added to select that later allow
	modification of that values -- Torsten).

	See also pcap(3).
*/
pcap_t *
pcap_open_live( char *device, int snaplen, int promisc, int to_ms, char *ebuf )
{
	/* Allocate a handle for this session and initialize the contents 
	 * to all nulls. */
	
	pcap_t	*handle = calloc( 1, sizeof(*handle) );
	if( handle == NULL ) {
		sprintf( ebuf, "calloc: %s", pcap_strerror(errno) );
		return NULL;
	}

	/* Initialize some components of the pcap structure. */

	memset( handle, 0, sizeof(*handle) );
	handle->snapshot	= snaplen;
	handle->md.timeout	= to_ms;
	handle->md.promisc	= promisc;
	handle->md.device	= strdup( device );
	if( handle->md.device == NULL ) {
		sprintf( ebuf, "strdup: %s", pcap_strerror(errno) );
		free( handle );
		return NULL;
	}

	/* Current Linux kernels use the protocol family PF_PACKET to 
	 * allow direct access to all packets on the network while 
	 * older kernels had a special socket type SOCK_PACKET to 
	 * implement this feature.
	 * While this old implementation is kind of obsolete we need
	 * to be compatible with older kernels for a while so we are 
	 * trying both methods with the newer method preferred. */
	
	if( ! (live_open_new(handle, device, promisc, to_ms, ebuf) ||
	       live_open_old(handle, device, promisc, to_ms, ebuf)) )
	{
		/* Both methods to open the packet socket failed. Tidy
		 * up and report our failure (ebuf is expected to be
		 * set by the functions above). */

		free( handle );
		return NULL;
	}
	
	/* Okay, now we have a packet stream open. Maybe we need to handle 
	 * a timeout? In that case we set the filehandle to nonblocking 
	 * so pcap_read can try reading the fd and call select if no data
	 * is available at once. */

	if( to_ms > 0 ) {
		int	flags = fcntl( handle->fd, F_GETFL );
		if( flags != -1 ) {
			flags |= O_NONBLOCK;
			flags = fcntl( handle->fd, F_SETFL, flags );
		}
		if( flags == -1 ) {
			sprintf(ebuf, "fcntl: %s", pcap_strerror(errno));
			pcap_close( handle );
			return NULL;
		}
	}

	return handle;
}

/*
	pcap_read:

	Read at most max_packets from the capture stream and 
	call the callback for each of them. Returns the number
	of packets handled or -1 if an error occured. 

	XXX: Can I rely on the Linux-specified behaviour of select 
	(returning the time left in the timeval structure)? I really
	don't want to query the system time before each select call...
*/
int
pcap_read(pcap_t *handle, int max_packets, pcap_handler callback, u_char *user)
{
	int		status, packets;
	fd_set		read_fds;
	struct timeval	tv;

	if( handle->md.timeout > 0 ) {
		tv.tv_usec	= (handle->md.timeout % 1000) * 1000;
		tv.tv_sec	= (handle->md.timeout / 1000);
	}
	
	for( packets = 0; max_packets == -1 || packets < max_packets; )
	{
		status = pcap_read_packet( handle, callback, user );

		if( status > 0 ) {
			packets++;
			continue;
		} else if( status == -1 )
			return -1;
			
		/* paranoia - the recvmsg call should block if we don't use 
		 * a timeout */
		if( handle->md.timeout <= 0 )
			continue;

		/* No packet available - go to sleep */
		FD_ZERO( &read_fds );
		FD_SET( handle->fd, &read_fds );
		status = select( handle->fd + 1, 
				 &read_fds, NULL, NULL, &tv );
		if( status == -1 ) {
			sprintf( handle->errbuf, "select: %s", 
				 pcap_strerror(errno) );
			return -1;
		} else if( status == 0 || 
			   (tv.tv_usec == 0 && tv.tv_sec == 0) )
			return packets;
	}

	return packets;
}
		
/*
	pcap_read_packet:

	Read a packet from the socket calling the handler provided by 
	the user. Returns 0 if no packet was there, 1 if a packet was
 	handled and -1 if an error occured.
*/
static int
pcap_read_packet( pcap_t *handle, pcap_handler callback, u_char *userdata )
{
	struct sockaddr		from;
	socklen_t		fromlen;
	int			packet_len, caplen;
	struct pcap_pkthdr	pcap_header;

	/* We don't currently use the from return value of recvfrom but
	 * this will probably implemented in the future. */
	
	/* Receive a single packet from the kernel */
	do {
		fromlen = sizeof(from);
		packet_len = recvfrom( 
			handle->fd, handle->buffer + handle->offset, 
			handle->snapshot, MSG_TRUNC, 
			(struct sockaddr *) &from, &fromlen );
	} while( packet_len == -1 && errno == EINTR );

	/* Check if some error occured */
	if( packet_len == -1 ) {
		if( errno == EAGAIN )
			return 0;	/* no packet there */
		else {
			sprintf( handle->errbuf, "recvfrom: %s", 
				 pcap_strerror(errno) );
			return -1;
		}
	}

	/* XXX: According to the kernel source we should get the real 
	 * packet len if calling recvfrom with MSG_TRUNC set. It does 
	 * not seem to work here :(, but it is supported by this code
	 * anyway. */
	
	caplen = packet_len;
	if( caplen > handle->snapshot )
		caplen = handle->snapshot;

	/* Run the packet filter if not using kernel filter */
	if( !handle->md.use_bpf && handle->fcode.bf_insns ) {
		if( bpf_filter(handle->fcode.bf_insns, handle->buffer, 
		                packet_len, caplen) == 0 )
		{
			/* rejected by filter */
			return 0;
		}
	}
	
	/* Fill in our own header data */
	
	if( ioctl(handle->fd, SIOCGSTAMP, &pcap_header.ts) == -1 ) {
		sprintf( "ioctl: %s", pcap_strerror(errno) );
		return -1;
	}
	pcap_header.caplen	= caplen;
	pcap_header.len		= packet_len;
	
	/* Call the user supplied callback function */
	handle->md.stat.ps_recv++;
	callback( userdata, &pcap_header, handle->buffer + handle->offset);

	return 1;
}

/*
	pcap_stats:

	Get the statistics for the given packet capture handle.
*/
int
pcap_stats( pcap_t *handle, struct pcap_stat *stats )
{
	*stats = handle->md.stat;
	return 0;
}

/*
	pcap_setfilter:

	Attach the given BPF code to the packet capture device. 
*/
int
pcap_setfilter( pcap_t *handle, struct bpf_program *filter )
{
#ifdef SO_ATTACH_FILTER
	struct sock_fprog	fcode;
#endif

	if( !handle )
		return -1;
	if( !filter ) {
		strcpy( handle->errbuf, "setfilter: No filter specified" );
		return -1;
	}

	/* Free old filter code if existing */
	handle->fcode.bf_len	= 0;
	if( handle->fcode.bf_insns ) {
		free( handle->fcode.bf_insns );
		handle->fcode.bf_insns = NULL;
	}


	/* Make our private copy of the filter */
	handle->fcode.bf_len   = filter->bf_len;
	handle->fcode.bf_insns = 
		malloc( filter->bf_len * sizeof(*filter->bf_insns) );
	if( handle->fcode.bf_insns == NULL ) {
		sprintf( handle->errbuf, "calloc: %s", pcap_strerror(errno) );
		return -1;
	} 
	memcpy( handle->fcode.bf_insns, filter->bf_insns, 
		filter->bf_len * sizeof(*filter->bf_insns) );

	/* Run user level packet filter by default. Will be overriden if 
	 * installing a kernel filter succeeds. */
	handle->md.use_bpf = 0;

	/* Install kernel level filter if possible */
	
#ifdef SO_ATTACH_FILTER
	/* Oh joy, the Linux kernel uses struct sock_fprog instead of 
	 * struct bpf_program and of course the length field is of 
	 * different size. Pointed out by Sebastian */

	fcode.filter	= (struct sock_filter *) handle->fcode.bf_insns;
	fcode.len	= filter->bf_len;
	if( filter->bf_len > USHRT_MAX ) {
		fprintf( stderr, "Warning: Filter to complex for kernel\n" );
		/* paranoid - should never happen */
	} 
	else if( setsockopt(handle->fd, SOL_SOCKET, SO_ATTACH_FILTER, 
		       &fcode, sizeof(fcode)) == 0 )
	{
		handle->md.use_bpf = 1;
	} else
	{
		/* Print a warning if kernel filter available but a problem
		 * occured using it. */
		if( errno != ENOPROTOOPT && errno != EOPNOTSUPP ) {
			fprintf( stderr, "Warning: Kernel filter failed: %s\n", 
				 pcap_strerror(errno) );
		}
	}
#endif

	return 0;
}


/*
	map_arphrd_to_dlt:

	Linux uses the ARP hardware type to identify the type of an 
	interface. pcap uses the DLT_xxx constants for this. This 
	function maps the ARPHRD_xxx constant to an appropriate
	DLT_xxx constant.

	Returns -1 if unable to map the type.
*/
static int map_arphrd_to_dlt( int arptype )
{
	switch( arptype ) {
	case ARPHRD_ETHER:
	case ARPHRD_METRICOM:
	case ARPHRD_LOOPBACK:	return DLT_EN10MB;
	case ARPHRD_EETHER:	return DLT_EN3MB;
	case ARPHRD_AX25:	return DLT_AX25;
	case ARPHRD_PRONET:	return DLT_PRONET;
	case ARPHRD_CHAOS:	return DLT_CHAOS;
	case ARPHRD_IEEE802:	return DLT_IEEE802;
	case ARPHRD_ARCNET:	return DLT_ARCNET;
	case ARPHRD_FDDI:	return DLT_FDDI;

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
	live_open_new:

	Try to open a packet socket using the new kernel interface.
	Returns 0 on failure.
	FIXME: 0 uses to mean success (Sebastian)
*/
static int
live_open_new( pcap_t *handle, char *device, int promisc, 
	       int to_ms, char *ebuf )
{
#ifdef HAVE_NETPACKET_PACKET_H
	int			sock_fd = -1, device_id, mtu, arptype;
	struct packet_mreq	mr;

	/* One shot loop used for error handling - bail out with break */

	do {

		/* Open a socket with protocol family packet. */
		sock_fd = socket( PF_PACKET, SOCK_RAW, htons(ETH_P_ALL) );
		if( sock_fd == -1 ) {
			sprintf( ebuf, "socket: %s", pcap_strerror(errno) );
			break;
		}

		/* It seems the kernel supports the new interface. */
		handle->md.sock_packet = 0;

		/* Currently we only support monitoring a single interface.
		 * While the kernel can do more I want to reimplement the 
		 * old features first before adding more. */

		if( !device ) {
			sprintf( ebuf, "pcap_open_live: No device given" );
			break;
		}

		/* What kind of frames do we have to deal with? Fall back 
		 * to cooked mode if we have an unknown interface type. */

		arptype		= iface_get_arptype(sock_fd, device, ebuf);
		if( arptype == -1 ) 
			break;
		handle->linktype = map_arphrd_to_dlt( arptype );
		if( handle->linktype == -1 ) {
			/* Unknown interface type - reopen in cooked mode */
			
			if( close(sock_fd) == -1 ) {
				sprintf("close: %s", pcap_strerror(errno));
				break;
			}
			sock_fd = socket( PF_PACKET, SOCK_DGRAM, 
					  htons(ETH_P_ALL) );
			if( sock_fd == -1 ) {
				sprintf( ebuf, "socket: %s", 
					       pcap_strerror(errno) );
				break;
			}

			fprintf( stderr, 
				"Warning: Falling back to cooked socket\n" );
			handle->linktype = DLT_RAW;
		}


		device_id = iface_get_id( sock_fd, device, ebuf );
		if( device_id == -1 )
			break;

		if( iface_bind(sock_fd, device_id, ebuf) == -1 )
			break;

		/* Select promiscous mode on/off */

		/* XXX: We got reports that this does not work in 2.3.99.
		 * Need to investigate. Using ioctl to switch the promisc 
		 * mode at device level costs us most of the benefits of 
		 * using the new kernel interface.
		 * UPDATE: I found the bug. The kernel checks mr_alen
		 * even if it is of zero interest for the request. A 
		 * random value there made the kernel return EINVAL. 
		 * Probably the right solution is to memset the whole 
		 * struct at first. */

		memset( &mr, 0, sizeof(mr) );
		mr.mr_ifindex = device_id;
		mr.mr_type    = promisc ? 
			PACKET_MR_PROMISC : PACKET_MR_ALLMULTI;
		if( setsockopt( sock_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, 
			        &mr, sizeof(mr) ) == -1 )
		{
			sprintf(ebuf, "setsockopt: %s", pcap_strerror(errno));
			break;
		}
		
		/* Compute the buffersize */

		mtu	= iface_get_mtu(sock_fd, device, ebuf);
		if( mtu == -1 )
			break;
		handle->bufsize	 = MAX_LINKHEADER_SIZE + mtu;
		
		/* Fill in the pcap structure */

		handle->fd 	 = sock_fd;
		handle->offset	 = 0;

		handle->buffer	 = malloc( handle->bufsize );
		if( !handle->buffer ) {
			sprintf( ebuf, "malloc: %s", pcap_strerror(errno) );
			break;
		}

		return 1;

	} while(0);

	if( sock_fd != -1 )
		close( sock_fd );
	return 0;
#else
	strcpy( ebuf, "New packet capturing interface not supported by build " 
                      "environment" );
	return 0;
#endif
}

#ifdef HAVE_NETPACKET_PACKET_H
/*
	iface_get_id:

	Return the index of the given device name. Fill ebuf and return 
	-1 on failure.
*/
static int
iface_get_id( int fd, const char *device, char *ebuf )
{
	struct ifreq	ifr;

	memset( &ifr, 0, sizeof(ifr) );
	strncpy( ifr.ifr_name, device, sizeof(ifr.ifr_name) );

	if( ioctl(fd, SIOCGIFINDEX, &ifr) == -1 ) {
		sprintf( ebuf, "ioctl: %s", pcap_strerror(errno) );
		return -1;
	}

	return ifr.ifr_ifindex;
}

/*
	iface_bind:

	Bind the socket associated with FD to the given device. 
*/
static int
iface_bind( int fd, int ifindex, char *ebuf )
{
	struct sockaddr_ll	sll;

	memset( &sll, 0, sizeof(sll) );
	sll.sll_family		= AF_PACKET;
	sll.sll_ifindex		= ifindex;
	sll.sll_protocol	= htons(ETH_P_ALL);

	if( bind(fd, (struct sockaddr *) &sll, sizeof(sll)) == -1 ) {
		sprintf( ebuf, "bind: %s", pcap_strerror(errno) );
		return -1;
	}

	return 0;
}

#endif


/* ===== Functions to interface to the older kernels ================== */

/* With older kernels promiscuous mode is kind of interesting because we
 * have to reset the interface before exiting. The problem can't really
 * be solved without some daemon taking care of managing usage counts. 
 * We save the promiscuous state of the device when opening the capture
 * stream and arrange for it to be reset on process exit.
 *
 * XXX: This solution is still not correct even for this case. The 
 * devices stay in promiscuous mode until the process exits. I need to 
 * modify pcap_close to solve this. */

struct ifreq	restore_ifr;
	/* Contains the device name and the interface flags to be restored
	 * at exit */

static void	restore_interface( void )
{
	int	status = socket(PF_INET, SOCK_PACKET, 0);

	if( status != -1 )
		status = ioctl(status, SIOCSIFFLAGS, &restore_ifr);

	if( status == -1 ) {
		fprintf(stderr, 
		"Can't restore interface flags. Please adjust manually. \n"
		"Hint: This can't happen with Linux >= 2.2.0.\n");
	}
}

/*
	live_open_old:

	Try to open a packet socket using the old kernel interface.
	Returns 0 on failure.
	FIXME: 0 uses to mean success (Sebastian)
*/
static int
live_open_old( pcap_t *handle, char *device, int promisc, 
	       int to_ms, char *ebuf )
{
	int		sock_fd = -1, mtu, arptype;
	struct ifreq	ifr;

	do {
		/* Open the socket */
		
		sock_fd = socket( PF_INET, SOCK_PACKET, htons(ETH_P_ALL) );
		if( sock_fd == -1 ) {
			sprintf( ebuf, "socket: %s", pcap_strerror(errno) );
			break;
		}

		/* It worked - we are using the old interface */
		handle->md.sock_packet = 1;

		/* Bind to the given device */

		if( !device ) {
			strcpy( ebuf, "pcap_open_live: No interface given" );
			break;
		}
		if( iface_bind_old(sock_fd, device, ebuf) == -1 )
			break;

		/* Go to promisc mode */
		if( promisc ) {
			memset( &ifr, 0, sizeof(ifr) );
			strncpy( ifr.ifr_name, device, sizeof(ifr.ifr_name) );
			if( ioctl(sock_fd, SIOCGIFFLAGS, &ifr) == -1 ) {
				sprintf( ebuf, "ioctl: %s", 
					 pcap_strerror(errno) );
				break;
			}
			if( (ifr.ifr_flags & IFF_PROMISC) == 0 ) {
				restore_ifr    = ifr;
				ifr.ifr_flags |= IFF_PROMISC;
				if( ioctl(sock_fd, SIOCSIFFLAGS, &ifr) == -1 ) {
					sprintf( ebuf, "ioctl: %s", 
						 pcap_strerror(errno) );
					break;
				}
				if( atexit(restore_interface) == -1 ) {
					restore_interface();
					strcpy( ebuf, "atexit failed" );
					break;
				}
			}
		}

		
		/* Compute the buffersize */

		mtu	= iface_get_mtu(sock_fd, device, ebuf);
		if( mtu == -1 )
			break;
		handle->bufsize	 = MAX_LINKHEADER_SIZE + mtu;
		
		/* All done - fill in the pcap handle */

		arptype = iface_get_arptype(sock_fd, device, ebuf);
		if( arptype == -1 )
			break;

		handle->fd 	 = sock_fd;
		handle->offset	 = 0;
		handle->linktype = map_arphrd_to_dlt( arptype );
		if( handle->linktype == -1 ) {
			sprintf(ebuf, "interface type of %s not supported", 
				      device);
			break;
		}
		handle->buffer	 = malloc( handle->bufsize );
		if( !handle->buffer ) {
			sprintf( ebuf, "malloc: %s", pcap_strerror(errno) );
			break;
		}

		return 1;
		
	} while(0);
		
	if( sock_fd != -1 )
		close( sock_fd );
	return 0;
}

/*
	iface_bind_old:

	Bind the socket associated with FD to the given device using the 
	interface of the old kernels.
*/
static int
iface_bind_old( int fd, const char *device, char *ebuf )
{
	struct sockaddr	saddr;

	memset( &saddr, 0, sizeof(saddr) );
	strncpy( saddr.sa_data, device, sizeof(saddr.sa_data) );
	if( bind(fd, &saddr, sizeof(saddr)) == -1 ) {
		sprintf( ebuf, "bind: %s", pcap_strerror(errno) );
		return -1;
	}

	return 0;
}


/* ===== System calls available on all supported kernels ============== */

/*
	iface_get_mtu:

	Query the kernel for the MTU of the given interface. 
*/
static int
iface_get_mtu( int fd, const char *device, char *ebuf )
{
	struct ifreq	ifr;

	memset( &ifr, 0, sizeof(ifr) );
	strncpy( ifr.ifr_name, device, sizeof(ifr.ifr_name) );

	if( ioctl(fd, SIOCGIFMTU, &ifr) == -1 ) {
		sprintf( ebuf, "ioctl: %s", pcap_strerror(errno) );
		return -1;
	}

	return ifr.ifr_mtu;
}

/*
	iface_get_arptype:

	Get the hardware type of the given interface as ARPHRD_xxx constant.
*/
static int
iface_get_arptype( int fd, const char *device, char *ebuf )
{
	struct ifreq	ifr;

	memset( &ifr, 0, sizeof(ifr) );
	strncpy( ifr.ifr_name, device, sizeof(ifr.ifr_name) );

	if( ioctl(fd, SIOCGIFHWADDR, &ifr) == -1 ) {
		sprintf( ebuf, "ioctl: %s", pcap_strerror(errno) );
		return -1;
	}

	return ifr.ifr_hwaddr.sa_family;
}

