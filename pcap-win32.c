/*
 * Copyright (c) 1999, 2000
 *	Politecnico di Torino.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the Politecnico
 * di Torino, and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef lint
static const char rcsid[] =
    "@(#) $Header: /tcpdump/master/libpcap/pcap-win32.c,v 1.7 2003-04-09 10:01:10 risso Exp $ (LBL)";
#endif

#include <pcap-int.h>
#include <packet32.h>
#include <Ntddndis.h>
#ifdef __MINGW32__
int* _errno();
#define errno (*_errno())
#endif /* __MINGW32__ */

#define	PcapBufSize 256000	/*dimension of the buffer in the pcap_t structure*/
#define	SIZE_BUF 1000000

/*
 * Header that the WinPcap driver associates to the packets.
 * Once was in bpf.h
 */
struct bpf_hdr {
	struct timeval	bh_tstamp;	/* time stamp */
	bpf_u_int32	bh_caplen;	/* length of captured portion */
	bpf_u_int32	bh_datalen;	/* original length of packet */
	u_short		bh_hdrlen;	/* length of bpf header (this struct
					   plus alignment padding) */
};

/* Start winsock */
int 
wsockinit()
{
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;
	wVersionRequested = MAKEWORD( 1, 1); 
	err = WSAStartup( wVersionRequested, &wsaData );
	if ( err != 0 )
	{
		return -1;
	}
	return 0;
}


int
pcap_stats(pcap_t *p, struct pcap_stat *ps)
{

	if(PacketGetStats(p->adapter, (struct bpf_stat*)ps) != TRUE){
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "PacketGetStats error: %s", pcap_win32strerror());
		return -1;
	}

	return 0;
}

int
pcap_read(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
	int cc;
	int n = 0;
	register u_char *bp, *ep;

	cc = p->cc;
	if (p->cc == 0) {

	    /* capture the packets */
		if(PacketReceivePacket(p->adapter,p->Packet,TRUE)==FALSE){
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "read error: PacketReceivePacket failed");
			return (-1);
		}
			
		cc = p->Packet->ulBytesReceived;

		bp = p->Packet->Buffer;
	} 
	else
		bp = p->bp;

	/*
	 * Loop through each packet.
	 */
#define bhp ((struct bpf_hdr *)bp)
	ep = bp + cc;
	while (bp < ep) {
		register int caplen, hdrlen;
		caplen = bhp->bh_caplen;
		hdrlen = bhp->bh_hdrlen;

		/*
		 * XXX A bpf_hdr matches a pcap_pkthdr.
		 */
		(*callback)(user, (struct pcap_pkthdr*)bp, bp + hdrlen);
		bp += BPF_WORDALIGN(caplen + hdrlen);
		if (++n >= cnt && cnt > 0) {
			p->bp = bp;
			p->cc = ep - bp;
			return (n);
		}
	}
#undef bhp
	p->cc = 0;
	return (n);
}


pcap_t *
pcap_open_live(const char *device, int snaplen, int promisc, int to_ms,
    char *ebuf)
{
	register pcap_t *p;
	NetType type;

	/* Init WinSock */
	wsockinit();

	p = (pcap_t *)malloc(sizeof(*p));
	if (p == NULL) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "malloc: %s", pcap_strerror(errno));
		return (NULL);
	}
	memset(p, 0, sizeof(*p));
	p->adapter=NULL;

	p->adapter=PacketOpenAdapter(device);
	if (p->adapter==NULL) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "Error opening adapter: %s", pcap_win32strerror());
		return NULL;
	}

	/*get network type*/
	if(PacketGetNetType (p->adapter,&type)==FALSE)
	{
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "Cannot determine the network type: %s", pcap_win32strerror());
		goto bad;
	}
	
	/*Set the linktype*/
	switch (type.LinkType) {

	case NdisMediumWan:
		p->linktype = DLT_EN10MB;
	break;

	case NdisMedium802_3:
		p->linktype = DLT_EN10MB;
	break;

	case NdisMediumFddi:
		p->linktype = DLT_FDDI;
	break;

	case NdisMedium802_5:			
		p->linktype = DLT_IEEE802;	
	break;

	case NdisMediumArcnetRaw:
		p->linktype = DLT_ARCNET;
	break;

	case NdisMediumArcnet878_2:
		p->linktype = DLT_ARCNET;
	break;

	case NdisMediumAtm:
		p->linktype = DLT_ATM_RFC1483;
	break;

	default:
		p->linktype = DLT_EN10MB;			/*an unknown adapter is assumed to be ethernet*/
	break;
	}

	/* Set promisquous mode */
	if (promisc) PacketSetHwFilter(p->adapter,NDIS_PACKET_TYPE_PROMISCUOUS);
	 else PacketSetHwFilter(p->adapter,NDIS_PACKET_TYPE_ALL_LOCAL);

	/* Set the buffer size */
	p->bufsize = PcapBufSize;

	p->buffer = (u_char *)malloc(PcapBufSize);
	if (p->buffer == NULL) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "malloc: %s", pcap_strerror(errno));
		goto bad;
	}

	p->snapshot = snaplen;

	/* allocate Packet structure used during the capture */
	if((p->Packet = PacketAllocatePacket())==NULL){
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "failed to allocate the PACKET structure");
		goto bad;
	}

	PacketInitPacket(p->Packet,(BYTE*)p->buffer,p->bufsize);

	/* allocate the standard buffer in the driver */
	if(PacketSetBuff( p->adapter, SIZE_BUF)==FALSE)
	{
		snprintf(ebuf, PCAP_ERRBUF_SIZE,"driver error: not enough memory to allocate the kernel buffer\n");
		goto bad;
	}

	/* tell the driver to copy the buffer only if it contains at least 16K */
	if(PacketSetMinToCopy(p->adapter,16000)==FALSE)
	{
		snprintf(ebuf, PCAP_ERRBUF_SIZE,"Error calling PacketSetMinToCopy: %s\n", pcap_win32strerror());
		goto bad;
	}

	PacketSetReadTimeout(p->adapter, to_ms);

	return (p);
bad:
	if (p->adapter)
	    PacketCloseAdapter(p->adapter);
	if (p->buffer != NULL)
		free(p->buffer);
	free(p);
	return (NULL);
}


int
pcap_setfilter(pcap_t *p, struct bpf_program *fp)
{
	if(p->adapter==NULL){
		/* Offline capture: make our own copy of the filter */
		if (install_bpf_program(p, fp) < 0)
			return (-1);
	}
	else if(PacketSetBpf(p->adapter,fp)==FALSE){
		/* kernel filter not installed. */
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "Driver error: cannot set bpf filter: %s", pcap_win32strerror());
		return (-1);
	}
	return (0);
}


/* Set the driver working mode */
int 
pcap_setmode(pcap_t *p, int mode){
	
	if (p->adapter==NULL)
	{
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "impossible to set mode while reading from a file");
		return -1;
	}

	if(PacketSetMode(p->adapter,mode)==FALSE)
	{
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "driver error: working mode not recognized");
		return -1;
	}

	return 0;
}

/* Send a packet to the network */
int 
pcap_sendpacket(pcap_t *p, u_char *buf, int size){
	LPPACKET PacketToSend;

	if (p->adapter==NULL)
	{
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "Writing a packet is allowed only on a physical adapter");
		return -1;
	}

	PacketToSend=PacketAllocatePacket();
	PacketInitPacket(PacketToSend,buf,size);
	if(PacketSendPacket(p->adapter,PacketToSend,TRUE) == FALSE){
		PacketFreePacket(PacketToSend);
		return -1;
	}

	PacketFreePacket(PacketToSend);
	return 0;
}

/* Set the dimension of the kernel-level capture buffer */
int 
pcap_setbuff(pcap_t *p, int dim)
{
	if (p->adapter==NULL)
	{
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "The kernel buffer size cannot be set while reading from a file");
		return -1;
	}
	
	if(PacketSetBuff(p->adapter,dim)==FALSE)
	{
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "driver error: not enough memory to allocate the kernel buffer");
		return -1;
	}
	return 0;
}

/*set the minimum amount of data that will release a read call*/
int 
pcap_setmintocopy(pcap_t *p, int size)
{
	if (p->adapter==NULL)
	{
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "Impossible to set the mintocopy parameter on an offline capture");
		return -1;
	}	

	if(PacketSetMinToCopy(p->adapter, size)==FALSE)
	{
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "driver error: unable to set the requested mintocopy size");
		return -1;
	}
	return 0;
}

int
pcap_set_datalink_platform(pcap_t *p, int dlt)
{
	return (0);
}
