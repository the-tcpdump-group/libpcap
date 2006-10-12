/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies 
 * nor the names of its contributors may be used to endorse or promote 
 * products derived from this software without specific prior written 
 * permission.
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
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * USB sniffig API implementation for linux platform
 * By Paolo Abeni <paolo.abeni@email.com>
 *
 */
 
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pcap-int.h"
#include "pcap/usb.h"

#ifdef NEED_STRERROR_H
#include "strerror.h"
#endif

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include <netinet/in.h>

#define USB_IFACE "usb"
#define USB_DIR "/sys/kernel/debug/usbmon"
#define USB_LINE_LEN 4096

/* forward declaration */
static int usb_read_linux(pcap_t *, int , pcap_handler , u_char *);
static int usb_inject_linux(pcap_t *, const void *, size_t);
static int usb_setfilter_linux(pcap_t *, struct bpf_program *);
static int usb_setdirection_linux(pcap_t *, pcap_direction_t);
static int usb_stats_linux(pcap_t *, struct pcap_stat *);
static void usb_close_linux(pcap_t *);

int 
usb_platform_finddevs(pcap_if_t **alldevsp, char *err_str)
{
    	pcap_if_t *devlist = *alldevsp;
	struct dirent* data;
	DIR* dir = opendir(USB_DIR);
	if (!dir) {
		/* it's not fatal, but it would be useful to give a message
		   about debugfs: 
			modprobe usbmon
			mount -t debugfs none_debugs /sys/kernel/debug
		 */
		return 0;
	}	
	
	/* scan usbmon directory */
	int ret = 0;
	while ((data = readdir(dir)) != 0)
	{
		char* name = data->d_name;
		int len = strlen(name);

	    	if ((len >= 2) && name[len -1]== 't')
		{
			int n = name[0] - '0';
			char dev_name[10], dev_descr[30];
			snprintf(dev_name, 10, USB_IFACE"%d", n);
			snprintf(dev_descr, 30, "usb bus number %d", n);
			
			if (pcap_add_if(&devlist, dev_name, 0, 
			    dev_descr, err_str) < 0)
			{
				ret = -1;
				break;
			}
		}
	}
	closedir(dir);
	
	*alldevsp = devlist;
	return ret;
}

pcap_t*
usb_open_live(const char* bus, int snaplen, int promisc , int to_ms, char* errmsg)
{
    	char 		full_path[USB_LINE_LEN];
	pcap_t		*handle;

	/* Allocate a handle for this session. */
	handle = malloc(sizeof(*handle));
	if (handle == NULL) {
		snprintf(errmsg, PCAP_ERRBUF_SIZE, "malloc: %s",
			pcap_strerror(errno));
		return NULL;
	}
	
	/* Initialize some components of the pcap structure. */
	memset(handle, 0, sizeof(*handle));
	handle->snapshot	= snaplen;
	handle->md.timeout	= to_ms;
	handle->bufsize = USB_LINE_LEN;
	handle->offset = 0;
	handle->linktype = DLT_USB;
	
	/* get usb bus index from device name */
	if (sscanf(bus, USB_IFACE"%d", &handle->md.ifindex) != 1)
	{
	    	snprintf(errmsg, PCAP_ERRBUF_SIZE,
			"Can't get usb bus index from %s", bus);
		free(handle);
		return NULL;
	}
	
	/* open text output file*/
	snprintf(full_path, USB_LINE_LEN, USB_DIR"/%dt", handle->md.ifindex);  
	handle->fd = open(full_path, O_RDONLY, 0);
	if (handle->fd < 0)
	{
		snprintf(errmsg, PCAP_ERRBUF_SIZE,
			"Can't open usb bus file %s: %s", full_path, strerror(errno));
		free(handle);
		return NULL;
	}
	
	handle->buffer = malloc(handle->bufsize + handle->offset);
	if (!handle->buffer) {
	        snprintf(errmsg, PCAP_ERRBUF_SIZE,
			 "malloc: %s", pcap_strerror(errno));
		usb_close_linux(handle);
		return NULL;
	}	
	
	/*
	 * "handle->fd" is a real file , so "select()" and "poll()"
	 * work on it.
	 */
	handle->selectable_fd = handle->fd;

	handle->read_op = usb_read_linux;
	handle->inject_op = usb_inject_linux;
	handle->setfilter_op = usb_setfilter_linux;
	handle->setdirection_op = usb_setdirection_linux;
	handle->set_datalink_op = NULL;	/* can't change data link type */
	handle->getnonblock_op = pcap_getnonblock_fd;
	handle->setnonblock_op = pcap_setnonblock_fd;
	handle->stats_op = usb_stats_linux;
	handle->close_op = usb_close_linux;

	return handle;
	
}

static inline int 
ascii_to_int(char c)
{
	return c < 'A' ? c- '0': ((c<'a') ? c - 'A' + 10: c-'a'+10);
}

/*
 * see <linux-kernel-source>/Documentation/usb/usbmon.txt and 
 * <linux-kernel-source>/drivers/usb/mon/mon_text.c for urb string 
 * format description
 */
static int
usb_read_linux(pcap_t *handle, int max_packets, pcap_handler callback, u_char *user)
{
	/* see:
	* /usr/src/linux/Documentation/usb/usbmon.txt 
	* for message format
	*/
	unsigned timestamp;
	int tag, cnt, ep_num, dev_addr, dummy, ret;
	char etype, pipeid1, pipeid2, status[16], urb_tag, line[4096];
	char *string = line;
	u_char * rawdata = handle->buffer;
	struct pcap_pkthdr pkth;
	pcap_usb_header* uhdr = (pcap_usb_header*)rawdata;
	pcap_urb_type_t urb_type = URB_UNKNOWN;
	
	/* ignore interrupt system call errors */
	do {
		ret = read(handle->fd, line, USB_LINE_LEN - 1);
		if (handle->break_loop)
		{
			handle->break_loop = 0;
			return -2;
		}
	} while ((ret == -1) && (errno == EINTR));
	if (ret < 0)
	{
		if (errno == EAGAIN)
			return 0;	/* no data there */

		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
		    "Can't read from fd %d: %s", handle->fd, strerror(errno));
		return -1;
	}
	
	/* read urb header; %n argument may increment return value, but it's 
	* not mandatory, so does not count on it*/
	string[ret] = 0;
	ret = sscanf(string, "%x %d %c %c%c:%d:%d %s%n", &tag, &timestamp, &etype, 
		&pipeid1, &pipeid2, &dev_addr, &ep_num, status, 
		&cnt);
	if (ret < 8)
	{
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
		    "Can't parse usb bus message '%s', too few token (expected 8 got %d)",
		    string, ret);
		return -1;
	}
	uhdr->endpoint_number = htonl(ep_num);
	uhdr->device_address = htonl(dev_addr);
	string += cnt;
	pkth.ts.tv_sec = timestamp / 1000000;
	pkth.ts.tv_usec = timestamp % 1000000;
	
	/* parse endpoint information */
	if (pipeid1 == 'C')
	{
		if (pipeid2 =='i')
			urb_type = URB_CONTROL_INPUT;
		else
			urb_type = URB_CONTROL_OUTPUT;
	}
	else if (pipeid1 == 'Z')
	{
		if (pipeid2 == 'i')
			urb_type = URB_ISOCHRONOUS_INPUT;
		else 
			urb_type = URB_ISOCHRONOUS_OUTPUT;
	}
	else if (pipeid1 == 'I')
	{
		if (pipeid2 == 'i')
			urb_type = URB_INTERRUPT_INPUT;
		else
			urb_type = URB_INTERRUPT_OUTPUT;
	}
	else if (pipeid1 == 'B')
	{
		if (pipeid2 == 'i')
			urb_type = URB_BULK_INPUT;
		else
			urb_type = URB_BULK_OUTPUT;
	}
	
	/* direction check*/
	if ((urb_type == URB_BULK_INPUT) || (urb_type == URB_INTERRUPT_INPUT) ||
	    	(urb_type == URB_ISOCHRONOUS_INPUT) || (urb_type == URB_CONTROL_INPUT))
	{
	    	if (handle->direction == PCAP_D_OUT)
			return 0;	
	}	    
	else
	    	if (handle->direction == PCAP_D_IN)
			return 0;	
	
	uhdr->urb_type = htonl(urb_type);
	pkth.caplen = sizeof(pcap_usb_header);
	rawdata += sizeof(pcap_usb_header);
	
	/* check if this is a setup packet */
	ret = sscanf(status, "%d", &dummy);
	if (ret != 1)
	{
		/* this a setup packet, setup data can be filled with underscore if
		* usbmon has not been able to read them, so we must parse this fields as 
		* strings */
		pcap_usb_setup* shdr;
		char str1[3], str2[3], str3[5], str4[5], str5[5];
		ret = sscanf(string, "%s %s %s %s %s%n", str1, str2, str3, str4, 
		str5, &cnt);
		if (ret < 5)
		{
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
				"Can't parse usb bus message '%s', too few token (expected 5 got %d)",
				string, ret);
			return -1;
		}
		string += cnt;
		
		/* try to convert to corresponding integer */
		shdr = (pcap_usb_setup*)rawdata;
		shdr->bmRequestType = strtoul(str1, 0, 16);
		shdr->bRequest = strtoul(str2, 0, 16);
		shdr->wValue = htons(strtoul(str3, 0, 16));
		shdr->wIndex = htons(strtoul(str4, 0, 16));
		shdr->wLength = htons(strtoul(str5, 0, 16));
		uhdr->setup_packet = 1;
		
		
		pkth.caplen += sizeof(pcap_usb_setup);
		rawdata += sizeof(pcap_usb_setup);
	}
	else 
		uhdr->setup_packet = 0;
	
	/* read urb data */
	ret = sscanf(string, " %d%n", &pkth.len, &cnt);
	if (ret < 1)
	{
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
		  "Can't parse urb length from '%s'", string);
		return -1;
	}
	string += cnt;
	handle->md.packets_read++;
	
	/* urb tag is not present if urb length is 0, so we can stop here 
	 * text parsing */
	pkth.len += pkth.caplen;	
	if (pkth.len == pkth.caplen)
		return 1;
	
	/* check for data presence; data is present if and only if urb tag is '=' */
	if (sscanf(string, " %c", &urb_tag) != 1)
	{
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			"Can't parse urb tag from '%s'", string);
		return -1;
	}
	
	if (urb_tag != '=')
	    	goto got;
	
	/* read all urb data; if urb length is greater then the usbmon internal 
	 * buffer length used by the kernel to spool the URB, we get only
	 * a partial information.
 	 * At least until linux 2.6.17 there is no way to set usbmon intenal buffer
	 * length and default value is 130. */
	while ((string[0] != 0) && (string[1] != 0) && (pkth.caplen < handle->snapshot))
	{
		rawdata[0] = ascii_to_int(string[0]) * 16 + ascii_to_int(string[1]);
		rawdata++;
		string+=2;
		if (string[0] == ' ')
			string++;
		pkth.caplen++;
	}
	
got:	
	handle->md.packets_read++;
	if (pkth.caplen > handle->snapshot)
		pkth.caplen = handle->snapshot;


	callback(user, &pkth, handle->buffer);
	return 1;
}

static int
usb_inject_linux(pcap_t *handle, const void *buf, size_t size)
{
	snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "inject not supported on "
    		"usb devices");
	return (-1);
}                           


static void
usb_close_linux(pcap_t* handle)
{
    /* handle fill be freed in pcap_close() 'common' code */
    close(handle->fd);
    free(handle->buffer);
}


static int 
usb_stats_linux(pcap_t *handle, struct pcap_stat *stats)
{
	int dummy, ret;
	char string[USB_LINE_LEN];
	snprintf(string, USB_LINE_LEN, USB_DIR"/%ds", handle->md.ifindex);
	
	int fd = open(string, O_RDONLY, 0);
	if (fd < 0)
	{
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
		"Can't open usb stats file %s: %s", string, strerror(errno));
		return -1;
	}
	
	/* read stats line */
	do {
		ret = read(fd, string, USB_LINE_LEN-1);
	} while ((ret == -1) && (errno == EINTR));
	close(fd);
	
	if (ret < 0)
	{
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			"Can't read stats from fd %d ", fd);
		return -1;
	}
	string[ret] = 0;
	
	/* extract info on dropped urbs */
	ret = sscanf(string, "nreaders %d text_lost %d", &dummy, &stats->ps_drop);
	if (ret != 2)
	{
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
		"Can't parse stat line '%s' expected 2 token got %d", string, ret);
		return -1;
	}
	
	stats->ps_recv = handle->md.packets_read;
	stats->ps_ifdrop = 0;
	return 0;
}

static int 
usb_setfilter_linux(pcap_t *p, struct bpf_program *fp)
{
    return 0;
}


static int 
usb_setdirection_linux(pcap_t *p, pcap_direction_t d)
{
    p->direction = d;
    return 0;
}
