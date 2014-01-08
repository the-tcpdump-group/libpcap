/*
 * Copyright (c) 2013 Jakub Zawadzki
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
 * 3. The name of the author may not be used to endorse or promote 
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
 */

/* Based on util/dvbtraffic/dvbtraffic.c @ 791:7263134fc0dc from dvb-apps under public domain
 * http://www.linuxtv.org/hg/dvb-apps/raw-file/7263134fc0dc/util/dvbtraffic/dvbtraffic.c */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef NEED_STRERROR_H
#include "strerror.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <dirent.h>

#include <linux/dvb/dmx.h>

#include "pcap-int.h"
#include "pcap-dvb.h"

struct pcap_dvb {
	int dvr_fd;
	int demux_fd;

	u_int	packets_read;	/* count of packets read */
};

static int
dvb_read(pcap_t *handle, int max_packets, pcap_handler callback, u_char *user)
{
	struct pcap_dvb *handlep = handle->priv;

	struct pcap_pkthdr pkth;
	unsigned char buf[188];
	ssize_t len;

	int count = 0;

	/* ignore interrupt system call error */
	do {
		len = read(handlep->dvr_fd, buf, sizeof(buf));
		if (handle->break_loop) {
			handle->break_loop = 0;
			return -2;
		}
	} while ((len == -1) && (errno == EINTR));

	if (len <= 0) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "read error (%s)", pcap_strerror(errno));
		return -1;
	}

	if (len != 188) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "only read %zd bytes", len);
		return -1;
	}

	if (buf[0] != 0x47) {
		/* TODO: resync */
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "first byte not SYNC (%.2x)", buf[0]);
		return -1;
	}

	pkth.caplen = pkth.len = len;

	gettimeofday(&pkth.ts, NULL);
	if (handle->fcode.bf_insns == NULL ||
	    bpf_filter(handle->fcode.bf_insns, (u_char *) buf, pkth.len, pkth.caplen))
	{
		handlep->packets_read++;
		callback(user, &pkth, (u_char *)buf);
		count++;
	}

	return count;
}

static int
dvb_write(pcap_t *handle, const void *buf, size_t size)
{
	snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "inject not supported on dvb devices");
	return -1;
}

static int
dvb_stats(pcap_t *handle, struct pcap_stat *stats)
{
	struct pcap_dvb *handlep = handle->priv;

	stats->ps_recv = handlep->packets_read;
	stats->ps_drop = 0;
	stats->ps_ifdrop = 0;
	return 0;
}

static int
dvb_dev_path(const char *dev, char demux_path[128], char dvr_path[128])
{
	int adapter, demux;
	int ret;

	if (strncmp(dev, "dvb", 3))
		return 0;

	dev += 3;

	if (dev[0] == ':') {
		dev++;
		ret = sscanf(dev, "%u,%u", &adapter, &demux);

		switch (ret) {
			case 2:
				/* OK, got adapter & demuxer */
				break;
			case 1:
				/* got adapter, demux default */
				demux = 0;
				break;

			default:
				/* XXX, device names? */
				return 0;
		}
	} else if (dev[0] == '\0') {
		/* default */
		adapter = demux = 0;

	} else
		return 0;

	snprintf(demux_path, 128, "/dev/dvb/adapter%d/demux%d", adapter, demux);
	snprintf(dvr_path, 128, "/dev/dvb/adapter%d/dvr%d", adapter, demux);

	return 1;
}

static int
dvb_get_int(char *x, int *p)
{
	if (*x == '\0')
		return 0;

	*p = (int) strtol(x, &x, 10);

	if (*x == '\0')
		return 1;

	return 0;
}

static void
dvb_cleanup(pcap_t *handle)
{
	struct pcap_dvb *handlep = handle->priv;

	if (handlep->dvr_fd) {
		close(handlep->dvr_fd);
		handlep->dvr_fd = -1;
	}

	if (handlep->demux_fd) {
		close(handlep->demux_fd);
		handlep->demux_fd = -1;
	}

	pcap_cleanup_live_common(handle);
}

static int
dvb_activate(pcap_t *handle)
{
	struct pcap_dvb *handlep = handle->priv;
	const char *dev = handle->opt.source;

	char demux_devname[128], dvr_devname[128];
	struct dmx_pes_filter_params flt;

	int fd;

	if (!dvb_dev_path(dev, demux_devname, dvr_devname)) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "Can't get adapter/demuxer from: %s", dev);
		return PCAP_ERROR;
	}

	handlep->demux_fd = handlep->dvr_fd = -1;

	/* Initialize some components of the pcap structure. */
	handle->bufsize = 0;
	handle->offset = 0;
	handle->linktype = DLT_MPEG_2_TS;
	handle->read_op = dvb_read;
	handle->inject_op = dvb_write;
	handle->setfilter_op = install_bpf_program; /* XXX, later add support for PID filtering */
	handle->setdirection_op = NULL;
	handle->set_datalink_op = NULL;      /* can't change data link type */
	handle->getnonblock_op = pcap_getnonblock_fd;
	handle->setnonblock_op = pcap_setnonblock_fd;
	handle->stats_op = dvb_stats;
	handle->cleanup_op = dvb_cleanup;

	handle->selectable_fd = handle->fd = -1;

	if (handle->opt.rfmon) {
		/*
		 * Monitor mode doesn't apply to dvb capturing
		 */
		pcap_cleanup_live_common(handle);
		return PCAP_ERROR_RFMON_NOTSUP;
	}

	handlep->dvr_fd = fd = open(dvr_devname, O_RDONLY);
	if (fd == -1) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "Could not open dvb device: '%s' (%s)", dvr_devname, pcap_strerror(errno));
		pcap_cleanup_live_common(handle);
		return PCAP_ERROR;
	}

	if (handle->opt.buffer_size != 0)
		ioctl(fd, DMX_SET_BUFFER_SIZE, handle->opt.buffer_size);

	handlep->demux_fd = fd = open(demux_devname, O_RDWR);
	if (fd == -1) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "Could not open demux device: '%s' (%s)", demux_devname, pcap_strerror(errno));
		dvb_cleanup(handle);
		return PCAP_ERROR;
	}


	/* XXX, for now process all PIDs */
	flt.pid = 0x2000;
	flt.input = DMX_IN_FRONTEND;
	flt.output = DMX_OUT_TS_TAP;
	flt.pes_type = DMX_PES_OTHER;
	flt.flags = 0;

	if (ioctl(fd, DMX_SET_PES_FILTER, &flt) == -1) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "Failed to set PID filter: %s", pcap_strerror(errno));
		dvb_cleanup(handle);
		return PCAP_ERROR;
	}

	if (ioctl(fd, DMX_START, 0) == -1) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "Failed to start demuxer: %s", pcap_strerror(errno));
		dvb_cleanup(handle);
		return PCAP_ERROR;
	}

	handle->selectable_fd = handlep->dvr_fd;

	return 0;
}

pcap_t *
dvb_create(const char *device, char *ebuf, int *is_ours)
{
	pcap_t *p;

	if (strcmp(device, "dvb") && 
		strncmp(device, "dvb:", 4))
	{
		*is_ours = 0;
		return NULL;
	}

	*is_ours = 1;
	p = pcap_create_common(device, ebuf, sizeof(struct pcap_dvb));
	if (p == NULL)
		return NULL;

	p->activate_op = dvb_activate;
	return p;
}

int 
dvb_findalldevs(pcap_if_t **alldevsp, char *err_str)
{
	pcap_if_t *found_dev = *alldevsp;
	DIR *dvb_dir, *adapter_dir;
	struct dirent *dvb_ent, *adapter_ent;

	/* Scan /dev/dvb directory to get all adapters and demuxers */

	dvb_dir = opendir("/dev/dvb");
	if (!dvb_dir)
		return 0;

	while ((dvb_ent = readdir(dvb_dir))) {
		static const char adapter_p[] = { 'a', 'd', 'a', 'p', 't', 'e', 'r' };
		static const char demux_p[] = { 'd', 'e', 'm', 'u', 'x' };

		char path[64];
		int adapter, demux;

		/* Does it starts with "adapter" ? */
		if (strncmp(dvb_ent->d_name, adapter_p, sizeof(adapter_p)))
			continue;

		if (!dvb_get_int(dvb_ent->d_name + sizeof(adapter_p), &adapter))
			continue;
		
		snprintf(path, sizeof(path), "/dev/dvb/adapter%d/", adapter);

		adapter_dir = opendir(path);
		if (!adapter_dir)
			continue;

		while ((adapter_ent = readdir(adapter_dir))) {
			char pcap_dev[64];
			char pcap_descr[128];

			/* Does it starts with "demux" ? */
			if (strncmp(adapter_ent->d_name, demux_p, sizeof(demux_p)))
				continue;

			if (!dvb_get_int(adapter_ent->d_name + sizeof(demux_p), &demux))
				continue;

			/* XXX check also if dvr exists? */

			snprintf(pcap_dev, sizeof(pcap_dev), "dvb:%d,%d", adapter, demux);
			snprintf(pcap_descr, sizeof(pcap_descr), "DVB adapter %d, demux %d", adapter, demux);

			if (pcap_add_if(&found_dev, pcap_dev, 0, pcap_descr, err_str) < 0)
				return -1;
		}

		closedir(adapter_dir);
	}

	closedir(dvb_dir);
	return 0;
}
