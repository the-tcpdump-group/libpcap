/*
 * Copyright (c) 2013 Michal Labedzki for Tieto Corporation
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
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pcap-int.h"

#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>

int
linux_kmsg_findalldevs(pcap_if_t **alldevsp, char *err_str)
{
    pcap_if_t  *found_dev = *alldevsp;
    int         ret = 0;
    char        dev_name[20];
    char        dev_descr[20];

    snprintf(dev_name, 20, "kmsg");
    snprintf(dev_descr, 20, "Kernel messages");

    if (pcap_add_if(&found_dev, dev_name, 0,
               dev_descr, err_str) < 0)
    {
        ret = -1;
    }

    return ret;
}

static time_t get_boot_time()
{
    struct sysinfo info;
    struct timeval tv;

    if (sysinfo(&info) != 0)
        return 0;

    if (gettimeofday(&tv, NULL) != 0)
        return 0;

    return tv.tv_sec - info.uptime;
}

static int
linux_kmsg_read(pcap_t *handle, int max_packets, pcap_handler callback, u_char *user)
{
    struct pcap_pkthdr pkth;
    int result;
    int i = 0;
    int i_char;
    int start_i;
    int start_ii;
    time_t ts;
    uint64_t multiplier = 1;

    result = read(handle->fd, handle->buffer, handle->bufsize);
    if (result < 0) return 0;

    pkth.caplen = result;
    pkth.len = result;

    /* skip priority */
    while (i + 1 <= handle->bufsize && handle->buffer[i] != ',')
    {
        i += 1;
    }
    i += 1;

    /* skip sequence number */
    while (i + 1 <= handle->bufsize && handle->buffer[i] != ',')
    {
        i += 1;
    }
    i += 1;

    /* get timestamp */
    start_i = i;
    while (i + 1 <= handle->bufsize && handle->buffer[i] != ',')
    {
        i += 1;
    }

    /* get timestamp - microseconds */
    pkth.ts.tv_usec = 0;
    multiplier = 1;
    for (i_char = i - 1; i_char >= start_i && i_char >  i - 1 - 6  ; i_char -= 1)
    {

        pkth.ts.tv_usec += (handle->buffer[i_char] - 0x30) * multiplier;
        multiplier *= 10;
    }

    /* get timestamp - seconds */
    pkth.ts.tv_sec = 0;
    multiplier  = 1;
    for (; i_char >= start_i ; i_char -= 1)
    {
        pkth.ts.tv_sec += (handle->buffer[i_char] - 0x30) * multiplier;
        multiplier *= 10;
    }

    /* try to get real system datetime */
    ts = get_boot_time();
    pkth.ts.tv_sec += ts;

    if (handle->fcode.bf_insns == NULL ||
        bpf_filter(handle->fcode.bf_insns, &handle->buffer[handle->offset],
        pkth.len, pkth.caplen))
    {
        callback(user, &pkth, &handle->buffer[handle->offset]);
        return 1;
    }

    return 0;
}

static int
linux_kmsg_inject(pcap_t *handle, const void *buf, size_t size)
{
    snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "inject not yet supported on "
            "kmsg devices");
    return -1;
}

static int
linux_kmsg_setdirection(pcap_t *p, pcap_direction_t d)
{
    p->direction = d;
    return 0;
}

static int
linux_kmsg_stats(pcap_t *handle, struct pcap_stat *stats)
{
    stats->ps_recv = 0;
    stats->ps_drop = 0;
    stats->ps_ifdrop = 0;

    return 0;
}

static int
linux_kmsg_activate(pcap_t* handle)
{
    int err = PCAP_ERROR;

    if (handle->opt.rfmon) {
        /* monitor mode doesn't apply to kmsg */
        return PCAP_ERROR_RFMON_NOTSUP;
    }

    /* initialize some components of the pcap structure */
    handle->bufsize = 65536;
    handle->offset = 0;
    handle->linktype = DLT_KMSG_LINUX;

    handle->read_op = linux_kmsg_read;
    handle->inject_op = linux_kmsg_inject;
    handle->setfilter_op = install_bpf_program; /* no kernel filtering */
    handle->setdirection_op = linux_kmsg_setdirection;
    handle->set_datalink_op = NULL; /* can't change data link type */
    handle->getnonblock_op = pcap_getnonblock_fd;
    handle->setnonblock_op = pcap_setnonblock_fd;
    handle->stats_op = linux_kmsg_stats;
    handle->md.ifindex = 0;

    handle->buffer = malloc(handle->bufsize);
    if (!handle->buffer) {
        snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "Can't allocate dump buffer: %s",
            pcap_strerror(errno));
        goto close_fail;
    }

    handle->fd = open("/dev/kmsg", O_RDONLY);
    if (handle->fd == -1) {
        snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "Can't open /dev/kmsg: %s",
            pcap_strerror(errno));
        goto close_fail;
    }

    handle->selectable_fd = handle->fd;

    return 0;

close_fail:
    pcap_cleanup_live_common(handle);
    return err;
}

pcap_t *
linux_kmsg_create(const char *device, char *ebuf, int *is_ours)
{
    pcap_t *p;
    const char *cp;

    cp = strrchr(device, '/');
    if (cp == NULL)
        cp = device;

    if (strncmp(cp, "kmsg", 4) != 0) {
        *is_ours = 0;
        return NULL;
    }

    *is_ours = 1;
    p = pcap_create_common(device, ebuf);
    if (p == NULL)
        return NULL;

    p->activate_op = linux_kmsg_activate;

    return p;
}
