/*
 * Copyright (c) 2017 Pure Storage, Inc.
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

#include <config.h>

#include "pcap-int.h"
#include "pcap-rdmasniff.h"

#include <infiniband/verbs.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h> /* for INT_MAX */
#include <sys/time.h>

#if !defined(IBV_FLOW_ATTR_SNIFFER)
#define IBV_FLOW_ATTR_SNIFFER	3
#endif

static const unsigned RDMASNIFF_NUM_RECEIVES = 128;
/*
 * This is used as a snapshot size, and the snapshot size is stored in
 * an int, so we make this an int.
 */
static const int RDMASNIFF_RECEIVE_SIZE = 10000;

struct pcap_rdmasniff {
	struct ibv_context *		context;
	struct ibv_comp_channel *	channel;
	struct ibv_pd *			pd;
	struct ibv_cq *			cq;
	struct ibv_qp *			qp;
	struct ibv_flow *               flow;
	struct ibv_mr *			mr;
	u_char *			oneshot_buffer;
	int                             cq_event;
	u_int                           packets_recv;
};

static int
rdmasniff_stats(pcap_t *handle, struct pcap_stat *stat)
{
	struct pcap_rdmasniff *priv = handle->priv;

	stat->ps_recv = priv->packets_recv;
	stat->ps_drop = 0;
	stat->ps_ifdrop = 0;

	return 0;
}

static void
rdmasniff_free_resources(struct pcap_rdmasniff *priv)
{
	if (priv->flow) {
		ibv_destroy_flow(priv->flow);
		priv->flow = NULL;
	}

	if (priv->qp) {
		ibv_destroy_qp(priv->qp);
		priv->qp = NULL;
	}

	if (priv->cq) {
		ibv_destroy_cq(priv->cq);
		priv->cq = NULL;
	}

	if (priv->mr) {
		ibv_dereg_mr(priv->mr);
		priv->mr = NULL;
	}

	if (priv->pd) {
		ibv_dealloc_pd(priv->pd);
		priv->pd = NULL;
	}

	if (priv->channel) {
		ibv_destroy_comp_channel(priv->channel);
		priv->channel = NULL;
	}

	if (priv->context) {
		ibv_close_device(priv->context);
		priv->context = NULL;
	}

	if (priv->oneshot_buffer) {
		free(priv->oneshot_buffer);
		priv->oneshot_buffer = NULL;
	}
}

static void
rdmasniff_cleanup(pcap_t *handle)
{
	struct pcap_rdmasniff *priv = handle->priv;

	rdmasniff_free_resources(priv);
	pcapint_cleanup_live_common(handle);
}

static void
rdmasniff_post_recv(pcap_t *handle, uint64_t wr_id)
{
	struct pcap_rdmasniff *priv = handle->priv;
	struct ibv_sge sg_entry;
	struct ibv_recv_wr wr, *bad_wr;

	sg_entry.length = RDMASNIFF_RECEIVE_SIZE;
	sg_entry.addr = (uintptr_t) handle->buffer + RDMASNIFF_RECEIVE_SIZE * wr_id;
	sg_entry.lkey = priv->mr->lkey;

	wr.wr_id = wr_id;
	wr.num_sge = 1;
	wr.sg_list = &sg_entry;
	wr.next = NULL;

	ibv_post_recv(priv->qp, &wr, &bad_wr);
}

static int
rdmasniff_read(pcap_t *handle, int max_packets, pcap_handler callback, u_char *user)
{
	struct pcap_rdmasniff *priv = handle->priv;
	struct ibv_cq *ev_cq;
	void *ev_ctx;
	struct ibv_wc wc;
	struct pcap_pkthdr pkth;
	u_char *pktd;
	int count = 0;

	if (!priv->cq_event) {
		while (ibv_get_cq_event(priv->channel, &ev_cq, &ev_ctx) < 0) {
			if (errno != EINTR) {
				return PCAP_ERROR;
			}
			if (handle->break_loop) {
				handle->break_loop = 0;
				return PCAP_ERROR_BREAK;
			}
		}
		ibv_ack_cq_events(priv->cq, 1);
		ibv_req_notify_cq(priv->cq, 0);
		priv->cq_event = 1;
	}

	/*
	 * This can conceivably process more than INT_MAX packets,
	 * which would overflow the packet count, causing it either
	 * to look like a negative number, and thus cause us to
	 * return a value that looks like an error, or overflow
	 * back into positive territory, and thus cause us to
	 * return a too-low count.
	 *
	 * Therefore, if the packet count is unlimited, we clip
	 * it at INT_MAX; this routine is not expected to
	 * process packets indefinitely, so that's not an issue.
	 */
	if (PACKET_COUNT_IS_UNLIMITED(max_packets))
		max_packets = INT_MAX;

	while (count < max_packets) {
		if (ibv_poll_cq(priv->cq, 1, &wc) != 1) {
			priv->cq_event = 0;
			break;
		}

		if (wc.status != IBV_WC_SUCCESS) {
			fprintf(stderr, "failed WC wr_id %" PRIu64 " status %d/%s\n",
				wc.wr_id,
				wc.status, ibv_wc_status_str(wc.status));
			continue;
		}

		pkth.len = wc.byte_len;
		pkth.caplen = min(pkth.len, (u_int)handle->snapshot);
		gettimeofday(&pkth.ts, NULL);

		pktd = handle->buffer + wc.wr_id * RDMASNIFF_RECEIVE_SIZE;

		if (handle->fcode.bf_insns == NULL ||
		    pcapint_filter(handle->fcode.bf_insns, pktd, pkth.len, pkth.caplen)) {
			callback(user, &pkth, pktd);
			++priv->packets_recv;
			++count;
		}

		rdmasniff_post_recv(handle, wc.wr_id);

		if (handle->break_loop) {
			handle->break_loop = 0;
			return PCAP_ERROR_BREAK;
		}
	}

	return count;
}

static void
rdmasniff_oneshot(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	struct oneshot_userdata *sp = (struct oneshot_userdata *) user;
	pcap_t *handle = sp->pd;
	struct pcap_rdmasniff *priv = handle->priv;

	*sp->hdr = *h;
	memcpy(priv->oneshot_buffer, bytes, h->caplen);
	*sp->pkt = priv->oneshot_buffer;
}

static struct ibv_device *
rdma_find_device_in_list(struct ibv_device **dev_list, int numdev,
    const char *device, const char **portp)
{
	const char *port;
	size_t namelen;

	/*
	 * The syntax of a name on which to capture is
	 * device[:port].
	 *
	 * Is there a port number following the device name?
	 */
	port = strchr(device, ':');
	if (port != NULL) {
		/*
		 * Yes. Get the length of the device name preceding
		 * the colon.
		 */
		namelen = port - device;

		/* Return a pointer to the port number after the colon. */
		if (portp != NULL)
			*portp = port + 1;
	} else {
		/* No. Get the length of the device name. */
		namelen = strlen(device);

		/* No port number. */
		if (portp != NULL)
			*portp = NULL;
	}

	for (int i = 0; i < numdev; ++i) {
		if (strlen(dev_list[i]->name) == namelen &&
		    strncmp(device, dev_list[i]->name, namelen) == 0) {
			/* Found the device in the list. */
			return dev_list[i];
		}
	}

	/* Didn't find it. */
	return NULL;
}

static int
rdmasniff_activate(pcap_t *handle)
{
	struct pcap_rdmasniff *priv = handle->priv;
	int ret;
	struct ibv_device **dev_list;
	int numdev;
	const char *port;
	unsigned long port_num;
	struct ibv_device *rdma_device;
	struct ibv_qp_init_attr qp_init_attr;
	struct ibv_qp_attr qp_attr;
	struct ibv_flow_attr flow_attr;
	struct ibv_port_attr port_attr;
	int errcode;

	dev_list = ibv_get_device_list(&numdev);
	if (!dev_list) {
		if (errno == EPERM) {
			/*
			 * This is not expected to occur, as enumerating
			 * devices shouldn't require special privileges.
			 */
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
				 "ibv_get_device_list() - root privileges may be required");
			ret = PCAP_ERROR_PERM_DENIED;
		} else if (errno == ENOSYS) {
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
				 "No kernel support for RDMA");
			ret = PCAP_ERROR_CAPTURE_NOTSUP;
		} else {
			pcapint_fmt_errmsg_for_errno(handle->errbuf,
						     PCAP_ERRBUF_SIZE, errno,
						     "ibv_get_device_list() failed");
			ret = PCAP_ERROR;
		}
		goto error;
	}
	if (!numdev) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			 "No RDMA devices found");
		ret = PCAP_ERROR_NO_SUCH_DEVICE;
		goto error;
	}

	rdma_device = rdma_find_device_in_list(dev_list, numdev,
	    handle->opt.device, &port);
	if (rdma_device == NULL) {
		/* Device not found in the list. */
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			      "Attempt to open %s failed - not a known RDMA device",
			      handle->opt.device);
		ret = PCAP_ERROR_NO_SUCH_DEVICE;
		goto error;
	}

	/*
	 * Do we have a port number?
	 *
	 * We treat either a missing port number (no colon in the name)
	 * or an empty port number (the colon has nothing after it) as
	 * referring to port 1, as that's what the previous code did.
	 *
	 * XXX - should an empty port number be treated as an error?
	 */
	if (port != NULL && *port != '\0') {
		char *endp;

		port_num = strtoul(port, &endp, 10);
		if ((port_num == 0 && endp == port) ||
		    *endp != '\0') {
			/* The port number isn't valid. */
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
				 "\"%s\" isn't a valid port number",
				 port);
			ret = PCAP_ERROR_NO_SUCH_DEVICE;
			goto error;
		}

		/*
		 * XXX - is there a port 0? The old code treated a
		 * return value of 0 as meaning "use port 1".
		 */
		if (port_num == 0)
			port_num = 1;
	} else {
		port_num = 1;
	}

	priv->context = ibv_open_device(rdma_device);
	if (!priv->context) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			 "ibv_open_device() failed");
		ret = PCAP_ERROR;
		goto error;
	}

	/*
	 * According to the ibv_get_device_list() documentation, now
	 * that we've opened the device, we can free the device list
	 * from which we got the struct ibv_device * for the device.
	 */
	ibv_free_device_list(dev_list);
	dev_list = NULL;

	errcode = ibv_query_port(priv->context, port_num, &port_attr);
	if (errcode != 0) {
		if (errcode == EINVAL) {
			/*
			 * According to RDMAmojo's ibv_query_port() page:
			 *
			 *    https://www.rdmamojo.com/2012/07/21/ibv_query_port/
			 *
			 * EINVAL means the port number is invalid, i.e.
			 * there's no such device "dev_name:port_num".
			 */
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
				 "Port number %lu is not valid", port_num);
			ret = PCAP_ERROR_NO_SUCH_DEVICE;
		} else {
			pcapint_fmt_errmsg_for_errno(handle->errbuf,
						     PCAP_ERRBUF_SIZE, errcode,
						     "Failed to get information for port %lu",
						     port_num);
			ret = PCAP_ERROR;
		}
		goto error;
	}
	switch (port_attr.link_layer) {

	case IBV_LINK_LAYER_INFINIBAND:
		handle->linktype = DLT_INFINIBAND;
		break;

	case IBV_LINK_LAYER_UNSPECIFIED:
		/*
		 * The RDMAmojo page
		 *
		 *    https://www.rdmamojo.com/2012/07/21/ibv_query_port/
		 *
		 * says this is a "legacy value, used to indicate that
		 * the link layer protocol is InfiniBand".
		 */
		handle->linktype = DLT_INFINIBAND;
		break;

	case IBV_LINK_LAYER_ETHERNET:
		handle->linktype = DLT_EN10MB;
		break;

	default:
		/* XXX - what should we do here? */
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			 "Unknown link layer type %u", port_attr.link_layer);
		ret = PCAP_ERROR;
		goto error;
	}

	priv->pd = ibv_alloc_pd(priv->context);
	if (!priv->pd) {
		pcapint_fmt_errmsg_for_errno(handle->errbuf,
					     PCAP_ERRBUF_SIZE, errno,
					     "Failed to alloc PD");
		ret = PCAP_ERROR;
		goto error;
	}

	priv->channel = ibv_create_comp_channel(priv->context);
	if (!priv->channel) {
		pcapint_fmt_errmsg_for_errno(handle->errbuf,
					     PCAP_ERRBUF_SIZE, errno,
					     "Failed to create comp channel");
		ret = PCAP_ERROR;
		goto error;
	}

	priv->cq = ibv_create_cq(priv->context, RDMASNIFF_NUM_RECEIVES,
				 NULL, priv->channel, 0);
	if (!priv->cq) {
		pcapint_fmt_errmsg_for_errno(handle->errbuf,
					     PCAP_ERRBUF_SIZE, errno,
					     "Failed to create CQ");
		ret = PCAP_ERROR;
		goto error;
	}

	ibv_req_notify_cq(priv->cq, 0);

	memset(&qp_init_attr, 0, sizeof qp_init_attr);
	qp_init_attr.send_cq = qp_init_attr.recv_cq = priv->cq;
	qp_init_attr.cap.max_recv_wr = RDMASNIFF_NUM_RECEIVES;
	qp_init_attr.cap.max_recv_sge = 1;
	qp_init_attr.qp_type = IBV_QPT_RAW_PACKET;
	priv->qp = ibv_create_qp(priv->pd, &qp_init_attr);
	if (!priv->qp) {
		if (errno == EPERM) {
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
#ifdef __linux__
				 "Failed to create QP - CAP_NET_RAW may be required");
#else
				 /* Root permission required? Something else? */
				 "Faile to create QP");
#endif
			ret = PCAP_ERROR_PERM_DENIED;
		} else {
			pcapint_fmt_errmsg_for_errno(handle->errbuf,
						     PCAP_ERRBUF_SIZE, errno,
						     "Failed to create QP");
			ret = PCAP_ERROR;
		}
		goto error;
	}

	memset(&qp_attr, 0, sizeof qp_attr);
	qp_attr.qp_state = IBV_QPS_INIT;
	qp_attr.port_num = port_num;
	errcode = ibv_modify_qp(priv->qp, &qp_attr, IBV_QP_STATE | IBV_QP_PORT);
	if (errcode != 0) {
		pcapint_fmt_errmsg_for_errno(handle->errbuf,
					     PCAP_ERRBUF_SIZE, errcode,
					     "Failed to modify QP to INIT");
		ret = PCAP_ERROR;
		goto error;
	}

	memset(&qp_attr, 0, sizeof qp_attr);
	qp_attr.qp_state = IBV_QPS_RTR;
	errcode = ibv_modify_qp(priv->qp, &qp_attr, IBV_QP_STATE);
	if (errcode != 0) {
		pcapint_fmt_errmsg_for_errno(handle->errbuf,
					     PCAP_ERRBUF_SIZE, errcode,
					     "Failed to modify QP to RTR");
		ret = PCAP_ERROR;
		goto error;
	}

	memset(&flow_attr, 0, sizeof flow_attr);
	flow_attr.type = IBV_FLOW_ATTR_SNIFFER;
	flow_attr.size = sizeof flow_attr;
	flow_attr.port = port_num;
	priv->flow = ibv_create_flow(priv->qp, &flow_attr);
	if (!priv->flow) {
		pcapint_fmt_errmsg_for_errno(handle->errbuf,
					     PCAP_ERRBUF_SIZE, errno,
					     "Failed to create flow");
		ret = PCAP_ERROR;
		goto error;
	}

	handle->bufsize = RDMASNIFF_NUM_RECEIVES * RDMASNIFF_RECEIVE_SIZE;
	handle->buffer = malloc(handle->bufsize);
	if (!handle->buffer) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			      "Failed to allocate receive buffer");
		ret = PCAP_ERROR;
		goto error;
	}

	priv->oneshot_buffer = malloc(RDMASNIFF_RECEIVE_SIZE);
	if (!priv->oneshot_buffer) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			      "Failed to allocate oneshot buffer");
		ret = PCAP_ERROR;
		goto error;
	}

	priv->mr = ibv_reg_mr(priv->pd, handle->buffer, handle->bufsize, IBV_ACCESS_LOCAL_WRITE);
	if (!priv->mr) {
		pcapint_fmt_errmsg_for_errno(handle->errbuf,
					     PCAP_ERRBUF_SIZE, errno,
					     "Failed to register MR");
		ret = PCAP_ERROR;
		goto error;
	}

	for (unsigned i = 0; i < RDMASNIFF_NUM_RECEIVES; ++i) {
		rdmasniff_post_recv(handle, i);
	}

	if (handle->snapshot <= 0 || handle->snapshot > RDMASNIFF_RECEIVE_SIZE)
		handle->snapshot = RDMASNIFF_RECEIVE_SIZE;

	handle->offset = 0;
	handle->read_op = rdmasniff_read;
	handle->stats_op = rdmasniff_stats;
	handle->cleanup_op = rdmasniff_cleanup;
	handle->setfilter_op = pcapint_install_bpf_program;
	handle->setdirection_op = NULL;
	handle->set_datalink_op = NULL;
	handle->getnonblock_op = pcapint_getnonblock_fd;
	handle->setnonblock_op = pcapint_setnonblock_fd;
	handle->oneshot_callback = rdmasniff_oneshot;
	handle->selectable_fd = priv->channel->fd;

	return 0;

error:
	if (dev_list != NULL)
		ibv_free_device_list(dev_list);
	rdmasniff_free_resources(priv);
	return ret;
}

pcap_t *
rdmasniff_create(const char *device, char *ebuf, int *is_ours)
{
	struct ibv_device **dev_list;
	int numdev;
	pcap_t *p = NULL;

	*is_ours = 0;

	dev_list = ibv_get_device_list(&numdev);
	if (!dev_list) {
		pcapint_fmt_errmsg_for_errno(ebuf,
					     PCAP_ERRBUF_SIZE, errno,
					     "ibv_get_device_list() failed");
		return NULL;
	}
	if (!numdev) {
		ibv_free_device_list(dev_list);
		return NULL;
	}

	/*
	 * Device names are defined by the driver, not by the libpcap
	 * module, so, to determine if the device name refers to an
	 * RDMA-capable device, we have to enumerate the devices
	 * and see if the device name, with the port number stripped
	 * off, matches one of them.
	 */
	if (rdma_find_device_in_list(dev_list, numdev, device, NULL) != NULL) {
		/*
		 * We found the device.
		 */
		*is_ours = 1;

		/*
		 * Allocate the pcap_t.
		 */
		p = PCAP_CREATE_COMMON(ebuf, struct pcap_rdmasniff);
		if (p) {
			/*
			 * We do *not* save the struct ibv_device *
			 * for the device that we found, as we will
			 * be freeing the array of structures, which
			 * means that the struct ibv_device * will
			 * not be usable - see the documentation for
			 * ibv_get_device_list().
			 *
			 * We do not save the device list, as that
			 * means that we can't free it up on a
			 * failed activate. Instead, we will redo the
			 * ibv_get_device_list() and the search in the
			 * activate routine.
			 */
			p->activate_op = rdmasniff_activate;
		}
	}

	/*
	 * Free up the device list.
	 */
	ibv_free_device_list(dev_list);
	return p;
}

int
rdmasniff_findalldevs(pcap_if_list_t *devlistp, char *err_str)
{
	struct ibv_device **dev_list;
	int numdev;
	int i;
	int ret = 0;

	dev_list = ibv_get_device_list(&numdev);
	if (!dev_list) {
		if (errno == ENOSYS) {
			/*
			 * No kernel support for RDMA, so no RDMA
			 * devices, so nothing more for us to do.
			 */
			return 0;
		}
		pcapint_fmt_errmsg_for_errno(err_str,
					     PCAP_ERRBUF_SIZE, errno,
					     "ibv_get_device_list() failed");
		return PCAP_ERROR;
	}

	for (i = 0; i < numdev; ++i) {
		/*
		 * XXX - do the notions of "up", "running", or
		 * "connected" apply here?
		 */
		if (!pcapint_add_dev(devlistp, dev_list[i]->name, 0, "RDMA sniffer", err_str)) {
			ret = PCAP_ERROR;
			break;
		}
	}

	ibv_free_device_list(dev_list);
	return ret;
}
