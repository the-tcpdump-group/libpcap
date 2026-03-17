/*
 * Copyright (c) 2026 Vincent Jardin, Free Mobile, Iliad
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS''AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * pcap-dpdk-pdump: libpcap capture module using DPDK pdump framework.
 *
 * This is different from pcap-dpdk.c which acts as a standalone DPDK
 * primary process: it calls rte_eal_init(), takes ownership of the NIC
 * (rte_eth_dev_configure, rte_eth_dev_start), and polls packets directly
 * with rte_eth_rx_burst(). That model cannot coexist with another DPDK
 * application that already owns the ports.
 *
 * This module instead runs as a DPDK secondary process and attaches to
 * an existing primary application (e.g. grout) via shared hugepages.
 * It uses the rte_pdump framework to mirror packets: the primary installs
 * lightweight RX/TX callbacks that copy packets into a shared rte_ring,
 * and this module drains the ring to deliver them to tcpdump. The primary
 * keeps full ownership of the NIC; the secondary never touches the port
 * configuration or queues.
 *
 * Device names use the "grout:" prefix (e.g. grout:0) to avoid conflicts
 * with the original "dpdk:" prefix from pcap-dpdk.c.
 *
 * Usage:
 *   tcpdump -i grout:0 -n
 *
 * The primary application must have been started with shared hugepages
 * (i.e. without --in-memory) and must have called rte_pdump_init().
 */

#include <config.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>
#include <sys/time.h>

#include <rte_config.h>
#include <rte_common.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_pdump.h>
#include <rte_ring.h>
#include <rte_version.h>

#include "diag-control.h"

#include "pcap-int.h"
#include "pcap-dpdk-pdump.h"

#define DPDK_PDUMP_PREFIX "grout:"
#define DPDK_PDUMP_PORTID_MAX 65535U
#define DPDK_PDUMP_DEV_NAME_MAX 32
#define DPDK_PDUMP_DEV_DESC_MAX 512
#define DPDK_PDUMP_DESC "grout pdump"
#define DPDK_PDUMP_MAC_ADDR_SIZE 32
#define DPDK_PDUMP_PCI_ADDR_SIZE 16
#define DPDK_PDUMP_DEF_MAC_ADDR "00:00:00:00:00:00"

#define DPDK_PDUMP_RING_SIZE 16384U
#define DPDK_PDUMP_NB_MBUFS 16383U
#define DPDK_PDUMP_MEMPOOL_CACHE 256
#define MAX_PKT_BURST 32
#define DPDK_PDUMP_DEF_MIN_SLEEP_MS 1

#ifdef RTE_ETHER_MAX_JUMBO_FRAME_LEN
#define DPDK_PDUMP_SNAPLEN RTE_ETHER_MAX_JUMBO_FRAME_LEN
#else
#define DPDK_PDUMP_SNAPLEN 9728
#endif

/* EAL init state: 0=not done, 1=success, <0=-rte_errno on failure */
static int is_dpdk_pre_inited;

/*
 * Default DPDK EAL arguments for the secondary process.
 * Can be overridden by setting the DPDK_CFG environment variable.
 *
 * --proc-type=secondary  Attach to an existing primary DPDK process
 *                        (e.g. grout) via shared hugepages instead of
 *                        initializing a new independent EAL instance.
 * -l0                    Use only lcore 0 for this secondary process.
 *                        A single lcore is enough since we only poll
 *                        an rte_ring, no datapath processing needed.
 * --no-telemetry         Disable the DPDK telemetry socket. Not needed
 *                        for packet capture and avoids conflicts with
 *                        the primary's telemetry endpoint.
 * --log-level=critical   Suppress non-fatal errors during secondary
 *                        attachment (e.g. mlx5 failing to probe ports
 *                        not owned by the primary process).
 */
static const char *dpdk_pdump_def_cfg = "--proc-type=secondary -l0 --no-telemetry --log-level=critical";

#ifdef HAVE_STRUCT_RTE_ETHER_ADDR
#define ETHER_ADDR_TYPE	struct rte_ether_addr
#else
#define ETHER_ADDR_TYPE	struct ether_addr
#endif

struct dpdk_ts_helper {
	struct timeval start_time;
	uint64_t start_cycles;
	uint64_t hz;
};

struct pcap_dpdk_pdump {
	uint16_t portid;
	struct rte_ring *ring;
	struct rte_mempool *mp;
	int nonblock;
	int pdump_enabled;
	uint64_t bpf_drop;
	struct timeval required_select_timeout;
	struct dpdk_ts_helper ts_helper;
	ETHER_ADDR_TYPE eth_addr;
	char mac_addr[DPDK_PDUMP_MAC_ADDR_SIZE];
	char pci_addr[DPDK_PDUMP_PCI_ADDR_SIZE];
	unsigned char pcap_tmp_buf[DPDK_PDUMP_SNAPLEN];
};

static void dpdk_pdump_fmt_errmsg_for_rte_errno(char *errbuf, size_t errbuflen,
    int errnum, const char *fmt, ...)
{
	va_list ap;
	size_t msglen;
	char *p;
	size_t remaining;

	va_start(ap, fmt);
	vsnprintf(errbuf, errbuflen, fmt, ap);
	va_end(ap);
	msglen = strlen(errbuf);

	if (msglen + 3 > errbuflen)
		return;
	p = errbuf + msglen;
	remaining = errbuflen - msglen;
	*p++ = ':';
	*p++ = ' ';
	*p = '\0';
	remaining -= 2;

	snprintf(p, remaining, "%s", rte_strerror(errnum));
}

static int dpdk_pdump_init_timer(struct pcap_dpdk_pdump *pd)
{
	gettimeofday(&pd->ts_helper.start_time, NULL);
	pd->ts_helper.start_cycles = rte_get_timer_cycles();
	pd->ts_helper.hz = rte_get_timer_hz();
	if (pd->ts_helper.hz == 0)
		return -1;
	return 0;
}

static inline void dpdk_pdump_calculate_timestamp(struct dpdk_ts_helper *helper,
    struct timeval *ts)
{
	uint64_t cycles;
	struct timeval cur_time;

	cycles = rte_get_timer_cycles() - helper->start_cycles;
	cur_time.tv_sec = (time_t)(cycles / helper->hz);
	cur_time.tv_usec = (suseconds_t)((cycles % helper->hz) * 1e6 / helper->hz);
	timeradd(&helper->start_time, &cur_time, ts);
}

static void dpdk_pdump_gather_data(unsigned char *data, uint32_t len,
    struct rte_mbuf *mbuf)
{
	uint32_t total_len = 0;

	while (mbuf && (total_len + mbuf->data_len) < len) {
		rte_memcpy(data + total_len, rte_pktmbuf_mtod(mbuf, void *),
		    mbuf->data_len);
		total_len += mbuf->data_len;
		mbuf = mbuf->next;
	}
}

static int dpdk_pdump_read_with_timeout(pcap_t *p, struct rte_mbuf **pkts,
    uint16_t burst_cnt)
{
	struct pcap_dpdk_pdump *pd = (struct pcap_dpdk_pdump *)(p->priv);
	int nb_rx = 0;
	int timeout_ms = p->opt.timeout;
	int sleep_ms = 0;

	if (pd->nonblock) {
		nb_rx = (int)rte_ring_dequeue_burst(pd->ring, (void **)pkts,
		    burst_cnt, NULL);
	} else {
		while (timeout_ms == 0 || sleep_ms < timeout_ms) {
			nb_rx = (int)rte_ring_dequeue_burst(pd->ring,
			    (void **)pkts, burst_cnt, NULL);
			if (nb_rx)
				break;
			if (p->break_loop)
				break;
			rte_delay_us_block(DPDK_PDUMP_DEF_MIN_SLEEP_MS * 1000);
			sleep_ms += DPDK_PDUMP_DEF_MIN_SLEEP_MS;
		}
	}
	return nb_rx;
}

/*
 * Build a VLAN-stripped copy of an ethernet frame for BPF filtering,
 * matching kernel AF_PACKET behavior. The kernel runs BPF on frames
 * with the 802.1Q tag removed, but delivers the original frame to
 * userspace so that tcpdump -e still shows VLAN information.
 *
 * Input:  [dst:6][src:6][0x8100][TCI:2][real_etype:2][payload...]
 * Output: [dst:6][src:6][real_etype:2][payload...]
 *
 * Returns the stripped length, or 0 if no VLAN tag was present.
 * The stripped frame is written to dst (must have room for len bytes).
 */
#define ETHER_ADDR_LEN 6
#define VLAN_TAG_LEN 4
#define ETHERTYPE_VLAN 0x8100

static uint32_t dpdk_pdump_strip_vlan_copy(const u_char *src, u_char *dst,
    uint32_t len)
{
	uint16_t ethertype;

	if (len < 2 * ETHER_ADDR_LEN + VLAN_TAG_LEN + 2)
		return 0;

	ethertype = (src[12] << 8) | src[13];
	if (ethertype != ETHERTYPE_VLAN)
		return 0;

	/* Copy MACs, skip 4-byte VLAN tag, copy rest. */
	memcpy(dst, src, 2 * ETHER_ADDR_LEN);
	memcpy(dst + 2 * ETHER_ADDR_LEN,
	    src + 2 * ETHER_ADDR_LEN + VLAN_TAG_LEN,
	    len - 2 * ETHER_ADDR_LEN - VLAN_TAG_LEN);
	return len - VLAN_TAG_LEN;
}

static int pcap_dpdk_pdump_dispatch(pcap_t *p, int max_cnt,
    pcap_handler cb, u_char *cb_arg)
{
	struct pcap_dpdk_pdump *pd = (struct pcap_dpdk_pdump *)(p->priv);
	int burst_cnt;
	int nb_rx;
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;
	struct pcap_pkthdr pcap_header;
	uint32_t pkt_len;
	uint32_t caplen;
	u_char *bp;
	int pkt_cnt = 0;
	u_char *large_buffer = NULL;
	/* Scratch buffer for VLAN-stripped frame used by BPF filter only. */
	u_char filter_buf[DPDK_PDUMP_SNAPLEN];

	if (PACKET_COUNT_IS_UNLIMITED(max_cnt))
		max_cnt = INT_MAX;

	burst_cnt = max_cnt < MAX_PKT_BURST ? max_cnt : MAX_PKT_BURST;

	while (pkt_cnt < max_cnt) {
		if (p->break_loop) {
			p->break_loop = 0;
			return PCAP_ERROR_BREAK;
		}

		nb_rx = dpdk_pdump_read_with_timeout(p, pkts_burst, burst_cnt);
		if (nb_rx == 0)
			break;

		pkt_cnt += nb_rx;
		for (int i = 0; i < nb_rx; i++) {
			m = pkts_burst[i];
			dpdk_pdump_calculate_timestamp(&pd->ts_helper,
			    &pcap_header.ts);
			pkt_len = rte_pktmbuf_pkt_len(m);
			caplen = pkt_len < (uint32_t)p->snapshot ?
			    pkt_len : (uint32_t)p->snapshot;
			rte_prefetch0(rte_pktmbuf_mtod(m, void *));

			bp = NULL;
			if (m->nb_segs == 1) {
				bp = rte_pktmbuf_mtod(m, u_char *);
			} else {
				if (pkt_len <= DPDK_PDUMP_SNAPLEN) {
					dpdk_pdump_gather_data(
					    pd->pcap_tmp_buf,
					    DPDK_PDUMP_SNAPLEN, m);
					bp = pd->pcap_tmp_buf;
				} else {
					large_buffer = (u_char *)malloc(
					    caplen);
					if (large_buffer != NULL) {
						dpdk_pdump_gather_data(
						    large_buffer, caplen, m);
						bp = large_buffer;
					}
				}
			}

			if (bp) {
				pcap_header.caplen = caplen;
				pcap_header.len = pkt_len;

				/*
				 * Match kernel AF_PACKET behavior: strip
				 * 802.1Q VLAN tag for BPF filtering only,
				 * but deliver the original frame (with
				 * VLAN tag) to the callback so tcpdump -e
				 * still shows VLAN information.
				 */
				u_char *filter_bp = bp;
				uint32_t filter_len = pkt_len;
				uint32_t filter_caplen = caplen;

				if (p->fcode.bf_insns != NULL &&
				    caplen <= DPDK_PDUMP_SNAPLEN) {
					uint32_t slen =
					    dpdk_pdump_strip_vlan_copy(
					    bp, filter_buf, caplen);
					if (slen > 0) {
						filter_bp = filter_buf;
						filter_len -= VLAN_TAG_LEN;
						filter_caplen = slen;
					}
				}

				if (p->fcode.bf_insns == NULL ||
				    pcapint_filter(p->fcode.bf_insns,
				    filter_bp, filter_len,
				    filter_caplen)) {
					cb(cb_arg, &pcap_header, bp);
				} else {
					pd->bpf_drop++;
				}
			}
			rte_pktmbuf_free(m);
			if (large_buffer) {
				free(large_buffer);
				large_buffer = NULL;
			}
		}
	}
	return pkt_cnt;
}

static int pcap_dpdk_pdump_inject(pcap_t *p, const void *buf _U_, int size _U_)
{
	pcapint_strlcpy(p->errbuf,
	    "dpdk pdump: packet injection not supported",
	    PCAP_ERRBUF_SIZE);
	return PCAP_ERROR;
}

static void pcap_dpdk_pdump_close(pcap_t *p)
{
	struct pcap_dpdk_pdump *pd = p->priv;

	if (pd == NULL)
		return;

	if (pd->pdump_enabled) {
		rte_pdump_disable(pd->portid, RTE_PDUMP_ALL_QUEUES,
		    RTE_PDUMP_FLAG_RXTX);
		pd->pdump_enabled = 0;
	}

	/* Drain remaining mbufs from the ring. */
	if (pd->ring) {
		struct rte_mbuf *pkts[MAX_PKT_BURST];
		int n;
		do {
			n = rte_ring_dequeue_burst(pd->ring, (void **)pkts,
			    MAX_PKT_BURST, NULL);
			for (int i = 0; i < n; i++)
				rte_pktmbuf_free(pkts[i]);
		} while (n > 0);
		rte_ring_free(pd->ring);
		pd->ring = NULL;
	}

	if (pd->mp) {
		rte_mempool_free(pd->mp);
		pd->mp = NULL;
	}

	pcapint_cleanup_live_common(p);
}

static int pcap_dpdk_pdump_stats(pcap_t *p, struct pcap_stat *ps)
{
	struct pcap_dpdk_pdump *pd = p->priv;
	struct rte_pdump_stats pdump_stats;
	int ret;

	if (ps == NULL)
		return 0;

	memset(ps, 0, sizeof(*ps));

	ret = rte_pdump_stats(pd->portid, &pdump_stats);
	if (ret == 0) {
		ps->ps_recv = (u_int)pdump_stats.accepted;
		ps->ps_drop = (u_int)(pdump_stats.nombuf +
		    pdump_stats.ringfull + pd->bpf_drop);
		ps->ps_ifdrop = (u_int)pdump_stats.filtered;
	}

	return 0;
}

static int pcap_dpdk_pdump_setnonblock(pcap_t *p, int nonblock)
{
	struct pcap_dpdk_pdump *pd = (struct pcap_dpdk_pdump *)(p->priv);
	pd->nonblock = nonblock;
	return 0;
}

static int pcap_dpdk_pdump_getnonblock(pcap_t *p)
{
	struct pcap_dpdk_pdump *pd = (struct pcap_dpdk_pdump *)(p->priv);
	return pd->nonblock;
}

static void eth_addr_str(ETHER_ADDR_TYPE *addrp, char *mac_str, int len)
{
	int offset = 0;

	if (addrp == NULL) {
		snprintf(mac_str, len - 1, DPDK_PDUMP_DEF_MAC_ADDR);
		return;
	}
	for (int i = 0; i < 6; i++) {
		if (offset >= len)
			return;
		if (i == 0) {
			snprintf(mac_str + offset, len - 1 - offset,
			    "%02X", addrp->addr_bytes[i]);
			offset += 2;
		} else {
			snprintf(mac_str + offset, len - 1 - offset,
			    ":%02X", addrp->addr_bytes[i]);
			offset += 3;
		}
	}
}

static uint16_t portid_by_device(const char *device)
{
	uint16_t ret = DPDK_PDUMP_PORTID_MAX;
	size_t len = strlen(device);
	size_t prefix_len = strlen(DPDK_PDUMP_PREFIX);
	unsigned long ret_ul;
	char *pEnd;

	if (len <= prefix_len ||
	    strncmp(device, DPDK_PDUMP_PREFIX, prefix_len))
		return ret;

	for (size_t i = prefix_len; device[i]; i++) {
		if (device[i] < '0' || device[i] > '9')
			return ret;
	}

	ret_ul = strtoul(&device[prefix_len], &pEnd, 10);
	if (pEnd == &device[prefix_len] || *pEnd != '\0')
		return ret;
	if (ret_ul >= DPDK_PDUMP_PORTID_MAX)
		return ret;

	ret = (uint16_t)ret_ul;
	return ret;
}

/*
 * Initialize DPDK EAL as a secondary process.
 * Returns: 1 on success, 0 if DPDK not available, PCAP_ERROR on failure.
 */
static int dpdk_pdump_pre_init(char *ebuf, int eaccess_not_fatal)
{
	char *dargv[64];
	int dargv_cnt = 0;
	char cfg_buf[1024];
	char *ptr_cfg;
	int ret;

	if (is_dpdk_pre_inited != 0) {
		if (is_dpdk_pre_inited < 0)
			goto error;
		return 1;
	}

	rte_log_set_global_level(RTE_LOG_ERR);

	ptr_cfg = getenv("DPDK_CFG");
	if (ptr_cfg == NULL)
		ptr_cfg = (char *)dpdk_pdump_def_cfg;

	snprintf(cfg_buf, sizeof(cfg_buf), "libpcap_dpdk_pdump %s", ptr_cfg);

	/* Parse cfg_buf into dargv. */
	memset(dargv, 0, sizeof(dargv));
	{
		int skip_space = 1;
		for (int i = 0; cfg_buf[i] && dargv_cnt < 63; i++) {
			if (skip_space && cfg_buf[i] != ' ') {
				skip_space = 0;
				dargv[dargv_cnt++] = cfg_buf + i;
			}
			if (!skip_space && cfg_buf[i] == ' ') {
				cfg_buf[i] = '\0';
				skip_space = 1;
			}
		}
		dargv[dargv_cnt] = NULL;
	}

	ret = rte_eal_init(dargv_cnt, dargv);
	if (ret == -1) {
		is_dpdk_pre_inited = -rte_errno;
		goto error;
	}

	/* Initialize pdump subsystem in secondary process so it can
	 * receive broadcast config from the primary after rte_pdump_enable(). */
	rte_pdump_init();

	is_dpdk_pre_inited = 1;
	return 1;

error:
	switch (-is_dpdk_pre_inited) {
	case EACCES:
		if (eaccess_not_fatal)
			return 0;
		snprintf(ebuf, PCAP_ERRBUF_SIZE,
		    "DPDK requires root permission");
		return PCAP_ERROR_PERM_DENIED;

	case EALREADY:
		is_dpdk_pre_inited = 1;
		return 1;

	case ENOTSUP:
		return 0;

	default:
		/*
		 * When enumerating devices, don't fail if the primary
		 * process is not running — just report no DPDK devices.
		 */
		if (eaccess_not_fatal)
			return 0;
		dpdk_pdump_fmt_errmsg_for_rte_errno(ebuf, PCAP_ERRBUF_SIZE,
		    -is_dpdk_pre_inited,
		    "dpdk pdump: EAL init failed");
		return PCAP_ERROR;
	}
}

static int pcap_dpdk_pdump_activate(pcap_t *p)
{
	struct pcap_dpdk_pdump *pd = p->priv;
	int ret = PCAP_ERROR;
	uint16_t portid = DPDK_PDUMP_PORTID_MAX;
	char ring_name[RTE_RING_NAMESIZE];
	char pool_name[RTE_MEMPOOL_NAMESIZE];

	do {
		char dpdk_pre_init_errbuf[PCAP_ERRBUF_SIZE];
		ret = dpdk_pdump_pre_init(dpdk_pre_init_errbuf, 0);
		if (ret < 0) {
DIAG_OFF_FORMAT_TRUNCATION
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "Can't open device %s: %s",
			    p->opt.device, dpdk_pre_init_errbuf);
DIAG_ON_FORMAT_TRUNCATION
			break;
		}
		if (ret == 0) {
DIAG_OFF_FORMAT_TRUNCATION
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "Can't open device %s: DPDK not available "
			    "(is the primary process running with shared "
			    "hugepages?)", p->opt.device);
DIAG_ON_FORMAT_TRUNCATION
			return PCAP_ERROR_NO_SUCH_DEVICE;
		}

		ret = dpdk_pdump_init_timer(pd);
		if (ret < 0) {
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "dpdk pdump: timer init failed for %s",
			    p->opt.device);
			ret = PCAP_ERROR;
			break;
		}

		portid = portid_by_device(p->opt.device);
		if (portid == DPDK_PDUMP_PORTID_MAX) {
DIAG_OFF_FORMAT_TRUNCATION
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "dpdk pdump: invalid device %s",
			    p->opt.device);
DIAG_ON_FORMAT_TRUNCATION
			ret = PCAP_ERROR_NO_SUCH_DEVICE;
			break;
		}

		if (!rte_eth_dev_is_valid_port(portid)) {
DIAG_OFF_FORMAT_TRUNCATION
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "dpdk pdump: port %u not found in primary",
			    portid);
DIAG_ON_FORMAT_TRUNCATION
			ret = PCAP_ERROR_NO_SUCH_DEVICE;
			break;
		}

		pd->portid = portid;

		if (p->snapshot <= 0 || p->snapshot > MAXIMUM_SNAPLEN)
			p->snapshot = MAXIMUM_SNAPLEN;

		/* Get MAC address from primary. */
		rte_eth_macaddr_get(portid, &pd->eth_addr);
		eth_addr_str(&pd->eth_addr, pd->mac_addr,
		    DPDK_PDUMP_MAC_ADDR_SIZE - 1);
		rte_eth_dev_get_name_by_port(portid, pd->pci_addr);

		/* Create ring for pdump packet copies. */
		snprintf(ring_name, sizeof(ring_name),
		    "pcap_pdump_r%u_%d", portid, getpid());
		pd->ring = rte_ring_create(ring_name, DPDK_PDUMP_RING_SIZE,
		    rte_socket_id(), 0);
		if (pd->ring == NULL) {
			dpdk_pdump_fmt_errmsg_for_rte_errno(p->errbuf,
			    PCAP_ERRBUF_SIZE, rte_errno,
			    "dpdk pdump: cannot create ring");
			ret = PCAP_ERROR;
			break;
		}

		/* Create mempool for pdump packet copies. */
		snprintf(pool_name, sizeof(pool_name),
		    "pcap_pdump_m%u_%d", portid, getpid());
		pd->mp = rte_pktmbuf_pool_create(pool_name,
		    DPDK_PDUMP_NB_MBUFS, DPDK_PDUMP_MEMPOOL_CACHE, 0,
		    RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
		if (pd->mp == NULL) {
			dpdk_pdump_fmt_errmsg_for_rte_errno(p->errbuf,
			    PCAP_ERRBUF_SIZE, rte_errno,
			    "dpdk pdump: cannot create mempool");
			ret = PCAP_ERROR;
			break;
		}

		/* Enable pdump on all queues, both RX and TX. */
		ret = rte_pdump_enable(portid, RTE_PDUMP_ALL_QUEUES,
		    RTE_PDUMP_FLAG_RXTX, pd->ring, pd->mp, NULL);
		if (ret < 0) {
			dpdk_pdump_fmt_errmsg_for_rte_errno(p->errbuf,
			    PCAP_ERRBUF_SIZE, -ret,
			    "dpdk pdump: cannot enable capture on port %u "
			    "(is the primary running with --pdump?)", portid);
			ret = PCAP_ERROR;
			break;
		}
		pd->pdump_enabled = 1;

		p->fd = pd->portid;
		p->linktype = DLT_EN10MB;
		p->selectable_fd = p->fd;
		p->read_op = pcap_dpdk_pdump_dispatch;
		p->inject_op = pcap_dpdk_pdump_inject;
		p->setfilter_op = pcapint_install_bpf_program;
		p->setdirection_op = NULL;
		p->set_datalink_op = NULL;
		p->getnonblock_op = pcap_dpdk_pdump_getnonblock;
		p->setnonblock_op = pcap_dpdk_pdump_setnonblock;
		p->stats_op = pcap_dpdk_pdump_stats;
		p->cleanup_op = pcap_dpdk_pdump_close;
		p->breakloop_op = pcapint_breakloop_common;

		pd->required_select_timeout.tv_sec = 0;
		pd->required_select_timeout.tv_usec =
		    DPDK_PDUMP_DEF_MIN_SLEEP_MS * 1000;
		p->required_select_timeout = &pd->required_select_timeout;

		ret = 0;
	} while (0);

	if (ret <= PCAP_ERROR) {
		pcapint_cleanup_live_common(p);
	} else {
		RTE_LOG(INFO, USER1,
		    "pdump: capturing on port %u (%s MAC:%s PCI:%s)\n",
		    portid, p->opt.device, pd->mac_addr, pd->pci_addr);
	}
	return ret;
}

pcap_t *pcap_dpdk_pdump_create(const char *device, char *ebuf, int *is_ours)
{
	pcap_t *p = NULL;

	*is_ours = 0;

	*is_ours = !strncmp(device, "grout:", 6);
	if (!*is_ours)
		return NULL;

	p = PCAP_CREATE_COMMON(ebuf, struct pcap_dpdk_pdump);
	if (p == NULL)
		return NULL;

	p->activate_op = pcap_dpdk_pdump_activate;
	return p;
}

int pcap_dpdk_pdump_findalldevs(pcap_if_list_t *devlistp, char *ebuf)
{
	int ret = 0;
	unsigned int nb_ports = 0;
	char dpdk_name[DPDK_PDUMP_DEV_NAME_MAX];
	char dpdk_desc[DPDK_PDUMP_DEV_DESC_MAX];
	ETHER_ADDR_TYPE eth_addr;
	char mac_addr[DPDK_PDUMP_MAC_ADDR_SIZE];
	char pci_addr[DPDK_PDUMP_PCI_ADDR_SIZE];

	do {
		char dpdk_pre_init_errbuf[PCAP_ERRBUF_SIZE];
		ret = dpdk_pdump_pre_init(dpdk_pre_init_errbuf, 1);
		if (ret < 0) {
DIAG_OFF_FORMAT_TRUNCATION
			snprintf(ebuf, PCAP_ERRBUF_SIZE,
			    "Can't look for DPDK devices: %s",
			    dpdk_pre_init_errbuf);
DIAG_ON_FORMAT_TRUNCATION
			ret = PCAP_ERROR;
			break;
		}
		if (ret == 0)
			break;

		nb_ports = rte_eth_dev_count_avail();
		if (nb_ports == 0) {
			ret = 0;
			break;
		}

		for (unsigned int i = 0; i < nb_ports; i++) {
			snprintf(dpdk_name, DPDK_PDUMP_DEV_NAME_MAX - 1,
			    "%s%u", DPDK_PDUMP_PREFIX, i);
			rte_eth_macaddr_get(i, &eth_addr);
			eth_addr_str(&eth_addr, mac_addr,
			    DPDK_PDUMP_MAC_ADDR_SIZE);
			rte_eth_dev_get_name_by_port(i, pci_addr);
			snprintf(dpdk_desc, DPDK_PDUMP_DEV_DESC_MAX - 1,
			    "%s %s, MAC:%s, PCI:%s",
			    DPDK_PDUMP_DESC, dpdk_name, mac_addr, pci_addr);
			if (pcapint_add_dev(devlistp, dpdk_name, 0,
			    dpdk_desc, ebuf) == NULL) {
				ret = PCAP_ERROR;
				break;
			}
		}
	} while (0);

	return ret;
}
