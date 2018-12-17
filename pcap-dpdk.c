/*
 * Copyright (C) 2018 All rights reserved.
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
Date: Dec 16, 2018

Description:
1. Pcap-dpdk provides libpcap the ability to use DPDK with the device name as dpdk:[portid], such as dpdk:0.
2. DPDK is a set of libraries and drivers for fast packet processing. (https://www.dpdk.org/) 

Limitations:
1. By default enable_dpdk is no, unless you set inlcudes and lib dir
by --with-dpdk-includes= --with-dpdk-libraries=
2. Only support link libdpdk.so dynamicly, because the libdpdk.a will not work correctly.
3. Only support read operation, and packet injection has not been supported yet.
4. I have tested on DPDK v18.11.
Usage:
1. compile DPDK as shared library and install.(https://github.com/DPDK/dpdk.git)

You shall modify the file $RTE_SDK/$RTE_TARGET/.config and set:
CONFIG_RTE_BUILD_SHARED_LIB=y

2. launch l2fwd that is one of DPDK examples correctly, and get device information.

You shall learn how to bind nic with DPDK-compatible driver by $RTE_SDK/usertools/dpdk-devbind.py, such as igb_uio.
And enable hugepages by dpdk-setup.sh

Then launch the l2fwd with dynamic dirver support. For example:
$RTE_SDK/examples/l2fwd/$RTE_TARGET/l2fwd -dlibrte_pmd_e1000.so -dlibrte_pmd_ixgbe.so -dlibrte_mempool_ring.so -- -p 0x1

3. compile libpcap with dpdk options.

you shall run the following command to generate a new configure

make clean
autoreconf

Then, run configure with dpdk options.
For Ubuntu, they are --with-dpdk-includes=/usr/local/include/dpdk/ --with-dpdk-libraries=/usr/local/lib

4. link your own program with libpcap, and use DPDK with the device name as dpdk[portid], such as dpdk:0.
And you shall set DPDK configure options by environment variable DPDK_CFG
For example, the testprogs/capturetest could be lanched by: 

env DPDK_CFG="--log-level=debug -l0 -dlibrte_pmd_e1000.so -dlibrte_pmd_ixgbe.so -dlibrte_mempool_ring.so" ./capturetest -i dpdk:0

The program will print the following message on my computer:

USER1: dpdk cfg: libpcap_dpdk --log-level=debug -l0 -dlibrte_pmd_e1000.so -dlibrte_pmd_ixgbe.so -dlibrte_mempool_ring.so
EAL: Detected 4 lcore(s)
EAL: Detected 1 NUMA nodes
EAL: Multi-process socket /var/run/dpdk/rte/mp_socket
EAL: No free hugepages reported in hugepages-1048576kB
EAL: Probing VFIO support...
EAL: PCI device 0000:00:19.0 on NUMA socket -1
EAL:   Invalid NUMA socket, default to 0
EAL:   probe driver: 8086:1559 net_e1000_em
USER1: pcap_dpdk_activate device dpdk:0 portid 0, pci_addr: 0000:00:19.0
USER1: Port 0 Link Up. Speed 1000 Mbps - full-duplex
USER1: Port 0, MAC address: [MAC ADDR]

Listening on dpdk:0
USER1: dpdk: lcoreid=0 runs for portid=0

*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <sys/time.h>

//header for calling dpdk
#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_bus.h>

#include "pcap-int.h"
#include "pcap-dpdk.h"

#define DPDK_LIB_NAME "libpcap_dpdk"
#define DPDK_ARGC_MAX 64 
#define DPDK_CFG_MAX_LEN 1024
#define DPDK_CFG_ENV_NAME "DPDK_CFG"
static char dpdk_cfg_buf[DPDK_CFG_MAX_LEN];
#define DPDK_PCI_ADDR_SIZE 16
#define DPDK_DEF_CFG "--log-level=debug -l0 -dlibrte_pmd_e1000.so -dlibrte_pmd_ixgbe.so -dlibrte_mempool_ring.so"
#define DPDK_PREFIX "dpdk:"
#define MBUF_POOL_NAME "mbuf_pool"
#define DPDK_TX_BUF_NAME "tx_buffer"
//The number of elements in the mbuf pool.
#define DPDK_NB_MBUFS 8192U
#define MEMPOOL_CACHE_SIZE 256
#define MAX_PKT_BURST 32 
// Configurable number of RX/TX ring descriptors
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024

static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

#define RTE_ETH_PCAP_SNAPLEN ETHER_MAX_JUMBO_FRAME_LEN

static struct rte_eth_dev_tx_buffer *tx_buffer;

struct dpdk_ts_helper{
	struct timeval start_time;
	uint64_t start_cycles;
	uint64_t hz;
};
struct pcap_dpdk{
	pcap_t * orig;
	uint16_t portid; // portid of DPDK
	pcap_handler cb; //callback and argument
	u_char *cb_arg;
	int max_cnt;
	int must_clear_promisc;
	int filter_in_userland;
	uint64_t rx_pkts;
	uint64_t bpf_drop;
	struct ether_addr eth_addr;
	struct rte_eth_stats stats;
	struct rte_mempool * pktmbuf_pool;
	struct dpdk_ts_helper ts_helper;
	char pci_addr[DPDK_PCI_ADDR_SIZE];
	unsigned char pcap_tmp_buf[RTE_ETH_PCAP_SNAPLEN];
	volatile sig_atomic_t break_loop;
};

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

static int dpdk_init_timer(struct pcap_dpdk *pd){
	gettimeofday(&(pd->ts_helper.start_time),NULL);
	pd->ts_helper.start_cycles = rte_get_timer_cycles();
	pd->ts_helper.hz = rte_get_timer_hz();
	if (pd->ts_helper.hz == 0){
		return -1;	
	}
	return 0;
}
static inline void calculate_timestamp(struct dpdk_ts_helper *helper,struct timeval *ts)
{
	uint64_t cycles;
	// delta
	struct timeval cur_time;
	cycles = rte_get_timer_cycles() - helper->start_cycles;
	cur_time.tv_sec = (time_t)(cycles/helper->hz);
	cur_time.tv_usec = (suseconds_t)((cycles%helper->hz)*1e6/helper->hz);
	timeradd(&(helper->start_time), &cur_time, ts);
}

static unsigned int dpdk_gather_data(unsigned char *data, struct rte_mbuf *mbuf)
{
	unsigned int total_len = 0;
	while (mbuf && (total_len+mbuf->data_len) < RTE_ETH_PCAP_SNAPLEN ){
		rte_memcpy(data+total_len, rte_pktmbuf_mtod(mbuf,void *),mbuf->data_len);
		total_len+=mbuf->data_len;
		mbuf=mbuf->next;
	}
	return total_len;
}

static void pcap_dpdk_breakloop(pcap_t *p)
{
	pcap_breakloop_common(p);
	struct pcap_dpdk *pd = (struct pcap_dpdk*)(p->priv);
	pd->break_loop = p->break_loop;	
}
static void dpdk_dispatch_inter(void *dpdk_user)
{
	if (dpdk_user == NULL){
		return;
	}
	pcap_t *p = dpdk_user;
	struct pcap_dpdk *pd = (struct pcap_dpdk*)(p->priv);
	int max_cnt = pd->max_cnt;
	pcap_handler cb = pd->cb;
	u_char *cb_arg = pd->cb_arg;
	int nb_rx=0;
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;
	struct pcap_pkthdr pcap_header;
	uint16_t portid = pd->portid;
	unsigned lcore_id = rte_lcore_id();
	unsigned master_lcore_id = rte_get_master_lcore();
	uint16_t data_len = 0;
	u_char *bp = NULL;
	int i=0;
	unsigned int gather_len =0;
	int pkt_cnt = 0;
	int is_accepted=0;
		
	if(lcore_id == master_lcore_id){
		RTE_LOG(INFO, USER1, "dpdk: lcoreid=%u runs for portid=%u\n", lcore_id, portid);
	}else{
		RTE_LOG(INFO, USER1, "dpdk: lcore %u has nothing to do\n", lcore_id);
	}
	//only use master lcore
	if (lcore_id != master_lcore_id){
		return;
	}
	while( max_cnt==-1 || pkt_cnt < max_cnt){
		if (pd->break_loop){
			break;
		}
		nb_rx = (int)rte_eth_rx_burst(portid, 0, pkts_burst, MAX_PKT_BURST);
		pkt_cnt += nb_rx;
		for ( i = 0; i < nb_rx; i++) {
			m = pkts_burst[i];
			calculate_timestamp(&(pd->ts_helper),&(pcap_header.ts));
			data_len = rte_pktmbuf_data_len(m);
			pcap_header.caplen = data_len; 
			pcap_header.len = data_len; 
			// volatile prefetch
			rte_prefetch0(rte_pktmbuf_mtod(m, void *));
			bp = NULL;
			if (m->nb_segs == 1)
			{
				bp = rte_pktmbuf_mtod(m, u_char *);
			}else{
				if (m->pkt_len <= ETHER_MAX_JUMBO_FRAME_LEN)
				{
					gather_len = dpdk_gather_data(pd->pcap_tmp_buf, m);
					bp = pd->pcap_tmp_buf;
					pcap_header.caplen = gather_len;
					pcap_header.len = gather_len;
				}else{
					// size too large
					// why only free this pkt
					rte_pktmbuf_free(m);
				}
			}
			if (bp){
				//default accpet all
				is_accepted=1;
				if (pd->filter_in_userland && p->fcode.bf_insns!=NULL)
				{
					if (!pcap_filter(p->fcode.bf_insns, bp, pcap_header.len, pcap_header.caplen)){
						//rejected
						is_accepted=0;
					}
				}
				if (is_accepted){
					cb(cb_arg, &pcap_header, bp);
				}else{
					pd->bpf_drop++;
				}
			}
		}
	}	
	pd->rx_pkts = pkt_cnt;
}
static int launch_one_lcore(void *dpdk_user)
{
	dpdk_dispatch_inter(dpdk_user);
	return 0;
}
static int pcap_dpdk_dispatch(pcap_t *p, int max_cnt, pcap_handler cb, u_char *pcap_user)
{
	unsigned lcore_id = 0;	
	struct pcap_dpdk *pd = (struct pcap_dpdk*)(p->priv);
	pd->rx_pkts=0;
	pd->cb = cb;
	pd->cb_arg = pcap_user;
	pd->max_cnt = max_cnt;
	pd->orig = p;
	void *dpdk_user = p;	
	// launch_one_lcore func will be called on every lcore include master core.
	rte_eal_mp_remote_launch(launch_one_lcore, dpdk_user, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			break;
		}
	}
	return pd->rx_pkts;	
}

static int pcap_dpdk_inject(pcap_t *p, const void *buf _U_, int size _U_)
{
	//not implemented yet
	pcap_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		errno, "dpdk error: Inject function has not be implemented yet");
	return PCAP_ERROR;
}

static void pcap_dpdk_close(pcap_t *p)
{
	struct pcap_dpdk *pd = p->priv;
	if (pd==NULL)
	{
		return;
	} 
	if (pd->must_clear_promisc)
	{
		rte_eth_promiscuous_disable(pd->portid);
	}
	rte_eth_dev_stop(pd->portid);
	rte_eth_dev_close(pd->portid);
	// free pcap_dpdk?
	pcap_cleanup_live_common(p);
} 

static int pcap_dpdk_setfilter(pcap_t *p, struct bpf_program *fp)
{
	//init bpf for dpdk, only support userspace bfp 
	struct pcap_dpdk * pd = p->priv;
	int ret=0;
	ret = install_bpf_program(p, fp); 
	if (ret==0){
		pd->filter_in_userland = 1;
	}
	return ret;
}

static void nic_stats_display(uint16_t portid)
{
	struct rte_eth_stats stats;
	rte_eth_stats_get(portid, &stats);
	RTE_LOG(INFO,USER1, "portid:%d, RX-packets: %-10"PRIu64"  RX-errors:  %-10"PRIu64
	       "  RX-bytes:  %-10"PRIu64"  RX-Imissed:  %-10"PRIu64"\n", portid, stats.ipackets, stats.ierrors,
	       stats.ibytes,stats.imissed);
}

static int pcap_dpdk_stats(pcap_t *p, struct pcap_stat *ps)
{
	struct pcap_dpdk *pd = p->priv;
	rte_eth_stats_get(pd->portid,&(pd->stats));
	ps->ps_recv = pd->stats.ipackets;
	ps->ps_drop = pd->stats.ierrors;
	ps->ps_drop += pd->bpf_drop;
	ps->ps_ifdrop = pd->stats.imissed;
	nic_stats_display(pd->portid);
	return 0;
}

static int pcap_dpdk_setnonblock(pcap_t *p, int fd _U_){
	pcap_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		errno, "dpdk error: setnonblock not support");
	return 0;
}

static int pcap_dpdk_getnonblock(pcap_t *p){
	pcap_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		errno, "dpdk error: getnonblock not support");
	return 0;
}

static int check_link_status(uint16_t portid, struct rte_eth_link *plink)
{
	uint8_t count = 0;
	int is_port_up = 0;
	int max_check_time = 2;
	int check_interval = 100; // 100ms
	for (count = 0; count <= max_check_time; count++) {
		memset(plink, 0, sizeof(struct rte_eth_link));
		rte_eth_link_get_nowait(portid, plink);
		if (plink->link_status == ETH_LINK_UP)
		{
			is_port_up = 1;
			break;
		}else{
			rte_delay_ms(check_interval);
		}
	}
	return is_port_up;
}

// return portid by device name, otherwise return -1
static uint16_t portid_by_device(char * device)
{
	uint16_t ret = -1;
	int len = strlen(device);
	int prefix_len = strlen(DPDK_PREFIX);
	unsigned long ret_ul = 0L;

	if (len<=prefix_len || strncmp(device, DPDK_PREFIX, prefix_len)) // check prefix dpdk:
	{
		return ret;
	}
	if (device[prefix_len]>='0' && device[prefix_len]<='9')
	{ // is digital
		ret_ul = strtoul(&(device[prefix_len]), NULL, 10);
		ret = (uint16_t)ret_ul;
	}
	return ret;
}

int parse_dpdk_cfg(char* dpdk_cfg,char** dargv)
{
	int cnt=0;
	memset(dargv,0,sizeof(dargv[0])*DPDK_ARGC_MAX);	
	//current process name
	int skip_space = 1;
	int i=0;
	RTE_LOG(INFO, USER1,"dpdk cfg: %s\n",dpdk_cfg);
	// find first non space char
	// The last opt is NULL
	for (i=0;dpdk_cfg[i] && cnt<DPDK_ARGC_MAX-1;i++){
		if (skip_space && dpdk_cfg[i]!=0x20){ // not space
			skip_space=!skip_space; // skip normal char
			dargv[cnt++] = dpdk_cfg+i;
		}
		if (!skip_space && dpdk_cfg[i]==0x20){ // fint a space
			dpdk_cfg[i]=0x00; // end of this opt
			skip_space=!skip_space; // skip space char
		}
	}
	dargv[cnt]=NULL;
	return cnt;
}
static int pcap_dpdk_activate(pcap_t *p)
{
	struct pcap_dpdk *pd = p->priv;
	pd->orig = p;
	int ret = PCAP_ERROR;
	uint16_t nb_ports=0;
	uint16_t portid=-1;
	unsigned nb_mbufs = DPDK_NB_MBUFS;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_txconf txq_conf;
	struct rte_eth_conf local_port_conf = port_conf;
	struct rte_eth_dev_info dev_info;
	int is_port_up = 0;
	struct rte_eth_link link;
	if (p == NULL)
	{
		return PCAP_ERROR;
	}

	do{
		//init EAL
		rte_log_set_global_level(RTE_LOG_DEBUG);
		int dargv_cnt=0;
		char * dargv[DPDK_ARGC_MAX];
		char *ptr_dpdk_cfg = getenv(DPDK_CFG_ENV_NAME);
		if (ptr_dpdk_cfg == NULL)
		{
			RTE_LOG(INFO,USER1,"env $DPDK_CFG is unset, so using default: %s\n",DPDK_DEF_CFG);
			ptr_dpdk_cfg = DPDK_DEF_CFG;
		}
		memset(dpdk_cfg_buf,0,sizeof(dpdk_cfg_buf));
		snprintf(dpdk_cfg_buf,DPDK_CFG_MAX_LEN-1,"%s %s",DPDK_LIB_NAME,ptr_dpdk_cfg);
		dargv_cnt = parse_dpdk_cfg(dpdk_cfg_buf,dargv);
		ret = rte_eal_init(dargv_cnt,dargv);
		if (ret < 0)
		{
			pcap_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "dpdk error: Init failed with device %s",
			    p->opt.device);
			ret = PCAP_ERROR;
			break;
		}
		ret = dpdk_init_timer(pd);
		if (ret<0)
		{
			pcap_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
				errno, "dpdk error: Init timer error with device %s",
				p->opt.device);
			ret = PCAP_ERROR;
			break;
		}

		nb_ports = rte_eth_dev_count_avail();
		if (nb_ports == 0)
		{
			pcap_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "dpdk error: No Ethernet ports");
			ret = PCAP_ERROR;
			break;
		}
		// parse portid
		portid = portid_by_device(p->opt.device);
		if (portid == -1){
			pcap_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "dpdk error: portid is invalid. device %s",
			    p->opt.device);
			ret = PCAP_ERROR;
			break;
		}

		if (portid >= nb_ports)
		{
			pcap_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "dpdk error: portid(%u) is larger than nb_ports(%u)",
			    portid, nb_ports);
			ret = PCAP_ERROR;
			break;
		}
		pd->portid = portid;
		if (p->snapshot <= 0 || p->snapshot > MAXIMUM_SNAPLEN)
		{
			p->snapshot = MAXIMUM_SNAPLEN;
		}
		// create the mbuf pool 
		pd->pktmbuf_pool = rte_pktmbuf_pool_create(MBUF_POOL_NAME, nb_mbufs,
			MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
			rte_socket_id());
		if (pd->pktmbuf_pool == NULL)
		{
			pcap_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "dpdk error: Cannot init mbuf pool");
			ret = PCAP_ERROR;
			break;
		}
		// config dev
		rte_eth_dev_info_get(portid, &dev_info);
		if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		{
			local_port_conf.txmode.offloads |=DEV_TX_OFFLOAD_MBUF_FAST_FREE;
		}
		// only support 1 queue
		ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);
		if (ret < 0)
		{
			pcap_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "dpdk error: Cannot configure device: err=%d, port=%u",
			    ret, portid);
			ret = PCAP_ERROR;
			break;	
		}
		// adjust rx tx
		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
		if (ret < 0)
		{
			pcap_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "dpdk error: Cannot adjust number of descriptors: err=%d, port=%u",
			    ret, portid);
			ret = PCAP_ERROR;
			break;	
		}
		// get MAC addr
		rte_eth_macaddr_get(portid, &(pd->eth_addr));

		// init one RX queue
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;
		ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
					     rte_eth_dev_socket_id(portid),
					     &rxq_conf,
					     pd->pktmbuf_pool);
		if (ret < 0)
		{
			pcap_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "dpdk error: rte_eth_rx_queue_setup:err=%d, port=%u",
			    ret, portid);
			ret = PCAP_ERROR;
			break;	
		}

		// init one TX queue 
		txq_conf = dev_info.default_txconf;
		txq_conf.offloads = local_port_conf.txmode.offloads;
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
				rte_eth_dev_socket_id(portid),
				&txq_conf);
		if (ret < 0)
		{
			pcap_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "dpdk error: rte_eth_tx_queue_setup:err=%d, port=%u",
			    ret, portid);
			ret = PCAP_ERROR;
			break;	
		}
		// Initialize TX buffers 
		tx_buffer = rte_zmalloc_socket(DPDK_TX_BUF_NAME,
				RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
				rte_eth_dev_socket_id(portid));
		if (tx_buffer == NULL)
		{
			pcap_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "dpdk error: Cannot allocate buffer for tx on port %u", portid);
			ret = PCAP_ERROR;
			break;	
		}
		rte_eth_tx_buffer_init(tx_buffer, MAX_PKT_BURST);
		// Start device
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
		{
			pcap_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "dpdk error: rte_eth_dev_start:err=%d, port=%u",
			    ret, portid);
			ret = PCAP_ERROR;
			break;
		}
		// set promisc mode
		pd->must_clear_promisc=1;
		rte_eth_promiscuous_enable(portid);
		// check link status
		is_port_up = check_link_status(portid, &link);
		if (!is_port_up){
			pcap_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "dpdk error: link is down, port=%u",portid);
			ret = PCAP_ERROR;
			break;
		}
		// reset statistics
		rte_eth_stats_reset(pd->portid);
		// format pcap_t 
		pd->portid = portid;
		p->fd = pd->portid; 
		if (p->snapshot <=0 || p->snapshot> MAXIMUM_SNAPLEN)
		{
			p->snapshot = MAXIMUM_SNAPLEN;
		}
		p->linktype = DLT_EN10MB; // Ethernet, the 10MB is historical.
		p->selectable_fd = p->fd;
		p->read_op = pcap_dpdk_dispatch;
		p->inject_op = pcap_dpdk_inject;
		p->setfilter_op = pcap_dpdk_setfilter;
		p->setdirection_op = NULL;
		p->set_datalink_op = NULL;
		p->getnonblock_op = pcap_dpdk_getnonblock;
		p->setnonblock_op = pcap_dpdk_setnonblock;
		p->stats_op = pcap_dpdk_stats;
		p->cleanup_op = pcap_dpdk_close;
		p->breakloop_op = pcap_dpdk_breakloop;
		ret = 0; // OK
	}while(0);
	rte_eth_dev_get_name_by_port(portid,pd->pci_addr);
	RTE_LOG(INFO, USER1,"%s device %s portid %d, pci_addr: %s\n", __FUNCTION__, p->opt.device, portid, pd->pci_addr);
	RTE_LOG(INFO, USER1,"Port %d Link Up. Speed %u Mbps - %s\n",
						portid, link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
	RTE_LOG(INFO, USER1,"Port %u, MAC address:", portid);
	for (int i=0; i<6; i++)
	{
		if (i==0)
		{
			fprintf(stderr,"%02X",pd->eth_addr.addr_bytes[i]);
		}else{
			fprintf(stderr,":%02X", pd->eth_addr.addr_bytes[i]);
		}
	}
	fprintf(stderr,"\n\n");
	if (ret == PCAP_ERROR)
	{
		pcap_cleanup_live_common(p);
	}
	return ret;
}

// device name for dpdk shoud be in the form as dpdk:number, such as dpdk:0
pcap_t * pcap_dpdk_create(const char *device, char *ebuf, int *is_ours)
{
	pcap_t *p=NULL;
	*is_ours = 0;

	*is_ours = !strncmp(device, "dpdk:", 5);
	if (! *is_ours)
		return NULL;
	//memset will happen
	p = pcap_create_common(ebuf, sizeof(struct pcap_dpdk));
		
	if (p == NULL)
		return NULL;
	p->activate_op = pcap_dpdk_activate;
	return p;
}

int pcap_dpdk_findalldevs(pcap_if_list_t *devlistp _U_, char *err_str _U_)
{
	return 0;
}
