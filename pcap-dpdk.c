/*
 * Copyright (C) 2018 jingle YANG. All rights reserved.
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
1. Pcap-dpdk provides libpcap the ability to use DPDK with the device name as dpdk:{portid}, such as dpdk:0.
2. DPDK is a set of libraries and drivers for fast packet processing. (https://www.dpdk.org/) 
3. The testprogs/capturetest provides 6.4Gbps/800,000 pps on Intel 10-Gigabit X540-AT2 with DPDK 18.11.

Limitations:
1. By default DPDK support is no, unless you explicitly set --enable-dpdk with ./configure or -DDISABLE_DPDK=OFF with cmake.
2. Only support link libdpdk.so dynamicly, because the libdpdk.a will not work correctly.
3. Only support read operation, and packet injection has not been supported yet.

Usage:
1. compile DPDK as shared library and install.(https://github.com/DPDK/dpdk.git)

You shall modify the file $RTE_SDK/$RTE_TARGET/.config and set:
CONFIG_RTE_BUILD_SHARED_LIB=y
By the following command:
sed -i 's/CONFIG_RTE_BUILD_SHARED_LIB=n/CONFIG_RTE_BUILD_SHARED_LIB=y/' $RTE_SDK/$RTE_TARGET/.config

2. launch l2fwd that is one of DPDK examples correctly, and get device information.

You shall learn how to bind nic with DPDK-compatible driver by $RTE_SDK/usertools/dpdk-devbind.py, such as igb_uio.
And enable hugepages by dpdk-setup.sh

Then launch the l2fwd with dynamic dirver support. For example:
$RTE_SDK/examples/l2fwd/$RTE_TARGET/l2fwd -dlibrte_pmd_e1000.so -dlibrte_pmd_ixgbe.so -dlibrte_mempool_ring.so -- -p 0x1

3. compile libpcap with dpdk options.

In order to find inlucde and lib automatically, you shall export DPDK envionment variable which are used for compiling DPDK.

export RTE_SDK={your DPDK base directory}
export RTE_TARGET={your target name}

3.1 with configure

./configure --enable-dpdk --with-dpdk-includes=$RTE_SDK/$RTE_TARGET/include --with-dpdk-libraries=$RTE_SDK/$RTE_TARGET/lib && make -s all && make -s testprogs && make install

3.2 with cmake

mkdir -p build && cd build && cmake -DDISABLE_DPDK=OFF -DDPDK_INC_DIR=$RTE_SDK/$RTE_TARGET/include -DDPDK_LIB_DIR=$RTE_SDK/$RTE_TARGET/lib" ../ && make -s all && make -s testprogs && make install 

4. link your own program with libpcap, and use DPDK with the device name as dpdk:{portid}, such as dpdk:0.
And you shall set DPDK configure options by environment variable DPDK_CFG
For example, the testprogs/capturetest could be lanched by: 

env DPDK_CFG="--log-level=debug -l0 -dlibrte_pmd_e1000.so -dlibrte_pmd_ixgbe.so -dlibrte_mempool_ring.so" ./capturetest -i dpdk:0
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

#define DPDK_DEF_LOG_LEV RTE_LOG_ERR
static int is_dpdk_pre_inited=0;
#define DPDK_LIB_NAME "libpcap_dpdk"
#define DPDK_DESC "Data Plane Development Kit (DPDK) Interface"
#define DPDK_ERR_PERM_MSG "permission denied, DPDK needs root permission"
#define DPDK_ARGC_MAX 64 
#define DPDK_CFG_MAX_LEN 1024
#define DPDK_DEV_NAME_MAX 32
#define DPDK_DEV_DESC_MAX 512 
#define DPDK_CFG_ENV_NAME "DPDK_CFG"
#define DPDK_DEF_MIN_SLEEP_MS 1
static char dpdk_cfg_buf[DPDK_CFG_MAX_LEN];
#define DPDK_MAC_ADDR_SIZE 32
#define DPDK_DEF_MAC_ADDR "00:00:00:00:00:00"
#define DPDK_PCI_ADDR_SIZE 16
#define DPDK_DEF_CFG "--log-level=error -l0 -dlibrte_pmd_e1000.so -dlibrte_pmd_ixgbe.so -dlibrte_mempool_ring.so"
#define DPDK_PREFIX "dpdk:"
#define DPDK_PORTID_MAX 65535U
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
	int must_clear_promisc;
	uint64_t bpf_drop;
	int nonblock;
	struct timeval required_select_timeout;
	struct timeval prev_ts;
	struct rte_eth_stats prev_stats;
	struct timeval curr_ts;
	struct rte_eth_stats curr_stats;
	uint64_t pps;
	uint64_t bps;
	struct rte_mempool * pktmbuf_pool;
	struct dpdk_ts_helper ts_helper;
	struct ether_addr eth_addr;
	char mac_addr[DPDK_MAC_ADDR_SIZE];
	char pci_addr[DPDK_PCI_ADDR_SIZE];
	unsigned char pcap_tmp_buf[RTE_ETH_PCAP_SNAPLEN];
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

static uint32_t dpdk_gather_data(unsigned char *data, int len, struct rte_mbuf *mbuf)
{
	uint32_t total_len = 0;
	while (mbuf && (total_len+mbuf->data_len) < len ){
		rte_memcpy(data+total_len, rte_pktmbuf_mtod(mbuf,void *),mbuf->data_len);
		total_len+=mbuf->data_len;
		mbuf=mbuf->next;
	}
	return total_len;
}


static int dpdk_read_with_timeout(pcap_t *p, uint16_t portid, uint16_t queueid,struct rte_mbuf **pkts_burst, const uint16_t burst_cnt){
	struct pcap_dpdk *pd = (struct pcap_dpdk*)(p->priv);
	int nb_rx = 0;	
	int timeout_ms = p->opt.timeout;
	int sleep_ms = 0;
	if (pd->nonblock){
		// In non-blocking mode, just read once, no mater how many packets are captured.
		nb_rx = (int)rte_eth_rx_burst(pd->portid, 0, pkts_burst, burst_cnt);
	}else{
		// In blocking mode, read many times until packets are captured or timeout or break_loop is setted.	
		// if timeout_ms == 0, it may be blocked forever.
		while (timeout_ms == 0 || sleep_ms < timeout_ms){
			nb_rx = (int)rte_eth_rx_burst(pd->portid, 0, pkts_burst, burst_cnt);
			if (nb_rx){ // got packets within timeout_ms
				break;	
			}else{ // no packet arrives at this round.
				if (p->break_loop){
					break;
				}
				// sleep for a very short while.
				// block sleep is the only choice, since usleep() will impact performance dramatically.
				rte_delay_us_block(DPDK_DEF_MIN_SLEEP_MS*1000);
				sleep_ms += DPDK_DEF_MIN_SLEEP_MS;
			}
		}
	}
	return nb_rx;
}

static int pcap_dpdk_dispatch(pcap_t *p, int max_cnt, pcap_handler cb, u_char *cb_arg)
{
	struct pcap_dpdk *pd = (struct pcap_dpdk*)(p->priv);
	int burst_cnt = 0;
	int nb_rx = 0;
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;
	struct pcap_pkthdr pcap_header;
	uint16_t portid = pd->portid;
	// In DPDK, pkt_len is sum of lengths for all segments. And data_len is for one segment
	uint32_t pkt_len = 0;
	int caplen = 0;
	u_char *bp = NULL;
	int i=0;
	unsigned int gather_len =0;
	int pkt_cnt = 0;
	int is_accepted=0;
	u_char *large_buffer=NULL;
	int timeout_ms = p->opt.timeout;

	if ( !PACKET_COUNT_IS_UNLIMITED(max_cnt) && max_cnt < MAX_PKT_BURST){
		burst_cnt = max_cnt;
	}else{
		burst_cnt = MAX_PKT_BURST;
	}

	while( PACKET_COUNT_IS_UNLIMITED(max_cnt) || pkt_cnt < max_cnt){
		if (p->break_loop){
			p->break_loop = 0;
			return PCAP_ERROR_BREAK;
		}
		// read once in non-blocking mode, or try many times waiting for timeout_ms.
		// if timeout_ms == 0, it will be blocked until one packet arrives or break_loop is setted.
		nb_rx = dpdk_read_with_timeout(p, portid, 0, pkts_burst, burst_cnt);
		if (nb_rx == 0){ 
			if (pd->nonblock){
				RTE_LOG(DEBUG, USER1, "dpdk: no packets available in non-blocking mode.\n");
			}else{
				if (p->break_loop){
					RTE_LOG(DEBUG, USER1, "dpdk: no packets available and break_loop is setted in blocking mode.\n");
					p->break_loop = 0;
					return PCAP_ERROR_BREAK;

				}
				RTE_LOG(DEBUG, USER1, "dpdk: no packets available for timeout %d ms in blocking mode.\n", timeout_ms);
			}
			// break if dpdk reads 0 packet, no matter in blocking(timeout) or non-blocking mode.
			break;	
		}
		pkt_cnt += nb_rx;
		for ( i = 0; i < nb_rx; i++) {
			m = pkts_burst[i];
			calculate_timestamp(&(pd->ts_helper),&(pcap_header.ts));
			pkt_len = rte_pktmbuf_pkt_len(m);
			// caplen = min(pkt_len, p->snapshot);
			// caplen will not be changed, no matter how long the rte_pktmbuf
			caplen = pkt_len < p->snapshot ? pkt_len: p->snapshot; 
			pcap_header.caplen = caplen;
			pcap_header.len = pkt_len; 
			// volatile prefetch
			rte_prefetch0(rte_pktmbuf_mtod(m, void *));
			bp = NULL;
			if (m->nb_segs == 1)
			{
				bp = rte_pktmbuf_mtod(m, u_char *);
			}else{
				// use fast buffer pcap_tmp_buf if pkt_len is small, no need to call malloc and free
				if ( pkt_len <= ETHER_MAX_JUMBO_FRAME_LEN)
				{
					gather_len = dpdk_gather_data(pd->pcap_tmp_buf, RTE_ETH_PCAP_SNAPLEN, m);
					bp = pd->pcap_tmp_buf;
				}else{ 
					// need call free later
					large_buffer = (u_char *)malloc(caplen*sizeof(u_char));
					gather_len = dpdk_gather_data(large_buffer, caplen, m); 
					bp = large_buffer;
				}
				
			}
			if (bp){
				if (p->fcode.bf_insns==NULL || pcap_filter(p->fcode.bf_insns, bp, pcap_header.len, pcap_header.caplen)){
					cb(cb_arg, &pcap_header, bp);
				}else{
					pd->bpf_drop++;
				}
			}
			//free all pktmbuf
			rte_pktmbuf_free(m);
			if (large_buffer){
				free(large_buffer);
				large_buffer=NULL;
			}
		}
	}	
	return pkt_cnt;
}

static int pcap_dpdk_inject(pcap_t *p, const void *buf _U_, int size _U_)
{
	//not implemented yet
	pcap_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		errno, "dpdk error: Inject function has not been implemented yet");
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
	pcap_cleanup_live_common(p);
} 

static void nic_stats_display(struct pcap_dpdk *pd)
{
	uint16_t portid = pd->portid;
	struct rte_eth_stats stats;
	rte_eth_stats_get(portid, &stats);
	RTE_LOG(INFO,USER1, "portid:%d, RX-packets: %-10"PRIu64"  RX-errors:  %-10"PRIu64
	       "  RX-bytes:  %-10"PRIu64"  RX-Imissed:  %-10"PRIu64"\n", portid, stats.ipackets, stats.ierrors,
	       stats.ibytes,stats.imissed);
	RTE_LOG(INFO,USER1, "portid:%d, RX-PPS: %-10"PRIu64" RX-Mbps: %.2lf\n", portid, pd->pps, pd->bps/1e6f );
}

static int pcap_dpdk_stats(pcap_t *p, struct pcap_stat *ps)
{
	struct pcap_dpdk *pd = p->priv;
	calculate_timestamp(&(pd->ts_helper), &(pd->curr_ts));
	rte_eth_stats_get(pd->portid,&(pd->curr_stats));
	if (ps){
		ps->ps_recv = pd->curr_stats.ipackets;
		ps->ps_drop = pd->curr_stats.ierrors;
		ps->ps_drop += pd->bpf_drop;
		ps->ps_ifdrop = pd->curr_stats.imissed;
	}
	uint64_t delta_pkt = pd->curr_stats.ipackets - pd->prev_stats.ipackets;
	struct timeval delta_tm;
	timersub(&(pd->curr_ts),&(pd->prev_ts), &delta_tm);
	uint64_t delta_usec = delta_tm.tv_sec*1e6+delta_tm.tv_usec;
	uint64_t delta_bit = (pd->curr_stats.ibytes-pd->prev_stats.ibytes)*8;
	RTE_LOG(DEBUG, USER1, "delta_usec: %-10"PRIu64" delta_pkt: %-10"PRIu64" delta_bit: %-10"PRIu64"\n", delta_usec, delta_pkt, delta_bit);
	pd->pps = (uint64_t)(delta_pkt*1e6f/delta_usec);
	pd->bps = (uint64_t)(delta_bit*1e6f/delta_usec);
	nic_stats_display(pd);
	pd->prev_stats = pd->curr_stats;
	pd->prev_ts = pd->curr_ts;
	return 0;
}

static int pcap_dpdk_setnonblock(pcap_t *p, int nonblock){
	struct pcap_dpdk *pd = (struct pcap_dpdk*)(p->priv);
	pd->nonblock = nonblock;
	return 0;
}

static int pcap_dpdk_getnonblock(pcap_t *p){
	struct pcap_dpdk *pd = (struct pcap_dpdk*)(p->priv);
	return pd->nonblock;
}
static int check_link_status(uint16_t portid, struct rte_eth_link *plink)
{
	// wait up to 9 seconds to get link status
	rte_eth_link_get(portid, plink);
	return plink->link_status == ETH_LINK_UP;
}
static void eth_addr_str(struct ether_addr *addrp, char* mac_str, int len)
{
	int offset=0;
	if (addrp == NULL){
		pcap_snprintf(mac_str, len-1, DPDK_DEF_MAC_ADDR);
		return;
	}
	for (int i=0; i<6; i++)
	{
		if (offset >= len)
		{ // buffer overflow
			return;
		}
		if (i==0)
		{
			pcap_snprintf(mac_str+offset, len-1-offset, "%02X",addrp->addr_bytes[i]);
			offset+=2; // FF
		}else{
			pcap_snprintf(mac_str+offset, len-1-offset, ":%02X", addrp->addr_bytes[i]);
			offset+=3; // :FF
		}
	}
	return;
}
// return portid by device name, otherwise return -1
static uint16_t portid_by_device(char * device)
{
	uint16_t ret = DPDK_PORTID_MAX; 
	int len = strlen(device);
	int prefix_len = strlen(DPDK_PREFIX);
	unsigned long ret_ul = 0L;
	char *pEnd;
	if (len<=prefix_len || strncmp(device, DPDK_PREFIX, prefix_len)) // check prefix dpdk:
	{
		return ret;
	}
	//check all chars are digital
	for (int i=prefix_len; device[i]; i++){
		if (device[i]<'0' || device[i]>'9'){
			return ret;	
		}
	}
	ret_ul = strtoul(&(device[prefix_len]), &pEnd, 10);
	if (pEnd == &(device[prefix_len]) || *pEnd != '\0'){
		return ret;
	}
	// too large for portid
	if (ret_ul >= DPDK_PORTID_MAX){ 
		return ret;
	}
	ret = (uint16_t)ret_ul;
	return ret;
}

static int parse_dpdk_cfg(char* dpdk_cfg,char** dargv)
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
		if (skip_space && dpdk_cfg[i]!=' '){ // not space
			skip_space=!skip_space; // skip normal char
			dargv[cnt++] = dpdk_cfg+i;
		}
		if (!skip_space && dpdk_cfg[i]==' '){ // fint a space
			dpdk_cfg[i]=0x00; // end of this opt
			skip_space=!skip_space; // skip space char
		}
	}
	dargv[cnt]=NULL;
	return cnt;
}

// only called once
static int dpdk_pre_init(char * ebuf)
{
	int dargv_cnt=0;
	char *dargv[DPDK_ARGC_MAX];
	char *ptr_dpdk_cfg = NULL;
	int ret = PCAP_ERROR; 
	// globale var
	if (is_dpdk_pre_inited)
	{
		// already inited
		return 0;
	}
	// check for root permission
	if( geteuid() != 0)
	{
		RTE_LOG(ERR, USER1, "%s\n", DPDK_ERR_PERM_MSG);
		pcap_fmt_errmsg_for_errno(ebuf, PCAP_ERRBUF_SIZE,
			    errno, "dpdk error: %s",
			    DPDK_ERR_PERM_MSG);
		ret = PCAP_ERROR_PERM_DENIED;
		return ret;	
	}
	// init EAL
	ptr_dpdk_cfg = getenv(DPDK_CFG_ENV_NAME);
	// set default log level to debug
	rte_log_set_global_level(DPDK_DEF_LOG_LEV);
	if (ptr_dpdk_cfg == NULL)
	{
		RTE_LOG(INFO,USER1,"env $DPDK_CFG is unset, so using default: %s\n",DPDK_DEF_CFG);
		ptr_dpdk_cfg = DPDK_DEF_CFG;
	}
	memset(dpdk_cfg_buf,0,sizeof(dpdk_cfg_buf));
	snprintf(dpdk_cfg_buf,DPDK_CFG_MAX_LEN-1,"%s %s",DPDK_LIB_NAME,ptr_dpdk_cfg);
	dargv_cnt = parse_dpdk_cfg(dpdk_cfg_buf,dargv);
	ret = rte_eal_init(dargv_cnt,dargv);
	// if init successed, we do not need to do it again later.
	if (ret == 0){
		is_dpdk_pre_inited = 1;
	}
	return ret;
}

static int pcap_dpdk_activate(pcap_t *p)
{
	struct pcap_dpdk *pd = p->priv;
	pd->orig = p;
	int ret = PCAP_ERROR;
	uint16_t nb_ports=0;
	uint16_t portid= DPDK_PORTID_MAX;
	unsigned nb_mbufs = DPDK_NB_MBUFS;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_txconf txq_conf;
	struct rte_eth_conf local_port_conf = port_conf;
	struct rte_eth_dev_info dev_info;
	int is_port_up = 0;
	struct rte_eth_link link;
	do{
		//init EAL
		ret = dpdk_pre_init(p->errbuf);
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

		portid = portid_by_device(p->opt.device);
		if (portid == DPDK_PORTID_MAX){
			pcap_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "dpdk error: portid is invalid. device %s",
			    p->opt.device);
			ret = PCAP_ERROR_NO_SUCH_DEVICE;
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
		eth_addr_str(&(pd->eth_addr), pd->mac_addr, DPDK_MAC_ADDR_SIZE-1);

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
		// set promiscuous mode
		if (p->opt.promisc){
			pd->must_clear_promisc=1;
			rte_eth_promiscuous_enable(portid);
		}
		// check link status
		is_port_up = check_link_status(portid, &link);
		if (!is_port_up){
			pcap_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "dpdk error: link is down, port=%u",portid);
			ret = PCAP_ERROR_IFACE_NOT_UP;
			break;
		}
		// reset statistics
		rte_eth_stats_reset(pd->portid);
		calculate_timestamp(&(pd->ts_helper), &(pd->prev_ts));
		rte_eth_stats_get(pd->portid,&(pd->prev_stats));	
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
		// using pcap_filter currently, though DPDK provides their own BPF function. Because DPDK BPF needs load a ELF file as a filter.
		p->setfilter_op = install_bpf_program;
		p->setdirection_op = NULL;
		p->set_datalink_op = NULL;
		p->getnonblock_op = pcap_dpdk_getnonblock;
		p->setnonblock_op = pcap_dpdk_setnonblock;
		p->stats_op = pcap_dpdk_stats;
		p->cleanup_op = pcap_dpdk_close;
		p->breakloop_op = pcap_breakloop_common;
		// set default timeout
		pd->required_select_timeout.tv_sec = 0;
		pd->required_select_timeout.tv_usec = DPDK_DEF_MIN_SLEEP_MS*1000;
		p->required_select_timeout = &pd->required_select_timeout;
		ret = 0; // OK
	}while(0);

	if (ret <= PCAP_ERROR) // all kinds of error code
	{
		pcap_cleanup_live_common(p);
	}else{
		rte_eth_dev_get_name_by_port(portid,pd->pci_addr);
		RTE_LOG(INFO, USER1,"Port %d device: %s, MAC:%s, PCI:%s\n", portid, p->opt.device, pd->mac_addr, pd->pci_addr);
		RTE_LOG(INFO, USER1,"Port %d Link Up. Speed %u Mbps - %s\n",
							portid, link.link_speed,
					(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
						("full-duplex") : ("half-duplex\n"));
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

int pcap_dpdk_findalldevs(pcap_if_list_t *devlistp, char *ebuf)
{
	int ret=0;
	int nb_ports = 0;
	char dpdk_name[DPDK_DEV_NAME_MAX];
	char dpdk_desc[DPDK_DEV_DESC_MAX];
	struct ether_addr eth_addr;
	char mac_addr[DPDK_MAC_ADDR_SIZE];
	char pci_addr[DPDK_PCI_ADDR_SIZE];
	do{
		ret = dpdk_pre_init(ebuf);
		if (ret < 0)
		{
			pcap_fmt_errmsg_for_errno(ebuf, PCAP_ERRBUF_SIZE,
			    errno, "error: Init failed with device");
			ret = PCAP_ERROR;
			break;
		}
		nb_ports = rte_eth_dev_count_avail();
		if (nb_ports == 0)
		{
			pcap_fmt_errmsg_for_errno(ebuf, PCAP_ERRBUF_SIZE,
			    errno, "DPDK error: No Ethernet ports");
			ret = PCAP_ERROR;
			break;
		}
		for (int i=0; i<nb_ports; i++){
			pcap_snprintf(dpdk_name,DPDK_DEV_NAME_MAX-1,"dpdk:%d",i);
			// mac addr 
			rte_eth_macaddr_get(i, &eth_addr);
			eth_addr_str(&eth_addr,mac_addr,DPDK_MAC_ADDR_SIZE);	
			// PCI addr
			rte_eth_dev_get_name_by_port(i,pci_addr);
			pcap_snprintf(dpdk_desc,DPDK_DEV_DESC_MAX-1,"%s %s, MAC:%s, PCI:%s", DPDK_DESC, dpdk_name, mac_addr, pci_addr);
			if (add_dev(devlistp, dpdk_name, 0, dpdk_desc, ebuf)==NULL){
				ret = PCAP_ERROR;
				break;
			}
		}	
	}while(0);	
	return ret;
}
