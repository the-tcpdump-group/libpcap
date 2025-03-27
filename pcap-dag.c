/*
 * pcap-dag.c: Packet capture interface for Endace DAG cards.
 *
 * Authors: Richard Littin, Sean Irvine ({richard,sean}@reeltwo.com)
 * Modifications: Jesper Peterson
 *                Koryn Grant
 *                Stephen Donnelly <stephen.donnelly@endace.com>
 */

#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <endian.h>
#include <limits.h>
#include <unistd.h>

#include "pcap-int.h"

#if __BYTE_ORDER == __BIG_ENDIAN
// Will need SWAPLL().
#include "pcap-util.h"
#endif

#include "dagapi.h"
#include "dagpci.h"
#include "dag_config_api.h"

#include "pcap-dag.h"

/*
 * DAG devices have names beginning with "dag", followed by a number
 * from 0 to DAG_MAX_BOARDS, then optionally a colon and a stream number
 * from 0 to DAG_STREAM_MAX.
 */
#ifndef DAG_MAX_BOARDS
#define DAG_MAX_BOARDS 32
#endif

#define ATM_CELL_SIZE		52
#define ATM_HDR_SIZE		4

/*
 * A header containing additional MTP information.
 */
#define MTP2_SENT_OFFSET		0	/* 1 byte */
#define MTP2_ANNEX_A_USED_OFFSET	1	/* 1 byte */
#define MTP2_LINK_NUMBER_OFFSET		2	/* 2 bytes */
#define MTP2_HDR_LEN			4	/* length of the header */

#define MTP2_ANNEX_A_NOT_USED      0
#define MTP2_ANNEX_A_USED          1
#define MTP2_ANNEX_A_USED_UNKNOWN  2

/* SunATM pseudo header */
struct sunatm_hdr {
	unsigned char	flags;		/* destination and traffic type */
	unsigned char	vpi;		/* VPI */
	unsigned short	vci;		/* VCI */
};

/*
 * Private data for capturing on DAG devices.
 */
struct pcap_dag {
	struct pcap_stat stat;
	u_char	*dag_mem_bottom;	/* DAG card current memory bottom pointer */
	u_char	*dag_mem_top;	/* DAG card current memory top pointer */
	int	dag_fcs_bits;	/* Number of checksum bits from link layer */
	int	dag_flags;	/* Flags */
	int	dag_devnum;	/* This is the N in "dagN" or "dagN:M". */
	int	dag_stream;	/* And this is the M. */
	int	dag_timeout;	/* timeout specified to pcap_open_live.
				 * Same as in linux above, introduce
				 * generally? */
	dag_card_ref_t dag_ref; /* DAG Configuration/Status API card reference */
	dag_component_t dag_root;	/* DAG CSAPI Root component */
	attr_uuid_t drop_attr;  /* DAG Stream Drop Attribute handle, if available */
	uint64_t drop_base;	// Rx stream drop counter initial value.
	struct timeval required_select_timeout;
				/* Timeout caller must use in event loops */
	uint8_t	tx_iface;	// Tx interface number
	uint8_t tx_align_bytes;	/* If necessary, add trailing padding to an
				 * ERF record to make it a multiple of this
				 * many bytes long.  DAG API calls this "ERF
				 * record alignment". */
	uint8_t terf_fcs_bytes;	// How many FCS bytes TERF is expecting.
};

#define ALIGN_BYTES_DEFAULT 8
#define ALIGN_BYTES_9_2 16
#define ALIGN_BYTES_MAX ALIGN_BYTES_9_2

typedef struct pcap_dag_node {
	struct pcap_dag_node *next;
	pcap_t *p;
	pid_t pid;
} pcap_dag_node_t;

static pcap_dag_node_t *pcap_dags = NULL;
static int atexit_handler_installed = 0;

#define MAX_DAG_PACKET 65536

static unsigned char TempPkt[MAX_DAG_PACKET];

#define TX_ONLY(stream) ((stream) % 2)
#define RX_ONLY(stream) (! TX_ONLY(stream))
#define RXTX_STR(stream) (TX_ONLY(stream) ? "Tx" : "Rx")

static int dag_stats(pcap_t *p, struct pcap_stat *ps);
static int dag_set_datalink(pcap_t *p, int dlt);
static int dag_get_datalink(pcap_t *p);
static int dag_setnonblock(pcap_t *p, int nonblock);

// Environment variables that can control behaviour of this libpcap module.
#define ENV_RX_FCS_BITS "ERF_FCS_BITS"
#define ENV_RX_FCS_NOSTRIP "ERF_DONT_STRIP_FCS"
#define ENV_TX_IFACE "ERF_TX_INTERFACE"

/*
 * Convert the return value of getenv() to an integer using matching stricter
 * than atoi().  If the environment variable is not set, return the default
 * value.  Otherwise return an integer in the interval [0, INT32_MAX] or -1 on
 * error.
 */
static int32_t
strtouint31(const char *str, const int32_t defaultval) {
	if (! str)
		return defaultval;
	if (! str[0])
		return -1;

	char * endp;
	unsigned long val = strtoul(str, &endp, 10);
	if (*endp || val > INT32_MAX)
		return -1;
	return (int32_t)val;
}

static void
delete_pcap_dag(const pcap_t *p)
{
	pcap_dag_node_t *curr = NULL, *prev = NULL;

	for (prev = NULL, curr = pcap_dags; curr != NULL && curr->p != p; prev = curr, curr = curr->next) {
		/* empty */
	}

	if (curr != NULL && curr->p == p) {
		if (prev != NULL) {
			prev->next = curr->next;
		} else {
			pcap_dags = curr->next;
		}
	}
}

/*
 * Performs a graceful shutdown of the DAG card, frees dynamic memory held
 * in the pcap_t structure, and closes the file descriptor for the DAG card.
 */

static void
dag_platform_cleanup(pcap_t *p)
{
	struct pcap_dag *pd = p->priv;

	/*
	 * Before stopping a Tx stream wait until the stream buffer has been
	 * drained, otherwise packets that have been buffered but have not yet
	 * been transmitted will be lost.
	 */
	if (TX_ONLY(pd->dag_stream))
		while (dag_get_stream_buffer_level64(p->fd, pd->dag_stream) > 0)
			usleep (10000);

	if(dag_stop_stream(p->fd, pd->dag_stream) < 0)
		fprintf(stderr,"dag_stop_stream: %s\n", strerror(errno));

	if(dag_detach_stream(p->fd, pd->dag_stream) < 0)
		fprintf(stderr,"dag_detach_stream: %s\n", strerror(errno));

	if(pd->dag_ref != NULL) {
		dag_config_dispose(pd->dag_ref);
		/*
		 * Note: we don't need to call close(p->fd) or
		 * dag_close(p->fd), as dag_config_dispose(pd->dag_ref)
		 * does this.
		 *
		 * Set p->fd to -1 to make sure that's not done.
		 */
		p->fd = -1;
		pd->dag_ref = NULL;
	}
	delete_pcap_dag(p);
	pcapint_cleanup_live_common(p);
}

static void
atexit_handler(void)
{
	while (pcap_dags != NULL) {
		if (pcap_dags->pid == getpid()) {
			if (pcap_dags->p != NULL)
				dag_platform_cleanup(pcap_dags->p);
		} else {
			delete_pcap_dag(pcap_dags->p);
		}
	}
}

static int
new_pcap_dag(pcap_t *p)
{
	pcap_dag_node_t *node = NULL;

	if ((node = malloc(sizeof(pcap_dag_node_t))) == NULL) {
		return -1;
	}

	if (!atexit_handler_installed) {
		atexit(atexit_handler);
		atexit_handler_installed = 1;
	}

	node->next = pcap_dags;
	node->p = p;
	node->pid = getpid();

	pcap_dags = node;

	return 0;
}

static unsigned int
dag_erf_ext_header_count(const uint8_t *erf, size_t len)
{
	uint32_t hdr_num = 0;
	uint8_t  hdr_type;

	/* basic sanity checks */
	if ( erf == NULL )
		return 0;
	if ( len < 16 )
		return 0;

	/* check if we have any extension headers */
	if (! (erf[8] & ERF_TYPE_MORE_EXT))
		return 0;

	/* loop over the extension headers */
	do {

		/* sanity check we have enough bytes */
		if ( len < (24 + (hdr_num * 8)) )
			return hdr_num;

		/* get the header type */
		hdr_type = erf[(16 + (hdr_num * 8))];
		hdr_num++;

	} while (hdr_type & ERF_TYPE_MORE_EXT);

	return hdr_num;
}

static int
dag_rxtx_mismatch(const char *func, pcap_t *p)
{
	const struct pcap_dag *pd = p->priv;

	snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "%s: device %s is %s-only",
	    func,
	    p->opt.device,
	    RXTX_STR(pd->dag_stream));
	return PCAP_ERROR;
}

static int
dag_read_notimpl(pcap_t *p, int cnt _U_, pcap_handler callback _U_, u_char *user _U_)
{
	return dag_rxtx_mismatch(__func__, p);
}

static int
dag_getnonblock_fd_notimpl(pcap_t *p)
{
	return dag_rxtx_mismatch(__func__, p);
}

static int
dag_stats_notimpl(pcap_t *p, struct pcap_stat *ps _U_)
{
	return dag_rxtx_mismatch(__func__, p);
}

static int
dag_setnonblock_notimpl(pcap_t *p, int nonblock _U_)
{
	return dag_rxtx_mismatch( __func__, p);
}

static int
dag_inject_notimpl(pcap_t *p, const void *buf _U_, int size _U_)
{
	return dag_rxtx_mismatch(__func__, p);
}

static int
dag_install_bpf_program_notimpl(pcap_t *p, struct bpf_program *fp _U_)
{
	return dag_rxtx_mismatch(__func__, p);
}

/*
 *  Read at most max_packets from the capture stream and call the callback
 *  for each of them. Returns the number of packets handled, PCAP_ERROR if an
 *  error occurred, or PCAP_ERROR_BREAK if we were told to break out of the loop.
 */
static int
dag_read(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
	struct pcap_dag *pd = p->priv;
	int processed = 0;
	unsigned int nonblocking = pd->dag_flags & DAGF_NONBLOCK;
	unsigned int num_ext_hdr = 0;
	unsigned int ticks_per_second;

	/* Get the next bufferful of packets (if necessary). */
	while (pd->dag_mem_top - pd->dag_mem_bottom < dag_record_size) {

		/*
		 * Has "pcap_breakloop()" been called?
		 */
		if (p->break_loop)
			return PCAP_ERROR_BREAK;

		/* dag_advance_stream() will block (unless nonblock is called)
		 * until 64kB of data has accumulated.
		 * If to_ms is set, it will timeout before 64kB has accumulated.
		 * We wait for 64kB because processing a few packets at a time
		 * can cause problems at high packet rates (>200kpps) due
		 * to inefficiencies.
		 * This does mean if to_ms is not specified the capture may 'hang'
		 * for long periods if the data rate is extremely slow (<64kB/sec)
		 * If non-block is specified it will return immediately. The user
		 * is then responsible for efficiency.
		 */
		if ( NULL == (pd->dag_mem_top = dag_advance_stream(p->fd, pd->dag_stream, &(pd->dag_mem_bottom))) ) {
		     return PCAP_ERROR;
		}

		if (nonblocking && (pd->dag_mem_top - pd->dag_mem_bottom < dag_record_size))
		{
			/* Pcap is configured to process only available packets, and there aren't any, return immediately. */
			return 0;
		}

		if(!nonblocking &&
		   pd->dag_timeout &&
		   (pd->dag_mem_top - pd->dag_mem_bottom < dag_record_size))
		{
			/* Blocking mode, but timeout set and no data has arrived, return anyway.*/
			return 0;
		}

	}

	/*
	 * Process the packets.
	 *
	 * This assumes that a single buffer of packets will have
	 * <= INT_MAX packets, so the packet count doesn't overflow.
	 */
	while (pd->dag_mem_top - pd->dag_mem_bottom >= dag_record_size) {

		unsigned short packet_len = 0;
		int caplen = 0;
		struct pcap_pkthdr	pcap_header;

		dag_record_t *header = (dag_record_t *)(pd->dag_mem_bottom);

		u_char *dp = ((u_char *)header); /* + dag_record_size; */
		unsigned short rlen;

		/*
		 * Has "pcap_breakloop()" been called?
		 */
		if (p->break_loop)
			return PCAP_ERROR_BREAK;

		rlen = ntohs(header->rlen);
		if (rlen < dag_record_size)
		{
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "%s: record too small", __func__);
			return PCAP_ERROR;
		}
		pd->dag_mem_bottom += rlen;

		uint8_t erf_type = header->type & ERF_TYPE_MASK;

		/* Count lost packets. */
		switch(erf_type) {
			/* in these types the color value overwrites the lctr */
		case ERF_TYPE_COLOR_HDLC_POS:
		case ERF_TYPE_COLOR_ETH:
		case ERF_TYPE_DSM_COLOR_HDLC_POS:
		case ERF_TYPE_DSM_COLOR_ETH:
		case ERF_TYPE_COLOR_MC_HDLC_POS:
		case ERF_TYPE_COLOR_HASH_ETH:
		case ERF_TYPE_COLOR_HASH_POS:
			break;

		default:
			if ( (pd->drop_attr == kNullAttributeUuid) && (header->lctr) ) {
				pd->stat.ps_drop += ntohs(header->lctr);
			}
		}

		if (erf_type == ERF_TYPE_PAD) {
			continue;
		}

		num_ext_hdr = dag_erf_ext_header_count(dp, rlen);

		/* ERF encapsulation */
		/* The Extensible Record Format is not dropped for this kind of encapsulation,
		 * and will be handled as a pseudo header by the decoding application.
		 * The information carried in the ERF header and in the optional subheader (if present)
		 * could be merged with the libpcap information, to offer a better decoding.
		 * The packet length is
		 * o the length of the packet on the link (header->wlen),
		 * o plus the length of the ERF header (dag_record_size), as the length of the
		 *   pseudo header will be adjusted during the decoding,
		 * o plus the length of the optional subheader (if present).
		 *
		 * The capture length is header.rlen and the byte stuffing for alignment will be dropped
		 * if the capture length is greater than the packet length.
		 */
		if (p->linktype == DLT_ERF) {
			packet_len = ntohs(header->wlen) + dag_record_size;
			caplen = rlen;
			switch (erf_type) {
			case ERF_TYPE_MC_AAL5:
			case ERF_TYPE_MC_ATM:
			case ERF_TYPE_MC_HDLC:
			case ERF_TYPE_MC_RAW_CHANNEL:
			case ERF_TYPE_MC_RAW:
			case ERF_TYPE_MC_AAL2:
			case ERF_TYPE_COLOR_MC_HDLC_POS:
				packet_len += 4; /* MC header */
				break;

			case ERF_TYPE_COLOR_HASH_ETH:
			case ERF_TYPE_DSM_COLOR_ETH:
			case ERF_TYPE_COLOR_ETH:
			case ERF_TYPE_ETH:
				packet_len += 2; /* ETH header */
				break;
			} /* switch type */

			/* Include ERF extension headers */
			packet_len += (8 * num_ext_hdr);

			if (caplen > packet_len) {
				caplen = packet_len;
			}
		} else {
			/* Other kind of encapsulation according to the header Type */

			/* Skip over generic ERF header */
			dp += dag_record_size;
			/* Skip over extension headers */
			dp += 8 * num_ext_hdr;

			switch(erf_type) {
			case ERF_TYPE_ATM:
			case ERF_TYPE_AAL5:
				if (erf_type == ERF_TYPE_AAL5) {
					packet_len = ntohs(header->wlen);
					caplen = rlen - dag_record_size;
				}
				/* FALLTHROUGH */
			case ERF_TYPE_MC_ATM:
				if (erf_type == ERF_TYPE_MC_ATM) {
					caplen = packet_len = ATM_CELL_SIZE;
					dp+=4;
				}
				/* FALLTHROUGH */
			case ERF_TYPE_MC_AAL5:
				if (erf_type == ERF_TYPE_MC_AAL5) {
					packet_len = ntohs(header->wlen);
					caplen = rlen - dag_record_size - 4;
					dp+=4;
				}
				/* Skip over extension headers */
				caplen -= (8 * num_ext_hdr);

				if (erf_type == ERF_TYPE_ATM) {
					caplen = packet_len = ATM_CELL_SIZE;
				}
				if (p->linktype == DLT_SUNATM) {
					struct sunatm_hdr *sunatm = (struct sunatm_hdr *)dp;
					unsigned long rawatm;

					rawatm = ntohl(*((uint32_t *)dp));
					sunatm->vci = htons((rawatm >>  4) & 0xffff);
					sunatm->vpi = (rawatm >> 20) & 0x00ff;
					sunatm->flags = ((header->flags.iface & 1) ? 0x80 : 0x00) |
						((sunatm->vpi == 0 && sunatm->vci == htons(5)) ? 6 :
						 ((sunatm->vpi == 0 && sunatm->vci == htons(16)) ? 5 :
						  ((dp[ATM_HDR_SIZE] == 0xaa &&
						    dp[ATM_HDR_SIZE+1] == 0xaa &&
						    dp[ATM_HDR_SIZE+2] == 0x03) ? 2 : 1)));

				} else if (p->linktype == DLT_ATM_RFC1483) {
					packet_len -= ATM_HDR_SIZE;
					caplen -= ATM_HDR_SIZE;
					dp += ATM_HDR_SIZE;
				} else
					continue;
				break;

			case ERF_TYPE_COLOR_HASH_ETH:
			case ERF_TYPE_DSM_COLOR_ETH:
			case ERF_TYPE_COLOR_ETH:
			case ERF_TYPE_ETH:
				if ((p->linktype != DLT_EN10MB) &&
				    (p->linktype != DLT_DOCSIS))
					continue;
				packet_len = ntohs(header->wlen);
				packet_len -= (pd->dag_fcs_bits >> 3);
				caplen = rlen - dag_record_size - 2;
				/* Skip over extension headers */
				caplen -= (8 * num_ext_hdr);
				if (caplen > packet_len) {
					caplen = packet_len;
				}
				dp += 2;
				break;

			case ERF_TYPE_COLOR_HASH_POS:
			case ERF_TYPE_DSM_COLOR_HDLC_POS:
			case ERF_TYPE_COLOR_HDLC_POS:
			case ERF_TYPE_HDLC_POS:
				if ((p->linktype != DLT_CHDLC) &&
				    (p->linktype != DLT_PPP_SERIAL) &&
				    (p->linktype != DLT_FRELAY))
					continue;
				packet_len = ntohs(header->wlen);
				packet_len -= (pd->dag_fcs_bits >> 3);
				caplen = rlen - dag_record_size;
				/* Skip over extension headers */
				caplen -= (8 * num_ext_hdr);
				if (caplen > packet_len) {
					caplen = packet_len;
				}
				break;

			case ERF_TYPE_COLOR_MC_HDLC_POS:
			case ERF_TYPE_MC_HDLC:
				if ((p->linktype != DLT_CHDLC) &&
				    (p->linktype != DLT_PPP_SERIAL) &&
				    (p->linktype != DLT_FRELAY) &&
				    (p->linktype != DLT_MTP2) &&
				    (p->linktype != DLT_MTP2_WITH_PHDR) &&
				    (p->linktype != DLT_LAPD))
					continue;
				packet_len = ntohs(header->wlen);
				packet_len -= (pd->dag_fcs_bits >> 3);
				caplen = rlen - dag_record_size - 4;
				/* Skip over extension headers */
				caplen -= (8 * num_ext_hdr);
				if (caplen > packet_len) {
					caplen = packet_len;
				}
				/* jump the MC_HDLC_HEADER */
				dp += 4;
				if (p->linktype == DLT_MTP2_WITH_PHDR) {
					/* Add the MTP2 Pseudo Header */
					caplen += MTP2_HDR_LEN;
					packet_len += MTP2_HDR_LEN;

					TempPkt[MTP2_SENT_OFFSET] = 0;
					TempPkt[MTP2_ANNEX_A_USED_OFFSET] = MTP2_ANNEX_A_USED_UNKNOWN;
					*(TempPkt+MTP2_LINK_NUMBER_OFFSET) = ((header->rec.mc_hdlc.mc_header>>16)&0x01);
					*(TempPkt+MTP2_LINK_NUMBER_OFFSET+1) = ((header->rec.mc_hdlc.mc_header>>24)&0xff);
					memcpy(TempPkt+MTP2_HDR_LEN, dp, caplen);
					dp = TempPkt;
				}
				break;

			case ERF_TYPE_IPV4:
				if ((p->linktype != DLT_RAW) &&
				    (p->linktype != DLT_IPV4))
					continue;
				packet_len = ntohs(header->wlen);
				caplen = rlen - dag_record_size;
				/* Skip over extension headers */
				caplen -= (8 * num_ext_hdr);
				if (caplen > packet_len) {
					caplen = packet_len;
				}
				break;

			case ERF_TYPE_IPV6:
				if ((p->linktype != DLT_RAW) &&
				    (p->linktype != DLT_IPV6))
					continue;
				packet_len = ntohs(header->wlen);
				caplen = rlen - dag_record_size;
				/* Skip over extension headers */
				caplen -= (8 * num_ext_hdr);
				if (caplen > packet_len) {
					caplen = packet_len;
				}
				break;

			/* These types have no matching 'native' DLT, but can be used with DLT_ERF above */
			case ERF_TYPE_MC_RAW:
			case ERF_TYPE_MC_RAW_CHANNEL:
			case ERF_TYPE_IP_COUNTER:
			case ERF_TYPE_TCP_FLOW_COUNTER:
			case ERF_TYPE_INFINIBAND:
			case ERF_TYPE_RAW_LINK:
			case ERF_TYPE_INFINIBAND_LINK:
			default:
				/* Unhandled ERF type.
				 * Ignore rather than generating error
				 */
				continue;
			} /* switch type */

		} /* ERF encapsulation */

		/*
		 * In this libpcap module the two length arguments of
		 * pcapint_filter() (the wire length and the captured length)
		 * can have different values.
		 *
		 * The wire length of this packet is packet_len, which is
		 * derived from ERF wlen; the captured length of this packet
		 * is caplen, which is derived from ERF rlen, which in turn
		 * depends on the card/stream slen; the snapshot length
		 * configured for this pcap handle is p->snapshot.
		 */
		if ((p->fcode.bf_insns == NULL) || pcapint_filter(p->fcode.bf_insns, dp, packet_len, caplen)) {

			/* convert between timestamp formats */
			register unsigned long long ts;

#if __BYTE_ORDER == __BIG_ENDIAN
			ts = SWAPLL(header->ts);
#else
			ts = header->ts;
#endif // __BYTE_ORDER

			switch (p->opt.tstamp_precision) {
			case PCAP_TSTAMP_PRECISION_NANO:
				ticks_per_second = 1000000000;
				break;
			case PCAP_TSTAMP_PRECISION_MICRO:
			default:
				ticks_per_second = 1000000;
				break;

			}
			pcap_header.ts.tv_sec = ts >> 32;
			ts = (ts & 0xffffffffULL) * ticks_per_second;
			ts += 0x80000000; /* rounding */
			pcap_header.ts.tv_usec = ts >> 32;
			if (pcap_header.ts.tv_usec >= ticks_per_second) {
				pcap_header.ts.tv_usec -= ticks_per_second;
				pcap_header.ts.tv_sec++;
			}

			/* Fill in our own header data */
			pcap_header.caplen = min(caplen, p->snapshot);
			pcap_header.len = packet_len;

			/* Count the packet. */
			pd->stat.ps_recv++;

			/* Call the user supplied callback function */
			callback(user, &pcap_header, dp);

			/* Only count packets that pass the filter, for consistency with standard Linux behaviour. */
			processed++;
			if (processed == cnt && !PACKET_COUNT_IS_UNLIMITED(cnt))
			{
				/* Reached the user-specified limit. */
				return cnt;
			}
		}
	}

	return processed;
}

/*
 * The minimum number of bytes in a valid Ethernet packet from the beginning
 * of the destination MAC address to the end of the payload, as far as DAG
 * TERF and IEEE 802.3 are concerned.
 */
#define ETH_MINLEN_NOFCS 60

// ...and the maximum, as far as DAG TERF is concerned.
#define ETH_MAXLEN_NOFCS 9596

/*
 * The minimum number of bytes in a valid Ethernet header: the destination and
 * the source MAC addresses, the EtherType.  (This does not take 802.1Q or
 * Q-in-Q into account.)
 */
#define ETH_MINLEN_HDRONLY 14

// Zero padding source (a bit oversized for ERF_TYPE_ETH purposes).
static const uint8_t tx_pad[ETH_MINLEN_NOFCS + 4 + ALIGN_BYTES_MAX];

/*
 * Take an Ethernet frame, build an ERF record around it and feed the record
 * into the [Tx-only] DAG stream.  The frame must not include FCS, which is
 * usually the case for DLT_EN10MB in libpcap.
 */
static int
dag_inject(pcap_t *p, const void *packet, const int plen)
{
	struct pcap_dag *pd = p->priv;

	if (plen <= ETH_MINLEN_HDRONLY || plen > ETH_MAXLEN_NOFCS) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "invalid packet size %d", plen);
		return PCAP_ERROR;
	}

	/*
	 * sizeof(struct dag_record_t) cannot be used because it is much
	 * greater than the specific ERF header in this buffer.
	 */
	const dag_size_t hlen = dag_record_size + 2;
	/*
	 * Some DAG hardware (e.g. 7.5G2) automatically pads outgoing Ethernet
	 * frames that are shorter than the minimum length to make them long
	 * enough.  Other DAG hardware (e.g. 9.2X2) rejects such frames.  Pad
	 * the frame here if necessary and remove this difference from the
	 * problem space.
	 *
	 * If the TERF is expecting Ethernet frames to have a non-zero number
	 * of FCS bytes (typically in order to strip the FCS correctly before
	 * further processing), append a dummy zero FCS of the expected size.
	 */
	const unsigned eth_pad_len = ETH_MINLEN_NOFCS
	    - min(plen, ETH_MINLEN_NOFCS) + pd->terf_fcs_bytes;
	const unsigned rlen = hlen + plen + eth_pad_len;
	const unsigned erf_pad_len = rlen % pd->tx_align_bytes ?
	    pd->tx_align_bytes - rlen % pd->tx_align_bytes :
	    0;
	dag_record_t header = {
		.type = ERF_TYPE_ETH,
		.flags.vlen = 1,
		.rlen = htons(rlen + erf_pad_len),
		.wlen = htons(plen + eth_pad_len),
		// Silence a -Wmissing-field-initializers from old GCC.
		.rec.eth = {0},
	};
	DAG_ERF_SET_IFACE(&header, pd->tx_iface);

	/*
	 * It is fine to feed less data than a complete ERF record at a time so
	 * long as a complete and well-formed ERF record eventually makes it
	 * into the buffer.  This simplifies the process when different parts
	 * of the ERF record come from different memory locations.
	 */
	if (dag_tx_stream_copy_bytes64(p->fd, pd->dag_stream, (uint8_t *)&header, hlen) < 0 ||
	    dag_tx_stream_copy_bytes64(p->fd, pd->dag_stream, (uint8_t *)packet, plen) < 0)
		goto fail;
	/*
	 * Possibly pad to the minimum packet length and/or append a dummy FCS
	 * and/or pad to the next multiple of the detected alignment unit.
	 */
	const unsigned pad_len = eth_pad_len + erf_pad_len;
	if (pad_len &&
	    dag_tx_stream_copy_bytes64(p->fd, pd->dag_stream, (uint8_t *)tx_pad, pad_len) < 0)
		goto fail;
	return plen;

fail:
	pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
	    errno, "dag_tx_stream_copy_bytes64 %s", p->opt.device);
	return PCAP_ERROR;
}

static int
dag_activate_tx(pcap_t *p)
{
	struct pcap_dag *pd = p->priv;

	const char * env = getenv(ENV_TX_IFACE);
	int32_t iface = strtouint31(env, 0);
	if (iface < 0) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "%s: failed parsing %s value \"%s\"",
		    __func__, ENV_TX_IFACE, env);
		return PCAP_ERROR;
	}
	uint32_t ifcount = dag_config_get_interface_count(pd->dag_ref);
	if ((uint32_t)iface >= ifcount) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "%s: invalid %s value %u: this card has %u interface(s)",
		    __func__, ENV_TX_IFACE, iface, ifcount);
		return PCAP_ERROR;
	}
	pd->tx_iface = (uint8_t)iface;

	const dag_card_inf_t *inf = dag_pciinfo(p->fd);
	if (! inf) {
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "dag_pciinfo");
		return PCAP_ERROR;
	}

	if (inf->device_code == PCI_DEVICE_ID_VDAG) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "vDAG Tx streams are not supported");
		return PCAP_ERROR;
	}

	// Determine the correct alignment/padding size for the card.
	switch(inf->device_code) {
	case PCI_DEVICE_ID_DAG9_2X2:
	case PCI_DEVICE_ID_DAG9_2SX2:
		pd->tx_align_bytes = ALIGN_BYTES_9_2;
		break;
	default:
		pd->tx_align_bytes = ALIGN_BYTES_DEFAULT;
	}

	// Read the TERF FCS size for later use by dag_inject().
	dag_component_t cfg_comp = dag_component_get_subcomponent(
	    pd->dag_root, kComponentTerf, 0);
	if (! cfg_comp) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "%s: dag_component_get_subcomponent",
		    __func__);
		return PCAP_ERROR;
	}

	attr_uuid_t cfg_uuid = dag_component_get_config_attribute_uuid(
	    cfg_comp, kUint32AttributeTerfStripCrc);
	if (cfg_uuid == kNullAttributeUuid) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "%s: dag_component_get_config_attribute_uuid",
		    __func__);
		return PCAP_ERROR;
	}

	uint32_t cfg_uint32;
	dag_err_t cfg_err = dag_config_get_uint32_attribute_ex(pd->dag_ref,
	    cfg_uuid, &cfg_uint32);
	if (cfg_err != kDagErrNone) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "%s: dag_config_get_uint32_attribute_ex",
		    __func__);
		return PCAP_ERROR;
	}

	switch (cfg_uint32) {
	case kTerfNoStrip:
		pd->terf_fcs_bytes = 0;
		break;
	case kTerfStrip16:
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "TERF FCS is configured to 16 bits, is this Ethernet?");
		return PCAP_ERROR;
	case kTerfStrip32:
		pd->terf_fcs_bytes = 4;
		break;
	default:
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "failed reading TERF FCS configuration");
		return PCAP_ERROR;
	}

	/*
	 * TODO: It would be nice to verify that the Tx port is
	 * configured for 32-bit Tx FCS, but it is not trivial to
	 * tell the exact subcomponent that has the attribute.
	 */

	return 0;
}

/*
 *  Get a handle for a live capture from the given DAG device.  The promisc
 *  flag is ignored because DAG cards are always promiscuous.  The to_ms
 *  parameter is used in setting the API polling parameters.
 *
 *  See also pcap(3).
 */
static int dag_activate(pcap_t* p)
{
	struct pcap_dag *pd = p->priv;
	char *s;
	int n;
	char * device = p->opt.device;
	int ret;
	dag_size_t mindata;
	struct timeval maxwait;
	struct timeval poll;

	/*
	 * dag_create() has validated the device name syntax and stored the
	 * parsed device and stream numbers to p->priv.  Validate these values
	 * semantically.
	 */
	if (pd->dag_devnum >= DAG_MAX_BOARDS) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "DAG device number %d is too large", pd->dag_devnum);
		ret = PCAP_ERROR_NO_SUCH_DEVICE;
		goto fail;
	}
	if (pd->dag_stream >= DAG_STREAM_MAX) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "DAG stream number %d is too large", pd->dag_stream);
		ret = PCAP_ERROR_NO_SUCH_DEVICE;
		goto fail;
	}
#ifndef ENABLE_DAG_TX
	if (TX_ONLY(pd->dag_stream)) {
		/*
		 * dag_findalldevs() does not return any Tx streams, so
		 * PCAP_ERROR_NO_SUCH_DEVICE is more consistent than
		 * PCAP_ERROR_CAPTURE_NOTSUP.
		 */
		ret = PCAP_ERROR_NO_SUCH_DEVICE;
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "%s: tx (odd numbered) streams not supported for capture", __func__);
		goto fail;
	}
#endif // ENABLE_DAG_TX

	/* setup device parameters */
	if((pd->dag_ref = dag_config_init(device)) == NULL) {
		/*
		 * XXX - does this reliably set errno?
		 */
		if (errno == ENOENT) {
			/*
			 * There's nothing more to say, so clear
			 * the error message.
			 */
			ret = PCAP_ERROR_NO_SUCH_DEVICE;
			p->errbuf[0] = '\0';
		} else if (errno == EPERM || errno == EACCES) {
			ret = PCAP_ERROR_PERM_DENIED;
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "Attempt to open %s failed with %s - additional privileges may be required",
			    device, (errno == EPERM) ? "EPERM" : "EACCES");
		} else {
			ret = PCAP_ERROR;
			pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "dag_config_init %s", device);
		}
		goto fail;
	}

	if((p->fd = dag_config_get_card_fd(pd->dag_ref)) < 0) {
		/*
		 * XXX - does this reliably set errno?
		 */
		ret = PCAP_ERROR;
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "dag_config_get_card_fd %s", device);
		goto failclose;
	}

	/* Open requested stream. Can fail if already locked or on error */
	if (dag_attach_stream64(p->fd, pd->dag_stream, 0, 0) < 0) {
		if (errno == ENOMEM) {
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "dag%u has no memory allocated to %s stream %u",
			    pd->dag_devnum, RXTX_STR(pd->dag_stream), pd->dag_stream);
			/*
			 * dag_findalldevs() does not return streams that do
			 * not have buffer memory, so PCAP_ERROR_NO_SUCH_DEVICE
			 * is more consistent than PCAP_ERROR_CAPTURE_NOTSUP.
			 */
			ret = PCAP_ERROR_NO_SUCH_DEVICE;
			goto failclose;
		} else if (errno == EINVAL) {
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "dag%u has no %s stream %u",
			    pd->dag_devnum, RXTX_STR(pd->dag_stream), pd->dag_stream);
			ret = PCAP_ERROR_NO_SUCH_DEVICE;
			goto failclose;
		}
		ret = PCAP_ERROR;
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "dag_attach_stream64");
		goto failclose;
	}

	/* Try to find Stream Drop attribute */
	pd->drop_attr = kNullAttributeUuid;
	pd->dag_root = dag_config_get_root_component(pd->dag_ref);
	if ( dag_component_get_subcomponent(pd->dag_root, kComponentStreamFeatures, 0) )
	{
		pd->drop_attr = dag_config_get_indexed_attribute_uuid(pd->dag_ref, kUint32AttributeStreamDropCount, pd->dag_stream);
		if (pd->drop_attr != kNullAttributeUuid)
			pd->drop_base = dag_config_get_uint64_attribute(
			    pd->dag_ref, pd->drop_attr);
	}

	/* Set up default poll parameters for stream
	 * Can be overridden by pcap_set_nonblock()
	 */
	if (dag_get_stream_poll64(p->fd, pd->dag_stream,
				&mindata, &maxwait, &poll) < 0) {
		ret = PCAP_ERROR;
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "dag_get_stream_poll64");
		goto faildetach;
	}

	/* Use the poll time as the required select timeout for callers
	 * who are using select()/etc. in an event loop waiting for
	 * packets to arrive.
	 */
	pd->required_select_timeout = poll;
	p->required_select_timeout = &pd->required_select_timeout;

	/*
	 * Turn a negative snapshot value (invalid), a snapshot value of
	 * 0 (unspecified), or a value bigger than the normal maximum
	 * value, into the maximum allowed value.
	 *
	 * If some application really *needs* a bigger snapshot
	 * length, we should just increase MAXIMUM_SNAPLEN.
	 */
	if (p->snapshot <= 0 || p->snapshot > MAXIMUM_SNAPLEN)
		p->snapshot = MAXIMUM_SNAPLEN;

	if (p->opt.immediate) {
		/* Call callback immediately.
		 * XXX - is this the right way to p this?
		 */
		mindata = 0;
	} else {
		/* Amount of data to collect in Bytes before calling callbacks.
		 * Important for efficiency, but can introduce latency
		 * at low packet rates if to_ms not set!
		 */
		mindata = 65536;
	}

	/* Obey opt.timeout (was to_ms) if supplied. This is a good idea!
	 * Recommend 10-100ms. Calls will time out even if no data arrived.
	 */
	maxwait.tv_sec = p->opt.timeout/1000;
	maxwait.tv_usec = (p->opt.timeout%1000) * 1000;

	if (dag_set_stream_poll64(p->fd, pd->dag_stream,
				mindata, &maxwait, &poll) < 0) {
		ret = PCAP_ERROR;
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "dag_set_stream_poll64");
		goto faildetach;
	}

	if(dag_start_stream(p->fd, pd->dag_stream) < 0) {
		ret = PCAP_ERROR;
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "dag_start_stream %s", device);
		goto faildetach;
	}

	/*
	 * Important! You have to ensure bottom is properly
	 * initialized to zero on startup, it won't give you
	 * a compiler warning if you make this mistake!
	 */
	pd->dag_mem_bottom = 0;
	pd->dag_mem_top = 0;

	/*
	 * Find out how many FCS bits we should strip.
	 * Assume Rx FCS length to be 32 bits unless the user has
	 * requested a different value, in which case validate it well.
	 */
	s = getenv(ENV_RX_FCS_BITS);
	switch ((n = strtouint31(s, 32))) {
	case 0:
	case 16:
	case 32:
		pd->dag_fcs_bits = n;
		break;
	default:
		ret = PCAP_ERROR;
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "%s %s: invalid %s value (%s) in environment",
		    __func__, device, ENV_RX_FCS_BITS, s);
		goto failstop;
	}

	/*
	 * Did the user request that they not be stripped?
	 */
	s = getenv(ENV_RX_FCS_NOSTRIP);
	switch ((n = strtouint31(s, 0))) {
	case 0:
		break;
	case 1:
		/* Yes.  Note the number of 16-bit words that will be
		   supplied. */
		p->linktype_ext = LT_FCS_DATALINK_EXT(pd->dag_fcs_bits/16);

		/* And don't strip them. */
		pd->dag_fcs_bits = 0;
		break;
	default:
		ret = PCAP_ERROR;
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "%s %s: invalid %s value (%s) in environment",
		    __func__, device, ENV_RX_FCS_NOSTRIP, s);
		goto failstop;
	}

	if (TX_ONLY(pd->dag_stream) && dag_activate_tx(p) < 0) {
		ret = PCAP_ERROR;
		goto failstop;
	}

	pd->dag_timeout	= p->opt.timeout;

	if (dag_get_datalink(p) < 0) {
		ret = PCAP_ERROR;
		goto failstop;
	}

	p->bufsize = 0;

	if (new_pcap_dag(p) < 0) {
		ret = PCAP_ERROR;
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "new_pcap_dag %s", device);
		goto failstop;
	}

	/*
	 * "select()" and "poll()" don't work on DAG device descriptors.
	 */
	p->selectable_fd = -1;

	p->read_op = RX_ONLY(pd->dag_stream) ?
	    dag_read :
	    dag_read_notimpl;
	p->inject_op = TX_ONLY(pd->dag_stream) ?
	    dag_inject :
	    dag_inject_notimpl;
	p->setfilter_op = RX_ONLY(pd->dag_stream) ?
	    pcapint_install_bpf_program :
	    dag_install_bpf_program_notimpl;
	p->setdirection_op = NULL; /* Not implemented.*/
	p->set_datalink_op = dag_set_datalink;
	p->getnonblock_op = RX_ONLY(pd->dag_stream) ?
	    pcapint_getnonblock_fd :
	    dag_getnonblock_fd_notimpl;
	p->setnonblock_op = RX_ONLY(pd->dag_stream) ?
	    dag_setnonblock :
	    dag_setnonblock_notimpl;
	p->stats_op = RX_ONLY(pd->dag_stream) ?
	    dag_stats :
	    dag_stats_notimpl;
	p->cleanup_op = dag_platform_cleanup;
	pd->stat.ps_drop = 0;
	pd->stat.ps_recv = 0;
	pd->stat.ps_ifdrop = 0;
	return 0;

failstop:
	if (dag_stop_stream(p->fd, pd->dag_stream) < 0) {
		fprintf(stderr,"dag_stop_stream: %s\n", strerror(errno));
	}

faildetach:
	if (dag_detach_stream(p->fd, pd->dag_stream) < 0)
		fprintf(stderr,"dag_detach_stream: %s\n", strerror(errno));

failclose:
	dag_config_dispose(pd->dag_ref);
	/*
	 * Note: we don't need to call close(p->fd) or dag_close(p->fd),
	 * as dag_config_dispose(pd->dag_ref) does this.
	 *
	 * Set p->fd to -1 to make sure that's not done.
	 */
	p->fd = -1;
	pd->dag_ref = NULL;
	delete_pcap_dag(p);

fail:
	pcapint_cleanup_live_common(p);

	return ret;
}

pcap_t *dag_create(const char *device, char *ebuf, int *is_ours)
{
	const char *cp;
	char *cpend;
	long devnum;
	pcap_t *p;
	long stream = 0;

	/*
	 * The nominal libpcap DAG device name format is either "dagN" or
	 * "dagN:M", as returned from dag_findalldevs().
	 *
	 * First attempt the most basic syntax validation.  If the device string
	 * does not look like a potentially valid DAG device name, reject it
	 * silently to have pcap_create() try another capture source type.
	 */
	*is_ours = 0;

	/* Does this look like a DAG device? */
	cp = device;
	/* Does it begin with "dag"? */
	if (strncmp(cp, "dag", 3) != 0) {
		/* Nope, doesn't begin with "dag" */
		return NULL;
	}
	/* Yes - is "dag" followed by a number from 0 to DAG_MAX_BOARDS-1 */
	cp += 3;
	devnum = strtol(cp, &cpend, 10);
	if (*cpend == ':') {
		/* Followed by a stream number. */
		stream = strtol(++cpend, &cpend, 10);
	}

	if (cpend == cp || *cpend != '\0') {
		/* Not followed by a number. */
		return NULL;
	}

	/*
	 * OK, it's probably ours, validate the syntax further.  From now on
	 * reject the device string authoritatively with an error message to
	 * have pcap_create() propagate the failure.  Validate the device and
	 * stream number ranges loosely only.
	 */
	*is_ours = 1;
	snprintf (ebuf, PCAP_ERRBUF_SIZE,
	    "DAG device name \"%s\" is invalid", device);

	if (devnum < 0 || devnum > INT_MAX) {
		/* Followed by a non-valid number. */
		return NULL;
	}

	if (stream < 0 || stream > INT_MAX) {
		/* Followed by a non-valid stream number. */
		return NULL;
	}

	/*
	 * The syntax validation done so far is lax enough to accept some
	 * device strings that are not actually acceptable in libpcap as
	 * defined above.  The device strings that are acceptable in libpcap
	 * are a strict subset of the device strings that are acceptable in
	 * dag_parse_name(), thus using the latter for validation in libpcap
	 * would not work reliably.  Instead from the detected device and
	 * stream numbers produce the acceptable device string(s) and require
	 * the input device string to match an acceptable string exactly.
	 */
	char buf[DAGNAME_BUFSIZE];
	snprintf(buf, sizeof(buf), "dag%ld:%ld", devnum, stream);
	char acceptable = ! strcmp(device, buf);
	if (! acceptable && stream == 0) {
		snprintf(buf, sizeof(buf), "dag%ld", devnum);
		acceptable = ! strcmp(device, buf);
	}
	if (! acceptable)
		return NULL;

	/*
	 * The device string syntax is acceptable, save the device and stream
	 * numbers for dag_activate(), which will do semantic and run-time
	 * validation and possibly reject the pcap_t using more specific error
	 * codes.
	 */
	ebuf[0] = '\0';
	p = PCAP_CREATE_COMMON(ebuf, struct pcap_dag);
	if (p == NULL)
		return NULL;

	p->activate_op = dag_activate;

	/*
	 * We claim that we support microsecond and nanosecond time
	 * stamps.
	 *
	 * XXX Our native precision is 2^-32s, but libpcap doesn't support
	 * power of two precisions yet. We can convert to either MICRO or NANO.
	 */
	p->tstamp_precision_list = malloc(2 * sizeof(u_int));
	if (p->tstamp_precision_list == NULL) {
		pcapint_fmt_errmsg_for_errno(ebuf, PCAP_ERRBUF_SIZE,
		    errno, "malloc");
		pcap_close(p);
		return NULL;
	}
	p->tstamp_precision_list[0] = PCAP_TSTAMP_PRECISION_MICRO;
	p->tstamp_precision_list[1] = PCAP_TSTAMP_PRECISION_NANO;
	p->tstamp_precision_count = 2;
	struct pcap_dag *pd = p->priv;
	pd->dag_devnum = (int)devnum;
	pd->dag_stream = (int)stream;
	return p;
}

static int
dag_stats(pcap_t *p, struct pcap_stat *ps) {
	struct pcap_dag *pd = p->priv;
	uint64_t stream_drop;
	dag_err_t dag_error;

	/*
	 * Packet records received (ps_recv) are counted in dag_read().
	 * Packet records dropped (ps_drop) are read from Stream Drop attribute if present,
	 * otherwise integrate the ERF Header lctr counts (if available) in dag_read().
	 * We are reporting that no records are dropped by the card/driver (ps_ifdrop).
	 */

	if(pd->drop_attr != kNullAttributeUuid) {
		/* Note this counter is cleared at start of capture and will wrap at UINT_MAX.
		 * The application is responsible for polling ps_drop frequently enough
		 * to detect each wrap and integrate total drop with a wider counter */
		if ((dag_error = dag_config_get_uint64_attribute_ex(pd->dag_ref, pd->drop_attr, &stream_drop)) == kDagErrNone) {
			pd->stat.ps_drop = (u_int)(stream_drop - pd->drop_base);
		} else {
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "reading stream drop attribute: %s",
				 dag_config_strerror(dag_error));
			return PCAP_ERROR;
		}
	}

	*ps = pd->stat;

	return 0;
}

static const char *
dag_device_description(const unsigned dagid)
{
	static char buf[128];
	snprintf(buf, sizeof(buf), "alias for dag%u:0", dagid);
	return buf;
}

static const char *
dag_stream_short_description(const unsigned stream)
{
	static char buf[128];
	snprintf(buf, sizeof(buf), "%s stream %u", RXTX_STR(stream), stream);
	return buf;
}

static const char *
dag_stream_long_description(const unsigned stream, const dag_size_t bufsize,
    const dag_card_inf_t * inf)
{
	static char buf[256];
	int done = snprintf(buf, sizeof(buf),
	    "%s stream %u, %" PRIu64 " MiB, %s",
	    RXTX_STR(stream),
	    stream,
	    bufsize / 1024 / 1024,
	    inf ? dag_device_name(inf->device_code, 1) : "N/A");
	if (inf->device_code != PCI_DEVICE_ID_VDAG)
		snprintf(buf + done, sizeof(buf) - done,
		    " rev %c at %s",
		    (inf && inf->brd_rev < 26) ? ('A' + inf->brd_rev) : '?',
		    inf ? inf->bus_id : "N/A");
	return buf;
}

/*
 * Add all DAG devices.
 */
int
dag_findalldevs(pcap_if_list_t *devlistp, char *errbuf)
{
	int c;
	int dagfd;
	const char * description;
	int stream, rxstreams;
	// A DAG card associates a link status with each physical port, but not
	// with the data streams.  The number of ports is a matter of hardware,
	// the number of streams and how each stream associates with zero or
	// more ports is a matter of how the user configures the card.  In this
	// context libpcap uses the streams only (i.e. "dag0" is a shorthand
	// for "dag0:0"), thus the notion of link status does not apply to the
	// resulting libpcap DAG capture devices.
	const bpf_u_int32 flags = PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE;
	FILE * sysfsinfo = NULL;

	/* Try all the DAGs 0-DAG_MAX_BOARDS */
	for (c = 0; c < DAG_MAX_BOARDS; c++) {
		char name[DAGNAME_BUFSIZE]; // libpcap device
		snprintf(name, sizeof(name), "dag%d", c);
		char dagname[DAGNAME_BUFSIZE]; // DAG API device
		snprintf(dagname, sizeof(dagname), "/dev/dag%d", c);
		if ( (dagfd = dag_open(dagname)) >= 0 ) {
			// Do not add a shorthand device for stream 0 (dagN) yet -- the
			// user can disable any stream in the card configuration.
			const dag_card_inf_t * inf = dag_pciinfo(dagfd); // NULL is fine
			// The count includes existing streams that have no buffer memory.
			rxstreams = dag_rx_get_stream_count(dagfd);
			if (rxstreams < 0) {
				pcapint_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE,
				    errno, "dag_rx_get_stream_count");
				goto failclose;
			}
			int txstreams = 0;
#ifdef ENABLE_DAG_TX
			txstreams = dag_tx_get_stream_count(dagfd);
			if (txstreams < 0) {
				pcapint_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE,
				    errno, "dag_tx_get_stream_count");
				goto failclose;
			}
#endif // ENABLE_DAG_TX
			for(stream = 0;
			    stream < DAG_STREAM_MAX && (rxstreams > 0 || txstreams > 0);
			    stream++) {
#ifndef ENABLE_DAG_TX
				if (TX_ONLY(stream))
					continue;
#endif // ENABLE_DAG_TX
				/*
				 * dag_attach_stream64() was used before to test if the
				 * stream exists, but it is not the best tool for the
				 * job because it tries to lock the stream exclusively.
				 * If the stream is already locked by another process,
				 * it fails with EBUSY, otherwise it creates a race
				 * condition for other processes that may be trying to
				 * lock the same stream at the same time.  Therefore
				 * dag_get_stream_buffer_size64() seems to be a better
				 * fit.
				 */
				dag_ssize_t bufsize = dag_get_stream_buffer_size64(dagfd, stream);
				if (bufsize < 0)
					continue; // Does not exist.
				// Only streams with buffer memory are usable.
				if (bufsize > 0 &&
				    (RX_ONLY(stream) || inf->device_code != PCI_DEVICE_ID_VDAG)) {
					description = dag_device_description (c);
					// a conditional shorthand device
					if (stream == 0 &&
					    pcapint_add_dev(devlistp, name, flags, description, errbuf) == NULL)
						goto failclose;
					// and the stream device
					snprintf(name,  sizeof(name), "dag%d:%d", c, stream);
					description = dag_stream_long_description(stream,
					    dag_get_stream_buffer_size64(dagfd, stream), inf);
					if (pcapint_add_dev(devlistp, name, flags, description, errbuf) == NULL) {
						goto failclose;
					}
				}
				if (RX_ONLY(stream))
					rxstreams--;
				else
					txstreams--;
			}
			dag_close(dagfd);
			dagfd = -1;
		} else if (errno == EACCES) {
			// The device exists, but the current user privileges are not
			// sufficient for dag_open().
			// Do not add a shorthand device for stream 0 yet -- same as above.
			// Try enumerating the streams using sysfs.  The file lists
			// all streams (Rx and Tx) that have non-zero amount of buffer
			// memory.
			char sysfspath[PATH_MAX];
			snprintf(sysfspath, sizeof(sysfspath), "/sys/devices/virtual/dag/%s/info", name);
			if ((sysfsinfo = fopen(sysfspath, "r"))) {
				char linebuf[1024];
				while (fgets(linebuf, sizeof(linebuf), sysfsinfo))
					if (1 == sscanf(linebuf, "Stream %u:", &stream)) {
#ifndef ENABLE_DAG_TX
						if (TX_ONLY(stream))
							continue;
#endif // ENABLE_DAG_TX
						// a conditional shorthand device
						description = dag_device_description(c);
						if (stream == 0 &&
						    pcapint_add_dev(devlistp, name, flags, description, errbuf) == NULL)
							goto failclose;
						// and the stream device
						snprintf(name,  sizeof(name), "dag%u:%u", c, stream);
						// TODO: Parse and describe the buffer size too.
						description = dag_stream_short_description(stream);
						if (pcapint_add_dev(devlistp, name, flags, description, errbuf) == NULL)
							goto failclose;
					}
				fclose(sysfsinfo);
				sysfsinfo = NULL;
			}
		} // errno == EACCES

	}
	return (0);

failclose:
	if (dagfd >= 0)
		dag_close(dagfd);
	if (sysfsinfo)
		fclose(sysfsinfo);
	return PCAP_ERROR;
}

static int
dag_set_datalink(pcap_t *p, int dlt)
{
	p->linktype = dlt;

	return (0);
}

static int
dag_setnonblock(pcap_t *p, int nonblock)
{
	struct pcap_dag *pd = p->priv;
	dag_size_t mindata;
	struct timeval maxwait;
	struct timeval poll;

	/*
	 * Set non-blocking mode on the FD.
	 * XXX - is that necessary?  If not, don't bother calling it,
	 * and have a "dag_getnonblock()" function that looks at
	 * "pd->dag_flags".
	 */
	if (pcapint_setnonblock_fd(p, nonblock) < 0)
		return PCAP_ERROR;

	if (dag_get_stream_poll64(p->fd, pd->dag_stream,
				&mindata, &maxwait, &poll) < 0) {
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "dag_get_stream_poll64");
		return PCAP_ERROR;
	}

	/* Amount of data to collect in Bytes before calling callbacks.
	 * Important for efficiency, but can introduce latency
	 * at low packet rates if to_ms not set!
	 */
	if(nonblock)
		mindata = 0;
	else
		mindata = 65536;

	if (dag_set_stream_poll64(p->fd, pd->dag_stream,
				mindata, &maxwait, &poll) < 0) {
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "dag_set_stream_poll64");
		return PCAP_ERROR;
	}

	if (nonblock) {
		pd->dag_flags |= DAGF_NONBLOCK;
	} else {
		pd->dag_flags &= ~DAGF_NONBLOCK;
	}
	return (0);
}

static int
dag_get_datalink(pcap_t *p)
{
	struct pcap_dag *pd = p->priv;

	/*
	 * There seems to be no trivial way to tell which ERF type(s) a Tx
	 * stream would accept.  Let's assume ERF_TYPE_ETH would work, which
	 * in libpcap terms means using DLT_EN10MB.
	 */
	if (TX_ONLY(pd->dag_stream))
		return (p->linktype = DLT_EN10MB);

	int index=0, dlt_index=0;
	uint8_t types[255];

	memset(types, 0, 255);

	if (p->dlt_list == NULL && (p->dlt_list = malloc(255*sizeof(*(p->dlt_list)))) == NULL) {
		pcapint_fmt_errmsg_for_errno(p->errbuf, sizeof(p->errbuf),
		    errno, "malloc");
		return PCAP_ERROR;
	}

	p->linktype = 0;

	/* Get list of possible ERF types for this card */
	if (dag_get_stream_erf_types(p->fd, pd->dag_stream, types, 255) < 0) {
		pcapint_fmt_errmsg_for_errno(p->errbuf, sizeof(p->errbuf),
		    errno, "dag_get_stream_erf_types");
		return PCAP_ERROR;
	}

	while (types[index]) {

		switch((types[index] & ERF_TYPE_MASK)) {

		case ERF_TYPE_HDLC_POS:
		case ERF_TYPE_COLOR_HDLC_POS:
		case ERF_TYPE_DSM_COLOR_HDLC_POS:
		case ERF_TYPE_COLOR_HASH_POS:
			p->dlt_list[dlt_index++] = DLT_CHDLC;
			p->dlt_list[dlt_index++] = DLT_PPP_SERIAL;
			p->dlt_list[dlt_index++] = DLT_FRELAY;
			if(!p->linktype)
				p->linktype = DLT_CHDLC;
			break;

		case ERF_TYPE_ETH:
		case ERF_TYPE_COLOR_ETH:
		case ERF_TYPE_DSM_COLOR_ETH:
		case ERF_TYPE_COLOR_HASH_ETH:
			/*
			 * This is (presumably) a real Ethernet capture; give it a
			 * link-layer-type list with DLT_EN10MB and DLT_DOCSIS, so
			 * that an application can let you choose it, in case you're
			 * capturing DOCSIS traffic that a Cisco Cable Modem
			 * Termination System is putting out onto an Ethernet (it
			 * doesn't put an Ethernet header onto the wire, it puts raw
			 * DOCSIS frames out on the wire inside the low-level
			 * Ethernet framing).
			 */
			p->dlt_list[dlt_index++] = DLT_EN10MB;
			p->dlt_list[dlt_index++] = DLT_DOCSIS;
			if(!p->linktype)
				p->linktype = DLT_EN10MB;
			break;

		case ERF_TYPE_ATM:
		case ERF_TYPE_AAL5:
		case ERF_TYPE_MC_ATM:
		case ERF_TYPE_MC_AAL5:
			p->dlt_list[dlt_index++] = DLT_ATM_RFC1483;
			p->dlt_list[dlt_index++] = DLT_SUNATM;
			if(!p->linktype)
				p->linktype = DLT_ATM_RFC1483;
			break;

		case ERF_TYPE_COLOR_MC_HDLC_POS:
		case ERF_TYPE_MC_HDLC:
			p->dlt_list[dlt_index++] = DLT_CHDLC;
			p->dlt_list[dlt_index++] = DLT_PPP_SERIAL;
			p->dlt_list[dlt_index++] = DLT_FRELAY;
			p->dlt_list[dlt_index++] = DLT_MTP2;
			p->dlt_list[dlt_index++] = DLT_MTP2_WITH_PHDR;
			p->dlt_list[dlt_index++] = DLT_LAPD;
			if(!p->linktype)
				p->linktype = DLT_CHDLC;
			break;

		case ERF_TYPE_IPV4:
			p->dlt_list[dlt_index++] = DLT_RAW;
			p->dlt_list[dlt_index++] = DLT_IPV4;
			if(!p->linktype)
				p->linktype = DLT_RAW;
			break;

		case ERF_TYPE_IPV6:
			p->dlt_list[dlt_index++] = DLT_RAW;
			p->dlt_list[dlt_index++] = DLT_IPV6;
			if(!p->linktype)
				p->linktype = DLT_RAW;
			break;

		case ERF_TYPE_LEGACY:
		case ERF_TYPE_MC_RAW:
		case ERF_TYPE_MC_RAW_CHANNEL:
		case ERF_TYPE_IP_COUNTER:
		case ERF_TYPE_TCP_FLOW_COUNTER:
		case ERF_TYPE_INFINIBAND:
		case ERF_TYPE_RAW_LINK:
		case ERF_TYPE_INFINIBAND_LINK:
		case ERF_TYPE_META:
		default:
			/* Libpcap cannot deal with these types yet */
			/* Add no 'native' DLTs, but still covered by DLT_ERF */
			break;

		} /* switch */
		index++;
	}

	p->dlt_list[dlt_index++] = DLT_ERF;

	p->dlt_count = dlt_index;

	if(!p->linktype)
		p->linktype = DLT_ERF;

	return p->linktype;
}

#ifdef DAG_ONLY
/*
 * This libpcap build supports only DAG cards, not regular network
 * interfaces.
 */

/*
 * There are no regular interfaces, just DAG interfaces.
 */
int
pcapint_platform_finddevs(pcap_if_list_t *devlistp _U_, char *errbuf _U_)
{
	return (0);
}

/*
 * Attempts to open a regular interface fail.
 */
pcap_t *
pcapint_create_interface(const char *device _U_, char *errbuf)
{
	snprintf(errbuf, PCAP_ERRBUF_SIZE, PCAP_ENODEV_MESSAGE, "DAG");
	return NULL;
}

/*
 * Libpcap version string.
 */
const char *
pcap_lib_version(void)
{
	return (PCAP_VERSION_STRING " (DAG-only)");
}
#endif
