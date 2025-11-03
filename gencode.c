/*
 * Copyright (c) 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 1998
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <config.h>

#ifdef _WIN32
  #include <ws2tcpip.h>
#else
  #include <netinet/in.h>
#endif /* _WIN32 */

#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#include "pcap-int.h"
#include "thread-local.h"

#include "extract.h"

#include "ethertype.h"
#include "llc.h"
#include "gencode.h"
#include "ieee80211.h"
#include "pflog.h"
#include "ppp.h"
#include "pcap/sll.h"
#include "pcap/ipnet.h"
#include "diag-control.h"
#include "pcap-util.h"

#include "scanner.h"

#if defined(__linux__)
#include <linux/types.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#endif

#ifdef _WIN32
  #ifdef HAVE_NPCAP_BPF_H
    /* Defines BPF extensions for Npcap */
    #include <npcap-bpf.h>
  #endif
    #if defined(__MINGW32__) && defined(DEFINE_ADDITIONAL_IPV6_STUFF)
/* IPv6 address */
struct in6_addr
  {
    union
      {
	uint8_t		u6_addr8[16];
	uint16_t	u6_addr16[8];
	uint32_t	u6_addr32[4];
      } in6_u;
#define s6_addr			in6_u.u6_addr8
#define s6_addr16		in6_u.u6_addr16
#define s6_addr32		in6_u.u6_addr32
#define s6_addr64		in6_u.u6_addr64
  };

typedef unsigned short	sa_family_t;

#define	__SOCKADDR_COMMON(sa_prefix) \
  sa_family_t sa_prefix##family

/* Ditto, for IPv6.  */
struct sockaddr_in6
  {
    __SOCKADDR_COMMON (sin6_);
    uint16_t sin6_port;		/* Transport layer port # */
    uint32_t sin6_flowinfo;	/* IPv6 flow information */
    struct in6_addr sin6_addr;	/* IPv6 address */
  };

      #ifndef EAI_ADDRFAMILY
struct addrinfo {
	int	ai_flags;	/* AI_PASSIVE, AI_CANONNAME */
	int	ai_family;	/* PF_xxx */
	int	ai_socktype;	/* SOCK_xxx */
	int	ai_protocol;	/* 0 or IPPROTO_xxx for IPv4 and IPv6 */
	size_t	ai_addrlen;	/* length of ai_addr */
	char	*ai_canonname;	/* canonical name for hostname */
	struct sockaddr *ai_addr;	/* binary address */
	struct addrinfo *ai_next;	/* next structure in linked list */
};
      #endif /* EAI_ADDRFAMILY */
    #endif /* defined(__MINGW32__) && defined(DEFINE_ADDITIONAL_IPV6_STUFF) */
#else /* _WIN32 */
  #include <netdb.h>	/* for "struct addrinfo" */
#endif /* _WIN32 */
#include <pcap/namedb.h>

#include "nametoaddr.h"

#define ETHERMTU	1500

#ifndef IPPROTO_HOPOPTS
#define IPPROTO_HOPOPTS 0
#endif
#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING 43
#endif
#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT 44
#endif
#ifndef IPPROTO_DSTOPTS
#define IPPROTO_DSTOPTS 60
#endif
#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

#define GENEVE_PORT 6081
#define VXLAN_PORT  4789


/*
 * from: NetBSD: if_arc.h,v 1.13 1999/11/19 20:41:19 thorpej Exp
 */

/* RFC 1051 */
#define	ARCTYPE_IP_OLD		240	/* IP protocol */
#define	ARCTYPE_ARP_OLD		241	/* address resolution protocol */

/* RFC 1201 */
#define	ARCTYPE_IP		212	/* IP protocol */
#define	ARCTYPE_ARP		213	/* address resolution protocol */
#define	ARCTYPE_REVARP		214	/* reverse addr resolution protocol */

#define	ARCTYPE_ATALK		221	/* Appletalk */
#define	ARCTYPE_BANIAN		247	/* Banyan Vines */
#define	ARCTYPE_IPX		250	/* Novell IPX */

#define ARCTYPE_INET6		0xc4	/* IPng */
#define ARCTYPE_DIAGNOSE	0x80	/* as per ANSI/ATA 878.1 */


/* Based on UNI3.1 standard by ATM Forum */

/* ATM traffic types based on VPI=0 and (the following VCI */
#define VCI_PPC			0x05	/* Point-to-point signal msg */
#define VCI_BCC			0x02	/* Broadcast signal msg */
#define VCI_OAMF4SC		0x03	/* Segment OAM F4 flow cell */
#define VCI_OAMF4EC		0x04	/* End-to-end OAM F4 flow cell */
#define VCI_METAC		0x01	/* Meta signal msg */
#define VCI_ILMIC		0x10	/* ILMI msg */

/* Q.2931 signalling messages */
#define CALL_PROCEED		0x02	/* call proceeding */
#define CONNECT			0x07	/* connect */
#define CONNECT_ACK		0x0f	/* connect_ack */
#define SETUP			0x05	/* setup */
#define RELEASE			0x4d	/* release */
#define RELEASE_DONE		0x5a	/* release_done */
#define RESTART			0x46	/* restart */
#define RESTART_ACK		0x4e	/* restart ack */
#define STATUS			0x7d	/* status */
#define STATUS_ENQ		0x75	/* status ack */
#define ADD_PARTY		0x80	/* add party */
#define ADD_PARTY_ACK		0x81	/* add party ack */
#define ADD_PARTY_REJ		0x82	/* add party rej */
#define DROP_PARTY		0x83	/* drop party */
#define DROP_PARTY_ACK		0x84	/* drop party ack */

/* Information Element Parameters in the signalling messages */
#define CAUSE			0x08	/* cause */
#define ENDPT_REF		0x54	/* endpoint reference */
#define AAL_PARA		0x58	/* ATM adaptation layer parameters */
#define TRAFF_DESCRIP		0x59	/* atm traffic descriptors */
#define CONNECT_ID		0x5a	/* connection identifier */
#define QOS_PARA		0x5c	/* quality of service parameters */
#define B_HIGHER		0x5d	/* broadband higher layer information */
#define B_BEARER		0x5e	/* broadband bearer capability */
#define B_LOWER			0x5f	/* broadband lower information */
#define CALLING_PARTY		0x6c	/* calling party number */
#define CALLED_PARTY		0x70	/* called party number */

#define Q2931			0x09

/* Q.2931 signalling general messages format */
#define PROTO_POS       0	/* offset of protocol discriminator */
#define CALL_REF_POS    2	/* offset of call reference value */
#define MSG_TYPE_POS    5	/* offset of message type */
#define MSG_LEN_POS     7	/* offset of message length */
#define IE_BEGIN_POS    9	/* offset of first information element */

/* format of signalling messages */
#define TYPE_POS	0
#define LEN_POS		2
#define FIELD_BEGIN_POS 4


/* SunATM header for ATM packet */
#define SUNATM_DIR_POS		0
#define SUNATM_VPI_POS		1
#define SUNATM_VCI_POS		2
#define SUNATM_PKT_BEGIN_POS	4	/* Start of ATM packet */

/* Protocol type values in the bottom for bits of the byte at SUNATM_DIR_POS. */
#define PT_LANE		0x01	/* LANE */
#define PT_LLC		0x02	/* LLC encapsulation */
#define PT_ILMI		0x05	/* ILMI */
#define PT_QSAAL	0x06	/* Q.SAAL */


/* Types missing from some systems */

/*
 * Network layer protocol identifiers
 */
#ifndef ISO8473_CLNP
#define ISO8473_CLNP		0x81
#endif
#ifndef	ISO9542_ESIS
#define	ISO9542_ESIS		0x82
#endif
#ifndef ISO9542X25_ESIS
#define ISO9542X25_ESIS		0x8a
#endif
#ifndef	ISO10589_ISIS
#define	ISO10589_ISIS		0x83
#endif

#define ISIS_L1_LAN_IIH      15
#define ISIS_L2_LAN_IIH      16
#define ISIS_PTP_IIH         17
#define ISIS_L1_LSP          18
#define ISIS_L2_LSP          20
#define ISIS_L1_CSNP         24
#define ISIS_L2_CSNP         25
#define ISIS_L1_PSNP         26
#define ISIS_L2_PSNP         27
/*
 * The maximum possible value can also be used as a bit mask because the
 * "PDU Type" field comprises the least significant 5 bits of a particular
 * octet, see sections 9.5~9.13 of ISO/IEC 10589:2002(E).
 */
#define ISIS_PDU_TYPE_MAX 0x1FU

#ifndef ISO8878A_CONS
#define	ISO8878A_CONS		0x84
#endif
#ifndef	ISO10747_IDRP
#define	ISO10747_IDRP		0x85
#endif

// Same as in tcpdump/print-sl.c.
#define SLIPDIR_IN 0
#define SLIPDIR_OUT 1

#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

/*
 * A valid jump instruction code is a bitwise OR of three values and one of the
 * values is BPF_JMP.  To make sure both of the other two values are always
 * present, define a macro of two arguments and use it instead of ORing the
 * values in place.
 *
 * Note that "ja L" (documented as "jmp L" in the 1993 BPF paper) does not quite
 * follow the pattern and there is no "ja x", but internally it works very much
 * like "ja #k", so JMP(BPF_JA, BPF_K) is appropriate enough.
 */
#define JMP(jtype, src) (BPF_JMP | (jtype) | (src))

/*
 * "Push" the current value of the link-layer header type and link-layer
 * header offset onto a "stack", and set a new value.  (It's not a
 * full-blown stack; we keep only the top two items.)
 */
#define PUSH_LINKHDR(cs, new_linktype, new_is_variable, new_constant_part, new_reg) \
{ \
	(cs)->prevlinktype = (cs)->linktype; \
	(cs)->off_prevlinkhdr = (cs)->off_linkhdr; \
	(cs)->linktype = (new_linktype); \
	(cs)->off_linkhdr.is_variable = (new_is_variable); \
	(cs)->off_linkhdr.constant_part = (new_constant_part); \
	(cs)->off_linkhdr.reg = (new_reg); \
	(cs)->is_encap = 0; \
}

/*
 * Offset "not set" value.
 */
#define OFFSET_NOT_SET	0xffffffffU

/*
 * Absolute offsets, which are offsets from the beginning of the raw
 * packet data, are, in the general case, the sum of a variable value
 * and a constant value; the variable value may be absent, in which
 * case the offset is only the constant value, and the constant value
 * may be zero, in which case the offset is only the variable value.
 *
 * bpf_abs_offset is a structure containing all that information:
 *
 *   is_variable is 1 if there's a variable part.
 *
 *   constant_part is the constant part of the value, possibly zero;
 *
 *   if is_variable is 1, reg is the register number for a register
 *   containing the variable value if the register has been assigned,
 *   and -1 otherwise.
 */
typedef struct {
	int	is_variable;
	u_int	constant_part;
	int	reg;
} bpf_abs_offset;

/*
 * Value passed to gen_load_a() to indicate what the offset argument
 * is relative to the beginning of.
 */
enum e_offrel {
	OR_PACKET,		/* full packet data */
	OR_LINKHDR,		/* link-layer header */
	OR_PREVLINKHDR,		/* previous link-layer header */
	OR_LLC,			/* 802.2 LLC header */
	OR_PREVMPLSHDR,		/* previous MPLS header */
	OR_LINKTYPE,		/* link-layer type */
	OR_LINKPL,		/* link-layer payload */
	OR_LINKPL_NOSNAP,	/* link-layer payload, with no SNAP header at the link layer */
	OR_TRAN_IPV4,		/* transport-layer header, with IPv4 network layer */
	OR_TRAN_IPV6		/* transport-layer header, with IPv6 network layer */
};

/*
 * We divvy out chunks of memory rather than call malloc each time so
 * we don't have to worry about leaking memory.  It's probably
 * not a big deal if all this memory was wasted but if this ever
 * goes into a library that would probably not be a good idea.
 *
 * XXX - this *is* in a library....
 */
#define NCHUNKS 16
#define CHUNK0SIZE 1024
struct chunk {
	size_t n_left;
	void *m;
};

/*
 * A chunk can store any of:
 *  - a string (guaranteed alignment 1 but present for completeness)
 *  - a block
 *  - an slist
 *  - an arth
 * For this simple allocator every allocated chunk gets rounded up to the
 * alignment needed for any chunk.
 */
struct chunk_align {
	char dummy;
	union {
		char c;
		struct block b;
		struct slist s;
		struct arth a;
	} u;
};
#define CHUNK_ALIGN (offsetof(struct chunk_align, u))

/* Code generator state */

struct _compiler_state {
	jmp_buf top_ctx;
	pcap_t *bpf_pcap;
	int error_set;

	struct icode ic;

	int snaplen;

	int linktype;
	int prevlinktype;
	int outermostlinktype;

	bpf_u_int32 netmask;
	int no_optimize;

	/* Hack for handling VLAN and MPLS stacks. */
	u_int label_stack_depth;
	u_int vlan_stack_depth;

	/* XXX */
	u_int pcap_fddipad;

	/*
	 * As errors are handled by a longjmp, anything allocated must
	 * be freed in the longjmp handler, so it must be reachable
	 * from that handler.
	 *
	 * One thing that's allocated is the result of pcap_nametoaddrinfo();
	 * it must be freed with freeaddrinfo().  This variable points to
	 * any addrinfo structure that would need to be freed.
	 */
	struct addrinfo *ai;

	/*
	 * Various code constructs need to know the layout of the packet.
	 * These values give the necessary offsets from the beginning
	 * of the packet data.
	 */

	/*
	 * Absolute offset of the beginning of the link-layer header.
	 */
	bpf_abs_offset off_linkhdr;

	/*
	 * If we're checking a link-layer header for a packet encapsulated
	 * in another protocol layer, this is the equivalent information
	 * for the previous layers' link-layer header from the beginning
	 * of the raw packet data.
	 */
	bpf_abs_offset off_prevlinkhdr;

	/*
	 * This is the equivalent information for the outermost layers'
	 * link-layer header.
	 */
	bpf_abs_offset off_outermostlinkhdr;

	/*
	 * Absolute offset of the beginning of the link-layer payload.
	 */
	bpf_abs_offset off_linkpl;

	/*
	 * "off_linktype" is the offset to information in the link-layer
	 * header giving the packet type. This is an absolute offset
	 * from the beginning of the packet.
	 *
	 * For Ethernet, it's the offset of the Ethernet type field; this
	 * means that it must have a value that skips VLAN tags.
	 *
	 * For link-layer types that always use 802.2 headers, it's the
	 * offset of the LLC header; this means that it must have a value
	 * that skips VLAN tags.
	 *
	 * For PPP, it's the offset of the PPP type field.
	 *
	 * For Cisco HDLC, it's the offset of the CHDLC type field.
	 *
	 * For BSD loopback, it's the offset of the AF_ value.
	 *
	 * For Linux cooked sockets, it's the offset of the type field.
	 *
	 * off_linktype.constant_part is set to OFFSET_NOT_SET for no
	 * encapsulation, in which case, IP is assumed.
	 */
	bpf_abs_offset off_linktype;

	/*
	 * TRUE if the link layer includes an ATM pseudo-header.
	 */
	int is_atm;

	/* TRUE if "geneve" or "vxlan" appeared in the filter; it
	 * causes us to generate code that checks for a Geneve or
	 * VXLAN header respectively and assume that later filters
	 * apply to the encapsulated payload.
	 */
	int is_encap;

	/*
	 * TRUE if we need variable length part of VLAN offset
	 */
	int is_vlan_vloffset;

	/*
	 * These are offsets for the ATM pseudo-header.
	 */
	u_int off_vpi;
	u_int off_vci;
	u_int off_proto;

	/*
	 * These are offsets for the MTP2 fields.
	 */
	u_int off_li;
	u_int off_li_hsl;

	/*
	 * These are offsets for the MTP3 fields.
	 */
	u_int off_sio;
	u_int off_opc;
	u_int off_dpc;
	u_int off_sls;

	/*
	 * This is the offset of the first byte after the ATM pseudo_header,
	 * or -1 if there is no ATM pseudo-header.
	 */
	u_int off_payload;

	/*
	 * These are offsets to the beginning of the network-layer header.
	 * They are relative to the beginning of the link-layer payload
	 * (i.e., they don't include off_linkhdr.constant_part or
	 * off_linkpl.constant_part).
	 *
	 * If the link layer never uses 802.2 LLC:
	 *
	 *	"off_nl" and "off_nl_nosnap" are the same.
	 *
	 * If the link layer always uses 802.2 LLC:
	 *
	 *	"off_nl" is the offset if there's a SNAP header following
	 *	the 802.2 header;
	 *
	 *	"off_nl_nosnap" is the offset if there's no SNAP header.
	 *
	 * If the link layer is Ethernet:
	 *
	 *	"off_nl" is the offset if the packet is an Ethernet II packet
	 *	(we assume no 802.3+802.2+SNAP);
	 *
	 *	"off_nl_nosnap" is the offset if the packet is an 802.3 packet
	 *	with an 802.2 header following it.
	 */
	u_int off_nl;
	u_int off_nl_nosnap;

	/*
	 * Here we handle simple allocation of the scratch registers.
	 * If too many registers are alloc'd, the allocator punts.
	 */
	int regused[BPF_MEMWORDS];
	int curreg;

	/*
	 * Memory chunks.
	 */
	struct chunk chunks[NCHUNKS];
	int cur_chunk;
};

/*
 * For use by routines outside this file.
 */
/* VARARGS */
void
bpf_set_error(compiler_state_t *cstate, const char *fmt, ...)
{
	va_list ap;

	/*
	 * If we've already set an error, don't override it.
	 * The lexical analyzer reports some errors by setting
	 * the error and then returning a LEX_ERROR token, which
	 * is not recognized by any grammar rule, and thus forces
	 * the parse to stop.  We don't want the error reported
	 * by the lexical analyzer to be overwritten by the syntax
	 * error.
	 */
	if (!cstate->error_set) {
		va_start(ap, fmt);
		(void)vsnprintf(cstate->bpf_pcap->errbuf, PCAP_ERRBUF_SIZE,
		    fmt, ap);
		va_end(ap);
		cstate->error_set = 1;
	}
}

/*
 * For use *ONLY* in routines in this file.
 */
static void PCAP_NORETURN bpf_error(compiler_state_t *, const char *, ...)
    PCAP_PRINTFLIKE(2, 3);

/* VARARGS */
static void PCAP_NORETURN
bpf_error(compiler_state_t *cstate, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void)vsnprintf(cstate->bpf_pcap->errbuf, PCAP_ERRBUF_SIZE,
	    fmt, ap);
	va_end(ap);
	longjmp(cstate->top_ctx, 1);
	/*NOTREACHED*/
#ifdef _AIX
	PCAP_UNREACHABLE
#endif /* _AIX */
}

static int init_linktype(compiler_state_t *, pcap_t *);

static void init_regs(compiler_state_t *);
static int alloc_reg(compiler_state_t *);
static void free_reg(compiler_state_t *, int);

static void initchunks(compiler_state_t *cstate);
static void *newchunk_nolongjmp(compiler_state_t *cstate, size_t);
static void *newchunk(compiler_state_t *cstate, size_t);
static void freechunks(compiler_state_t *cstate);
static inline struct block *new_block(compiler_state_t *cstate, int);
static inline struct slist *new_stmt(compiler_state_t *cstate, int);
static struct block *gen_retblk(compiler_state_t *cstate, int);
static inline void syntax(compiler_state_t *cstate);

static void backpatch(struct block *, struct block *);
static void merge(struct block *, struct block *);
static struct block *gen_cmp(compiler_state_t *, enum e_offrel, u_int,
    u_int, bpf_u_int32);
static struct block *gen_cmp_gt(compiler_state_t *, enum e_offrel, u_int,
    u_int, bpf_u_int32);
static struct block *gen_cmp_ge(compiler_state_t *, enum e_offrel, u_int,
    u_int, bpf_u_int32);
static struct block *gen_cmp_lt(compiler_state_t *, enum e_offrel, u_int,
    u_int, bpf_u_int32);
static struct block *gen_cmp_le(compiler_state_t *, enum e_offrel, u_int,
    u_int, bpf_u_int32);
static struct block *gen_cmp_ne(compiler_state_t *, enum e_offrel, u_int,
    u_int size, bpf_u_int32);
static struct block *gen_mcmp(compiler_state_t *, enum e_offrel, u_int,
    u_int, bpf_u_int32, bpf_u_int32);
static struct block *gen_mcmp_ne(compiler_state_t *, enum e_offrel, u_int,
    u_int, bpf_u_int32, bpf_u_int32);
static struct block *gen_bcmp(compiler_state_t *, enum e_offrel, u_int,
    u_int, const u_char *);
static struct block *gen_jmp_k(compiler_state_t *, const int,
    const bpf_u_int32, struct slist *);
static struct block *gen_jmp_x(compiler_state_t *, const int, struct slist *);
static struct block *gen_set(compiler_state_t *, bpf_u_int32, struct slist *);
static struct block *gen_unset(compiler_state_t *, bpf_u_int32, struct slist *);
static struct block *gen_ncmp(compiler_state_t *, enum e_offrel, u_int,
    u_int, bpf_u_int32, int, int, bpf_u_int32);
static struct slist *gen_load_absoffsetrel(compiler_state_t *, bpf_abs_offset *,
    u_int, u_int);
static struct slist *gen_load_a(compiler_state_t *, enum e_offrel, u_int,
    u_int);
static struct slist *gen_loadx_iphdrlen(compiler_state_t *);
static struct block *gen_uncond(compiler_state_t *, int);
static inline struct block *gen_true(compiler_state_t *);
static inline struct block *gen_false(compiler_state_t *);
static struct block *gen_ether_linktype(compiler_state_t *, bpf_u_int32);
static struct block *gen_ipnet_linktype(compiler_state_t *, bpf_u_int32);
static struct block *gen_linux_sll_linktype(compiler_state_t *, bpf_u_int32);
static struct slist *gen_load_pflog_llprefixlen(compiler_state_t *);
static struct slist *gen_load_prism_llprefixlen(compiler_state_t *);
static struct slist *gen_load_avs_llprefixlen(compiler_state_t *);
static struct slist *gen_load_radiotap_llprefixlen(compiler_state_t *);
static struct slist *gen_load_ppi_llprefixlen(compiler_state_t *);
static void insert_compute_vloffsets(compiler_state_t *, struct block *);
static struct slist *gen_abs_offset_varpart(compiler_state_t *,
    bpf_abs_offset *);
static uint16_t ethertype_to_ppptype(compiler_state_t *, bpf_u_int32);
static struct block *gen_linktype(compiler_state_t *, bpf_u_int32);
static struct block *gen_snap(compiler_state_t *, bpf_u_int32, bpf_u_int32);
static struct block *gen_llc_linktype(compiler_state_t *, bpf_u_int32);
static struct block *gen_hostop(compiler_state_t *, bpf_u_int32, bpf_u_int32,
    int, u_int, u_int);
static struct block *gen_hostop6(compiler_state_t *, struct in6_addr *,
    struct in6_addr *, int, u_int, u_int);
static struct block *gen_wlanhostop(compiler_state_t *, const u_char *, int);
static unsigned char is_mac48_linktype(const int);
static struct block *gen_mac48host(compiler_state_t *, const u_char *,
    const u_char, const char *);
static struct block *gen_mac48host_byname(compiler_state_t *, const char *,
    const u_char, const char *);
static struct block *gen_mac8host(compiler_state_t *, const uint8_t,
    const u_char, const char *);
static struct block *gen_dnhostop(compiler_state_t *, bpf_u_int32, int);
static struct block *gen_mpls_linktype(compiler_state_t *, bpf_u_int32);
static struct block *gen_host(compiler_state_t *, bpf_u_int32, bpf_u_int32,
    int, int, int);
static struct block *gen_host6(compiler_state_t *, struct in6_addr *,
    struct in6_addr *, int, int, int);
static struct block *gen_host46_byname(compiler_state_t *, const char *,
    const u_char, const u_char, const u_char);
static struct block *gen_gateway(compiler_state_t *, const char *, const u_char);
static struct block *gen_ip_proto(compiler_state_t *, const uint8_t);
static struct block *gen_ip6_proto(compiler_state_t *, const uint8_t);
static struct block *gen_ipfrag(compiler_state_t *);
static struct block *gen_portatom(compiler_state_t *, int, uint16_t);
static struct block *gen_portrangeatom(compiler_state_t *, u_int, uint16_t,
    uint16_t);
static struct block *gen_portatom6(compiler_state_t *, int, uint16_t);
static struct block *gen_portrangeatom6(compiler_state_t *, u_int, uint16_t,
    uint16_t);
static struct block *gen_port(compiler_state_t *, uint16_t, int, int);
static struct block *gen_port_common(compiler_state_t *, int, struct block *);
static struct block *gen_portrange(compiler_state_t *, uint16_t, uint16_t,
    int, int);
static struct block *gen_port6(compiler_state_t *, uint16_t, int, int);
static struct block *gen_port6_common(compiler_state_t *, int, struct block *);
static struct block *gen_portrange6(compiler_state_t *, uint16_t, uint16_t,
    int, int);
static int lookup_proto(compiler_state_t *, const char *, const struct qual);
#if !defined(NO_PROTOCHAIN)
static struct block *gen_protochain(compiler_state_t *, bpf_u_int32, int);
#endif /* !defined(NO_PROTOCHAIN) */
static struct block *gen_proto(compiler_state_t *, bpf_u_int32, int);
static struct slist *xfer_to_x(compiler_state_t *, struct arth *);
static struct slist *xfer_to_a(compiler_state_t *, struct arth *);
static struct block *gen_mac_multicast(compiler_state_t *, int);
static struct block *gen_len(compiler_state_t *, int, int);
static struct block *gen_encap_ll_check(compiler_state_t *cstate);

static struct block *gen_atmfield_code_internal(compiler_state_t *, int,
    bpf_u_int32, int, int);
static struct block *gen_atmtype_llc(compiler_state_t *);
static struct block *gen_msg_abbrev(compiler_state_t *, const uint8_t);
static struct block *gen_atm_prototype(compiler_state_t *, const uint8_t);
static struct block *gen_atm_vpi(compiler_state_t *, const uint8_t);
static struct block *gen_atm_vci(compiler_state_t *, const uint16_t);

static void
initchunks(compiler_state_t *cstate)
{
	int i;

	for (i = 0; i < NCHUNKS; i++) {
		cstate->chunks[i].n_left = 0;
		cstate->chunks[i].m = NULL;
	}
	cstate->cur_chunk = 0;
}

static void *
newchunk_nolongjmp(compiler_state_t *cstate, size_t n)
{
	struct chunk *cp;
	int k;
	size_t size;

	/* Round up to chunk alignment. */
	n = (n + CHUNK_ALIGN - 1) & ~(CHUNK_ALIGN - 1);

	cp = &cstate->chunks[cstate->cur_chunk];
	if (n > cp->n_left) {
		++cp;
		k = ++cstate->cur_chunk;
		if (k >= NCHUNKS) {
			bpf_set_error(cstate, "out of memory");
			return (NULL);
		}
		size = CHUNK0SIZE << k;
		cp->m = calloc(1, size);
		if (cp->m == NULL) {
			bpf_set_error(cstate, "out of memory");
			return (NULL);
		}
		cp->n_left = size;
		if (n > size) {
			bpf_set_error(cstate, "out of memory");
			return (NULL);
		}
	}
	cp->n_left -= n;
	return (void *)((char *)cp->m + cp->n_left);
}

static void *
newchunk(compiler_state_t *cstate, size_t n)
{
	void *p;

	p = newchunk_nolongjmp(cstate, n);
	if (p == NULL) {
		longjmp(cstate->top_ctx, 1);
		/*NOTREACHED*/
	}
	return (p);
}

static void
freechunks(compiler_state_t *cstate)
{
	int i;

	for (i = 0; i < NCHUNKS; ++i)
		if (cstate->chunks[i].m != NULL)
			free(cstate->chunks[i].m);
}

/*
 * A strdup whose allocations are freed after code generation is over.
 * This is used by the lexical analyzer, so it can't longjmp; it just
 * returns NULL on an allocation error, and the callers must check
 * for it.
 */
char *
sdup(compiler_state_t *cstate, const char *s)
{
	size_t n = strlen(s) + 1;
	char *cp = newchunk_nolongjmp(cstate, n);

	if (cp == NULL)
		return (NULL);
	pcapint_strlcpy(cp, s, n);
	return (cp);
}

static inline struct block *
new_block(compiler_state_t *cstate, int code)
{
	struct block *p;

	p = (struct block *)newchunk(cstate, sizeof(*p));
	p->s.code = code;
	p->head = p;

	return p;
}

static inline struct slist *
new_stmt(compiler_state_t *cstate, int code)
{
	struct slist *p;

	p = (struct slist *)newchunk(cstate, sizeof(*p));
	p->s.code = code;

	return p;
}

static struct block *
gen_retblk_internal(compiler_state_t *cstate, int v)
{
	struct block *b = new_block(cstate, BPF_RET|BPF_K);

	b->s.k = v;
	return b;
}

static struct block *
gen_retblk(compiler_state_t *cstate, int v)
{
	if (setjmp(cstate->top_ctx)) {
		/*
		 * gen_retblk() only fails because a memory
		 * allocation failed in newchunk(), meaning
		 * that it can't return a pointer.
		 *
		 * Return NULL.
		 */
		return NULL;
	}
	return gen_retblk_internal(cstate, v);
}

static inline PCAP_NORETURN_DEF void
syntax(compiler_state_t *cstate)
{
	bpf_error(cstate, "syntax error in filter expression");
}

/*
 * For the given integer return a string with the keyword (or the nominal
 * keyword if there is more than one).  This is a simpler version of tok2str()
 * in tcpdump because in this problem space a valid integer value is not
 * greater than 71.
 */
static const char *
qual2kw(const char *kind, const unsigned id, const char *tokens[],
    const size_t size)
{
	static char buf[4][64];
	static int idx = 0;

	if (id < size && tokens[id])
		return tokens[id];

	char *ret = buf[idx];
	idx = (idx + 1) % (sizeof(buf) / sizeof(buf[0]));
	ret[0] = '\0'; // just in case
	snprintf(ret, sizeof(buf[0]), "<invalid %s %u>", kind, id);
	return ret;
}

// protocol qualifier keywords
static const char *
pqkw(const unsigned id)
{
	const char * tokens[] = {
		[Q_LINK] = "link",
		[Q_IP] = "ip",
		[Q_ARP] = "arp",
		[Q_RARP] = "rarp",
		[Q_SCTP] = "sctp",
		[Q_TCP] = "tcp",
		[Q_UDP] = "udp",
		[Q_ICMP] = "icmp",
		[Q_IGMP] = "igmp",
		[Q_IGRP] = "igrp",
		[Q_ATALK] = "atalk",
		[Q_DECNET] = "decnet",
		[Q_LAT] = "lat",
		[Q_SCA] = "sca",
		[Q_MOPRC] = "moprc",
		[Q_MOPDL] = "mopdl",
		[Q_IPV6] = "ip6",
		[Q_ICMPV6] = "icmp6",
		[Q_AH] = "ah",
		[Q_ESP] = "esp",
		[Q_PIM] = "pim",
		[Q_VRRP] = "vrrp",
		[Q_AARP] = "aarp",
		[Q_ISO] = "iso",
		[Q_ESIS] = "esis",
		[Q_ISIS] = "isis",
		[Q_CLNP] = "clnp",
		[Q_STP] = "stp",
		[Q_IPX] = "ipx",
		[Q_NETBEUI] = "netbeui",
		[Q_ISIS_L1] = "l1",
		[Q_ISIS_L2] = "l2",
		[Q_ISIS_IIH] = "iih",
		[Q_ISIS_SNP] = "snp",
		[Q_ISIS_CSNP] = "csnp",
		[Q_ISIS_PSNP] = "psnp",
		[Q_ISIS_LSP] = "lsp",
		[Q_RADIO] = "radio",
		[Q_CARP] = "carp",
	};
	return qual2kw("proto", id, tokens, sizeof(tokens) / sizeof(tokens[0]));
}

// direction qualifier keywords
static const char *
dqkw(const unsigned id)
{
	const char * tokens[] = {
		[Q_SRC] = "src",
		[Q_DST] = "dst",
		[Q_OR] = "src or dst",
		[Q_AND] = "src and dst",
		[Q_ADDR1] = "addr1",
		[Q_ADDR2] = "addr2",
		[Q_ADDR3] = "addr3",
		[Q_ADDR4] = "addr4",
		[Q_RA] = "ra",
		[Q_TA] = "ta",
	};
	return qual2kw("dir", id, tokens, sizeof(tokens) / sizeof(tokens[0]));
}

// type (in the man page) / address (in the code) qualifier keywords
static const char *
tqkw(const unsigned id)
{
	const char * tokens[] = {
		[Q_HOST] = "host",
		[Q_NET] = "net",
		[Q_PORT] = "port",
		[Q_GATEWAY] = "gateway",
		[Q_PROTO] = "proto",
		[Q_PROTOCHAIN] = "protochain",
		[Q_PORTRANGE] = "portrange",
	};
	return qual2kw("type", id, tokens, sizeof(tokens) / sizeof(tokens[0]));
}

// ATM keywords
static const char *
atmkw(const unsigned id)
{
	const char * tokens[] = {
		[A_METAC] = "metac",
		[A_BCC] = "bcc",
		[A_OAMF4SC] = "oamf4sc",
		[A_OAMF4EC] = "oamf4ec",
		[A_SC] = "sc",
		[A_ILMIC] = "ilmic",
		[A_OAM] = "oam",
		[A_OAMF4] = "oamf4",
		[A_LANE] = "lane",
		[A_VPI] = "vpi",
		[A_VCI] = "vci",
		[A_CONNECTMSG] = "connectmsg",
		[A_METACONNECT] = "metaconnect",
	};
	return qual2kw("ATM keyword", id, tokens, sizeof(tokens) / sizeof(tokens[0]));
}

// SS7 keywords
static const char *
ss7kw(const unsigned id)
{
	const char * tokens[] = {
		[M_FISU] = "fisu",
		[M_LSSU] = "lssu",
		[M_MSU] = "msu",
		[MH_FISU] = "hfisu",
		[MH_LSSU] = "hlssu",
		[MH_MSU] = "hmsu",
		[M_SIO] = "sio",
		[M_OPC] = "opc",
		[M_DPC] = "dpc",
		[M_SLS] = "sls",
		[MH_SIO] = "hsio",
		[MH_OPC] = "hopc",
		[MH_DPC] = "hdpc",
		[MH_SLS] = "hsls",
	};
	return qual2kw("MTP keyword", id, tokens, sizeof(tokens) / sizeof(tokens[0]));
}

// Produce as descriptive an identification string of the DLT as possible.
static const char *
pcapint_datalink_val_to_string(const int dlt)
{
	static thread_local char ret[1024];
	const char *name = pcap_datalink_val_to_name(dlt);
	const char *descr = pcap_datalink_val_to_description(dlt);
	/*
	 * Belt and braces: if dlt_choices[] continues to be defined the way it is
	 * defined now and everything goes well, either both pointers are NULL or
	 * both pointers are not NULL.  But let's not rely on that.
	 */
	if (name) {
		if (descr)
			snprintf(ret, sizeof(ret), "DLT_%s (%s)", name, descr);
		else
			snprintf(ret, sizeof(ret), "DLT_%s", name);
		return ret;
	}
	// name == NULL
	if (descr) {
		snprintf(ret, sizeof(ret), "DLT %d (%s)", dlt, descr);
		return ret;
	}
	// Both are NULL, use a function that always returns a non-NULL.
	return pcap_datalink_val_to_description_or_dlt(dlt);
}

static PCAP_NORETURN_DEF void
fail_kw_on_dlt(compiler_state_t *cstate, const char *keyword)
{
	bpf_error(cstate, "'%s' not supported on %s", keyword,
	    pcapint_datalink_val_to_string(cstate->linktype));
}

static void
assert_pflog(compiler_state_t *cstate, const char *kw)
{
	if (cstate->linktype != DLT_PFLOG)
		bpf_error(cstate, "'%s' supported only on PFLOG linktype", kw);
}

static void
assert_atm(compiler_state_t *cstate, const char *kw)
{
	/*
	 * Belt and braces: init_linktype() sets either all of these struct
	 * members (for DLT_SUNATM) or none (otherwise).
	 */
	if (cstate->linktype != DLT_SUNATM ||
	    ! cstate->is_atm ||
	    cstate->off_vpi == OFFSET_NOT_SET ||
	    cstate->off_vci == OFFSET_NOT_SET ||
	    cstate->off_proto == OFFSET_NOT_SET ||
	    cstate->off_payload == OFFSET_NOT_SET)
		bpf_error(cstate, "'%s' supported only on SUNATM", kw);
}

static void
assert_ss7(compiler_state_t *cstate, const char *kw)
{
	switch (cstate->linktype) {
	case DLT_MTP2:
	case DLT_ERF:
	case DLT_MTP2_WITH_PHDR:
		// Belt and braces, same as in assert_atm().
		if (cstate->off_sio != OFFSET_NOT_SET &&
		    cstate->off_opc != OFFSET_NOT_SET &&
		    cstate->off_dpc != OFFSET_NOT_SET &&
		    cstate->off_sls != OFFSET_NOT_SET)
			return;
	}
	bpf_error(cstate, "'%s' supported only on SS7", kw);
}

static void
assert_maxval(compiler_state_t *cstate, const char *name,
    const bpf_u_int32 val, const bpf_u_int32 maxval)
{
	if (val > maxval)
		bpf_error(cstate, "%s %u greater than maximum %u",
		    name, val, maxval);
}

#define ERRSTR_802_11_ONLY_KW "'%s' is valid for 802.11 syntax only"
#define ERRSTR_INVALID_QUAL "'%s' is not a valid qualifier for '%s'"
#define ERRSTR_UNKNOWN_MAC48HOST "unknown Ethernet-like host '%s'"
#define ERRSTR_INVALID_IPV4_ADDR "invalid IPv4 address '%s'"
#define ERRSTR_FUNC_VAR_INT "internal error in %s(): %s == %d"

// Validate a port/portrange proto qualifier and map to an IP protocol number.
static int
port_pq_to_ipproto(compiler_state_t *cstate, const int proto, const char *kw)
{
	switch (proto) {
	case Q_UDP:
		return IPPROTO_UDP;
	case Q_TCP:
		return IPPROTO_TCP;
	case Q_SCTP:
		return IPPROTO_SCTP;
	case Q_DEFAULT:
		return PROTO_UNDEF;
	}
	bpf_error(cstate, ERRSTR_INVALID_QUAL, pqkw(proto), kw);
}

int
pcap_compile(pcap_t *p, struct bpf_program *program,
	     const char *buf, int optimize, bpf_u_int32 mask)
{
#ifdef _WIN32
	int err;
	WSADATA wsaData;
#endif
	compiler_state_t cstate;
	yyscan_t scanner = NULL;
	YY_BUFFER_STATE in_buffer = NULL;
	u_int len;
	int rc;

	/*
	 * If this pcap_t hasn't been activated, it doesn't have a
	 * link-layer type, so we can't use it.
	 */
	if (!p->activated) {
		(void)snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "not-yet-activated pcap_t passed to pcap_compile");
		return (PCAP_ERROR);
	}

#ifdef _WIN32
	/*
	 * Initialize Winsock, asking for the latest version (2.2),
	 * as we may be calling Winsock routines to translate
	 * host names to addresses.
	 */
	err = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (err != 0) {
		pcapint_fmt_errmsg_for_win32_err(p->errbuf, PCAP_ERRBUF_SIZE,
		    err, "Error calling WSAStartup()");
		return (PCAP_ERROR);
	}
#endif

#ifdef ENABLE_REMOTE
	/*
	 * If the device on which we're capturing need to be notified
	 * that a new filter is being compiled, do so.
	 *
	 * This allows them to save a copy of it, in case, for example,
	 * they're implementing a form of remote packet capture, and
	 * want the remote machine to filter out the packets in which
	 * it's sending the packets it's captured.
	 *
	 * XXX - the fact that we happen to be compiling a filter
	 * doesn't necessarily mean we'll be installing it as the
	 * filter for this pcap_t; we might be running it from userland
	 * on captured packets to do packet classification.  We really
	 * need a better way of handling this, but this is all that
	 * the WinPcap remote capture code did.
	 */
	if (p->save_current_filter_op != NULL)
		(p->save_current_filter_op)(p, buf);
#endif

	initchunks(&cstate);
	cstate.no_optimize = 0;
	cstate.ai = NULL;
	cstate.ic.root = NULL;
	cstate.ic.cur_mark = 0;
	cstate.bpf_pcap = p;
	cstate.error_set = 0;
	init_regs(&cstate);

	cstate.netmask = mask;

	cstate.snaplen = pcap_snapshot(p);
	if (cstate.snaplen == 0) {
		(void)snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			 "snaplen of 0 rejects all packets");
		rc = PCAP_ERROR;
		goto quit;
	}

	if (pcap_lex_init(&scanner) != 0) {
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "can't initialize scanner");
		rc = PCAP_ERROR;
		goto quit;
	}
	in_buffer = pcap__scan_string(buf ? buf : "", scanner);

	/*
	 * Associate the compiler state with the lexical analyzer
	 * state.
	 */
	pcap_set_extra(&cstate, scanner);

	if (init_linktype(&cstate, p) == -1) {
		rc = PCAP_ERROR;
		goto quit;
	}
	if (pcap_parse(scanner, &cstate) != 0) {
		if (cstate.ai != NULL)
			freeaddrinfo(cstate.ai);
		rc = PCAP_ERROR;
		goto quit;
	}

	if (cstate.ic.root == NULL) {
		cstate.ic.root = gen_retblk(&cstate, cstate.snaplen);

		/*
		 * Catch errors reported by gen_retblk().
		 */
		if (cstate.ic.root== NULL) {
			rc = PCAP_ERROR;
			goto quit;
		}
	}

	if (optimize && !cstate.no_optimize) {
		if (bpf_optimize(&cstate.ic, p->errbuf) == -1) {
			/* Failure */
			rc = PCAP_ERROR;
			goto quit;
		}
		if (cstate.ic.root == NULL ||
		    (cstate.ic.root->s.code == (BPF_RET|BPF_K) && cstate.ic.root->s.k == 0)) {
			(void)snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "expression rejects all packets");
			rc = PCAP_ERROR;
			goto quit;
		}
	}
	program->bf_insns = icode_to_fcode(&cstate.ic,
	    cstate.ic.root, &len, p->errbuf);
	if (program->bf_insns == NULL) {
		/* Failure */
		rc = PCAP_ERROR;
		goto quit;
	}
	program->bf_len = len;

	rc = 0;  /* We're all okay */

quit:
	/*
	 * Clean up everything for the lexical analyzer.
	 */
	if (in_buffer != NULL)
		pcap__delete_buffer(in_buffer, scanner);
	if (scanner != NULL)
		pcap_lex_destroy(scanner);

	/*
	 * Clean up our own allocated memory.
	 */
	freechunks(&cstate);

#ifdef _WIN32
	WSACleanup();
#endif

	return (rc);
}

/*
 * entry point for using the compiler with no pcap open
 * pass in all the stuff that is needed explicitly instead.
 */
int
pcap_compile_nopcap(int snaplen_arg, int linktype_arg,
		    struct bpf_program *program,
		    const char *buf, int optimize, bpf_u_int32 mask)
{
	pcap_t *p;
	int ret;

	p = pcap_open_dead(linktype_arg, snaplen_arg);
	if (p == NULL)
		return (PCAP_ERROR);
	ret = pcap_compile(p, program, buf, optimize, mask);
	pcap_close(p);
	return (ret);
}

/*
 * Clean up a "struct bpf_program" by freeing all the memory allocated
 * in it.
 */
void
pcap_freecode(struct bpf_program *program)
{
	program->bf_len = 0;
	if (program->bf_insns != NULL) {
		free((char *)program->bf_insns);
		program->bf_insns = NULL;
	}
}

/*
 * Backpatch the blocks in 'list' to 'target'.  The 'sense' field indicates
 * which of the jt and jf fields has been resolved and which is a pointer
 * back to another unresolved block (or nil).  At least one of the fields
 * in each block is already resolved.
 */
static void
backpatch(struct block *list, struct block *target)
{
	struct block *next;

	while (list) {
		if (!list->sense) {
			next = JT(list);
			JT(list) = target;
		} else {
			next = JF(list);
			JF(list) = target;
		}
		list = next;
	}
}

/*
 * Merge the lists in b0 and b1, using the 'sense' field to indicate
 * which of jt and jf is the link.
 */
static void
merge(struct block *b0, struct block *b1)
{
	struct block **p = &b0;

	/* Find end of list. */
	while (*p)
		p = !((*p)->sense) ? &JT(*p) : &JF(*p);

	/* Concatenate the lists. */
	*p = b1;
}

int
finish_parse(compiler_state_t *cstate, struct block *p)
{
	/*
	 * Catch errors reported by us and routines below us, and return -1
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (-1);

	/*
	 * Insert before the statements of the first (root) block any
	 * statements needed to load the lengths of any variable-length
	 * headers into registers.
	 *
	 * XXX - a fancier strategy would be to insert those before the
	 * statements of all blocks that use those lengths and that
	 * have no predecessors that use them, so that we only compute
	 * the lengths if we need them.  There might be even better
	 * approaches than that.
	 *
	 * However, those strategies would be more complicated, and
	 * as we don't generate code to compute a length if the
	 * program has no tests that use the length, and as most
	 * tests will probably use those lengths, we would just
	 * postpone computing the lengths so that it's not done
	 * for tests that fail early, and it's not clear that's
	 * worth the effort.
	 */
	insert_compute_vloffsets(cstate, p->head);

	/*
	 * For DLT_PPI captures, generate a check of the per-packet
	 * DLT value to make sure it's DLT_IEEE802_11.
	 *
	 * XXX - TurboCap cards use DLT_PPI for Ethernet.
	 * Can we just define some DLT_ETHERNET_WITH_PHDR pseudo-header
	 * with appropriate Ethernet information and use that rather
	 * than using something such as DLT_PPI where you don't know
	 * the link-layer header type until runtime, which, in the
	 * general case, would force us to generate both Ethernet *and*
	 * 802.11 code (*and* anything else for which PPI is used)
	 * and choose between them early in the BPF program?
	 */
	if (cstate->linktype == DLT_PPI) {
		struct block *ppi_dlt_check = gen_cmp(cstate, OR_PACKET,
			4, BPF_W, SWAPLONG(DLT_IEEE802_11));
		gen_and(ppi_dlt_check, p);
	}

	backpatch(p, gen_retblk_internal(cstate, cstate->snaplen));
	p->sense = !p->sense;
	backpatch(p, gen_retblk_internal(cstate, 0));
	cstate->ic.root = p->head;
	return (0);
}

void
gen_and(struct block *b0, struct block *b1)
{
	backpatch(b0, b1->head);
	b0->sense = !b0->sense;
	b1->sense = !b1->sense;
	merge(b1, b0);
	b1->sense = !b1->sense;
	b1->head = b0->head;
}

void
gen_or(struct block *b0, struct block *b1)
{
	b0->sense = !b0->sense;
	backpatch(b0, b1->head);
	b0->sense = !b0->sense;
	merge(b1, b0);
	b1->head = b0->head;
}

void
gen_not(struct block *b)
{
	b->sense = !b->sense;
}

static struct block *
gen_cmp(compiler_state_t *cstate, enum e_offrel offrel, u_int offset,
    u_int size, bpf_u_int32 v)
{
	return gen_ncmp(cstate, offrel, offset, size, 0xffffffff, BPF_JEQ, 0, v);
}

static struct block *
gen_cmp_gt(compiler_state_t *cstate, enum e_offrel offrel, u_int offset,
    u_int size, bpf_u_int32 v)
{
	return gen_ncmp(cstate, offrel, offset, size, 0xffffffff, BPF_JGT, 0, v);
}

static struct block *
gen_cmp_ge(compiler_state_t *cstate, enum e_offrel offrel, u_int offset,
    u_int size, bpf_u_int32 v)
{
	return gen_ncmp(cstate, offrel, offset, size, 0xffffffff, BPF_JGE, 0, v);
}

static struct block *
gen_cmp_lt(compiler_state_t *cstate, enum e_offrel offrel, u_int offset,
    u_int size, bpf_u_int32 v)
{
	return gen_ncmp(cstate, offrel, offset, size, 0xffffffff, BPF_JGE, 1, v);
}

static struct block *
gen_cmp_le(compiler_state_t *cstate, enum e_offrel offrel, u_int offset,
    u_int size, bpf_u_int32 v)
{
	return gen_ncmp(cstate, offrel, offset, size, 0xffffffff, BPF_JGT, 1, v);
}

static struct block *
gen_cmp_ne(compiler_state_t *cstate, enum e_offrel offrel, u_int offset,
    u_int size, bpf_u_int32 v)
{
	return gen_ncmp(cstate, offrel, offset, size, 0xffffffff, BPF_JEQ, 1, v);
}

static struct block *
gen_mcmp(compiler_state_t *cstate, enum e_offrel offrel, u_int offset,
    u_int size, bpf_u_int32 v, bpf_u_int32 mask)
{
	/*
	 * For any A: if mask == 0, it means A & mask == 0, so the result is
	 * true iff v == 0.  In this case ideally the caller should have
	 * skipped this invocation and have fewer statement blocks to juggle.
	 * If the caller could have skipped, but has not, produce a block with
	 * fewer statements.
	 *
	 * This could be done in gen_ncmp() in a more generic way, but this
	 * function is the only code path that can have mask == 0.
	 */
	if (mask == 0)
		return v ? gen_false(cstate) : gen_true(cstate);

	return gen_ncmp(cstate, offrel, offset, size, mask, BPF_JEQ, 0, v);
}

static struct block *
gen_mcmp_ne(compiler_state_t *cstate, enum e_offrel offrel, u_int offset,
    u_int size, bpf_u_int32 v, bpf_u_int32 mask)
{
	return gen_ncmp(cstate, offrel, offset, size, mask, BPF_JEQ, 1, v);
}

static struct block *
gen_bcmp(compiler_state_t *cstate, enum e_offrel offrel, u_int offset,
    u_int size, const u_char *v)
{
	struct block *b, *tmp;

	b = NULL;
	while (size >= 4) {
		const u_char *p = &v[size - 4];

		tmp = gen_cmp(cstate, offrel, offset + size - 4, BPF_W,
		    EXTRACT_BE_U_4(p));
		if (b != NULL)
			gen_and(b, tmp);
		b = tmp;
		size -= 4;
	}
	while (size >= 2) {
		const u_char *p = &v[size - 2];

		tmp = gen_cmp(cstate, offrel, offset + size - 2, BPF_H,
		    EXTRACT_BE_U_2(p));
		if (b != NULL)
			gen_and(b, tmp);
		b = tmp;
		size -= 2;
	}
	if (size > 0) {
		tmp = gen_cmp(cstate, offrel, offset, BPF_B, v[0]);
		if (b != NULL)
			gen_and(b, tmp);
		b = tmp;
	}
	return b;
}

/*
 * Generate an instruction block for one of {"jeq #k", "jgt #k", "jge #k",
 * "jset #k", "ja L"}.
 */
static struct block *
gen_jmp_k(compiler_state_t *cstate, const int jtype, const bpf_u_int32 v,
          struct slist *stmts)
{
	struct block *b = new_block(cstate, JMP(jtype, BPF_K));
	b->s.k = v;
	b->stmts = stmts;
	return b;
}

/*
 * Generate an instruction block for one of {"jeq x", "jgt x", "jge x",
 * "jset x"}.
 */
static struct block *
gen_jmp_x(compiler_state_t *cstate, const int jtype, struct slist *stmts)
{
	struct block *b = new_block(cstate, JMP(jtype, BPF_X));
	b->stmts = stmts;
	return b;
}

static struct block *
gen_set(compiler_state_t *cstate, bpf_u_int32 v, struct slist *stmts)
{
	return gen_jmp_k(cstate, BPF_JSET, v, stmts);
}

static struct block *
gen_unset(compiler_state_t *cstate, bpf_u_int32 v, struct slist *stmts)
{
	struct block *b = gen_set(cstate, v, stmts);
	gen_not(b);
	return b;
}

/*
 * AND the field of size "size" at offset "offset" relative to the header
 * specified by "offrel" with "mask", and compare it with the value "v"
 * with the test specified by "jtype"; if "reverse" is true, the test
 * should test the opposite of "jtype".
 */
static struct block *
gen_ncmp(compiler_state_t *cstate, enum e_offrel offrel, u_int offset,
    u_int size, bpf_u_int32 mask, int jtype, int reverse,
    bpf_u_int32 v)
{
	struct slist *s, *s2;
	struct block *b;

	s = gen_load_a(cstate, offrel, offset, size);

	if (mask != 0xffffffff) {
		s2 = new_stmt(cstate, BPF_ALU|BPF_AND|BPF_K);
		s2->s.k = mask;
		sappend(s, s2);
	}

	b = gen_jmp_k(cstate, jtype, v, s);
	if (reverse)
		gen_not(b);
	return b;
}

static int
init_linktype(compiler_state_t *cstate, pcap_t *p)
{
	cstate->pcap_fddipad = p->fddipad;

	/*
	 * We start out with only one link-layer header.
	 */
	cstate->outermostlinktype = pcap_datalink(p);
	cstate->off_outermostlinkhdr.constant_part = 0;
	cstate->off_outermostlinkhdr.is_variable = 0;
	cstate->off_outermostlinkhdr.reg = -1;

	cstate->prevlinktype = cstate->outermostlinktype;
	cstate->off_prevlinkhdr.constant_part = 0;
	cstate->off_prevlinkhdr.is_variable = 0;
	cstate->off_prevlinkhdr.reg = -1;

	cstate->linktype = cstate->outermostlinktype;
	cstate->off_linkhdr.constant_part = 0;
	cstate->off_linkhdr.is_variable = 0;
	cstate->off_linkhdr.reg = -1;

	/*
	 * XXX
	 */
	cstate->off_linkpl.constant_part = 0;
	cstate->off_linkpl.is_variable = 0;
	cstate->off_linkpl.reg = -1;

	cstate->off_linktype.constant_part = 0;
	cstate->off_linktype.is_variable = 0;
	cstate->off_linktype.reg = -1;

	/*
	 * Assume it's not raw ATM with a pseudo-header, for now.
	 */
	cstate->is_atm = 0;
	cstate->off_vpi = OFFSET_NOT_SET;
	cstate->off_vci = OFFSET_NOT_SET;
	cstate->off_proto = OFFSET_NOT_SET;
	cstate->off_payload = OFFSET_NOT_SET;

	/*
	 * And not encapsulated with either Geneve or VXLAN.
	 */
	cstate->is_encap = 0;

	/*
	 * No variable length VLAN offset by default
	 */
	cstate->is_vlan_vloffset = 0;

	/*
	 * And assume we're not doing SS7.
	 */
	cstate->off_li = OFFSET_NOT_SET;
	cstate->off_li_hsl = OFFSET_NOT_SET;
	cstate->off_sio = OFFSET_NOT_SET;
	cstate->off_opc = OFFSET_NOT_SET;
	cstate->off_dpc = OFFSET_NOT_SET;
	cstate->off_sls = OFFSET_NOT_SET;

	cstate->label_stack_depth = 0;
	cstate->vlan_stack_depth = 0;

	switch (cstate->linktype) {

	case DLT_ARCNET:
		cstate->off_linktype.constant_part = 2;
		cstate->off_linkpl.constant_part = 6;
		cstate->off_nl = 0;		/* XXX in reality, variable! */
		cstate->off_nl_nosnap = 0;	/* no 802.2 LLC */
		break;

	case DLT_ARCNET_LINUX:
		cstate->off_linktype.constant_part = 4;
		cstate->off_linkpl.constant_part = 8;
		cstate->off_nl = 0;		/* XXX in reality, variable! */
		cstate->off_nl_nosnap = 0;	/* no 802.2 LLC */
		break;

	case DLT_EN10MB:
		cstate->off_linktype.constant_part = 12;
		cstate->off_linkpl.constant_part = 14;	/* Ethernet header length */
		cstate->off_nl = 0;		/* Ethernet II */
		cstate->off_nl_nosnap = 3;	/* 802.3+802.2 */
		break;

	case DLT_SLIP:
		/*
		 * SLIP doesn't have a link level type.  The 16 byte
		 * header is hacked into our SLIP driver.
		 */
		cstate->off_linktype.constant_part = OFFSET_NOT_SET;
		cstate->off_linkpl.constant_part = 16;
		cstate->off_nl = 0;
		cstate->off_nl_nosnap = 0;	/* no 802.2 LLC */
		break;

	case DLT_SLIP_BSDOS:
		/* XXX this may be the same as the DLT_PPP_BSDOS case */
		cstate->off_linktype.constant_part = OFFSET_NOT_SET;
		/* XXX end */
		cstate->off_linkpl.constant_part = 24;
		cstate->off_nl = 0;
		cstate->off_nl_nosnap = 0;	/* no 802.2 LLC */
		break;

	case DLT_NULL:
	case DLT_LOOP:
		cstate->off_linktype.constant_part = 0;
		cstate->off_linkpl.constant_part = 4;
		cstate->off_nl = 0;
		cstate->off_nl_nosnap = 0;	/* no 802.2 LLC */
		break;

	case DLT_ENC:
		cstate->off_linktype.constant_part = 0;
		cstate->off_linkpl.constant_part = 12;
		cstate->off_nl = 0;
		cstate->off_nl_nosnap = 0;	/* no 802.2 LLC */
		break;

	case DLT_PPP:
	case DLT_PPP_PPPD:
	case DLT_C_HDLC:		/* BSD/OS Cisco HDLC */
	case DLT_HDLC:			/* NetBSD (Cisco) HDLC */
	case DLT_PPP_SERIAL:		/* NetBSD sync/async serial PPP */
		cstate->off_linktype.constant_part = 2;	/* skip HDLC-like framing */
		cstate->off_linkpl.constant_part = 4;	/* skip HDLC-like framing and protocol field */
		cstate->off_nl = 0;
		cstate->off_nl_nosnap = 0;	/* no 802.2 LLC */
		break;

	case DLT_PPP_ETHER:
		/*
		 * This does not include the Ethernet header, and
		 * only covers session state.
		 */
		cstate->off_linktype.constant_part = 6;
		cstate->off_linkpl.constant_part = 8;
		cstate->off_nl = 0;
		cstate->off_nl_nosnap = 0;	/* no 802.2 LLC */
		break;

	case DLT_PPP_BSDOS:
		cstate->off_linktype.constant_part = 5;
		cstate->off_linkpl.constant_part = 24;
		cstate->off_nl = 0;
		cstate->off_nl_nosnap = 0;	/* no 802.2 LLC */
		break;

	case DLT_FDDI:
		/*
		 * FDDI doesn't really have a link-level type field.
		 * We set "off_linktype" to the offset of the LLC header.
		 *
		 * To check for Ethernet types, we assume that SSAP = SNAP
		 * is being used and pick out the encapsulated Ethernet type.
		 * XXX - should we generate code to check for SNAP?
		 */
		cstate->off_linktype.constant_part = 13;
		cstate->off_linktype.constant_part += cstate->pcap_fddipad;
		cstate->off_linkpl.constant_part = 13;	/* FDDI MAC header length */
		cstate->off_linkpl.constant_part += cstate->pcap_fddipad;
		cstate->off_nl = 8;		/* 802.2+SNAP */
		cstate->off_nl_nosnap = 3;	/* 802.2 */
		break;

	case DLT_IEEE802:
		/*
		 * Token Ring doesn't really have a link-level type field.
		 * We set "off_linktype" to the offset of the LLC header.
		 *
		 * To check for Ethernet types, we assume that SSAP = SNAP
		 * is being used and pick out the encapsulated Ethernet type.
		 * XXX - should we generate code to check for SNAP?
		 *
		 * XXX - the header is actually variable-length.
		 * Some various Linux patched versions gave 38
		 * as "off_linktype" and 40 as "off_nl"; however,
		 * if a token ring packet has *no* routing
		 * information, i.e. is not source-routed, the correct
		 * values are 20 and 22, as they are in the vanilla code.
		 *
		 * A packet is source-routed iff the uppermost bit
		 * of the first byte of the source address, at an
		 * offset of 8, has the uppermost bit set.  If the
		 * packet is source-routed, the total number of bytes
		 * of routing information is 2 plus bits 0x1F00 of
		 * the 16-bit value at an offset of 14 (shifted right
		 * 8 - figure out which byte that is).
		 */
		cstate->off_linktype.constant_part = 14;
		cstate->off_linkpl.constant_part = 14;	/* Token Ring MAC header length */
		cstate->off_nl = 8;		/* 802.2+SNAP */
		cstate->off_nl_nosnap = 3;	/* 802.2 */
		break;

	case DLT_PRISM_HEADER:
	case DLT_IEEE802_11_RADIO_AVS:
	case DLT_IEEE802_11_RADIO:
		cstate->off_linkhdr.is_variable = 1;
		/* Fall through, 802.11 doesn't have a variable link
		 * prefix but is otherwise the same. */
		/* FALLTHROUGH */

	case DLT_IEEE802_11:
		/*
		 * 802.11 doesn't really have a link-level type field.
		 * We set "off_linktype.constant_part" to the offset of
		 * the LLC header.
		 *
		 * To check for Ethernet types, we assume that SSAP = SNAP
		 * is being used and pick out the encapsulated Ethernet type.
		 * XXX - should we generate code to check for SNAP?
		 *
		 * We also handle variable-length radio headers here.
		 * The Prism header is in theory variable-length, but in
		 * practice it's always 144 bytes long.  However, some
		 * drivers on Linux use ARPHRD_IEEE80211_PRISM, but
		 * sometimes or always supply an AVS header, so we
		 * have to check whether the radio header is a Prism
		 * header or an AVS header, so, in practice, it's
		 * variable-length.
		 */
		cstate->off_linktype.constant_part = 24;
		cstate->off_linkpl.constant_part = 0;	/* link-layer header is variable-length */
		cstate->off_linkpl.is_variable = 1;
		cstate->off_nl = 8;		/* 802.2+SNAP */
		cstate->off_nl_nosnap = 3;	/* 802.2 */
		break;

	case DLT_PPI:
		/*
		 * At the moment we treat PPI the same way that we treat
		 * normal Radiotap encoded packets. The difference is in
		 * the function that generates the code at the beginning
		 * to compute the header length.  Since this code generator
		 * of PPI supports bare 802.11 encapsulation only (i.e.
		 * the encapsulated DLT should be DLT_IEEE802_11) we
		 * generate code to check for this too.
		 */
		cstate->off_linktype.constant_part = 24;
		cstate->off_linkpl.constant_part = 0;	/* link-layer header is variable-length */
		cstate->off_linkpl.is_variable = 1;
		cstate->off_linkhdr.is_variable = 1;
		cstate->off_nl = 8;		/* 802.2+SNAP */
		cstate->off_nl_nosnap = 3;	/* 802.2 */
		break;

	case DLT_ATM_RFC1483:
	case DLT_ATM_CLIP:	/* Linux ATM defines this */
		/*
		 * assume routed, non-ISO PDUs
		 * (i.e., LLC = 0xAA-AA-03, OUT = 0x00-00-00)
		 *
		 * XXX - what about ISO PDUs, e.g. CLNP, ISIS, ESIS,
		 * or PPP with the PPP NLPID (e.g., PPPoA)?  The
		 * latter would presumably be treated the way PPPoE
		 * should be, so you can do "pppoe and udp port 2049"
		 * or "pppoa and tcp port 80" and have it check for
		 * PPPo{A,E} and a PPP protocol of IP and....
		 */
		cstate->off_linktype.constant_part = 0;
		cstate->off_linkpl.constant_part = 0;	/* packet begins with LLC header */
		cstate->off_nl = 8;		/* 802.2+SNAP */
		cstate->off_nl_nosnap = 3;	/* 802.2 */
		break;

	case DLT_SUNATM:
		/*
		 * Full Frontal ATM; you get AALn PDUs with an ATM
		 * pseudo-header.
		 */
		cstate->is_atm = 1;
		cstate->off_vpi = SUNATM_VPI_POS;
		cstate->off_vci = SUNATM_VCI_POS;
		cstate->off_proto = PROTO_POS;
		cstate->off_payload = SUNATM_PKT_BEGIN_POS;
		cstate->off_linktype.constant_part = cstate->off_payload;
		cstate->off_linkpl.constant_part = cstate->off_payload;	/* if LLC-encapsulated */
		cstate->off_nl = 8;		/* 802.2+SNAP */
		cstate->off_nl_nosnap = 3;	/* 802.2 */
		break;

	case DLT_RAW:
	case DLT_IPV4:
	case DLT_IPV6:
		cstate->off_linktype.constant_part = OFFSET_NOT_SET;
		cstate->off_linkpl.constant_part = 0;
		cstate->off_nl = 0;
		cstate->off_nl_nosnap = 0;	/* no 802.2 LLC */
		break;

	case DLT_LINUX_SLL:	/* fake header for Linux cooked socket v1 */
		cstate->off_linktype.constant_part = 14;
		cstate->off_linkpl.constant_part = 16;
		cstate->off_nl = 0;
		cstate->off_nl_nosnap = 0;	/* no 802.2 LLC */
		break;

	case DLT_LINUX_SLL2:	/* fake header for Linux cooked socket v2 */
		cstate->off_linktype.constant_part = 0;
		cstate->off_linkpl.constant_part = 20;
		cstate->off_nl = 0;
		cstate->off_nl_nosnap = 0;	/* no 802.2 LLC */
		break;

	case DLT_LTALK:
		/*
		 * LocalTalk does have a 1-byte type field in the LLAP header,
		 * but really it just indicates whether there is a "short" or
		 * "long" DDP packet following.
		 */
		cstate->off_linktype.constant_part = OFFSET_NOT_SET;
		cstate->off_linkpl.constant_part = 0;
		cstate->off_nl = 0;
		cstate->off_nl_nosnap = 0;	/* no 802.2 LLC */
		break;

	case DLT_IP_OVER_FC:
		/*
		 * RFC 2625 IP-over-Fibre-Channel doesn't really have a
		 * link-level type field.  We set "off_linktype" to the
		 * offset of the LLC header.
		 *
		 * To check for Ethernet types, we assume that SSAP = SNAP
		 * is being used and pick out the encapsulated Ethernet type.
		 * XXX - should we generate code to check for SNAP? RFC
		 * 2625 says SNAP should be used.
		 */
		cstate->off_linktype.constant_part = 16;
		cstate->off_linkpl.constant_part = 16;
		cstate->off_nl = 8;		/* 802.2+SNAP */
		cstate->off_nl_nosnap = 3;	/* 802.2 */
		break;

	case DLT_FRELAY:
		/*
		 * XXX - we should set this to handle SNAP-encapsulated
		 * frames (NLPID of 0x80).
		 */
		cstate->off_linktype.constant_part = OFFSET_NOT_SET;
		cstate->off_linkpl.constant_part = 0;
		cstate->off_nl = 0;
		cstate->off_nl_nosnap = 0;	/* no 802.2 LLC */
		break;

		/*
		 * the only BPF-interesting FRF.16 frames are non-control frames;
		 * Frame Relay has a variable length link-layer
		 * so lets start with offset 4 for now and increments later on (FIXME);
		 */
	case DLT_MFR:
		cstate->off_linktype.constant_part = OFFSET_NOT_SET;
		cstate->off_linkpl.constant_part = 0;
		cstate->off_nl = 4;
		cstate->off_nl_nosnap = 0;	/* XXX - for now -> no 802.2 LLC */
		break;

	case DLT_APPLE_IP_OVER_IEEE1394:
		cstate->off_linktype.constant_part = 16;
		cstate->off_linkpl.constant_part = 18;
		cstate->off_nl = 0;
		cstate->off_nl_nosnap = 0;	/* no 802.2 LLC */
		break;

	case DLT_SYMANTEC_FIREWALL:
		cstate->off_linktype.constant_part = 6;
		cstate->off_linkpl.constant_part = 44;
		cstate->off_nl = 0;		/* Ethernet II */
		cstate->off_nl_nosnap = 0;	/* XXX - what does it do with 802.3 packets? */
		break;

	case DLT_PFLOG:
		cstate->off_linktype.constant_part = 0;
		cstate->off_linkpl.constant_part = 0;	/* link-layer header is variable-length */
		cstate->off_linkpl.is_variable = 1;
		cstate->off_nl = 0;
		cstate->off_nl_nosnap = 0;	/* no 802.2 LLC */
		break;

	case DLT_JUNIPER_MFR:
	case DLT_JUNIPER_MLFR:
	case DLT_JUNIPER_MLPPP:
	case DLT_JUNIPER_PPP:
	case DLT_JUNIPER_CHDLC:
	case DLT_JUNIPER_FRELAY:
		cstate->off_linktype.constant_part = 4;
		cstate->off_linkpl.constant_part = 4;
		cstate->off_nl = 0;
		cstate->off_nl_nosnap = OFFSET_NOT_SET;	/* no 802.2 LLC */
		break;

	case DLT_JUNIPER_ATM1:
		cstate->off_linktype.constant_part = 4;		/* in reality variable between 4-8 */
		cstate->off_linkpl.constant_part = 4;	/* in reality variable between 4-8 */
		cstate->off_nl = 0;
		cstate->off_nl_nosnap = 10;
		break;

	case DLT_JUNIPER_ATM2:
		cstate->off_linktype.constant_part = 8;		/* in reality variable between 8-12 */
		cstate->off_linkpl.constant_part = 8;	/* in reality variable between 8-12 */
		cstate->off_nl = 0;
		cstate->off_nl_nosnap = 10;
		break;

		/* frames captured on a Juniper PPPoE service PIC
		 * contain raw ethernet frames */
	case DLT_JUNIPER_PPPOE:
	case DLT_JUNIPER_ETHER:
		cstate->off_linkpl.constant_part = 14;
		cstate->off_linktype.constant_part = 16;
		cstate->off_nl = 18;		/* Ethernet II */
		cstate->off_nl_nosnap = 21;	/* 802.3+802.2 */
		break;

	case DLT_JUNIPER_PPPOE_ATM:
		cstate->off_linktype.constant_part = 4;
		cstate->off_linkpl.constant_part = 6;
		cstate->off_nl = 0;
		cstate->off_nl_nosnap = OFFSET_NOT_SET;	/* no 802.2 LLC */
		break;

	case DLT_JUNIPER_GGSN:
		cstate->off_linktype.constant_part = 6;
		cstate->off_linkpl.constant_part = 12;
		cstate->off_nl = 0;
		cstate->off_nl_nosnap = OFFSET_NOT_SET;	/* no 802.2 LLC */
		break;

	case DLT_JUNIPER_ES:
		cstate->off_linktype.constant_part = 6;
		cstate->off_linkpl.constant_part = OFFSET_NOT_SET;	/* not really a network layer but raw IP addresses */
		cstate->off_nl = OFFSET_NOT_SET;	/* not really a network layer but raw IP addresses */
		cstate->off_nl_nosnap = OFFSET_NOT_SET;	/* no 802.2 LLC */
		break;

	case DLT_JUNIPER_MONITOR:
		cstate->off_linktype.constant_part = 12;
		cstate->off_linkpl.constant_part = 12;
		cstate->off_nl = 0;			/* raw IP/IP6 header */
		cstate->off_nl_nosnap = OFFSET_NOT_SET;	/* no 802.2 LLC */
		break;

	case DLT_BACNET_MS_TP:
		/*
		 * The third octet of an MS/TP frame is Frame Type, but it is
		 * the MS/TP frame type [0..7] rather than a network protocol
		 * type.  It can be tested using "link[2]".  If in future it
		 * becomes necessary to have a solution that matches the
		 * problem space better, it would need to be a new special
		 * primitive that works on MS/TP DLT(s) only and takes names
		 * for the types, for example, "ms-tp type token".
		 */
		cstate->off_linktype.constant_part = OFFSET_NOT_SET;
		cstate->off_linkpl.constant_part = OFFSET_NOT_SET;
		cstate->off_nl = OFFSET_NOT_SET;
		cstate->off_nl_nosnap = OFFSET_NOT_SET;
		break;

	case DLT_JUNIPER_SERVICES:
		cstate->off_linktype.constant_part = 12;
		cstate->off_linkpl.constant_part = OFFSET_NOT_SET;	/* L3 proto location dep. on cookie type */
		cstate->off_nl = OFFSET_NOT_SET;	/* L3 proto location dep. on cookie type */
		cstate->off_nl_nosnap = OFFSET_NOT_SET;	/* no 802.2 LLC */
		break;

	case DLT_JUNIPER_VP:
		cstate->off_linktype.constant_part = 18;
		cstate->off_linkpl.constant_part = OFFSET_NOT_SET;
		cstate->off_nl = OFFSET_NOT_SET;
		cstate->off_nl_nosnap = OFFSET_NOT_SET;
		break;

	case DLT_JUNIPER_ST:
		cstate->off_linktype.constant_part = 18;
		cstate->off_linkpl.constant_part = OFFSET_NOT_SET;
		cstate->off_nl = OFFSET_NOT_SET;
		cstate->off_nl_nosnap = OFFSET_NOT_SET;
		break;

	case DLT_JUNIPER_ISM:
		cstate->off_linktype.constant_part = 8;
		cstate->off_linkpl.constant_part = OFFSET_NOT_SET;
		cstate->off_nl = OFFSET_NOT_SET;
		cstate->off_nl_nosnap = OFFSET_NOT_SET;
		break;

	case DLT_JUNIPER_VS:
	case DLT_JUNIPER_SRX_E2E:
	case DLT_JUNIPER_FIBRECHANNEL:
	case DLT_JUNIPER_ATM_CEMIC:
		cstate->off_linktype.constant_part = 8;
		cstate->off_linkpl.constant_part = OFFSET_NOT_SET;
		cstate->off_nl = OFFSET_NOT_SET;
		cstate->off_nl_nosnap = OFFSET_NOT_SET;
		break;

	case DLT_MTP2:
		cstate->off_li = 2;
		cstate->off_li_hsl = 4;
		cstate->off_sio = 3;
		cstate->off_opc = 4;
		cstate->off_dpc = 4;
		cstate->off_sls = 7;
		cstate->off_linktype.constant_part = OFFSET_NOT_SET;
		cstate->off_linkpl.constant_part = OFFSET_NOT_SET;
		cstate->off_nl = OFFSET_NOT_SET;
		cstate->off_nl_nosnap = OFFSET_NOT_SET;
		break;

	case DLT_MTP2_WITH_PHDR:
		cstate->off_li = 6;
		cstate->off_li_hsl = 8;
		cstate->off_sio = 7;
		cstate->off_opc = 8;
		cstate->off_dpc = 8;
		cstate->off_sls = 11;
		cstate->off_linktype.constant_part = OFFSET_NOT_SET;
		cstate->off_linkpl.constant_part = OFFSET_NOT_SET;
		cstate->off_nl = OFFSET_NOT_SET;
		cstate->off_nl_nosnap = OFFSET_NOT_SET;
		break;

	case DLT_ERF:
		cstate->off_li = 22;
		cstate->off_li_hsl = 24;
		cstate->off_sio = 23;
		cstate->off_opc = 24;
		cstate->off_dpc = 24;
		cstate->off_sls = 27;
		cstate->off_linktype.constant_part = OFFSET_NOT_SET;
		cstate->off_linkpl.constant_part = OFFSET_NOT_SET;
		cstate->off_nl = OFFSET_NOT_SET;
		cstate->off_nl_nosnap = OFFSET_NOT_SET;
		break;

	case DLT_PFSYNC:
		cstate->off_linktype.constant_part = OFFSET_NOT_SET;
		cstate->off_linkpl.constant_part = 4;
		cstate->off_nl = 0;
		cstate->off_nl_nosnap = 0;
		break;

	case DLT_AX25_KISS:
		/*
		 * Currently, only raw "link[N:M]" filtering is supported.
		 */
		cstate->off_linktype.constant_part = OFFSET_NOT_SET;	/* variable, min 15, max 71 steps of 7 */
		cstate->off_linkpl.constant_part = OFFSET_NOT_SET;
		cstate->off_nl = OFFSET_NOT_SET;	/* variable, min 16, max 71 steps of 7 */
		cstate->off_nl_nosnap = OFFSET_NOT_SET;	/* no 802.2 LLC */
		break;

	case DLT_IPNET:
		cstate->off_linktype.constant_part = 1;
		cstate->off_linkpl.constant_part = 24;	/* ipnet header length */
		cstate->off_nl = 0;
		cstate->off_nl_nosnap = OFFSET_NOT_SET;
		break;

	case DLT_NETANALYZER:
		cstate->off_linkhdr.constant_part = 4;	/* Ethernet header is past 4-byte pseudo-header */
		cstate->off_linktype.constant_part = cstate->off_linkhdr.constant_part + 12;
		cstate->off_linkpl.constant_part = cstate->off_linkhdr.constant_part + 14;	/* pseudo-header+Ethernet header length */
		cstate->off_nl = 0;		/* Ethernet II */
		cstate->off_nl_nosnap = 3;	/* 802.3+802.2 */
		break;

	case DLT_NETANALYZER_TRANSPARENT:
		cstate->off_linkhdr.constant_part = 12;	/* MAC header is past 4-byte pseudo-header, preamble, and SFD */
		cstate->off_linktype.constant_part = cstate->off_linkhdr.constant_part + 12;
		cstate->off_linkpl.constant_part = cstate->off_linkhdr.constant_part + 14;	/* pseudo-header+preamble+SFD+Ethernet header length */
		cstate->off_nl = 0;		/* Ethernet II */
		cstate->off_nl_nosnap = 3;	/* 802.3+802.2 */
		break;

	case DLT_EN3MB:
		/*
		 * Currently, only raw "link[N:M]" filtering is supported.
		 */
		cstate->off_linktype.constant_part = OFFSET_NOT_SET;	/* variable, min 15, max 71 steps of 7 */
		cstate->off_linkpl.constant_part = OFFSET_NOT_SET;
		cstate->off_nl = OFFSET_NOT_SET;	/* variable, min 16, max 71 steps of 7 */
		cstate->off_nl_nosnap = OFFSET_NOT_SET;	/* no 802.2 LLC */
		break;

	case DLT_AX25:
		/*
		 * Currently, only raw "link[N:M]" filtering is supported.
		 */
		cstate->off_linktype.constant_part = OFFSET_NOT_SET;	/* variable, min 15, max 71 steps of 7 */
		cstate->off_linkpl.constant_part = OFFSET_NOT_SET;
		cstate->off_nl = OFFSET_NOT_SET;	/* variable, min 16, max 71 steps of 7 */
		cstate->off_nl_nosnap = OFFSET_NOT_SET;	/* no 802.2 LLC */
		break;

	case DLT_PRONET:
		/*
		 * Currently, only raw "link[N:M]" filtering is supported.
		 */
		cstate->off_linktype.constant_part = OFFSET_NOT_SET;	/* variable, min 15, max 71 steps of 7 */
		cstate->off_linkpl.constant_part = OFFSET_NOT_SET;
		cstate->off_nl = OFFSET_NOT_SET;	/* variable, min 16, max 71 steps of 7 */
		cstate->off_nl_nosnap = OFFSET_NOT_SET;	/* no 802.2 LLC */
		break;

	case DLT_CHAOS:
		/*
		 * Currently, only raw "link[N:M]" filtering is supported.
		 */
		cstate->off_linktype.constant_part = OFFSET_NOT_SET;	/* variable, min 15, max 71 steps of 7 */
		cstate->off_linkpl.constant_part = OFFSET_NOT_SET;
		cstate->off_nl = OFFSET_NOT_SET;	/* variable, min 16, max 71 steps of 7 */
		cstate->off_nl_nosnap = OFFSET_NOT_SET;	/* no 802.2 LLC */
		break;

#ifdef DLT_HIPPI
	case DLT_HIPPI:
		/*
		 * Currently, only raw "link[N:M]" filtering is supported.
		 */
		cstate->off_linktype.constant_part = OFFSET_NOT_SET;	/* variable, min 15, max 71 steps of 7 */
		cstate->off_linkpl.constant_part = OFFSET_NOT_SET;
		cstate->off_nl = OFFSET_NOT_SET;	/* variable, min 16, max 71 steps of 7 */
		cstate->off_nl_nosnap = OFFSET_NOT_SET;	/* no 802.2 LLC */
		break;

#endif

	case DLT_REDBACK_SMARTEDGE:
		/*
		 * Currently, only raw "link[N:M]" filtering is supported.
		 */
		cstate->off_linktype.constant_part = OFFSET_NOT_SET;	/* variable, min 15, max 71 steps of 7 */
		cstate->off_linkpl.constant_part = OFFSET_NOT_SET;
		cstate->off_nl = OFFSET_NOT_SET;	/* variable, min 16, max 71 steps of 7 */
		cstate->off_nl_nosnap = OFFSET_NOT_SET;	/* no 802.2 LLC */
		break;


#ifdef DLT_HHDLC
	case DLT_HHDLC:
		/*
		 * Currently, only raw "link[N:M]" filtering is supported.
		 */
		cstate->off_linktype.constant_part = OFFSET_NOT_SET;	/* variable, min 15, max 71 steps of 7 */
		cstate->off_linkpl.constant_part = OFFSET_NOT_SET;
		cstate->off_nl = OFFSET_NOT_SET;	/* variable, min 16, max 71 steps of 7 */
		cstate->off_nl_nosnap = OFFSET_NOT_SET;	/* no 802.2 LLC */
		break;

#endif

	default:
		/*
		 * For values in the range in which we've assigned new
		 * DLT_ values, only raw "link[N:M]" filtering is supported.
		 */
		if (cstate->linktype >= DLT_HIGH_MATCHING_MIN &&
		    cstate->linktype <= DLT_HIGH_MATCHING_MAX) {
			cstate->off_linktype.constant_part = OFFSET_NOT_SET;
			cstate->off_linkpl.constant_part = OFFSET_NOT_SET;
			cstate->off_nl = OFFSET_NOT_SET;
			cstate->off_nl_nosnap = OFFSET_NOT_SET;
		} else {
			bpf_set_error(cstate, "unknown data link type %d",
			    cstate->linktype);
			return (-1);
		}
		break;
	}

	cstate->off_outermostlinkhdr = cstate->off_prevlinkhdr = cstate->off_linkhdr;
	return (0);
}

/*
 * Load a value relative to the specified absolute offset.
 */
static struct slist *
gen_load_absoffsetrel(compiler_state_t *cstate, bpf_abs_offset *abs_offset,
    u_int offset, u_int size)
{
	struct slist *s, *s2;

	s = gen_abs_offset_varpart(cstate, abs_offset);

	/*
	 * If "s" is non-null, it has code to arrange that the X register
	 * contains the variable part of the absolute offset, so we
	 * generate a load relative to that, with an offset of
	 * abs_offset->constant_part + offset.
	 *
	 * Otherwise, we can do an absolute load with an offset of
	 * abs_offset->constant_part + offset.
	 */
	if (s != NULL) {
		/*
		 * "s" points to a list of statements that puts the
		 * variable part of the absolute offset into the X register.
		 * Do an indirect load, to use the X register as an offset.
		 */
		s2 = new_stmt(cstate, BPF_LD|BPF_IND|size);
		s2->s.k = abs_offset->constant_part + offset;
		sappend(s, s2);
	} else {
		/*
		 * There is no variable part of the absolute offset, so
		 * just do an absolute load.
		 */
		s = new_stmt(cstate, BPF_LD|BPF_ABS|size);
		s->s.k = abs_offset->constant_part + offset;
	}
	return s;
}

/*
 * Load a value relative to the beginning of the specified header.
 */
static struct slist *
gen_load_a(compiler_state_t *cstate, enum e_offrel offrel, u_int offset,
    u_int size)
{
	struct slist *s, *s2;

	/*
	 * Squelch warnings from compilers that *don't* assume that
	 * offrel always has a valid enum value and therefore don't
	 * assume that we'll always go through one of the case arms.
	 *
	 * If we have a default case, compilers that *do* assume that
	 * will then complain about the default case code being
	 * unreachable.
	 *
	 * Damned if you do, damned if you don't.
	 */
	s = NULL;

	switch (offrel) {

	case OR_PACKET:
		s = new_stmt(cstate, BPF_LD|BPF_ABS|size);
		s->s.k = offset;
		break;

	case OR_LINKHDR:
		s = gen_load_absoffsetrel(cstate, &cstate->off_linkhdr, offset, size);
		break;

	case OR_PREVLINKHDR:
		s = gen_load_absoffsetrel(cstate, &cstate->off_prevlinkhdr, offset, size);
		break;

	case OR_LLC:
		s = gen_load_absoffsetrel(cstate, &cstate->off_linkpl, offset, size);
		break;

	case OR_PREVMPLSHDR:
		s = gen_load_absoffsetrel(cstate, &cstate->off_linkpl, cstate->off_nl - 4 + offset, size);
		break;

	case OR_LINKPL:
		s = gen_load_absoffsetrel(cstate, &cstate->off_linkpl, cstate->off_nl + offset, size);
		break;

	case OR_LINKPL_NOSNAP:
		s = gen_load_absoffsetrel(cstate, &cstate->off_linkpl, cstate->off_nl_nosnap + offset, size);
		break;

	case OR_LINKTYPE:
		s = gen_load_absoffsetrel(cstate, &cstate->off_linktype, offset, size);
		break;

	case OR_TRAN_IPV4:
		/*
		 * Load the X register with the length of the IPv4 header
		 * (plus the offset of the link-layer header, if it's
		 * preceded by a variable-length header such as a radio
		 * header), in bytes.
		 */
		s = gen_loadx_iphdrlen(cstate);

		/*
		 * Load the item at {offset of the link-layer payload} +
		 * {offset, relative to the start of the link-layer
		 * payload, of the IPv4 header} + {length of the IPv4 header} +
		 * {specified offset}.
		 *
		 * If the offset of the link-layer payload is variable,
		 * the variable part of that offset is included in the
		 * value in the X register, and we include the constant
		 * part in the offset of the load.
		 */
		s2 = new_stmt(cstate, BPF_LD|BPF_IND|size);
		s2->s.k = cstate->off_linkpl.constant_part + cstate->off_nl + offset;
		sappend(s, s2);
		break;

	case OR_TRAN_IPV6:
		s = gen_load_absoffsetrel(cstate, &cstate->off_linkpl, cstate->off_nl + 40 + offset, size);
		break;
	}
	return s;
}

/*
 * Generate code to load into the X register the sum of the length of
 * the IPv4 header and the variable part of the offset of the link-layer
 * payload.
 */
static struct slist *
gen_loadx_iphdrlen(compiler_state_t *cstate)
{
	struct slist *s, *s2;

	s = gen_abs_offset_varpart(cstate, &cstate->off_linkpl);
	if (s != NULL) {
		/*
		 * The offset of the link-layer payload has a variable
		 * part.  "s" points to a list of statements that put
		 * the variable part of that offset into the X register.
		 *
		 * The 4*([k]&0xf) addressing mode can't be used, as we
		 * don't have a constant offset, so we have to load the
		 * value in question into the A register and add to it
		 * the value from the X register.
		 */
		s2 = new_stmt(cstate, BPF_LD|BPF_IND|BPF_B);
		s2->s.k = cstate->off_linkpl.constant_part + cstate->off_nl;
		sappend(s, s2);
		s2 = new_stmt(cstate, BPF_ALU|BPF_AND|BPF_K);
		s2->s.k = 0xf;
		sappend(s, s2);
		s2 = new_stmt(cstate, BPF_ALU|BPF_LSH|BPF_K);
		s2->s.k = 2;
		sappend(s, s2);

		/*
		 * The A register now contains the length of the IP header.
		 * We need to add to it the variable part of the offset of
		 * the link-layer payload, which is still in the X
		 * register, and move the result into the X register.
		 */
		sappend(s, new_stmt(cstate, BPF_ALU|BPF_ADD|BPF_X));
		sappend(s, new_stmt(cstate, BPF_MISC|BPF_TAX));
	} else {
		/*
		 * The offset of the link-layer payload is a constant,
		 * so no code was generated to load the (nonexistent)
		 * variable part of that offset.
		 *
		 * This means we can use the 4*([k]&0xf) addressing
		 * mode.  Load the length of the IPv4 header, which
		 * is at an offset of cstate->off_nl from the beginning of
		 * the link-layer payload, and thus at an offset of
		 * cstate->off_linkpl.constant_part + cstate->off_nl from the beginning
		 * of the raw packet data, using that addressing mode.
		 */
		s = new_stmt(cstate, BPF_LDX|BPF_MSH|BPF_B);
		s->s.k = cstate->off_linkpl.constant_part + cstate->off_nl;
	}
	return s;
}


static struct block *
gen_uncond(compiler_state_t *cstate, int rsense)
{
	struct slist *s;

	s = new_stmt(cstate, BPF_LD|BPF_IMM);
	s->s.k = !rsense;
	return gen_jmp_k(cstate, BPF_JEQ, 0, s);
}

static inline struct block *
gen_true(compiler_state_t *cstate)
{
	return gen_uncond(cstate, 1);
}

static inline struct block *
gen_false(compiler_state_t *cstate)
{
	return gen_uncond(cstate, 0);
}

/*
 * Generate code to match a particular packet type.
 *
 * "proto" is an Ethernet type value, if > ETHERMTU, or an LLC SAP
 * value, if <= ETHERMTU.  We use that to determine whether to
 * match the type/length field or to check the type/length field for
 * a value <= ETHERMTU to see whether it's a type field and then do
 * the appropriate test.
 */
static struct block *
gen_ether_linktype(compiler_state_t *cstate, bpf_u_int32 ll_proto)
{
	struct block *b0, *b1;

	switch (ll_proto) {

	case LLCSAP_ISONS:
	case LLCSAP_IP:
	case LLCSAP_NETBEUI:
		/*
		 * OSI protocols and NetBEUI always use 802.2 encapsulation,
		 * so we check the DSAP and SSAP.
		 *
		 * LLCSAP_IP checks for IP-over-802.2, rather
		 * than IP-over-Ethernet or IP-over-SNAP.
		 *
		 * XXX - should we check both the DSAP and the
		 * SSAP, like this, or should we check just the
		 * DSAP, as we do for other types <= ETHERMTU
		 * (i.e., other SAP values)?
		 */
		b0 = gen_cmp_le(cstate, OR_LINKTYPE, 0, BPF_H, ETHERMTU);
		b1 = gen_cmp(cstate, OR_LLC, 0, BPF_H, (ll_proto << 8) | ll_proto);
		gen_and(b0, b1);
		return b1;

	case LLCSAP_IPX:
		/*
		 * Check for;
		 *
		 *	Ethernet_II frames, which are Ethernet
		 *	frames with a frame type of ETHERTYPE_IPX;
		 *
		 *	Ethernet_802.3 frames, which are 802.3
		 *	frames (i.e., the type/length field is
		 *	a length field, <= ETHERMTU, rather than
		 *	a type field) with the first two bytes
		 *	after the Ethernet/802.3 header being
		 *	0xFFFF;
		 *
		 *	Ethernet_802.2 frames, which are 802.3
		 *	frames with an 802.2 LLC header and
		 *	with the IPX LSAP as the DSAP in the LLC
		 *	header;
		 *
		 *	Ethernet_SNAP frames, which are 802.3
		 *	frames with an LLC header and a SNAP
		 *	header and with an OUI of 0x000000
		 *	(encapsulated Ethernet) and a protocol
		 *	ID of ETHERTYPE_IPX in the SNAP header.
		 *
		 * XXX - should we generate the same code both
		 * for tests for LLCSAP_IPX and for ETHERTYPE_IPX?
		 */

		/*
		 * This generates code to check both for the
		 * IPX LSAP (Ethernet_802.2) and for Ethernet_802.3.
		 */
		b0 = gen_cmp(cstate, OR_LLC, 0, BPF_B, LLCSAP_IPX);
		b1 = gen_cmp(cstate, OR_LLC, 0, BPF_H, 0xFFFF);
		gen_or(b0, b1);

		/*
		 * Now we add code to check for SNAP frames with
		 * ETHERTYPE_IPX, i.e. Ethernet_SNAP.
		 */
		b0 = gen_snap(cstate, 0x000000, ETHERTYPE_IPX);
		gen_or(b0, b1);

		/*
		 * Now we generate code to check for 802.3
		 * frames in general.
		 */
		b0 = gen_cmp_le(cstate, OR_LINKTYPE, 0, BPF_H, ETHERMTU);

		/*
		 * Now add the check for 802.3 frames before the
		 * check for Ethernet_802.2 and Ethernet_802.3,
		 * as those checks should only be done on 802.3
		 * frames, not on Ethernet frames.
		 */
		gen_and(b0, b1);

		/*
		 * Now add the check for Ethernet_II frames, and
		 * do that before checking for the other frame
		 * types.
		 */
		b0 = gen_cmp(cstate, OR_LINKTYPE, 0, BPF_H, ETHERTYPE_IPX);
		gen_or(b0, b1);
		return b1;

	case ETHERTYPE_ATALK:
	case ETHERTYPE_AARP:
		/*
		 * EtherTalk (AppleTalk protocols on Ethernet link
		 * layer) may use 802.2 encapsulation.
		 */

		/*
		 * Check for 802.2 encapsulation (EtherTalk phase 2?);
		 * we check for an Ethernet type field less or equal than
		 * 1500, which means it's an 802.3 length field.
		 */
		b0 = gen_cmp_le(cstate, OR_LINKTYPE, 0, BPF_H, ETHERMTU);

		/*
		 * 802.2-encapsulated ETHERTYPE_ATALK packets are
		 * SNAP packets with an organization code of
		 * 0x080007 (Apple, for Appletalk) and a protocol
		 * type of ETHERTYPE_ATALK (Appletalk).
		 *
		 * 802.2-encapsulated ETHERTYPE_AARP packets are
		 * SNAP packets with an organization code of
		 * 0x000000 (encapsulated Ethernet) and a protocol
		 * type of ETHERTYPE_AARP (Appletalk ARP).
		 */
		if (ll_proto == ETHERTYPE_ATALK)
			b1 = gen_snap(cstate, 0x080007, ETHERTYPE_ATALK);
		else	/* ll_proto == ETHERTYPE_AARP */
			b1 = gen_snap(cstate, 0x000000, ETHERTYPE_AARP);
		gen_and(b0, b1);

		/*
		 * Check for Ethernet encapsulation (Ethertalk
		 * phase 1?); we just check for the Ethernet
		 * protocol type.
		 */
		b0 = gen_cmp(cstate, OR_LINKTYPE, 0, BPF_H, ll_proto);

		gen_or(b0, b1);
		return b1;

	default:
		if (ll_proto <= ETHERMTU) {
			assert_maxval(cstate, "LLC DSAP", ll_proto, UINT8_MAX);
			/*
			 * This is an LLC SAP value, so the frames
			 * that match would be 802.2 frames.
			 * Check that the frame is an 802.2 frame
			 * (i.e., that the length/type field is
			 * a length field, <= ETHERMTU) and
			 * then check the DSAP.
			 */
			b0 = gen_cmp_le(cstate, OR_LINKTYPE, 0, BPF_H, ETHERMTU);
			b1 = gen_cmp(cstate, OR_LINKTYPE, 2, BPF_B, ll_proto);
			gen_and(b0, b1);
			return b1;
		} else {
			assert_maxval(cstate, "EtherType", ll_proto, UINT16_MAX);
			/*
			 * This is an Ethernet type, so compare
			 * the length/type field with it (if
			 * the frame is an 802.2 frame, the length
			 * field will be <= ETHERMTU, and, as
			 * "ll_proto" is > ETHERMTU, this test
			 * will fail and the frame won't match,
			 * which is what we want).
			 */
			return gen_cmp(cstate, OR_LINKTYPE, 0, BPF_H, ll_proto);
		}
	}
}

static struct block *
gen_loopback_linktype(compiler_state_t *cstate, bpf_u_int32 ll_proto)
{
	/*
	 * For DLT_NULL, the link-layer header is a 32-bit word
	 * containing an AF_ value in *host* byte order, and for
	 * DLT_ENC, the link-layer header begins with a 32-bit
	 * word containing an AF_ value in host byte order.
	 *
	 * In addition, if we're reading a saved capture file,
	 * the host byte order in the capture may not be the
	 * same as the host byte order on this machine.
	 *
	 * For DLT_LOOP, the link-layer header is a 32-bit
	 * word containing an AF_ value in *network* byte order.
	 */
	if (cstate->linktype == DLT_NULL || cstate->linktype == DLT_ENC) {
		/*
		 * The AF_ value is in host byte order, but the BPF
		 * interpreter will convert it to network byte order.
		 *
		 * If this is a save file, and it's from a machine
		 * with the opposite byte order to ours, we byte-swap
		 * the AF_ value.
		 *
		 * Then we run it through "htonl()", and generate
		 * code to compare against the result.
		 */
		if (cstate->bpf_pcap->rfile != NULL && cstate->bpf_pcap->swapped)
			ll_proto = SWAPLONG(ll_proto);
		ll_proto = htonl(ll_proto);
	}
	return (gen_cmp(cstate, OR_LINKHDR, 0, BPF_W, ll_proto));
}

/*
 * "proto" is an Ethernet type value and for IPNET, if it is not IPv4
 * or IPv6 then we have an error.
 */
static struct block *
gen_ipnet_linktype(compiler_state_t *cstate, bpf_u_int32 ll_proto)
{
	switch (ll_proto) {

	case ETHERTYPE_IP:
		return gen_cmp(cstate, OR_LINKTYPE, 0, BPF_B, IPH_AF_INET);
		/*NOTREACHED*/

	case ETHERTYPE_IPV6:
		return gen_cmp(cstate, OR_LINKTYPE, 0, BPF_B, IPH_AF_INET6);
		/*NOTREACHED*/

	default:
		break;
	}

	return gen_false(cstate);
}

/*
 * Generate code to match a particular packet type.
 *
 * "ll_proto" is an Ethernet type value, if > ETHERMTU, or an LLC SAP
 * value, if <= ETHERMTU.  We use that to determine whether to
 * match the type field or to check the type field for the special
 * LINUX_SLL_P_802_2 value and then do the appropriate test.
 */
static struct block *
gen_linux_sll_linktype(compiler_state_t *cstate, bpf_u_int32 ll_proto)
{
	struct block *b0, *b1;

	switch (ll_proto) {

	case LLCSAP_ISONS:
	case LLCSAP_IP:
	case LLCSAP_NETBEUI:
		/*
		 * OSI protocols and NetBEUI always use 802.2 encapsulation,
		 * so we check the DSAP and SSAP.
		 *
		 * LLCSAP_IP checks for IP-over-802.2, rather
		 * than IP-over-Ethernet or IP-over-SNAP.
		 *
		 * XXX - should we check both the DSAP and the
		 * SSAP, like this, or should we check just the
		 * DSAP, as we do for other types <= ETHERMTU
		 * (i.e., other SAP values)?
		 */
		b0 = gen_cmp(cstate, OR_LINKTYPE, 0, BPF_H, LINUX_SLL_P_802_2);
		b1 = gen_cmp(cstate, OR_LLC, 0, BPF_H, (ll_proto << 8) | ll_proto);
		gen_and(b0, b1);
		return b1;

	case LLCSAP_IPX:
		/*
		 *	Ethernet_II frames, which are Ethernet
		 *	frames with a frame type of ETHERTYPE_IPX;
		 *
		 *	Ethernet_802.3 frames, which have a frame
		 *	type of LINUX_SLL_P_802_3;
		 *
		 *	Ethernet_802.2 frames, which are 802.3
		 *	frames with an 802.2 LLC header (i.e, have
		 *	a frame type of LINUX_SLL_P_802_2) and
		 *	with the IPX LSAP as the DSAP in the LLC
		 *	header;
		 *
		 *	Ethernet_SNAP frames, which are 802.3
		 *	frames with an LLC header and a SNAP
		 *	header and with an OUI of 0x000000
		 *	(encapsulated Ethernet) and a protocol
		 *	ID of ETHERTYPE_IPX in the SNAP header.
		 *
		 * First, do the checks on LINUX_SLL_P_802_2
		 * frames; generate the check for either
		 * Ethernet_802.2 or Ethernet_SNAP frames, and
		 * then put a check for LINUX_SLL_P_802_2 frames
		 * before it.
		 */
		b0 = gen_cmp(cstate, OR_LLC, 0, BPF_B, LLCSAP_IPX);
		b1 = gen_snap(cstate, 0x000000, ETHERTYPE_IPX);
		gen_or(b0, b1);
		b0 = gen_cmp(cstate, OR_LINKTYPE, 0, BPF_H, LINUX_SLL_P_802_2);
		gen_and(b0, b1);

		/*
		 * Now check for 802.3 frames and OR that with
		 * the previous test.
		 */
		b0 = gen_cmp(cstate, OR_LINKTYPE, 0, BPF_H, LINUX_SLL_P_802_3);
		gen_or(b0, b1);

		/*
		 * Now add the check for Ethernet_II frames, and
		 * do that before checking for the other frame
		 * types.
		 */
		b0 = gen_cmp(cstate, OR_LINKTYPE, 0, BPF_H, ETHERTYPE_IPX);
		gen_or(b0, b1);
		return b1;

	case ETHERTYPE_ATALK:
	case ETHERTYPE_AARP:
		/*
		 * EtherTalk (AppleTalk protocols on Ethernet link
		 * layer) may use 802.2 encapsulation.
		 */

		/*
		 * Check for 802.2 encapsulation (EtherTalk phase 2?);
		 * we check for the 802.2 protocol type in the
		 * "Ethernet type" field.
		 */
		b0 = gen_cmp(cstate, OR_LINKTYPE, 0, BPF_H, LINUX_SLL_P_802_2);

		/*
		 * 802.2-encapsulated ETHERTYPE_ATALK packets are
		 * SNAP packets with an organization code of
		 * 0x080007 (Apple, for Appletalk) and a protocol
		 * type of ETHERTYPE_ATALK (Appletalk).
		 *
		 * 802.2-encapsulated ETHERTYPE_AARP packets are
		 * SNAP packets with an organization code of
		 * 0x000000 (encapsulated Ethernet) and a protocol
		 * type of ETHERTYPE_AARP (Appletalk ARP).
		 */
		if (ll_proto == ETHERTYPE_ATALK)
			b1 = gen_snap(cstate, 0x080007, ETHERTYPE_ATALK);
		else	/* ll_proto == ETHERTYPE_AARP */
			b1 = gen_snap(cstate, 0x000000, ETHERTYPE_AARP);
		gen_and(b0, b1);

		/*
		 * Check for Ethernet encapsulation (Ethertalk
		 * phase 1?); we just check for the Ethernet
		 * protocol type.
		 */
		b0 = gen_cmp(cstate, OR_LINKTYPE, 0, BPF_H, ll_proto);

		gen_or(b0, b1);
		return b1;

	default:
		if (ll_proto <= ETHERMTU) {
			assert_maxval(cstate, "LLC DSAP", ll_proto, UINT8_MAX);
			/*
			 * This is an LLC SAP value, so the frames
			 * that match would be 802.2 frames.
			 * Check for the 802.2 protocol type
			 * in the "Ethernet type" field, and
			 * then check the DSAP.
			 */
			b0 = gen_cmp(cstate, OR_LINKTYPE, 0, BPF_H, LINUX_SLL_P_802_2);
			b1 = gen_cmp(cstate, OR_LINKHDR, cstate->off_linkpl.constant_part, BPF_B,
			     ll_proto);
			gen_and(b0, b1);
			return b1;
		} else {
			assert_maxval(cstate, "EtherType", ll_proto, UINT16_MAX);
			/*
			 * This is an Ethernet type, so compare
			 * the length/type field with it (if
			 * the frame is an 802.2 frame, the length
			 * field will be <= ETHERMTU, and, as
			 * "ll_proto" is > ETHERMTU, this test
			 * will fail and the frame won't match,
			 * which is what we want).
			 */
			return gen_cmp(cstate, OR_LINKTYPE, 0, BPF_H, ll_proto);
		}
	}
}

/*
 * Load a value relative to the beginning of the link-layer header after the
 * pflog header.
 */
static struct slist *
gen_load_pflog_llprefixlen(compiler_state_t *cstate)
{
	struct slist *s1, *s2;

	/*
	 * Generate code to load the length of the pflog header into
	 * the register assigned to hold that length, if one has been
	 * assigned.  (If one hasn't been assigned, no code we've
	 * generated uses that prefix, so we don't need to generate any
	 * code to load it.)
	 */
	if (cstate->off_linkpl.reg != -1) {
		/*
		 * The length is in the first byte of the header.
		 */
		s1 = new_stmt(cstate, BPF_LD|BPF_B|BPF_ABS);
		s1->s.k = 0;

		/*
		 * Round it up to a multiple of 4.
		 * Add 3, and clear the lower 2 bits.
		 */
		s2 = new_stmt(cstate, BPF_ALU|BPF_ADD|BPF_K);
		s2->s.k = 3;
		sappend(s1, s2);
		s2 = new_stmt(cstate, BPF_ALU|BPF_AND|BPF_K);
		s2->s.k = 0xfffffffc;
		sappend(s1, s2);

		/*
		 * Now allocate a register to hold that value and store
		 * it.
		 */
		s2 = new_stmt(cstate, BPF_ST);
		s2->s.k = cstate->off_linkpl.reg;
		sappend(s1, s2);

		/*
		 * Now move it into the X register.
		 */
		s2 = new_stmt(cstate, BPF_MISC|BPF_TAX);
		sappend(s1, s2);

		return (s1);
	} else
		return (NULL);
}

static struct slist *
gen_load_prism_llprefixlen(compiler_state_t *cstate)
{
	struct slist *s1, *s2;
	struct slist *sjeq_avs_cookie;
	struct slist *sjcommon;

	/*
	 * This code is not compatible with the optimizer, as
	 * we are generating jmp instructions within a normal
	 * slist of instructions
	 */
	cstate->no_optimize = 1;

	/*
	 * Generate code to load the length of the radio header into
	 * the register assigned to hold that length, if one has been
	 * assigned.  (If one hasn't been assigned, no code we've
	 * generated uses that prefix, so we don't need to generate any
	 * code to load it.)
	 *
	 * Some Linux drivers use ARPHRD_IEEE80211_PRISM but sometimes
	 * or always use the AVS header rather than the Prism header.
	 * We load a 4-byte big-endian value at the beginning of the
	 * raw packet data, and see whether, when masked with 0xFFFFF000,
	 * it's equal to 0x80211000.  If so, that indicates that it's
	 * an AVS header (the masked-out bits are the version number).
	 * Otherwise, it's a Prism header.
	 *
	 * XXX - the Prism header is also, in theory, variable-length,
	 * but no known software generates headers that aren't 144
	 * bytes long.
	 */
	if (cstate->off_linkhdr.reg != -1) {
		/*
		 * Load the cookie.
		 */
		s1 = new_stmt(cstate, BPF_LD|BPF_W|BPF_ABS);
		s1->s.k = 0;

		/*
		 * AND it with 0xFFFFF000.
		 */
		s2 = new_stmt(cstate, BPF_ALU|BPF_AND|BPF_K);
		s2->s.k = 0xFFFFF000;
		sappend(s1, s2);

		/*
		 * Compare with 0x80211000.
		 */
		sjeq_avs_cookie = new_stmt(cstate, JMP(BPF_JEQ, BPF_K));
		sjeq_avs_cookie->s.k = 0x80211000;
		sappend(s1, sjeq_avs_cookie);

		/*
		 * If it's AVS:
		 *
		 * The 4 bytes at an offset of 4 from the beginning of
		 * the AVS header are the length of the AVS header.
		 * That field is big-endian.
		 */
		s2 = new_stmt(cstate, BPF_LD|BPF_W|BPF_ABS);
		s2->s.k = 4;
		sappend(s1, s2);
		sjeq_avs_cookie->s.jt = s2;

		/*
		 * Now jump to the code to allocate a register
		 * into which to save the header length and
		 * store the length there.  (The "jump always"
		 * instruction needs to have the k field set;
		 * it's added to the PC, so, as we're jumping
		 * over a single instruction, it should be 1.)
		 */
		sjcommon = new_stmt(cstate, JMP(BPF_JA, BPF_K));
		sjcommon->s.k = 1;
		sappend(s1, sjcommon);

		/*
		 * Now for the code that handles the Prism header.
		 * Just load the length of the Prism header (144)
		 * into the A register.  Have the test for an AVS
		 * header branch here if we don't have an AVS header.
		 */
		s2 = new_stmt(cstate, BPF_LD|BPF_W|BPF_IMM);
		s2->s.k = 144;
		sappend(s1, s2);
		sjeq_avs_cookie->s.jf = s2;

		/*
		 * Now allocate a register to hold that value and store
		 * it.  The code for the AVS header will jump here after
		 * loading the length of the AVS header.
		 */
		s2 = new_stmt(cstate, BPF_ST);
		s2->s.k = cstate->off_linkhdr.reg;
		sappend(s1, s2);
		sjcommon->s.jf = s2;

		/*
		 * Now move it into the X register.
		 */
		s2 = new_stmt(cstate, BPF_MISC|BPF_TAX);
		sappend(s1, s2);

		return (s1);
	} else
		return (NULL);
}

static struct slist *
gen_load_avs_llprefixlen(compiler_state_t *cstate)
{
	struct slist *s1, *s2;

	/*
	 * Generate code to load the length of the AVS header into
	 * the register assigned to hold that length, if one has been
	 * assigned.  (If one hasn't been assigned, no code we've
	 * generated uses that prefix, so we don't need to generate any
	 * code to load it.)
	 */
	if (cstate->off_linkhdr.reg != -1) {
		/*
		 * The 4 bytes at an offset of 4 from the beginning of
		 * the AVS header are the length of the AVS header.
		 * That field is big-endian.
		 */
		s1 = new_stmt(cstate, BPF_LD|BPF_W|BPF_ABS);
		s1->s.k = 4;

		/*
		 * Now allocate a register to hold that value and store
		 * it.
		 */
		s2 = new_stmt(cstate, BPF_ST);
		s2->s.k = cstate->off_linkhdr.reg;
		sappend(s1, s2);

		/*
		 * Now move it into the X register.
		 */
		s2 = new_stmt(cstate, BPF_MISC|BPF_TAX);
		sappend(s1, s2);

		return (s1);
	} else
		return (NULL);
}

static struct slist *
gen_load_radiotap_llprefixlen(compiler_state_t *cstate)
{
	struct slist *s1, *s2;

	/*
	 * Generate code to load the length of the radiotap header into
	 * the register assigned to hold that length, if one has been
	 * assigned.  (If one hasn't been assigned, no code we've
	 * generated uses that prefix, so we don't need to generate any
	 * code to load it.)
	 */
	if (cstate->off_linkhdr.reg != -1) {
		/*
		 * The 2 bytes at offsets of 2 and 3 from the beginning
		 * of the radiotap header are the length of the radiotap
		 * header; unfortunately, it's little-endian, so we have
		 * to load it a byte at a time and construct the value.
		 */

		/*
		 * Load the high-order byte, at an offset of 3, shift it
		 * left a byte, and put the result in the X register.
		 */
		s1 = new_stmt(cstate, BPF_LD|BPF_B|BPF_ABS);
		s1->s.k = 3;
		s2 = new_stmt(cstate, BPF_ALU|BPF_LSH|BPF_K);
		sappend(s1, s2);
		s2->s.k = 8;
		s2 = new_stmt(cstate, BPF_MISC|BPF_TAX);
		sappend(s1, s2);

		/*
		 * Load the next byte, at an offset of 2, and OR the
		 * value from the X register into it.
		 */
		s2 = new_stmt(cstate, BPF_LD|BPF_B|BPF_ABS);
		sappend(s1, s2);
		s2->s.k = 2;
		s2 = new_stmt(cstate, BPF_ALU|BPF_OR|BPF_X);
		sappend(s1, s2);

		/*
		 * Now allocate a register to hold that value and store
		 * it.
		 */
		s2 = new_stmt(cstate, BPF_ST);
		s2->s.k = cstate->off_linkhdr.reg;
		sappend(s1, s2);

		/*
		 * Now move it into the X register.
		 */
		s2 = new_stmt(cstate, BPF_MISC|BPF_TAX);
		sappend(s1, s2);

		return (s1);
	} else
		return (NULL);
}

/*
 * At the moment we treat PPI as normal Radiotap encoded
 * packets. The difference is in the function that generates
 * the code at the beginning to compute the header length.
 * Since this code generator of PPI supports bare 802.11
 * encapsulation only (i.e. the encapsulated DLT should be
 * DLT_IEEE802_11) we generate code to check for this too;
 * that's done in finish_parse().
 */
static struct slist *
gen_load_ppi_llprefixlen(compiler_state_t *cstate)
{
	struct slist *s1, *s2;

	/*
	 * Generate code to load the length of the radiotap header
	 * into the register assigned to hold that length, if one has
	 * been assigned.
	 */
	if (cstate->off_linkhdr.reg != -1) {
		/*
		 * The 2 bytes at offsets of 2 and 3 from the beginning
		 * of the radiotap header are the length of the radiotap
		 * header; unfortunately, it's little-endian, so we have
		 * to load it a byte at a time and construct the value.
		 */

		/*
		 * Load the high-order byte, at an offset of 3, shift it
		 * left a byte, and put the result in the X register.
		 */
		s1 = new_stmt(cstate, BPF_LD|BPF_B|BPF_ABS);
		s1->s.k = 3;
		s2 = new_stmt(cstate, BPF_ALU|BPF_LSH|BPF_K);
		sappend(s1, s2);
		s2->s.k = 8;
		s2 = new_stmt(cstate, BPF_MISC|BPF_TAX);
		sappend(s1, s2);

		/*
		 * Load the next byte, at an offset of 2, and OR the
		 * value from the X register into it.
		 */
		s2 = new_stmt(cstate, BPF_LD|BPF_B|BPF_ABS);
		sappend(s1, s2);
		s2->s.k = 2;
		s2 = new_stmt(cstate, BPF_ALU|BPF_OR|BPF_X);
		sappend(s1, s2);

		/*
		 * Now allocate a register to hold that value and store
		 * it.
		 */
		s2 = new_stmt(cstate, BPF_ST);
		s2->s.k = cstate->off_linkhdr.reg;
		sappend(s1, s2);

		/*
		 * Now move it into the X register.
		 */
		s2 = new_stmt(cstate, BPF_MISC|BPF_TAX);
		sappend(s1, s2);

		return (s1);
	} else
		return (NULL);
}

/*
 * Load a value relative to the beginning of the link-layer header after the 802.11
 * header, i.e. LLC_SNAP.
 * The link-layer header doesn't necessarily begin at the beginning
 * of the packet data; there might be a variable-length prefix containing
 * radio information.
 */
static struct slist *
gen_load_802_11_header_len(compiler_state_t *cstate, struct slist *s, struct slist *snext)
{
	struct slist *s2;
	struct slist *sjset_data_frame_1;
	struct slist *sjset_data_frame_2;
	struct slist *sjset_qos;
	struct slist *sjset_radiotap_flags_present;
	struct slist *sjset_radiotap_ext_present;
	struct slist *sjset_radiotap_tsft_present;
	struct slist *sjset_tsft_datapad, *sjset_notsft_datapad;
	struct slist *s_roundup;

	if (cstate->off_linkpl.reg == -1) {
		/*
		 * No register has been assigned to the offset of
		 * the link-layer payload, which means nobody needs
		 * it; don't bother computing it - just return
		 * what we already have.
		 */
		return (s);
	}

	/*
	 * This code is not compatible with the optimizer, as
	 * we are generating jmp instructions within a normal
	 * slist of instructions
	 */
	cstate->no_optimize = 1;

	/*
	 * If "s" is non-null, it has code to arrange that the X register
	 * contains the length of the prefix preceding the link-layer
	 * header.
	 *
	 * Otherwise, the length of the prefix preceding the link-layer
	 * header is "off_outermostlinkhdr.constant_part".
	 */
	if (s == NULL) {
		/*
		 * There is no variable-length header preceding the
		 * link-layer header.
		 *
		 * Load the length of the fixed-length prefix preceding
		 * the link-layer header (if any) into the X register,
		 * and store it in the cstate->off_linkpl.reg register.
		 * That length is off_outermostlinkhdr.constant_part.
		 */
		s = new_stmt(cstate, BPF_LDX|BPF_IMM);
		s->s.k = cstate->off_outermostlinkhdr.constant_part;
	}

	/*
	 * The X register contains the offset of the beginning of the
	 * link-layer header; add 24, which is the minimum length
	 * of the MAC header for a data frame, to that, and store it
	 * in cstate->off_linkpl.reg, and then load the Frame Control field,
	 * which is at the offset in the X register, with an indexed load.
	 */
	s2 = new_stmt(cstate, BPF_MISC|BPF_TXA);
	sappend(s, s2);
	s2 = new_stmt(cstate, BPF_ALU|BPF_ADD|BPF_K);
	s2->s.k = 24;
	sappend(s, s2);
	s2 = new_stmt(cstate, BPF_ST);
	s2->s.k = cstate->off_linkpl.reg;
	sappend(s, s2);

	s2 = new_stmt(cstate, BPF_LD|BPF_IND|BPF_B);
	s2->s.k = 0;
	sappend(s, s2);

	/*
	 * Check the Frame Control field to see if this is a data frame;
	 * a data frame has the 0x08 bit (b3) in that field set and the
	 * 0x04 bit (b2) clear.
	 */
	sjset_data_frame_1 = new_stmt(cstate, JMP(BPF_JSET, BPF_K));
	sjset_data_frame_1->s.k = IEEE80211_FC0_TYPE_DATA;
	sappend(s, sjset_data_frame_1);

	/*
	 * If b3 is set, test b2, otherwise go to the first statement of
	 * the rest of the program.
	 */
	sjset_data_frame_1->s.jt = sjset_data_frame_2 = new_stmt(cstate, JMP(BPF_JSET, BPF_K));
	sjset_data_frame_2->s.k = IEEE80211_FC0_TYPE_CTL;
	sappend(s, sjset_data_frame_2);
	sjset_data_frame_1->s.jf = snext;

	/*
	 * If b2 is not set, this is a data frame; test the QoS bit.
	 * Otherwise, go to the first statement of the rest of the
	 * program.
	 */
	sjset_data_frame_2->s.jt = snext;
	sjset_data_frame_2->s.jf = sjset_qos = new_stmt(cstate, JMP(BPF_JSET, BPF_K));
	sjset_qos->s.k = IEEE80211_FC0_SUBTYPE_QOS;
	sappend(s, sjset_qos);

	/*
	 * If it's set, add 2 to cstate->off_linkpl.reg, to skip the QoS
	 * field.
	 * Otherwise, go to the first statement of the rest of the
	 * program.
	 */
	sjset_qos->s.jt = s2 = new_stmt(cstate, BPF_LD|BPF_MEM);
	s2->s.k = cstate->off_linkpl.reg;
	sappend(s, s2);
	s2 = new_stmt(cstate, BPF_ALU|BPF_ADD|BPF_IMM);
	s2->s.k = 2;
	sappend(s, s2);
	s2 = new_stmt(cstate, BPF_ST);
	s2->s.k = cstate->off_linkpl.reg;
	sappend(s, s2);

	/*
	 * If we have a radiotap header, look at it to see whether
	 * there's Atheros padding between the MAC-layer header
	 * and the payload.
	 *
	 * Note: all of the fields in the radiotap header are
	 * little-endian, so we byte-swap all of the values
	 * we test against, as they will be loaded as big-endian
	 * values.
	 *
	 * XXX - in the general case, we would have to scan through
	 * *all* the presence bits, if there's more than one word of
	 * presence bits.  That would require a loop, meaning that
	 * we wouldn't be able to run the filter in the kernel.
	 *
	 * We assume here that the Atheros adapters that insert the
	 * annoying padding don't have multiple antennae and therefore
	 * do not generate radiotap headers with multiple presence words.
	 */
	if (cstate->linktype == DLT_IEEE802_11_RADIO) {
		/*
		 * Is the IEEE80211_RADIOTAP_FLAGS bit (0x0000002) set
		 * in the first presence flag word?
		 */
		sjset_qos->s.jf = s2 = new_stmt(cstate, BPF_LD|BPF_ABS|BPF_W);
		s2->s.k = 4;
		sappend(s, s2);

		sjset_radiotap_flags_present = new_stmt(cstate, JMP(BPF_JSET, BPF_K));
		sjset_radiotap_flags_present->s.k = SWAPLONG(0x00000002);
		sappend(s, sjset_radiotap_flags_present);

		/*
		 * If not, skip all of this.
		 */
		sjset_radiotap_flags_present->s.jf = snext;

		/*
		 * Otherwise, is the "extension" bit set in that word?
		 */
		sjset_radiotap_ext_present = new_stmt(cstate, JMP(BPF_JSET, BPF_K));
		sjset_radiotap_ext_present->s.k = SWAPLONG(0x80000000);
		sappend(s, sjset_radiotap_ext_present);
		sjset_radiotap_flags_present->s.jt = sjset_radiotap_ext_present;

		/*
		 * If so, skip all of this.
		 */
		sjset_radiotap_ext_present->s.jt = snext;

		/*
		 * Otherwise, is the IEEE80211_RADIOTAP_TSFT bit set?
		 */
		sjset_radiotap_tsft_present = new_stmt(cstate, JMP(BPF_JSET, BPF_K));
		sjset_radiotap_tsft_present->s.k = SWAPLONG(0x00000001);
		sappend(s, sjset_radiotap_tsft_present);
		sjset_radiotap_ext_present->s.jf = sjset_radiotap_tsft_present;

		/*
		 * If IEEE80211_RADIOTAP_TSFT is set, the flags field is
		 * at an offset of 16 from the beginning of the raw packet
		 * data (8 bytes for the radiotap header and 8 bytes for
		 * the TSFT field).
		 *
		 * Test whether the IEEE80211_RADIOTAP_F_DATAPAD bit (0x20)
		 * is set.
		 */
		s2 = new_stmt(cstate, BPF_LD|BPF_ABS|BPF_B);
		s2->s.k = 16;
		sappend(s, s2);
		sjset_radiotap_tsft_present->s.jt = s2;

		sjset_tsft_datapad = new_stmt(cstate, JMP(BPF_JSET, BPF_K));
		sjset_tsft_datapad->s.k = 0x20;
		sappend(s, sjset_tsft_datapad);

		/*
		 * If IEEE80211_RADIOTAP_TSFT is not set, the flags field is
		 * at an offset of 8 from the beginning of the raw packet
		 * data (8 bytes for the radiotap header).
		 *
		 * Test whether the IEEE80211_RADIOTAP_F_DATAPAD bit (0x20)
		 * is set.
		 */
		s2 = new_stmt(cstate, BPF_LD|BPF_ABS|BPF_B);
		s2->s.k = 8;
		sappend(s, s2);
		sjset_radiotap_tsft_present->s.jf = s2;

		sjset_notsft_datapad = new_stmt(cstate, JMP(BPF_JSET, BPF_K));
		sjset_notsft_datapad->s.k = 0x20;
		sappend(s, sjset_notsft_datapad);

		/*
		 * In either case, if IEEE80211_RADIOTAP_F_DATAPAD is
		 * set, round the length of the 802.11 header to
		 * a multiple of 4.  Do that by adding 3 and then
		 * dividing by and multiplying by 4, which we do by
		 * ANDing with ~3.
		 */
		s_roundup = new_stmt(cstate, BPF_LD|BPF_MEM);
		s_roundup->s.k = cstate->off_linkpl.reg;
		sappend(s, s_roundup);
		s2 = new_stmt(cstate, BPF_ALU|BPF_ADD|BPF_IMM);
		s2->s.k = 3;
		sappend(s, s2);
		s2 = new_stmt(cstate, BPF_ALU|BPF_AND|BPF_IMM);
		s2->s.k = (bpf_u_int32)~3;
		sappend(s, s2);
		s2 = new_stmt(cstate, BPF_ST);
		s2->s.k = cstate->off_linkpl.reg;
		sappend(s, s2);

		sjset_tsft_datapad->s.jt = s_roundup;
		sjset_tsft_datapad->s.jf = snext;
		sjset_notsft_datapad->s.jt = s_roundup;
		sjset_notsft_datapad->s.jf = snext;
	} else
		sjset_qos->s.jf = snext;

	return s;
}

static void
insert_compute_vloffsets(compiler_state_t *cstate, struct block *b)
{
	struct slist *s;

	/* There is an implicit dependency between the link
	 * payload and link header since the payload computation
	 * includes the variable part of the header. Therefore,
	 * if nobody else has allocated a register for the link
	 * header and we need it, do it now. */
	if (cstate->off_linkpl.reg != -1 && cstate->off_linkhdr.is_variable &&
	    cstate->off_linkhdr.reg == -1)
		cstate->off_linkhdr.reg = alloc_reg(cstate);

	/*
	 * For link-layer types that have a variable-length header
	 * preceding the link-layer header, generate code to load
	 * the offset of the link-layer header into the register
	 * assigned to that offset, if any.
	 *
	 * XXX - this, and the next switch statement, won't handle
	 * encapsulation of 802.11 or 802.11+radio information in
	 * some other protocol stack.  That's significantly more
	 * complicated.
	 */
	switch (cstate->outermostlinktype) {

	case DLT_PRISM_HEADER:
		s = gen_load_prism_llprefixlen(cstate);
		break;

	case DLT_IEEE802_11_RADIO_AVS:
		s = gen_load_avs_llprefixlen(cstate);
		break;

	case DLT_IEEE802_11_RADIO:
		s = gen_load_radiotap_llprefixlen(cstate);
		break;

	case DLT_PPI:
		s = gen_load_ppi_llprefixlen(cstate);
		break;

	default:
		s = NULL;
		break;
	}

	/*
	 * For link-layer types that have a variable-length link-layer
	 * header, generate code to load the offset of the link-layer
	 * payload into the register assigned to that offset, if any.
	 */
	switch (cstate->outermostlinktype) {

	case DLT_IEEE802_11:
	case DLT_PRISM_HEADER:
	case DLT_IEEE802_11_RADIO_AVS:
	case DLT_IEEE802_11_RADIO:
	case DLT_PPI:
		s = gen_load_802_11_header_len(cstate, s, b->stmts);
		break;

	case DLT_PFLOG:
		s = gen_load_pflog_llprefixlen(cstate);
		break;
	}

	/*
	 * If there is no initialization yet and we need variable
	 * length offsets for VLAN, initialize them to zero
	 */
	if (s == NULL && cstate->is_vlan_vloffset) {
		struct slist *s2;

		if (cstate->off_linkpl.reg == -1)
			cstate->off_linkpl.reg = alloc_reg(cstate);
		if (cstate->off_linktype.reg == -1)
			cstate->off_linktype.reg = alloc_reg(cstate);

		s = new_stmt(cstate, BPF_LD|BPF_W|BPF_IMM);
		s->s.k = 0;
		s2 = new_stmt(cstate, BPF_ST);
		s2->s.k = cstate->off_linkpl.reg;
		sappend(s, s2);
		s2 = new_stmt(cstate, BPF_ST);
		s2->s.k = cstate->off_linktype.reg;
		sappend(s, s2);
	}

	/*
	 * If we have any offset-loading code, append all the
	 * existing statements in the block to those statements,
	 * and make the resulting list the list of statements
	 * for the block.
	 */
	if (s != NULL) {
		sappend(s, b->stmts);
		b->stmts = s;
	}
}

/*
 * Take an absolute offset, and:
 *
 *    if it has no variable part, return NULL;
 *
 *    if it has a variable part, generate code to load the register
 *    containing that variable part into the X register, returning
 *    a pointer to that code - if no register for that offset has
 *    been allocated, allocate it first.
 *
 * (The code to set that register will be generated later, but will
 * be placed earlier in the code sequence.)
 */
static struct slist *
gen_abs_offset_varpart(compiler_state_t *cstate, bpf_abs_offset *off)
{
	struct slist *s;

	if (off->is_variable) {
		if (off->reg == -1) {
			/*
			 * We haven't yet assigned a register for the
			 * variable part of the offset of the link-layer
			 * header; allocate one.
			 */
			off->reg = alloc_reg(cstate);
		}

		/*
		 * Load the register containing the variable part of the
		 * offset of the link-layer header into the X register.
		 */
		s = new_stmt(cstate, BPF_LDX|BPF_MEM);
		s->s.k = off->reg;
		return s;
	} else {
		/*
		 * That offset isn't variable, there's no variable part,
		 * so we don't need to generate any code.
		 */
		return NULL;
	}
}

/*
 * Map an Ethernet type to the equivalent PPP type.
 */
static uint16_t
ethertype_to_ppptype(compiler_state_t *cstate, bpf_u_int32 ll_proto)
{
	switch (ll_proto) {

	case ETHERTYPE_IP:
		return PPP_IP;

	case ETHERTYPE_IPV6:
		return PPP_IPV6;

	case ETHERTYPE_DN:
		return PPP_DECNET;

	case ETHERTYPE_ATALK:
		return PPP_APPLE;

	case ETHERTYPE_NS:
		return PPP_NS;

	case LLCSAP_ISONS:
		return PPP_OSI;

	case LLCSAP_8021D:
		/*
		 * I'm assuming the "Bridging PDU"s that go
		 * over PPP are Spanning Tree Protocol
		 * Bridging PDUs.
		 */
		return PPP_BRPDU;

	case LLCSAP_IPX:
		return PPP_IPX;
	}
	assert_maxval(cstate, "PPP protocol", ll_proto, UINT16_MAX);
	return (uint16_t)ll_proto;
}

/*
 * Generate any tests that, for encapsulation of a link-layer packet
 * inside another protocol stack, need to be done to check for those
 * link-layer packets (and that haven't already been done by a check
 * for that encapsulation).
 */
static struct block *
gen_prevlinkhdr_check(compiler_state_t *cstate)
{
	if (cstate->is_encap)
		return gen_encap_ll_check(cstate);

	switch (cstate->prevlinktype) {

	case DLT_SUNATM:
		/*
		 * This is LANE-encapsulated Ethernet; check that the LANE
		 * packet doesn't begin with an LE Control marker, i.e.
		 * that it's data, not a control message.
		 *
		 * (We've already generated a test for LANE.)
		 */
		return gen_cmp_ne(cstate, OR_PREVLINKHDR, SUNATM_PKT_BEGIN_POS, BPF_H, 0xFF00);

	default:
		/*
		 * No such tests are necessary.
		 */
		return NULL;
	}
	/*NOTREACHED*/
}

/*
 * The three different values we should check for when checking for an
 * IPv6 packet with DLT_NULL.
 */
#define BSD_AFNUM_INET6_BSD	24	/* NetBSD, OpenBSD, BSD/OS, Npcap */
#define BSD_AFNUM_INET6_FREEBSD	28	/* FreeBSD */
#define BSD_AFNUM_INET6_DARWIN	30	/* macOS, iOS, other Darwin-based OSes */

/*
 * Generate code to match a particular packet type by matching the
 * link-layer type field or fields in the 802.2 LLC header.
 *
 * "proto" is an Ethernet type value, if > ETHERMTU, or an LLC SAP
 * value, if <= ETHERMTU.
 */
static struct block *
gen_linktype(compiler_state_t *cstate, bpf_u_int32 ll_proto)
{
	struct block *b0, *b1, *b2;

	/* are we checking MPLS-encapsulated packets? */
	if (cstate->label_stack_depth > 0)
		return gen_mpls_linktype(cstate, ll_proto);

	switch (cstate->linktype) {

	case DLT_EN10MB:
	case DLT_NETANALYZER:
	case DLT_NETANALYZER_TRANSPARENT:
		/* Geneve has an EtherType regardless of whether there is an
		 * L2 header. VXLAN always has an EtherType. */
		if (!cstate->is_encap)
			b0 = gen_prevlinkhdr_check(cstate);
		else
			b0 = NULL;

		b1 = gen_ether_linktype(cstate, ll_proto);
		if (b0 != NULL)
			gen_and(b0, b1);
		return b1;
		/*NOTREACHED*/

	case DLT_C_HDLC:
	case DLT_HDLC:
		assert_maxval(cstate, "HDLC protocol", ll_proto, UINT16_MAX);
		switch (ll_proto) {

		case LLCSAP_ISONS:
			ll_proto = (ll_proto << 8 | LLCSAP_ISONS);
			/* fall through */

		default:
			return gen_cmp(cstate, OR_LINKTYPE, 0, BPF_H, ll_proto);
			/*NOTREACHED*/
		}

	case DLT_IEEE802_11:
	case DLT_PRISM_HEADER:
	case DLT_IEEE802_11_RADIO_AVS:
	case DLT_IEEE802_11_RADIO:
	case DLT_PPI:
		/*
		 * Check that we have a data frame.
		 */
		b0 = gen_mcmp(cstate, OR_LINKHDR, 0, BPF_B,
			IEEE80211_FC0_TYPE_DATA,
			IEEE80211_FC0_TYPE_MASK);

		/*
		 * Now check for the specified link-layer type.
		 */
		b1 = gen_llc_linktype(cstate, ll_proto);
		gen_and(b0, b1);
		return b1;
		/*NOTREACHED*/

	case DLT_FDDI:
		/*
		 * XXX - check for LLC frames.
		 */
		return gen_llc_linktype(cstate, ll_proto);
		/*NOTREACHED*/

	case DLT_IEEE802:
		/*
		 * XXX - check for LLC PDUs, as per IEEE 802.5.
		 */
		return gen_llc_linktype(cstate, ll_proto);
		/*NOTREACHED*/

	case DLT_ATM_RFC1483:
	case DLT_ATM_CLIP:
	case DLT_IP_OVER_FC:
		return gen_llc_linktype(cstate, ll_proto);
		/*NOTREACHED*/

	case DLT_SUNATM:
		/*
		 * Check for an LLC-encapsulated version of this protocol;
		 * if we were checking for LANE, linktype would no longer
		 * be DLT_SUNATM.
		 *
		 * Check for LLC encapsulation and then check the protocol.
		 */
		b0 = gen_atm_prototype(cstate, PT_LLC);
		b1 = gen_llc_linktype(cstate, ll_proto);
		gen_and(b0, b1);
		return b1;
		/*NOTREACHED*/

	case DLT_LINUX_SLL:
		return gen_linux_sll_linktype(cstate, ll_proto);
		/*NOTREACHED*/

	case DLT_SLIP:
	case DLT_SLIP_BSDOS:
	case DLT_RAW:
		/*
		 * These types don't provide any type field; packets
		 * are always IPv4 or IPv6.
		 *
		 * XXX - for IPv4, check for a version number of 4, and,
		 * for IPv6, check for a version number of 6?
		 */
		switch (ll_proto) {

		case ETHERTYPE_IP:
			/* Check for a version number of 4. */
			return gen_mcmp(cstate, OR_LINKHDR, 0, BPF_B, 0x40, 0xF0);

		case ETHERTYPE_IPV6:
			/* Check for a version number of 6. */
			return gen_mcmp(cstate, OR_LINKHDR, 0, BPF_B, 0x60, 0xF0);

		default:
			return gen_false(cstate);	/* always false */
		}
		/*NOTREACHED*/

	case DLT_IPV4:
		/*
		 * Raw IPv4, so no type field.
		 */
		if (ll_proto == ETHERTYPE_IP)
			return gen_true(cstate);	/* always true */

		/* Checking for something other than IPv4; always false */
		return gen_false(cstate);
		/*NOTREACHED*/

	case DLT_IPV6:
		/*
		 * Raw IPv6, so no type field.
		 */
		if (ll_proto == ETHERTYPE_IPV6)
			return gen_true(cstate);	/* always true */

		/* Checking for something other than IPv6; always false */
		return gen_false(cstate);
		/*NOTREACHED*/

	case DLT_PPP:
	case DLT_PPP_PPPD:
	case DLT_PPP_SERIAL:
	case DLT_PPP_ETHER:
		/*
		 * We use Ethernet protocol types inside libpcap;
		 * map them to the corresponding PPP protocol types.
		 */
		return gen_cmp(cstate, OR_LINKTYPE, 0, BPF_H,
		    ethertype_to_ppptype(cstate, ll_proto));
		/*NOTREACHED*/

	case DLT_PPP_BSDOS:
		/*
		 * We use Ethernet protocol types inside libpcap;
		 * map them to the corresponding PPP protocol types.
		 */
		switch (ll_proto) {

		case ETHERTYPE_IP:
			/*
			 * Also check for Van Jacobson-compressed IP.
			 * XXX - do this for other forms of PPP?
			 */
			b0 = gen_cmp(cstate, OR_LINKTYPE, 0, BPF_H, PPP_IP);
			b1 = gen_cmp(cstate, OR_LINKTYPE, 0, BPF_H, PPP_VJC);
			gen_or(b0, b1);
			b0 = gen_cmp(cstate, OR_LINKTYPE, 0, BPF_H, PPP_VJNC);
			gen_or(b1, b0);
			return b0;

		default:
			return gen_cmp(cstate, OR_LINKTYPE, 0, BPF_H,
			    ethertype_to_ppptype(cstate, ll_proto));
		}
		/*NOTREACHED*/

	case DLT_NULL:
	case DLT_LOOP:
	case DLT_ENC:
		switch (ll_proto) {

		case ETHERTYPE_IP:
			return (gen_loopback_linktype(cstate, AF_INET));

		case ETHERTYPE_IPV6:
			/*
			 * AF_ values may, unfortunately, be platform-
			 * dependent; AF_INET isn't, because everybody
			 * used 4.2BSD's value, but AF_INET6 is, because
			 * 4.2BSD didn't have a value for it (given that
			 * IPv6 didn't exist back in the early 1980's),
			 * and they all picked their own values.
			 *
			 * This means that, if we're reading from a
			 * savefile, we need to check for all the
			 * possible values.
			 *
			 * If we're doing a live capture, we only need
			 * to check for this platform's value; however,
			 * Npcap uses 24, which isn't Windows's AF_INET6
			 * value.  (Given the multiple different values,
			 * programs that read pcap files shouldn't be
			 * checking for their platform's AF_INET6 value
			 * anyway, they should check for all of the
			 * possible values. and they might as well do
			 * that even for live captures.)
			 */
			if (cstate->bpf_pcap->rfile != NULL) {
				/*
				 * Savefile - check for all three
				 * possible IPv6 values.
				 */
				b0 = gen_loopback_linktype(cstate, BSD_AFNUM_INET6_BSD);
				b1 = gen_loopback_linktype(cstate, BSD_AFNUM_INET6_FREEBSD);
				gen_or(b0, b1);
				b0 = gen_loopback_linktype(cstate, BSD_AFNUM_INET6_DARWIN);
				gen_or(b0, b1);
				return (b1);
			} else {
				/*
				 * Live capture, so we only need to
				 * check for the value used on this
				 * platform.
				 */
#ifdef _WIN32
				/*
				 * Npcap doesn't use Windows's AF_INET6,
				 * as that collides with AF_IPX on
				 * some BSDs (both have the value 23).
				 * Instead, it uses 24.
				 */
				return (gen_loopback_linktype(cstate, 24));
#else /* _WIN32 */
#ifdef AF_INET6
				return (gen_loopback_linktype(cstate, AF_INET6));
#else /* AF_INET6 */
				/*
				 * I guess this platform doesn't support
				 * IPv6, so we just reject all packets.
				 */
				return gen_false(cstate);
#endif /* AF_INET6 */
#endif /* _WIN32 */
			}

		default:
			/*
			 * Not a type on which we support filtering.
			 * XXX - support those that have AF_ values
			 * #defined on this platform, at least?
			 */
			return gen_false(cstate);
		}

	case DLT_PFLOG:
		/*
		 * af field is host byte order in contrast to the rest of
		 * the packet.
		 */
		if (ll_proto == ETHERTYPE_IP)
			return (gen_cmp(cstate, OR_LINKHDR, offsetof(struct pfloghdr, af),
			    BPF_B, AF_INET));
		else if (ll_proto == ETHERTYPE_IPV6)
			return (gen_cmp(cstate, OR_LINKHDR, offsetof(struct pfloghdr, af),
			    BPF_B, AF_INET6));
		else
			return gen_false(cstate);
		/*NOTREACHED*/

	case DLT_ARCNET:
	case DLT_ARCNET_LINUX:
		/*
		 * In ARCnet header the 8-bit SC (System Code) field identifies
		 * the higher-level protocol in the INFO (Information) part of
		 * the packet, same as the 16-bit EtherType > 1500 in Ethernet.
		 * RFC 1051 (March 1988) allocated ARCTYPE_IP_OLD to IPv4 and
		 * ARCTYPE_ARP_OLD to ARP, RFC 1201 (February 1991) allocated
		 * ARCTYPE_IP to IPv4 and ARCTYPE_ARP to ARP.  ARCnet header
		 * encoding and length differ between the two specifications.
		 *
		 * This DLT case previously matched IPv4 and ARP by ORing, for
		 * backward compatibility reasons, respective SCs from RFC 1051
		 * and RFC 1201.  This worked as expected when a filter program
		 * tested SC to tell whether a packet is an IPv4/ARP packet,
		 * but did not access INFO (where the IPv4 or ARP header is).
		 *
		 * However, for filter expressions that need to access INFO the
		 * C code that processes IPv4/ARP header fields generates
		 * exactly one match and uses the DLT's off_linkpl, which
		 * init_linktype() initializes to RFC 1201 encoding, so
		 * combining that with an RFC 1051 SC match produced incorrect
		 * filter programs.  This is why this DLT case in the current
		 * implementation matches RFC 1201 SCs only.
		 *
		 * XXX should we check for first fragment if the protocol
		 * uses PHDS?
		 */
		switch (ll_proto) {

		default:
			return gen_false(cstate);

		case ETHERTYPE_IPV6:
			return (gen_cmp(cstate, OR_LINKTYPE, 0, BPF_B,
				ARCTYPE_INET6));

		case ETHERTYPE_IP:
			return gen_cmp(cstate, OR_LINKTYPE, 0, BPF_B,
			    ARCTYPE_IP);

		case ETHERTYPE_ARP:
			return gen_cmp(cstate, OR_LINKTYPE, 0, BPF_B,
			    ARCTYPE_ARP);

		case ETHERTYPE_REVARP:
			return (gen_cmp(cstate, OR_LINKTYPE, 0, BPF_B,
			    ARCTYPE_REVARP));

		case ETHERTYPE_ATALK:
			return (gen_cmp(cstate, OR_LINKTYPE, 0, BPF_B,
			    ARCTYPE_ATALK));
		}
		/*NOTREACHED*/

	case DLT_LTALK:
		switch (ll_proto) {
		case ETHERTYPE_ATALK:
			return gen_true(cstate);
		default:
			return gen_false(cstate);
		}
		/*NOTREACHED*/

	case DLT_FRELAY:
		/*
		 * XXX - assumes a 2-byte Frame Relay header with
		 * DLCI and flags.  What if the address is longer?
		 */
		switch (ll_proto) {

		case ETHERTYPE_IP:
			/*
			 * Check for the special NLPID for IP.
			 */
			return gen_cmp(cstate, OR_LINKHDR, 2, BPF_H, (0x03<<8) | 0xcc);

		case ETHERTYPE_IPV6:
			/*
			 * Check for the special NLPID for IPv6.
			 */
			return gen_cmp(cstate, OR_LINKHDR, 2, BPF_H, (0x03<<8) | 0x8e);

		case LLCSAP_ISONS:
			/*
			 * Check for several OSI protocols.
			 *
			 * Frame Relay packets typically have an OSI
			 * NLPID at the beginning; we check for each
			 * of them.
			 *
			 * What we check for is the NLPID and a frame
			 * control field of UI, i.e. 0x03 followed
			 * by the NLPID.
			 */
			b0 = gen_cmp(cstate, OR_LINKHDR, 2, BPF_H, (0x03<<8) | ISO8473_CLNP);
			b1 = gen_cmp(cstate, OR_LINKHDR, 2, BPF_H, (0x03<<8) | ISO9542_ESIS);
			b2 = gen_cmp(cstate, OR_LINKHDR, 2, BPF_H, (0x03<<8) | ISO10589_ISIS);
			gen_or(b1, b2);
			gen_or(b0, b2);
			return b2;

		default:
			return gen_false(cstate);
		}
		/*NOTREACHED*/

	case DLT_MFR:
		break; // not implemented

	case DLT_JUNIPER_MFR:
	case DLT_JUNIPER_MLFR:
	case DLT_JUNIPER_MLPPP:
	case DLT_JUNIPER_ATM1:
	case DLT_JUNIPER_ATM2:
	case DLT_JUNIPER_PPPOE:
	case DLT_JUNIPER_PPPOE_ATM:
	case DLT_JUNIPER_GGSN:
	case DLT_JUNIPER_ES:
	case DLT_JUNIPER_MONITOR:
	case DLT_JUNIPER_SERVICES:
	case DLT_JUNIPER_ETHER:
	case DLT_JUNIPER_PPP:
	case DLT_JUNIPER_FRELAY:
	case DLT_JUNIPER_CHDLC:
	case DLT_JUNIPER_VP:
	case DLT_JUNIPER_ST:
	case DLT_JUNIPER_ISM:
	case DLT_JUNIPER_VS:
	case DLT_JUNIPER_SRX_E2E:
	case DLT_JUNIPER_FIBRECHANNEL:
	case DLT_JUNIPER_ATM_CEMIC:

		/* just lets verify the magic number for now -
		 * on ATM we may have up to 6 different encapsulations on the wire
		 * and need a lot of heuristics to figure out that the payload
		 * might be;
		 *
		 * FIXME encapsulation specific BPF_ filters
		 */
		return gen_mcmp(cstate, OR_LINKHDR, 0, BPF_W, 0x4d474300, 0xffffff00); /* compare the magic number */

	case DLT_IPNET:
		return gen_ipnet_linktype(cstate, ll_proto);

	default:
		/*
		 * Does this link-layer header type have a field
		 * indicating the type of the next protocol?  If
		 * so, off_linktype.constant_part will be the offset of that
		 * field in the packet; if not, it will be OFFSET_NOT_SET.
		 */
		if (cstate->off_linktype.constant_part != OFFSET_NOT_SET) {
			/*
			 * Yes; assume it's an Ethernet type.  (If
			 * it's not, it needs to be handled specially
			 * above.)
			 */
			assert_maxval(cstate, "EtherType", ll_proto, UINT16_MAX);
			return gen_cmp(cstate, OR_LINKTYPE, 0, BPF_H, ll_proto);
			/*NOTREACHED */
		}
	}
	/*
	 * For example, using the fixed-size NFLOG header it is possible
	 * to tell only the address family of the packet, other meaningful
	 * data is either missing or behind TLVs.
	 */
	bpf_error(cstate, "link-layer type filtering not implemented for %s",
	    pcapint_datalink_val_to_string(cstate->linktype));
}

/*
 * Check for an LLC SNAP packet with a given organization code and
 * protocol type; we check the entire contents of the 802.2 LLC and
 * snap headers, checking for DSAP and SSAP of SNAP and a control
 * field of 0x03 in the LLC header, and for the specified organization
 * code and protocol type in the SNAP header.
 */
static struct block *
gen_snap(compiler_state_t *cstate, bpf_u_int32 orgcode, bpf_u_int32 ptype)
{
	u_char snapblock[8];

	snapblock[0] = LLCSAP_SNAP;		/* DSAP = SNAP */
	snapblock[1] = LLCSAP_SNAP;		/* SSAP = SNAP */
	snapblock[2] = 0x03;			/* control = UI */
	snapblock[3] = (u_char)(orgcode >> 16);	/* upper 8 bits of organization code */
	snapblock[4] = (u_char)(orgcode >> 8);	/* middle 8 bits of organization code */
	snapblock[5] = (u_char)(orgcode >> 0);	/* lower 8 bits of organization code */
	snapblock[6] = (u_char)(ptype >> 8);	/* upper 8 bits of protocol type */
	snapblock[7] = (u_char)(ptype >> 0);	/* lower 8 bits of protocol type */
	return gen_bcmp(cstate, OR_LLC, 0, 8, snapblock);
}

/*
 * Generate code to match frames with an LLC header.
 */
static struct block *
gen_llc_internal(compiler_state_t *cstate)
{
	struct block *b0, *b1;

	switch (cstate->linktype) {

	case DLT_EN10MB:
		/*
		 * We check for an Ethernet type field less or equal than
		 * 1500, which means it's an 802.3 length field.
		 */
		b0 = gen_cmp_le(cstate, OR_LINKTYPE, 0, BPF_H, ETHERMTU);

		/*
		 * Now check for the purported DSAP and SSAP not being
		 * 0xFF, to rule out NetWare-over-802.3.
		 */
		b1 = gen_cmp_ne(cstate, OR_LLC, 0, BPF_H, 0xFFFF);
		gen_and(b0, b1);
		return b1;

	case DLT_SUNATM:
		/*
		 * We check for LLC traffic.
		 */
		return gen_atmtype_llc(cstate);

	case DLT_IEEE802:	/* Token Ring */
		/*
		 * XXX - check for LLC frames.
		 */
		return gen_true(cstate);

	case DLT_FDDI:
		/*
		 * XXX - check for LLC frames.
		 */
		return gen_true(cstate);

	case DLT_ATM_RFC1483:
		/*
		 * For LLC encapsulation, these are defined to have an
		 * 802.2 LLC header.
		 *
		 * For VC encapsulation, they don't, but there's no
		 * way to check for that; the protocol used on the VC
		 * is negotiated out of band.
		 */
		return gen_true(cstate);

	case DLT_IEEE802_11:
	case DLT_PRISM_HEADER:
	case DLT_IEEE802_11_RADIO:
	case DLT_IEEE802_11_RADIO_AVS:
	case DLT_PPI:
		/*
		 * Check that we have a data frame.
		 */
		return gen_mcmp(cstate, OR_LINKHDR, 0, BPF_B,
			IEEE80211_FC0_TYPE_DATA,
			IEEE80211_FC0_TYPE_MASK);

	default:
		fail_kw_on_dlt(cstate, "llc");
		/*NOTREACHED*/
	}
}

struct block *
gen_llc(compiler_state_t *cstate)
{
	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	return gen_llc_internal(cstate);
}

struct block *
gen_llc_i(compiler_state_t *cstate)
{
	struct block *b0, *b1;
	struct slist *s;

	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	/*
	 * Check whether this is an LLC frame.
	 */
	b0 = gen_llc_internal(cstate);

	/*
	 * Load the control byte and test the low-order bit; it must
	 * be clear for I frames.
	 */
	s = gen_load_a(cstate, OR_LLC, 2, BPF_B);
	b1 = gen_unset(cstate, 0x01, s);

	gen_and(b0, b1);
	return b1;
}

struct block *
gen_llc_s(compiler_state_t *cstate)
{
	struct block *b0, *b1;

	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	/*
	 * Check whether this is an LLC frame.
	 */
	b0 = gen_llc_internal(cstate);

	/*
	 * Now compare the low-order 2 bit of the control byte against
	 * the appropriate value for S frames.
	 */
	b1 = gen_mcmp(cstate, OR_LLC, 2, BPF_B, LLC_S_FMT, 0x03);
	gen_and(b0, b1);
	return b1;
}

struct block *
gen_llc_u(compiler_state_t *cstate)
{
	struct block *b0, *b1;

	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	/*
	 * Check whether this is an LLC frame.
	 */
	b0 = gen_llc_internal(cstate);

	/*
	 * Now compare the low-order 2 bit of the control byte against
	 * the appropriate value for U frames.
	 */
	b1 = gen_mcmp(cstate, OR_LLC, 2, BPF_B, LLC_U_FMT, 0x03);
	gen_and(b0, b1);
	return b1;
}

struct block *
gen_llc_s_subtype(compiler_state_t *cstate, bpf_u_int32 subtype)
{
	struct block *b0, *b1;

	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	/*
	 * Check whether this is an LLC frame.
	 */
	b0 = gen_llc_internal(cstate);

	/*
	 * Now check for an S frame with the appropriate type.
	 */
	b1 = gen_mcmp(cstate, OR_LLC, 2, BPF_B, subtype, LLC_S_CMD_MASK);
	gen_and(b0, b1);
	return b1;
}

struct block *
gen_llc_u_subtype(compiler_state_t *cstate, bpf_u_int32 subtype)
{
	struct block *b0, *b1;

	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	/*
	 * Check whether this is an LLC frame.
	 */
	b0 = gen_llc_internal(cstate);

	/*
	 * Now check for a U frame with the appropriate type.
	 */
	b1 = gen_mcmp(cstate, OR_LLC, 2, BPF_B, subtype, LLC_U_CMD_MASK);
	gen_and(b0, b1);
	return b1;
}

/*
 * Generate code to match a particular packet type, for link-layer types
 * using 802.2 LLC headers.
 *
 * This is *NOT* used for Ethernet; "gen_ether_linktype()" is used
 * for that - it handles the D/I/X Ethernet vs. 802.3+802.2 issues.
 *
 * "proto" is an Ethernet type value, if > ETHERMTU, or an LLC SAP
 * value, if <= ETHERMTU.  We use that to determine whether to
 * match the DSAP or both DSAP and LSAP or to check the OUI and
 * protocol ID in a SNAP header.
 */
static struct block *
gen_llc_linktype(compiler_state_t *cstate, bpf_u_int32 ll_proto)
{
	/*
	 * XXX - handle token-ring variable-length header.
	 */
	switch (ll_proto) {

	case LLCSAP_IP:
	case LLCSAP_ISONS:
	case LLCSAP_NETBEUI:
		/*
		 * XXX - should we check both the DSAP and the
		 * SSAP, like this, or should we check just the
		 * DSAP, as we do for other SAP values?
		 */
		return gen_cmp(cstate, OR_LLC, 0, BPF_H, (bpf_u_int32)
			     ((ll_proto << 8) | ll_proto));

	case LLCSAP_IPX:
		/*
		 * XXX - are there ever SNAP frames for IPX on
		 * non-Ethernet 802.x networks?
		 */
		return gen_cmp(cstate, OR_LLC, 0, BPF_B, LLCSAP_IPX);

	case ETHERTYPE_ATALK:
		/*
		 * 802.2-encapsulated ETHERTYPE_ATALK packets are
		 * SNAP packets with an organization code of
		 * 0x080007 (Apple, for Appletalk) and a protocol
		 * type of ETHERTYPE_ATALK (Appletalk).
		 *
		 * XXX - check for an organization code of
		 * encapsulated Ethernet as well?
		 */
		return gen_snap(cstate, 0x080007, ETHERTYPE_ATALK);

	default:
		/*
		 * XXX - we don't have to check for IPX 802.3
		 * here, but should we check for the IPX Ethertype?
		 */
		if (ll_proto <= ETHERMTU) {
			assert_maxval(cstate, "LLC DSAP", ll_proto, UINT8_MAX);
			/*
			 * This is an LLC SAP value, so check
			 * the DSAP.
			 */
			return gen_cmp(cstate, OR_LLC, 0, BPF_B, ll_proto);
		} else {
			assert_maxval(cstate, "EtherType", ll_proto, UINT16_MAX);
			/*
			 * This is an Ethernet type; we assume that it's
			 * unlikely that it'll appear in the right place
			 * at random, and therefore check only the
			 * location that would hold the Ethernet type
			 * in a SNAP frame with an organization code of
			 * 0x000000 (encapsulated Ethernet).
			 *
			 * XXX - if we were to check for the SNAP DSAP and
			 * LSAP, as per XXX, and were also to check for an
			 * organization code of 0x000000 (encapsulated
			 * Ethernet), we'd do
			 *
			 *	return gen_snap(cstate, 0x000000, ll_proto);
			 *
			 * here; for now, we don't, as per the above.
			 * I don't know whether it's worth the extra CPU
			 * time to do the right check or not.
			 */
			return gen_cmp(cstate, OR_LLC, 6, BPF_H, ll_proto);
		}
	}
}

static struct block *
gen_hostop(compiler_state_t *cstate, bpf_u_int32 addr, bpf_u_int32 mask,
    int dir, u_int src_off, u_int dst_off)
{
	struct block *b0, *b1;
	u_int offset;

	switch (dir) {

	case Q_SRC:
		offset = src_off;
		break;

	case Q_DST:
		offset = dst_off;
		break;

	case Q_AND:
		b0 = gen_hostop(cstate, addr, mask, Q_SRC, src_off, dst_off);
		b1 = gen_hostop(cstate, addr, mask, Q_DST, src_off, dst_off);
		gen_and(b0, b1);
		return b1;

	case Q_DEFAULT:
	case Q_OR:
		b0 = gen_hostop(cstate, addr, mask, Q_SRC, src_off, dst_off);
		b1 = gen_hostop(cstate, addr, mask, Q_DST, src_off, dst_off);
		gen_or(b0, b1);
		return b1;

	default:
		bpf_error(cstate, ERRSTR_802_11_ONLY_KW, dqkw(dir));
		/*NOTREACHED*/
	}
	return gen_mcmp(cstate, OR_LINKPL, offset, BPF_W, addr, mask);
}

static struct block *
gen_hostop6(compiler_state_t *cstate, struct in6_addr *addr,
    struct in6_addr *mask, int dir, u_int src_off, u_int dst_off)
{
	struct block *b0, *b1;
	u_int offset;
	/*
	 * Code below needs to access four separate 32-bit parts of the 128-bit
	 * IPv6 address and mask.  In some OSes this is as simple as using the
	 * s6_addr32 pseudo-member of struct in6_addr, which contains a union of
	 * 8-, 16- and 32-bit arrays.  In other OSes this is not the case, as
	 * far as libpcap sees it.  Hence copy the data before use to avoid
	 * potential unaligned memory access and the associated compiler
	 * warnings (whether genuine or not).
	 */
	bpf_u_int32 a[4], m[4];

	switch (dir) {

	case Q_SRC:
		offset = src_off;
		break;

	case Q_DST:
		offset = dst_off;
		break;

	case Q_AND:
		b0 = gen_hostop6(cstate, addr, mask, Q_SRC, src_off, dst_off);
		b1 = gen_hostop6(cstate, addr, mask, Q_DST, src_off, dst_off);
		gen_and(b0, b1);
		return b1;

	case Q_DEFAULT:
	case Q_OR:
		b0 = gen_hostop6(cstate, addr, mask, Q_SRC, src_off, dst_off);
		b1 = gen_hostop6(cstate, addr, mask, Q_DST, src_off, dst_off);
		gen_or(b0, b1);
		return b1;

	default:
		bpf_error(cstate, ERRSTR_802_11_ONLY_KW, dqkw(dir));
		/*NOTREACHED*/
	}
	/* this order is important */
	memcpy(a, addr, sizeof(a));
	memcpy(m, mask, sizeof(m));
	b1 = NULL;
	for (int i = 3; i >= 0; i--) {
		// Same as the Q_IP case in gen_host().
		if (m[i] == 0 && a[i] == 0)
			continue;
		b0 = gen_mcmp(cstate, OR_LINKPL, offset + 4 * i, BPF_W,
		    ntohl(a[i]), ntohl(m[i]));
		if (b1)
			gen_and(b0, b1);
		else
			b1 = b0;
	}
	return b1 ? b1 : gen_true(cstate);
}

/*
 * Like gen_mac48host(), but for DLT_IEEE802_11 (802.11 wireless LAN) and
 * various 802.11 + radio headers.
 */
static struct block *
gen_wlanhostop(compiler_state_t *cstate, const u_char *eaddr, int dir)
{
	struct block *b0, *b1, *b2;
	struct slist *s;

#ifdef ENABLE_WLAN_FILTERING_PATCH
	/*
	 * TODO GV 20070613
	 * We need to disable the optimizer because the optimizer is buggy
	 * and wipes out some LD instructions generated by the below
	 * code to validate the Frame Control bits
	 */
	cstate->no_optimize = 1;
#endif /* ENABLE_WLAN_FILTERING_PATCH */

	switch (dir) {
	case Q_SRC:
		/*
		 * Oh, yuk.
		 *
		 *	For control frames, there is no SA.
		 *
		 *	For management frames, SA is at an
		 *	offset of 10 from the beginning of
		 *	the packet.
		 *
		 *	For data frames, SA is at an offset
		 *	of 10 from the beginning of the packet
		 *	if From DS is clear, at an offset of
		 *	16 from the beginning of the packet
		 *	if From DS is set and To DS is clear,
		 *	and an offset of 24 from the beginning
		 *	of the packet if From DS is set and To DS
		 *	is set.
		 */

		/*
		 * Generate the tests to be done for data frames
		 * with From DS set.
		 *
		 * First, check for To DS set, i.e. check "link[1] & 0x01".
		 */
		s = gen_load_a(cstate, OR_LINKHDR, 1, BPF_B);
		b1 = gen_set(cstate, IEEE80211_FC1_DIR_TODS, s);

		/*
		 * If To DS is set, the SA is at 24.
		 */
		b0 = gen_bcmp(cstate, OR_LINKHDR, 24, 6, eaddr);
		gen_and(b1, b0);

		/*
		 * Now, check for To DS not set, i.e. check
		 * "!(link[1] & 0x01)".
		 */
		s = gen_load_a(cstate, OR_LINKHDR, 1, BPF_B);
		b2 = gen_unset(cstate, IEEE80211_FC1_DIR_TODS, s);

		/*
		 * If To DS is not set, the SA is at 16.
		 */
		b1 = gen_bcmp(cstate, OR_LINKHDR, 16, 6, eaddr);
		gen_and(b2, b1);

		/*
		 * Now OR together the last two checks.  That gives
		 * the complete set of checks for data frames with
		 * From DS set.
		 */
		gen_or(b1, b0);

		/*
		 * Now check for From DS being set, and AND that with
		 * the ORed-together checks.
		 */
		s = gen_load_a(cstate, OR_LINKHDR, 1, BPF_B);
		b1 = gen_set(cstate, IEEE80211_FC1_DIR_FROMDS, s);
		gen_and(b1, b0);

		/*
		 * Now check for data frames with From DS not set.
		 */
		s = gen_load_a(cstate, OR_LINKHDR, 1, BPF_B);
		b2 = gen_unset(cstate, IEEE80211_FC1_DIR_FROMDS, s);

		/*
		 * If From DS isn't set, the SA is at 10.
		 */
		b1 = gen_bcmp(cstate, OR_LINKHDR, 10, 6, eaddr);
		gen_and(b2, b1);

		/*
		 * Now OR together the checks for data frames with
		 * From DS not set and for data frames with From DS
		 * set; that gives the checks done for data frames.
		 */
		gen_or(b1, b0);

		/*
		 * Now check for a data frame.
		 * I.e, check "link[0] & 0x08".
		 */
		s = gen_load_a(cstate, OR_LINKHDR, 0, BPF_B);
		b1 = gen_set(cstate, IEEE80211_FC0_TYPE_DATA, s);

		/*
		 * AND that with the checks done for data frames.
		 */
		gen_and(b1, b0);

		/*
		 * If the high-order bit of the type value is 0, this
		 * is a management frame.
		 * I.e, check "!(link[0] & 0x08)".
		 */
		s = gen_load_a(cstate, OR_LINKHDR, 0, BPF_B);
		b2 = gen_unset(cstate, IEEE80211_FC0_TYPE_DATA, s);

		/*
		 * For management frames, the SA is at 10.
		 */
		b1 = gen_bcmp(cstate, OR_LINKHDR, 10, 6, eaddr);
		gen_and(b2, b1);

		/*
		 * OR that with the checks done for data frames.
		 * That gives the checks done for management and
		 * data frames.
		 */
		gen_or(b1, b0);

		/*
		 * If the low-order bit of the type value is 1,
		 * this is either a control frame or a frame
		 * with a reserved type, and thus not a
		 * frame with an SA.
		 *
		 * I.e., check "!(link[0] & 0x04)".
		 */
		s = gen_load_a(cstate, OR_LINKHDR, 0, BPF_B);
		b1 = gen_unset(cstate, IEEE80211_FC0_TYPE_CTL, s);

		/*
		 * AND that with the checks for data and management
		 * frames.
		 */
		gen_and(b1, b0);
		return b0;

	case Q_DST:
		/*
		 * Oh, yuk.
		 *
		 *	For control frames, there is no DA.
		 *
		 *	For management frames, DA is at an
		 *	offset of 4 from the beginning of
		 *	the packet.
		 *
		 *	For data frames, DA is at an offset
		 *	of 4 from the beginning of the packet
		 *	if To DS is clear and at an offset of
		 *	16 from the beginning of the packet
		 *	if To DS is set.
		 */

		/*
		 * Generate the tests to be done for data frames.
		 *
		 * First, check for To DS set, i.e. "link[1] & 0x01".
		 */
		s = gen_load_a(cstate, OR_LINKHDR, 1, BPF_B);
		b1 = gen_set(cstate, IEEE80211_FC1_DIR_TODS, s);

		/*
		 * If To DS is set, the DA is at 16.
		 */
		b0 = gen_bcmp(cstate, OR_LINKHDR, 16, 6, eaddr);
		gen_and(b1, b0);

		/*
		 * Now, check for To DS not set, i.e. check
		 * "!(link[1] & 0x01)".
		 */
		s = gen_load_a(cstate, OR_LINKHDR, 1, BPF_B);
		b2 = gen_unset(cstate, IEEE80211_FC1_DIR_TODS, s);

		/*
		 * If To DS is not set, the DA is at 4.
		 */
		b1 = gen_bcmp(cstate, OR_LINKHDR, 4, 6, eaddr);
		gen_and(b2, b1);

		/*
		 * Now OR together the last two checks.  That gives
		 * the complete set of checks for data frames.
		 */
		gen_or(b1, b0);

		/*
		 * Now check for a data frame.
		 * I.e, check "link[0] & 0x08".
		 */
		s = gen_load_a(cstate, OR_LINKHDR, 0, BPF_B);
		b1 = gen_set(cstate, IEEE80211_FC0_TYPE_DATA, s);

		/*
		 * AND that with the checks done for data frames.
		 */
		gen_and(b1, b0);

		/*
		 * If the high-order bit of the type value is 0, this
		 * is a management frame.
		 * I.e, check "!(link[0] & 0x08)".
		 */
		s = gen_load_a(cstate, OR_LINKHDR, 0, BPF_B);
		b2 = gen_unset(cstate, IEEE80211_FC0_TYPE_DATA, s);

		/*
		 * For management frames, the DA is at 4.
		 */
		b1 = gen_bcmp(cstate, OR_LINKHDR, 4, 6, eaddr);
		gen_and(b2, b1);

		/*
		 * OR that with the checks done for data frames.
		 * That gives the checks done for management and
		 * data frames.
		 */
		gen_or(b1, b0);

		/*
		 * If the low-order bit of the type value is 1,
		 * this is either a control frame or a frame
		 * with a reserved type, and thus not a
		 * frame with an SA.
		 *
		 * I.e., check "!(link[0] & 0x04)".
		 */
		s = gen_load_a(cstate, OR_LINKHDR, 0, BPF_B);
		b1 = gen_unset(cstate, IEEE80211_FC0_TYPE_CTL, s);

		/*
		 * AND that with the checks for data and management
		 * frames.
		 */
		gen_and(b1, b0);
		return b0;

	case Q_AND:
		b0 = gen_wlanhostop(cstate, eaddr, Q_SRC);
		b1 = gen_wlanhostop(cstate, eaddr, Q_DST);
		gen_and(b0, b1);
		return b1;

	case Q_DEFAULT:
	case Q_OR:
		b0 = gen_wlanhostop(cstate, eaddr, Q_SRC);
		b1 = gen_wlanhostop(cstate, eaddr, Q_DST);
		gen_or(b0, b1);
		return b1;

	/*
	 * XXX - add BSSID keyword?
	 */
	case Q_ADDR1:
		return (gen_bcmp(cstate, OR_LINKHDR, 4, 6, eaddr));

	case Q_ADDR2:
		/*
		 * Not present in CTS or ACK control frames.
		 */
		b0 = gen_mcmp_ne(cstate, OR_LINKHDR, 0, BPF_B, IEEE80211_FC0_TYPE_CTL,
			IEEE80211_FC0_TYPE_MASK);
		b1 = gen_mcmp_ne(cstate, OR_LINKHDR, 0, BPF_B, IEEE80211_FC0_SUBTYPE_CTS,
			IEEE80211_FC0_SUBTYPE_MASK);
		b2 = gen_mcmp_ne(cstate, OR_LINKHDR, 0, BPF_B, IEEE80211_FC0_SUBTYPE_ACK,
			IEEE80211_FC0_SUBTYPE_MASK);
		gen_and(b1, b2);
		gen_or(b0, b2);
		b1 = gen_bcmp(cstate, OR_LINKHDR, 10, 6, eaddr);
		gen_and(b2, b1);
		return b1;

	case Q_ADDR3:
		/*
		 * Not present in control frames.
		 */
		b0 = gen_mcmp_ne(cstate, OR_LINKHDR, 0, BPF_B, IEEE80211_FC0_TYPE_CTL,
			IEEE80211_FC0_TYPE_MASK);
		b1 = gen_bcmp(cstate, OR_LINKHDR, 16, 6, eaddr);
		gen_and(b0, b1);
		return b1;

	case Q_ADDR4:
		/*
		 * Present only if the direction mask has both "From DS"
		 * and "To DS" set.  Neither control frames nor management
		 * frames should have both of those set, so we don't
		 * check the frame type.
		 */
		b0 = gen_mcmp(cstate, OR_LINKHDR, 1, BPF_B,
			IEEE80211_FC1_DIR_DSTODS, IEEE80211_FC1_DIR_MASK);
		b1 = gen_bcmp(cstate, OR_LINKHDR, 24, 6, eaddr);
		gen_and(b0, b1);
		return b1;

	case Q_RA:
		/*
		 * Not present in management frames; addr1 in other
		 * frames.
		 */

		/*
		 * If the high-order bit of the type value is 0, this
		 * is a management frame.
		 * I.e, check "(link[0] & 0x08)".
		 */
		s = gen_load_a(cstate, OR_LINKHDR, 0, BPF_B);
		b1 = gen_set(cstate, IEEE80211_FC0_TYPE_DATA, s);

		/*
		 * Check addr1.
		 */
		b0 = gen_bcmp(cstate, OR_LINKHDR, 4, 6, eaddr);

		/*
		 * AND that with the check of addr1.
		 */
		gen_and(b1, b0);
		return (b0);

	case Q_TA:
		/*
		 * Not present in management frames; addr2, if present,
		 * in other frames.
		 */

		/*
		 * Not present in CTS or ACK control frames.
		 */
		b0 = gen_mcmp_ne(cstate, OR_LINKHDR, 0, BPF_B, IEEE80211_FC0_TYPE_CTL,
			IEEE80211_FC0_TYPE_MASK);
		b1 = gen_mcmp_ne(cstate, OR_LINKHDR, 0, BPF_B, IEEE80211_FC0_SUBTYPE_CTS,
			IEEE80211_FC0_SUBTYPE_MASK);
		b2 = gen_mcmp_ne(cstate, OR_LINKHDR, 0, BPF_B, IEEE80211_FC0_SUBTYPE_ACK,
			IEEE80211_FC0_SUBTYPE_MASK);
		gen_and(b1, b2);
		gen_or(b0, b2);

		/*
		 * If the high-order bit of the type value is 0, this
		 * is a management frame.
		 * I.e, check "(link[0] & 0x08)".
		 */
		s = gen_load_a(cstate, OR_LINKHDR, 0, BPF_B);
		b1 = gen_set(cstate, IEEE80211_FC0_TYPE_DATA, s);

		/*
		 * AND that with the check for frames other than
		 * CTS and ACK frames.
		 */
		gen_and(b1, b2);

		/*
		 * Check addr2.
		 */
		b1 = gen_bcmp(cstate, OR_LINKHDR, 10, 6, eaddr);
		gen_and(b2, b1);
		return b1;
	}
	bpf_error(cstate, ERRSTR_FUNC_VAR_INT, __func__, "dir", dir);
	/*NOTREACHED*/
}

/*
 * This is quite tricky because there may be pad bytes in front of the
 * DECNET header, and then there are two possible data packet formats that
 * carry both src and dst addresses, plus 5 packet types in a format that
 * carries only the src node, plus 2 types that use a different format and
 * also carry just the src node.
 *
 * Yuck.
 *
 * Instead of doing those all right, we just look for data packets with
 * 0 or 1 bytes of padding.  If you want to look at other packets, that
 * will require a lot more hacking.
 *
 * To add support for filtering on DECNET "areas" (network numbers)
 * one would want to add a "mask" argument to this routine.  That would
 * make the filter even more inefficient, although one could be clever
 * and not generate masking instructions if the mask is 0xFFFF.
 */
static struct block *
gen_dnhostop(compiler_state_t *cstate, bpf_u_int32 addr, int dir)
{
	struct block *b0, *b1, *b2, *tmp;
	u_int offset_lh;	/* offset if long header is received */
	u_int offset_sh;	/* offset if short header is received */

	switch (dir) {

	case Q_DST:
		offset_sh = 1;	/* follows flags */
		offset_lh = 7;	/* flgs,darea,dsubarea,HIORD */
		break;

	case Q_SRC:
		offset_sh = 3;	/* follows flags, dstnode */
		offset_lh = 15;	/* flgs,darea,dsubarea,did,sarea,ssub,HIORD */
		break;

	case Q_AND:
		/* Inefficient because we do our Calvinball dance twice */
		b0 = gen_dnhostop(cstate, addr, Q_SRC);
		b1 = gen_dnhostop(cstate, addr, Q_DST);
		gen_and(b0, b1);
		return b1;

	case Q_DEFAULT:
	case Q_OR:
		/* Inefficient because we do our Calvinball dance twice */
		b0 = gen_dnhostop(cstate, addr, Q_SRC);
		b1 = gen_dnhostop(cstate, addr, Q_DST);
		gen_or(b0, b1);
		return b1;

	default:
		bpf_error(cstate, ERRSTR_802_11_ONLY_KW, dqkw(dir));
		/*NOTREACHED*/
	}
	/*
	 * In a DECnet message inside an Ethernet frame the first two bytes
	 * immediately after EtherType are the [little-endian] DECnet message
	 * length, which is irrelevant in this context.
	 *
	 * "pad = 1" means the third byte equals 0x81, thus it is the PLENGTH
	 * 8-bit bitmap of the optional padding before the packet route header.
	 * The bitmap always has bit 7 set to 1 and in this case has bits 0-6
	 * (TOTAL-PAD-SEQUENCE-LENGTH) set to integer value 1.  The latter
	 * means there aren't any PAD bytes after the bitmap, so the header
	 * begins at the fourth byte.  "pad = 0" means bit 7 of the third byte
	 * is set to 0, thus the header begins at the third byte.
	 *
	 * The header can be in several (as mentioned above) formats, all of
	 * which begin with the FLAGS 8-bit bitmap, which always has bit 7
	 * (PF, "pad field") set to 0 regardless of any padding present before
	 * the header.  "Short header" means bits 0-2 of the bitmap encode the
	 * integer value 2 (SFDP), and "long header" means value 6 (LFDP).
	 *
	 * To test PLENGTH and FLAGS, use multiple-byte constants with the
	 * values and the masks, this maps to the required single bytes of
	 * the message correctly on both big-endian and little-endian hosts.
	 * For the DECnet address use SWAPSHORT(), which always swaps bytes,
	 * because the wire encoding is little-endian and BPF multiple-byte
	 * loads are big-endian.  When the destination address is near enough
	 * to PLENGTH and FLAGS, generate one 32-bit comparison instead of two
	 * smaller ones.
	 */
	/* Check for pad = 1, long header case */
	tmp = gen_mcmp(cstate, OR_LINKPL, 2, BPF_H, 0x8106U, 0xFF07U);
	b1 = gen_cmp(cstate, OR_LINKPL, 2 + 1 + offset_lh,
	    BPF_H, SWAPSHORT(addr));
	gen_and(tmp, b1);
	/* Check for pad = 0, long header case */
	tmp = gen_mcmp(cstate, OR_LINKPL, 2, BPF_B, 0x06U, 0x07U);
	b2 = gen_cmp(cstate, OR_LINKPL, 2 + offset_lh, BPF_H,
	    SWAPSHORT(addr));
	gen_and(tmp, b2);
	gen_or(b2, b1);
	/* Check for pad = 1, short header case */
	if (dir == Q_DST) {
		b2 = gen_mcmp(cstate, OR_LINKPL, 2, BPF_W,
		    0x81020000U | SWAPSHORT(addr),
		    0xFF07FFFFU);
	} else {
		tmp = gen_mcmp(cstate, OR_LINKPL, 2, BPF_H, 0x8102U, 0xFF07U);
		b2 = gen_cmp(cstate, OR_LINKPL, 2 + 1 + offset_sh, BPF_H,
		    SWAPSHORT(addr));
		gen_and(tmp, b2);
	}
	gen_or(b2, b1);
	/* Check for pad = 0, short header case */
	if (dir == Q_DST) {
		b2 = gen_mcmp(cstate, OR_LINKPL, 2, BPF_W,
		    0x02000000U | SWAPSHORT(addr) << 8,
		    0x07FFFF00U);
	} else {
		tmp = gen_mcmp(cstate, OR_LINKPL, 2, BPF_B, 0x02U, 0x07U);
		b2 = gen_cmp(cstate, OR_LINKPL, 2 + offset_sh, BPF_H,
		    SWAPSHORT(addr));
		gen_and(tmp, b2);
	}
	gen_or(b2, b1);

	return b1;
}

/*
 * Generate a check for IPv4 or IPv6 for MPLS-encapsulated packets;
 * test the bottom-of-stack bit, and then check the version number
 * field in the IP header.
 */
static struct block *
gen_mpls_linktype(compiler_state_t *cstate, bpf_u_int32 ll_proto)
{
	struct block *b0, *b1;

	switch (ll_proto) {

	case ETHERTYPE_IP:
		/* match the bottom-of-stack bit */
		b0 = gen_mcmp(cstate, OR_LINKPL, (u_int)-2, BPF_B, 0x01, 0x01);
		/* match the IPv4 version number */
		b1 = gen_mcmp(cstate, OR_LINKPL, 0, BPF_B, 0x40, 0xf0);
		gen_and(b0, b1);
		return b1;

	case ETHERTYPE_IPV6:
		/* match the bottom-of-stack bit */
		b0 = gen_mcmp(cstate, OR_LINKPL, (u_int)-2, BPF_B, 0x01, 0x01);
		/* match the IPv6 version number */
		b1 = gen_mcmp(cstate, OR_LINKPL, 0, BPF_B, 0x60, 0xf0);
		gen_and(b0, b1);
		return b1;

	default:
		/* FIXME add other L3 proto IDs */
		bpf_error(cstate, "unsupported protocol over mpls");
		/*NOTREACHED*/
	}
}

static struct block *
gen_host(compiler_state_t *cstate, bpf_u_int32 addr, bpf_u_int32 mask,
    int proto, int dir, int type)
{
	struct block *b0, *b1;

	switch (proto) {

	case Q_DEFAULT:
		b0 = gen_host(cstate, addr, mask, Q_IP, dir, type);
		/*
		 * Only check for non-IPv4 addresses if we're not
		 * checking MPLS-encapsulated packets.
		 */
		if (cstate->label_stack_depth == 0) {
			b1 = gen_host(cstate, addr, mask, Q_ARP, dir, type);
			gen_or(b0, b1);
			b0 = gen_host(cstate, addr, mask, Q_RARP, dir, type);
			gen_or(b1, b0);
		}
		return b0;

	case Q_IP:
		b0 = gen_linktype(cstate, ETHERTYPE_IP);
		/*
		 * Belt and braces: if other code works correctly, any host
		 * bits are clear and mask == 0 means addr == 0.  In this case
		 * the call to gen_hostop() would produce an "always true"
		 * instruction block and ANDing it with the link type check
		 * would be a no-op.
		 */
		if (mask == 0 && addr == 0)
			return b0;
		b1 = gen_hostop(cstate, addr, mask, dir, 12, 16);
		gen_and(b0, b1);
		return b1;

	case Q_RARP:
		b0 = gen_linktype(cstate, ETHERTYPE_REVARP);
		// Same as for Q_IP above.
		if (mask == 0 && addr == 0)
			return b0;
		b1 = gen_hostop(cstate, addr, mask, dir, 14, 24);
		gen_and(b0, b1);
		return b1;

	case Q_ARP:
		b0 = gen_linktype(cstate, ETHERTYPE_ARP);
		// Same as for Q_IP above.
		if (mask == 0 && addr == 0)
			return b0;
		b1 = gen_hostop(cstate, addr, mask, dir, 14, 24);
		gen_and(b0, b1);
		return b1;

	case Q_DECNET:
		b0 = gen_linktype(cstate, ETHERTYPE_DN);
		b1 = gen_dnhostop(cstate, addr, dir);
		gen_and(b0, b1);
		return b1;
	}
	bpf_error(cstate, ERRSTR_INVALID_QUAL, pqkw(proto),
	    type == Q_NET ? "ip net" : "ip host");
	/*NOTREACHED*/
}

static struct block *
gen_host6(compiler_state_t *cstate, struct in6_addr *addr,
    struct in6_addr *mask, int proto, int dir, int type)
{
	struct block *b0, *b1;

	switch (proto) {

	case Q_DEFAULT:
	case Q_IPV6:
		b0 = gen_linktype(cstate, ETHERTYPE_IPV6);
		// Same as the Q_IP case in gen_host().
		if (
			! memcmp(mask, &in6addr_any, sizeof(struct in6_addr)) &&
			! memcmp(addr, &in6addr_any, sizeof(struct in6_addr))
		)
			return b0;
		b1 = gen_hostop6(cstate, addr, mask, dir, 8, 24);
		gen_and(b0, b1);
		return b1;
	}
	bpf_error(cstate, ERRSTR_INVALID_QUAL, pqkw(proto),
	    type == Q_NET ? "ip6 net" : "ip6 host");
	/*NOTREACHED*/
}

static struct block *
gen_host46_byname(compiler_state_t *cstate, const char *name,
    const u_char proto4, const u_char proto6, const u_char dir)
{
	if ((cstate->ai = pcap_nametoaddrinfo(name)) == NULL)
		bpf_error(cstate, "unknown host '%s'", name);
	struct block *ret = NULL;
	struct in6_addr mask128;
	memset(&mask128, 0xff, sizeof(mask128));

	/*
	 * For a hostname that resolves to both IPv4 and IPv6 addresses the
	 * AF_INET addresses may come before or after the AF_INET6 addresses
	 * depending on which getaddrinfo() implementation it is, what the
	 * resolving host's network configuration is and (on Linux with glibc)
	 * the contents of gai.conf(5).  This is because getaddrinfo() presumes
	 * a subsequent bind(2) or connect(2) use of the addresses, which is
	 * not the case here, so there is no sense in preserving the order of
	 * the AFs in the resolved addresses.  However, there is sense in
	 * hard-coding the order of AFs when generating a match block for more
	 * than one AF because this way the result reflects fewer external
	 * effects and is easier to test.
	 */

	/*
	 * Ignore any IPv4 addresses when resolving "ip6 host NAME", validate
	 * all other proto qualifiers in gen_host().
	 */
	if (proto4 != Q_IPV6) {
		for (struct addrinfo *ai = cstate->ai; ai; ai = ai->ai_next) {
			if (ai->ai_family != AF_INET)
				continue;
			struct sockaddr_in *sin4 =
			    (struct sockaddr_in *)ai->ai_addr;
			struct block *host4 = gen_host(cstate, ntohl(sin4->sin_addr.s_addr),
			    0xffffffff, proto4, dir, Q_HOST);
			if (ret)
				gen_or(ret, host4);
			ret = host4;
		}
	}

	/*
	 * Ignore any IPv6 addresses when resolving "(arp|ip|rarp) host NAME",
	 * validate all other proto qualifiers in gen_host6().
	 */
	if (proto6 != Q_ARP && proto6 != Q_IP && proto6 != Q_RARP) {
		for (struct addrinfo *ai = cstate->ai; ai; ai = ai->ai_next) {
			if (ai->ai_family != AF_INET6)
				continue;
			struct sockaddr_in6 *sin6 =
			    (struct sockaddr_in6 *)ai->ai_addr;
			struct block *host6 = gen_host6(cstate, &sin6->sin6_addr,
			    &mask128, proto6, dir, Q_HOST);
			if (ret)
				gen_or(ret, host6);
			ret = host6;
		}
	}

	freeaddrinfo(cstate->ai);
	cstate->ai = NULL;

	if (! ret)
		bpf_error(cstate, "unknown host '%s'%s", name,
		    proto4 == Q_DEFAULT
		    ? ""
		    : " for specified address family");
	return ret;
}

static unsigned char
is_mac48_linktype(const int linktype)
{
	switch (linktype) {
	case DLT_EN10MB:
	case DLT_FDDI:
	case DLT_IEEE802:
	case DLT_IEEE802_11:
	case DLT_IEEE802_11_RADIO:
	case DLT_IEEE802_11_RADIO_AVS:
	case DLT_IP_OVER_FC:
	case DLT_NETANALYZER:
	case DLT_NETANALYZER_TRANSPARENT:
	case DLT_PPI:
	case DLT_PRISM_HEADER:
		return 1;
	default:
		return 0;
	}
}

static struct block *
gen_mac48host(compiler_state_t *cstate, const u_char *eaddr, const u_char dir,
    const char *keyword)
{
	struct block *b1 = NULL;
	u_int src_off, dst_off;

	switch (cstate->linktype) {
	case DLT_EN10MB:
	case DLT_NETANALYZER:
	case DLT_NETANALYZER_TRANSPARENT:
		b1 = gen_prevlinkhdr_check(cstate);
		src_off = 6;
		dst_off = 0;
		break;
	case DLT_FDDI:
		src_off = 6 + 1 + cstate->pcap_fddipad;
		dst_off = 0 + 1 + cstate->pcap_fddipad;
		break;
	case DLT_IEEE802:
		src_off = 8;
		dst_off = 2;
		break;
	case DLT_IEEE802_11:
	case DLT_PRISM_HEADER:
	case DLT_IEEE802_11_RADIO_AVS:
	case DLT_IEEE802_11_RADIO:
	case DLT_PPI:
		return gen_wlanhostop(cstate, eaddr, dir);
	case DLT_IP_OVER_FC:
		/*
		 * Assume that the addresses are IEEE 48-bit MAC addresses,
		 * as RFC 2625 states.
		 */
		src_off = 10;
		dst_off = 2;
		break;
	case DLT_SUNATM:
		/*
		 * This is LLC-multiplexed traffic; if it were
		 * LANE, cstate->linktype would have been set to
		 * DLT_EN10MB.
		 */
		 /* FALLTHROUGH */
	default:
		fail_kw_on_dlt(cstate, keyword);
	}

	struct block *b0, *tmp;

	switch (dir) {
	case Q_SRC:
		b0 = gen_bcmp(cstate, OR_LINKHDR, src_off, 6, eaddr);
		break;
	case Q_DST:
		b0 = gen_bcmp(cstate, OR_LINKHDR, dst_off, 6, eaddr);
		break;
	case Q_AND:
		tmp = gen_bcmp(cstate, OR_LINKHDR, src_off, 6, eaddr);
		b0 = gen_bcmp(cstate, OR_LINKHDR, dst_off, 6, eaddr);
		gen_and(tmp, b0);
		break;
	case Q_DEFAULT:
	case Q_OR:
		tmp = gen_bcmp(cstate, OR_LINKHDR, src_off, 6, eaddr);
		b0 = gen_bcmp(cstate, OR_LINKHDR, dst_off, 6, eaddr);
		gen_or(tmp, b0);
		break;
	default:
		bpf_error(cstate, ERRSTR_802_11_ONLY_KW, dqkw(dir));
	}

	if (b1 != NULL)
		gen_and(b1, b0);
	return b0;
}

static struct block *
gen_mac48host_byname(compiler_state_t *cstate, const char *name,
    const u_char dir, const char *context)
{
	if (! is_mac48_linktype(cstate->linktype))
		fail_kw_on_dlt(cstate, context);

	u_char *eaddrp = pcap_ether_hostton(name);
	if (eaddrp == NULL)
		bpf_error(cstate, ERRSTR_UNKNOWN_MAC48HOST, name);
	u_char eaddr[6];
	memcpy(eaddr, eaddrp, sizeof(eaddr));
	free(eaddrp);

	return gen_mac48host(cstate, eaddr, dir, context);
}

static struct block *
gen_mac8host(compiler_state_t *cstate, const uint8_t mac8, const u_char dir,
    const char *context)
{
	u_int src_off, dst_off;

	switch (cstate->linktype) {
	case DLT_ARCNET:
	case DLT_ARCNET_LINUX:
		/*
		 * ARCnet is different from Ethernet: the source address comes
		 * before the destination address, each is one byte long.
		 * This holds for all three "buffer formats" in RFC 1201
		 * Section 2.1, see also page 4-10 in the 1983 edition of the
		 * "ARCNET Designer's Handbook" published by Datapoint
		 * (document number 61610-01).
		 */
		src_off = 0;
		dst_off = 1;
		break;
	case DLT_BACNET_MS_TP:
		/*
		 * MS/TP resembles both Ethernet (in that the destination
		 * station address precedes the source station address) and
		 * ARCnet (in that a station address is one byte long).
		 */
		src_off = 4;
		dst_off = 3;
		break;
	default:
		fail_kw_on_dlt(cstate, context);
	}

	struct block *src, *dst;

	switch (dir) {
	case Q_SRC:
		return gen_cmp(cstate, OR_LINKHDR, src_off, BPF_B, mac8);
	case Q_DST:
		return gen_cmp(cstate, OR_LINKHDR, dst_off, BPF_B, mac8);
	case Q_AND:
		src = gen_cmp(cstate, OR_LINKHDR, src_off, BPF_B, mac8);
		dst = gen_cmp(cstate, OR_LINKHDR, dst_off, BPF_B, mac8);
		gen_and(src, dst);
		return dst;
	case Q_DEFAULT:
	case Q_OR:
		src = gen_cmp(cstate, OR_LINKHDR, src_off, BPF_B, mac8);
		dst = gen_cmp(cstate, OR_LINKHDR, dst_off, BPF_B, mac8);
		gen_or(src, dst);
		return dst;
	default:
		bpf_error(cstate, ERRSTR_INVALID_QUAL, dqkw(dir), context);
	}
}

/*
 * This primitive is non-directional by design, so the grammar does not allow
 * to qualify it with a direction.
 */
static struct block *
gen_gateway(compiler_state_t *cstate, const char *name, const u_char proto)
{
	switch (proto) {
	case Q_DEFAULT:
	case Q_IP:
	case Q_ARP:
	case Q_RARP:
		break;
	default:
		bpf_error(cstate, ERRSTR_INVALID_QUAL, pqkw(proto), "gateway");
	}

	struct block *b0 = gen_mac48host_byname(cstate, name, Q_OR, "gateway");
	/*
	 * For "gateway NAME" not qualified with a protocol skip the IPv6 leg
	 * of the name-to-address translation to match the documented
	 * IPv4-only behaviour.
	 */
	struct block *b1 = gen_host46_byname(cstate, name, proto, Q_IP, Q_OR);
	gen_not(b1);
	gen_and(b0, b1);
	return b1;
}

static struct block *
gen_proto_abbrev_internal(compiler_state_t *cstate, int proto)
{
	struct block *b0;
	struct block *b1;

	switch (proto) {

	case Q_SCTP:
		return gen_proto(cstate, IPPROTO_SCTP, Q_DEFAULT);

	case Q_TCP:
		return gen_proto(cstate, IPPROTO_TCP, Q_DEFAULT);

	case Q_UDP:
		return gen_proto(cstate, IPPROTO_UDP, Q_DEFAULT);

	case Q_ICMP:
		return gen_proto(cstate, IPPROTO_ICMP, Q_IP);

#ifndef	IPPROTO_IGMP
#define	IPPROTO_IGMP	2
#endif

	case Q_IGMP:
		return gen_proto(cstate, IPPROTO_IGMP, Q_IP);

#ifndef	IPPROTO_IGRP
#define	IPPROTO_IGRP	9
#endif
	case Q_IGRP:
		return gen_proto(cstate, IPPROTO_IGRP, Q_IP);

#ifndef IPPROTO_PIM
#define IPPROTO_PIM	103
#endif

	case Q_PIM:
		return gen_proto(cstate, IPPROTO_PIM, Q_DEFAULT);

#ifndef IPPROTO_VRRP
#define IPPROTO_VRRP	112
#endif

	case Q_VRRP:
		return gen_proto(cstate, IPPROTO_VRRP, Q_IP);

#ifndef IPPROTO_CARP
#define IPPROTO_CARP	112
#endif

	case Q_CARP:
		return gen_proto(cstate, IPPROTO_CARP, Q_IP);

	case Q_IP:
		return gen_linktype(cstate, ETHERTYPE_IP);

	case Q_ARP:
		return gen_linktype(cstate, ETHERTYPE_ARP);

	case Q_RARP:
		return gen_linktype(cstate, ETHERTYPE_REVARP);

	case Q_ATALK:
		return gen_linktype(cstate, ETHERTYPE_ATALK);

	case Q_AARP:
		return gen_linktype(cstate, ETHERTYPE_AARP);

	case Q_DECNET:
		return gen_linktype(cstate, ETHERTYPE_DN);

	case Q_SCA:
		return gen_linktype(cstate, ETHERTYPE_SCA);

	case Q_LAT:
		return gen_linktype(cstate, ETHERTYPE_LAT);

	case Q_MOPDL:
		return gen_linktype(cstate, ETHERTYPE_MOPDL);

	case Q_MOPRC:
		return gen_linktype(cstate, ETHERTYPE_MOPRC);

	case Q_IPV6:
		return gen_linktype(cstate, ETHERTYPE_IPV6);

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6	58
#endif
	case Q_ICMPV6:
		return gen_proto(cstate, IPPROTO_ICMPV6, Q_IPV6);

#ifndef IPPROTO_AH
#define IPPROTO_AH	51
#endif
	case Q_AH:
		return gen_proto(cstate, IPPROTO_AH, Q_DEFAULT);

#ifndef IPPROTO_ESP
#define IPPROTO_ESP	50
#endif
	case Q_ESP:
		return gen_proto(cstate, IPPROTO_ESP, Q_DEFAULT);

	case Q_ISO:
		return gen_linktype(cstate, LLCSAP_ISONS);

	case Q_ESIS:
		return gen_proto(cstate, ISO9542_ESIS, Q_ISO);

	case Q_ISIS:
		return gen_proto(cstate, ISO10589_ISIS, Q_ISO);

	case Q_ISIS_L1: /* all IS-IS Level1 PDU-Types */
		b0 = gen_proto(cstate, ISIS_L1_LAN_IIH, Q_ISIS);
		b1 = gen_proto(cstate, ISIS_PTP_IIH, Q_ISIS); /* FIXME extract the circuit-type bits */
		gen_or(b0, b1);
		b0 = gen_proto(cstate, ISIS_L1_LSP, Q_ISIS);
		gen_or(b0, b1);
		b0 = gen_proto(cstate, ISIS_L1_CSNP, Q_ISIS);
		gen_or(b0, b1);
		b0 = gen_proto(cstate, ISIS_L1_PSNP, Q_ISIS);
		gen_or(b0, b1);
		return b1;

	case Q_ISIS_L2: /* all IS-IS Level2 PDU-Types */
		b0 = gen_proto(cstate, ISIS_L2_LAN_IIH, Q_ISIS);
		b1 = gen_proto(cstate, ISIS_PTP_IIH, Q_ISIS); /* FIXME extract the circuit-type bits */
		gen_or(b0, b1);
		b0 = gen_proto(cstate, ISIS_L2_LSP, Q_ISIS);
		gen_or(b0, b1);
		b0 = gen_proto(cstate, ISIS_L2_CSNP, Q_ISIS);
		gen_or(b0, b1);
		b0 = gen_proto(cstate, ISIS_L2_PSNP, Q_ISIS);
		gen_or(b0, b1);
		return b1;

	case Q_ISIS_IIH: /* all IS-IS Hello PDU-Types */
		b0 = gen_proto(cstate, ISIS_L1_LAN_IIH, Q_ISIS);
		b1 = gen_proto(cstate, ISIS_L2_LAN_IIH, Q_ISIS);
		gen_or(b0, b1);
		b0 = gen_proto(cstate, ISIS_PTP_IIH, Q_ISIS);
		gen_or(b0, b1);
		return b1;

	case Q_ISIS_LSP:
		b0 = gen_proto(cstate, ISIS_L1_LSP, Q_ISIS);
		b1 = gen_proto(cstate, ISIS_L2_LSP, Q_ISIS);
		gen_or(b0, b1);
		return b1;

	case Q_ISIS_SNP:
		b0 = gen_proto(cstate, ISIS_L1_CSNP, Q_ISIS);
		b1 = gen_proto(cstate, ISIS_L2_CSNP, Q_ISIS);
		gen_or(b0, b1);
		b0 = gen_proto(cstate, ISIS_L1_PSNP, Q_ISIS);
		gen_or(b0, b1);
		b0 = gen_proto(cstate, ISIS_L2_PSNP, Q_ISIS);
		gen_or(b0, b1);
		return b1;

	case Q_ISIS_CSNP:
		b0 = gen_proto(cstate, ISIS_L1_CSNP, Q_ISIS);
		b1 = gen_proto(cstate, ISIS_L2_CSNP, Q_ISIS);
		gen_or(b0, b1);
		return b1;

	case Q_ISIS_PSNP:
		b0 = gen_proto(cstate, ISIS_L1_PSNP, Q_ISIS);
		b1 = gen_proto(cstate, ISIS_L2_PSNP, Q_ISIS);
		gen_or(b0, b1);
		return b1;

	case Q_CLNP:
		return gen_proto(cstate, ISO8473_CLNP, Q_ISO);

	case Q_STP:
		return gen_linktype(cstate, LLCSAP_8021D);

	case Q_IPX:
		return gen_linktype(cstate, LLCSAP_IPX);

	case Q_NETBEUI:
		return gen_linktype(cstate, LLCSAP_NETBEUI);
	}
	bpf_error(cstate, "'%s' cannot be used as an abbreviation", pqkw(proto));
}

struct block *
gen_proto_abbrev(compiler_state_t *cstate, int proto)
{
	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	return gen_proto_abbrev_internal(cstate, proto);
}

static struct block *
gen_ip_proto(compiler_state_t *cstate, const uint8_t proto)
{
	return gen_cmp(cstate, OR_LINKPL, 9, BPF_B, proto);
}

static struct block *
gen_ip6_proto(compiler_state_t *cstate, const uint8_t proto)
{
	return gen_cmp(cstate, OR_LINKPL, 6, BPF_B, proto);
}

static struct block *
gen_ipfrag(compiler_state_t *cstate)
{
	struct slist *s;

	/* not IPv4 frag other than the first frag */
	s = gen_load_a(cstate, OR_LINKPL, 6, BPF_H);
	return gen_unset(cstate, 0x1fff, s);
}

/*
 * Generate a comparison to a port value in the transport-layer header
 * at the specified offset from the beginning of that header.
 *
 * XXX - this handles a variable-length prefix preceding the link-layer
 * header, such as the radiotap or AVS radio prefix, but doesn't handle
 * variable-length link-layer headers (such as Token Ring or 802.11
 * headers).
 */
static struct block *
gen_portatom(compiler_state_t *cstate, int off, uint16_t v)
{
	return gen_cmp(cstate, OR_TRAN_IPV4, off, BPF_H, v);
}

static struct block *
gen_portatom6(compiler_state_t *cstate, int off, uint16_t v)
{
	return gen_cmp(cstate, OR_TRAN_IPV6, off, BPF_H, v);
}

static struct block *
gen_port(compiler_state_t *cstate, uint16_t port, int proto, int dir)
{
	struct block *b1, *tmp;

	switch (dir) {
	case Q_SRC:
		b1 = gen_portatom(cstate, 0, port);
		break;

	case Q_DST:
		b1 = gen_portatom(cstate, 2, port);
		break;

	case Q_AND:
		tmp = gen_portatom(cstate, 0, port);
		b1 = gen_portatom(cstate, 2, port);
		gen_and(tmp, b1);
		break;

	case Q_DEFAULT:
	case Q_OR:
		tmp = gen_portatom(cstate, 0, port);
		b1 = gen_portatom(cstate, 2, port);
		gen_or(tmp, b1);
		break;

	default:
		bpf_error(cstate, ERRSTR_INVALID_QUAL, dqkw(dir), "port");
		/*NOTREACHED*/
	}

	return gen_port_common(cstate, proto, b1);
}

static struct block *
gen_port_common(compiler_state_t *cstate, int proto, struct block *b1)
{
	struct block *b0, *tmp;

	/*
	 * ether proto ip
	 *
	 * For FDDI, RFC 1188 says that SNAP encapsulation is used,
	 * not LLC encapsulation with LLCSAP_IP.
	 *
	 * For IEEE 802 networks - which includes 802.5 token ring
	 * (which is what DLT_IEEE802 means) and 802.11 - RFC 1042
	 * says that SNAP encapsulation is used, not LLC encapsulation
	 * with LLCSAP_IP.
	 *
	 * For LLC-encapsulated ATM/"Classical IP", RFC 1483 and
	 * RFC 2225 say that SNAP encapsulation is used, not LLC
	 * encapsulation with LLCSAP_IP.
	 *
	 * So we always check for ETHERTYPE_IP.
	 *
	 * At the time of this writing all three L4 protocols the "port" and
	 * "portrange" primitives support (TCP, UDP and SCTP) have the source
	 * and the destination ports identically encoded in the transport
	 * protocol header.  So without a proto qualifier the only difference
	 * between the implemented cases is the protocol number and all other
	 * checks need to be made exactly once.
	 *
	 * If the expression syntax in future starts to support ports for
	 * another L4 protocol that has unsigned integer ports encoded using a
	 * different size and/or offset, this will require a different code.
	 */
	switch (proto) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
	case IPPROTO_SCTP:
		tmp = gen_ip_proto(cstate, (uint8_t)proto);
		break;

	case PROTO_UNDEF:
		tmp = gen_ip_proto(cstate, IPPROTO_SCTP);
		gen_or(gen_ip_proto(cstate, IPPROTO_UDP), tmp);
		gen_or(gen_ip_proto(cstate, IPPROTO_TCP), tmp);
		break;

	default:
		bpf_error(cstate, ERRSTR_FUNC_VAR_INT, __func__, "proto", proto);
	}
	// Not a fragment other than the first fragment.
	b0 = gen_ipfrag(cstate);
	gen_and(tmp, b0);
	gen_and(b0, b1);
	// "link proto \ip"
	gen_and(gen_linktype(cstate, ETHERTYPE_IP), b1);
	return b1;
}

static struct block *
gen_port6(compiler_state_t *cstate, uint16_t port, int proto, int dir)
{
	struct block *b1, *tmp;

	switch (dir) {
	case Q_SRC:
		b1 = gen_portatom6(cstate, 0, port);
		break;

	case Q_DST:
		b1 = gen_portatom6(cstate, 2, port);
		break;

	case Q_AND:
		tmp = gen_portatom6(cstate, 0, port);
		b1 = gen_portatom6(cstate, 2, port);
		gen_and(tmp, b1);
		break;

	case Q_DEFAULT:
	case Q_OR:
		tmp = gen_portatom6(cstate, 0, port);
		b1 = gen_portatom6(cstate, 2, port);
		gen_or(tmp, b1);
		break;

	default:
		bpf_error(cstate, ERRSTR_INVALID_QUAL, dqkw(dir), "port");
		/*NOTREACHED*/
	}

	return gen_port6_common(cstate, proto, b1);
}

static struct block *
gen_port6_common(compiler_state_t *cstate, int proto, struct block *b1)
{
	struct block *tmp;

	// "ip6 proto 'ip_proto'"
	switch (proto) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
	case IPPROTO_SCTP:
		tmp = gen_ip6_proto(cstate, (uint8_t)proto);
		break;

	case PROTO_UNDEF:
		// Same as in gen_port_common().
		tmp = gen_ip6_proto(cstate, IPPROTO_SCTP);
		gen_or(gen_ip6_proto(cstate, IPPROTO_UDP), tmp);
		gen_or(gen_ip6_proto(cstate, IPPROTO_TCP), tmp);
		break;

	default:
		bpf_error(cstate, ERRSTR_FUNC_VAR_INT, __func__, "proto", proto);
	}
	// XXX - catch the first fragment of a fragmented packet?
	gen_and(tmp, b1);
	// "link proto \ip6"
	gen_and(gen_linktype(cstate, ETHERTYPE_IPV6), b1);
	return b1;
}

/* gen_portrange code */
static struct block *
gen_portrangeatom(compiler_state_t *cstate, u_int off, uint16_t v1,
    uint16_t v2)
{
	if (v1 == v2)
		return gen_portatom(cstate, off, v1);

	struct block *b1, *b2;

	b1 = gen_cmp_ge(cstate, OR_TRAN_IPV4, off, BPF_H, min(v1, v2));
	b2 = gen_cmp_le(cstate, OR_TRAN_IPV4, off, BPF_H, max(v1, v2));

	gen_and(b1, b2);

	return b2;
}

static struct block *
gen_portrange(compiler_state_t *cstate, uint16_t port1, uint16_t port2,
    int proto, int dir)
{
	struct block *b1, *tmp;

	switch (dir) {
	case Q_SRC:
		b1 = gen_portrangeatom(cstate, 0, port1, port2);
		break;

	case Q_DST:
		b1 = gen_portrangeatom(cstate, 2, port1, port2);
		break;

	case Q_AND:
		tmp = gen_portrangeatom(cstate, 0, port1, port2);
		b1 = gen_portrangeatom(cstate, 2, port1, port2);
		gen_and(tmp, b1);
		break;

	case Q_DEFAULT:
	case Q_OR:
		tmp = gen_portrangeatom(cstate, 0, port1, port2);
		b1 = gen_portrangeatom(cstate, 2, port1, port2);
		gen_or(tmp, b1);
		break;

	default:
		bpf_error(cstate, ERRSTR_INVALID_QUAL, dqkw(dir), "portrange");
		/*NOTREACHED*/
	}

	return gen_port_common(cstate, proto, b1);
}

static struct block *
gen_portrangeatom6(compiler_state_t *cstate, u_int off, uint16_t v1,
    uint16_t v2)
{
	if (v1 == v2)
		return gen_portatom6(cstate, off, v1);

	struct block *b1, *b2;

	b1 = gen_cmp_ge(cstate, OR_TRAN_IPV6, off, BPF_H, min(v1, v2));
	b2 = gen_cmp_le(cstate, OR_TRAN_IPV6, off, BPF_H, max(v1, v2));

	gen_and(b1, b2);

	return b2;
}

static struct block *
gen_portrange6(compiler_state_t *cstate, uint16_t port1, uint16_t port2,
    int proto, int dir)
{
	struct block *b1, *tmp;

	switch (dir) {
	case Q_SRC:
		b1 = gen_portrangeatom6(cstate, 0, port1, port2);
		break;

	case Q_DST:
		b1 = gen_portrangeatom6(cstate, 2, port1, port2);
		break;

	case Q_AND:
		tmp = gen_portrangeatom6(cstate, 0, port1, port2);
		b1 = gen_portrangeatom6(cstate, 2, port1, port2);
		gen_and(tmp, b1);
		break;

	case Q_DEFAULT:
	case Q_OR:
		tmp = gen_portrangeatom6(cstate, 0, port1, port2);
		b1 = gen_portrangeatom6(cstate, 2, port1, port2);
		gen_or(tmp, b1);
		break;

	default:
		bpf_error(cstate, ERRSTR_INVALID_QUAL, dqkw(dir), "portrange");
		/*NOTREACHED*/
	}

	return gen_port6_common(cstate, proto, b1);
}

static int
lookup_proto(compiler_state_t *cstate, const char *name, const struct qual q)
{
	/*
	 * Do not check here whether q.proto is valid (e.g. in "udp proto abc"
	 * fail the "abc", but not the "udp proto").  Likewise, do not check
	 * here whether the combination of q.proto and q.addr is valid (e.g.
	 * in "(link|iso|isis) protochain abc" fail the "abc", but not the
	 * "(link|iso|isis) protochain").
	 *
	 * On the one hand, this avoids a layering violation: gen_proto() and
	 * gen_protochain() implement the semantic checks.  On the other hand,
	 * the protocol name lookup error arguably is a problem smaller than
	 * the semantic error, hence the latter ought to be the reported cause
	 * of failure in both cases.  In future this potentially could be made
	 * more consistent by attempting the lookup after the semantic checks.
	 */

	int v = PROTO_UNDEF;
	switch (q.proto) {

	case Q_DEFAULT:
	case Q_IP:
	case Q_IPV6:
		v = pcap_nametoproto(name);
		break;

	case Q_LINK:
		/* XXX should look up h/w protocol type based on cstate->linktype */
		v = pcap_nametoeproto(name);
		if (v == PROTO_UNDEF)
			v = pcap_nametollc(name);
		break;

	case Q_ISO:
		if (strcmp(name, "esis") == 0)
			v = ISO9542_ESIS;
		else if (strcmp(name, "isis") == 0)
			v = ISO10589_ISIS;
		else if (strcmp(name, "clnp") == 0)
			v = ISO8473_CLNP;
		break;

	// "isis proto" is a valid syntax, but it takes only numeric IDs.
	}
	// In theory, the only possible negative value of v is PROTO_UNDEF.
	if (v >= 0)
		return v;

	if (q.proto == Q_DEFAULT)
		bpf_error(cstate, "unknown '%s' value '%s'",
		    tqkw(q.addr), name);
	bpf_error(cstate, "unknown '%s %s' value '%s'",
	    pqkw(q.proto), tqkw(q.addr), name);
}

#if !defined(NO_PROTOCHAIN)
/*
 * This primitive is non-directional by design, so the grammar does not allow
 * to qualify it with a direction.
 */
static struct block *
gen_protochain(compiler_state_t *cstate, bpf_u_int32 v, int proto)
{
	struct block *b0, *b;
	struct slist *s[100];
	int fix2, fix3, fix4, fix5;
	int ahcheck, again, end;
	int i, max;
	int reg2 = alloc_reg(cstate);

	memset(s, 0, sizeof(s));
	fix3 = fix4 = fix5 = 0;

	switch (proto) {
	case Q_IP:
	case Q_IPV6:
		assert_maxval(cstate, "protocol number", v, UINT8_MAX);
		break;
	case Q_DEFAULT:
		b0 = gen_protochain(cstate, v, Q_IP);
		b = gen_protochain(cstate, v, Q_IPV6);
		gen_or(b0, b);
		return b;
	default:
		bpf_error(cstate, ERRSTR_INVALID_QUAL, pqkw(proto), "protochain");
		/*NOTREACHED*/
	}

	/*
	 * We don't handle variable-length prefixes before the link-layer
	 * header, or variable-length link-layer headers, here yet.
	 * We might want to add BPF instructions to do the protochain
	 * work, to simplify that and, on platforms that have a BPF
	 * interpreter with the new instructions, let the filtering
	 * be done in the kernel.  (We already require a modified BPF
	 * engine to do the protochain stuff, to support backward
	 * branches, and backward branch support is unlikely to appear
	 * in kernel BPF engines.)
	 *
	 * Hence in the current implementation the gen_abs_offset_varpart()
	 * invocations incurred from gen_load_a() and gen_loadx_iphdrlen()
	 * below do not affect the offset because off_linkpl.is_variable == 0.
	 */
	if (cstate->off_linkpl.is_variable)
		bpf_error(cstate, "'protochain' not supported with variable length headers");

	/*
	 * To quote a comment in optimize.c:
	 *
	 * "These data structures are used in a Cocke and Schwartz style
	 * value numbering scheme.  Since the flowgraph is acyclic,
	 * exit values can be propagated from a node's predecessors
	 * provided it is uniquely defined."
	 *
	 * "Acyclic" means "no backward branches", which means "no
	 * loops", so we have to turn the optimizer off.
	 */
	cstate->no_optimize = 1;

	/*
	 * s[0] is a dummy entry to protect other BPF insn from damage
	 * by s[fix] = foo with uninitialized variable "fix".  It is somewhat
	 * hard to find interdependency made by jump table fixup.
	 */
	i = 0;
	s[i] = new_stmt(cstate, 0);	/*dummy*/
	i++;

	switch (proto) {
	case Q_IP:
		b0 = gen_linktype(cstate, ETHERTYPE_IP);

		/* A = ip->ip_p */
		s[i] = gen_load_a(cstate, OR_LINKPL, 9, BPF_B);
		i++;
		/* X = ip->ip_hl << 2 */
		s[i] = gen_loadx_iphdrlen(cstate);
		i++;
		break;

	case Q_IPV6:
		b0 = gen_linktype(cstate, ETHERTYPE_IPV6);

		/* A = ip6->ip_nxt */
		s[i] = gen_load_a(cstate, OR_LINKPL, 6, BPF_B);
		i++;
		/* X = sizeof(struct ip6_hdr) */
		s[i] = new_stmt(cstate, BPF_LDX|BPF_IMM);
		s[i]->s.k = 40;
		i++;
		break;

	default:
		bpf_error(cstate, "unsupported proto to gen_protochain");
		/*NOTREACHED*/
	}

	/* again: if (A == v) goto end; else fall through; */
	again = i;
	s[i] = new_stmt(cstate, JMP(BPF_JEQ, BPF_K));
	s[i]->s.k = v;
	s[i]->s.jt = NULL;		/*later*/
	s[i]->s.jf = NULL;		/*update in next stmt*/
	fix5 = i;
	i++;

#ifndef IPPROTO_NONE
#define IPPROTO_NONE	59
#endif
	/* if (A == IPPROTO_NONE) goto end */
	s[i] = new_stmt(cstate, JMP(BPF_JEQ, BPF_K));
	s[i]->s.jt = NULL;	/*later*/
	s[i]->s.jf = NULL;	/*update in next stmt*/
	s[i]->s.k = IPPROTO_NONE;
	s[fix5]->s.jf = s[i];
	fix2 = i;
	i++;

	if (proto == Q_IPV6) {
		int v6start, v6end, v6advance, j;

		v6start = i;
		/* if (A == IPPROTO_HOPOPTS) goto v6advance */
		s[i] = new_stmt(cstate, JMP(BPF_JEQ, BPF_K));
		s[i]->s.jt = NULL;	/*later*/
		s[i]->s.jf = NULL;	/*update in next stmt*/
		s[i]->s.k = IPPROTO_HOPOPTS;
		s[fix2]->s.jf = s[i];
		i++;
		/* if (A == IPPROTO_DSTOPTS) goto v6advance */
		s[i - 1]->s.jf = s[i] = new_stmt(cstate, JMP(BPF_JEQ, BPF_K));
		s[i]->s.jt = NULL;	/*later*/
		s[i]->s.jf = NULL;	/*update in next stmt*/
		s[i]->s.k = IPPROTO_DSTOPTS;
		i++;
		/* if (A == IPPROTO_ROUTING) goto v6advance */
		s[i - 1]->s.jf = s[i] = new_stmt(cstate, JMP(BPF_JEQ, BPF_K));
		s[i]->s.jt = NULL;	/*later*/
		s[i]->s.jf = NULL;	/*update in next stmt*/
		s[i]->s.k = IPPROTO_ROUTING;
		i++;
		/* if (A == IPPROTO_FRAGMENT) goto v6advance; else goto ahcheck; */
		s[i - 1]->s.jf = s[i] = new_stmt(cstate, JMP(BPF_JEQ, BPF_K));
		s[i]->s.jt = NULL;	/*later*/
		s[i]->s.jf = NULL;	/*later*/
		s[i]->s.k = IPPROTO_FRAGMENT;
		fix3 = i;
		v6end = i;
		i++;

		/* v6advance: */
		v6advance = i;

		/*
		 * in short,
		 * A = P[X + packet head];
		 * X = X + (P[X + packet head + 1] + 1) * 8;
		 */
		/* A = P[X + packet head] */
		s[i] = new_stmt(cstate, BPF_LD|BPF_IND|BPF_B);
		s[i]->s.k = cstate->off_linkpl.constant_part + cstate->off_nl;
		i++;
		/* MEM[reg2] = A */
		s[i] = new_stmt(cstate, BPF_ST);
		s[i]->s.k = reg2;
		i++;
		/* A = P[X + packet head + 1]; */
		s[i] = new_stmt(cstate, BPF_LD|BPF_IND|BPF_B);
		s[i]->s.k = cstate->off_linkpl.constant_part + cstate->off_nl + 1;
		i++;
		/* A += 1 */
		s[i] = new_stmt(cstate, BPF_ALU|BPF_ADD|BPF_K);
		s[i]->s.k = 1;
		i++;
		/* A *= 8 */
		s[i] = new_stmt(cstate, BPF_ALU|BPF_MUL|BPF_K);
		s[i]->s.k = 8;
		i++;
		/* A += X */
		s[i] = new_stmt(cstate, BPF_ALU|BPF_ADD|BPF_X);
		s[i]->s.k = 0;
		i++;
		/* X = A; */
		s[i] = new_stmt(cstate, BPF_MISC|BPF_TAX);
		i++;
		/* A = MEM[reg2] */
		s[i] = new_stmt(cstate, BPF_LD|BPF_MEM);
		s[i]->s.k = reg2;
		i++;

		/* goto again; (must use BPF_JA for backward jump) */
		s[i] = new_stmt(cstate, JMP(BPF_JA, BPF_K));
		s[i]->s.k = again - i - 1;
		s[i - 1]->s.jf = s[i];
		i++;

		/* fixup */
		for (j = v6start; j <= v6end; j++)
			s[j]->s.jt = s[v6advance];
	} else {
		/* nop */
		s[i] = new_stmt(cstate, BPF_ALU|BPF_ADD|BPF_K);
		s[i]->s.k = 0;
		s[fix2]->s.jf = s[i];
		i++;
	}

	/* ahcheck: */
	ahcheck = i;
	/* if (A == IPPROTO_AH) then fall through; else goto end; */
	s[i] = new_stmt(cstate, JMP(BPF_JEQ, BPF_K));
	s[i]->s.jt = NULL;	/*later*/
	s[i]->s.jf = NULL;	/*later*/
	s[i]->s.k = IPPROTO_AH;
	if (fix3)
		s[fix3]->s.jf = s[ahcheck];
	fix4 = i;
	i++;

	/*
	 * in short,
	 * A = P[X];
	 * X = X + (P[X + 1] + 2) * 4;
	 */
	/* A = P[X + packet head]; */
	s[i] = new_stmt(cstate, BPF_LD|BPF_IND|BPF_B);
	s[i]->s.k = cstate->off_linkpl.constant_part + cstate->off_nl;
	s[i - 1]->s.jt = s[i];
	i++;
	/* MEM[reg2] = A */
	s[i] = new_stmt(cstate, BPF_ST);
	s[i]->s.k = reg2;
	i++;
	/* A = X */
	s[i - 1]->s.jt = s[i] = new_stmt(cstate, BPF_MISC|BPF_TXA);
	i++;
	/* A += 1 */
	s[i] = new_stmt(cstate, BPF_ALU|BPF_ADD|BPF_K);
	s[i]->s.k = 1;
	i++;
	/* X = A */
	s[i] = new_stmt(cstate, BPF_MISC|BPF_TAX);
	i++;
	/* A = P[X + packet head] */
	s[i] = new_stmt(cstate, BPF_LD|BPF_IND|BPF_B);
	s[i]->s.k = cstate->off_linkpl.constant_part + cstate->off_nl;
	i++;
	/* A += 2 */
	s[i] = new_stmt(cstate, BPF_ALU|BPF_ADD|BPF_K);
	s[i]->s.k = 2;
	i++;
	/* A *= 4 */
	s[i] = new_stmt(cstate, BPF_ALU|BPF_MUL|BPF_K);
	s[i]->s.k = 4;
	i++;
	/* X = A; */
	s[i] = new_stmt(cstate, BPF_MISC|BPF_TAX);
	i++;
	/* A = MEM[reg2] */
	s[i] = new_stmt(cstate, BPF_LD|BPF_MEM);
	s[i]->s.k = reg2;
	i++;

	/* goto again; (must use BPF_JA for backward jump) */
	s[i] = new_stmt(cstate, JMP(BPF_JA, BPF_K));
	s[i]->s.k = again - i - 1;
	i++;

	/* end: nop */
	end = i;
	s[i] = new_stmt(cstate, BPF_ALU|BPF_ADD|BPF_K);
	s[i]->s.k = 0;
	s[fix2]->s.jt = s[end];
	s[fix4]->s.jf = s[end];
	s[fix5]->s.jt = s[end];
	i++;

	/*
	 * make slist chain
	 */
	max = i;
	for (i = 0; i < max - 1; i++)
		s[i]->next = s[i + 1];
	s[max - 1]->next = NULL;

	/*
	 * emit final check
	 * Remember, s[0] is dummy.
	 */
	b = gen_jmp_k(cstate, BPF_JEQ, v, s[1]);

	free_reg(cstate, reg2);

	gen_and(b0, b);
	return b;
}
#endif /* !defined(NO_PROTOCHAIN) */

/*
 * Generate code that checks whether the packet is a packet for protocol
 * <proto> and whether the type field in that protocol's header has
 * the value <v>, e.g. if <proto> is Q_IP, it checks whether it's an
 * IP packet and checks the protocol number in the IP header against <v>.
 *
 * If <proto> is Q_DEFAULT, i.e. just "proto" was specified, it checks
 * against Q_IP and Q_IPV6.
 *
 * This primitive is non-directional by design, so the grammar does not allow
 * to qualify it with a direction.
 */
static struct block *
gen_proto(compiler_state_t *cstate, bpf_u_int32 v, int proto)
{
	struct block *b0, *b1;
	struct block *b2;

	switch (proto) {
	case Q_DEFAULT:
		b0 = gen_proto(cstate, v, Q_IP);
		b1 = gen_proto(cstate, v, Q_IPV6);
		gen_or(b0, b1);
		return b1;

	case Q_LINK:
		return gen_linktype(cstate, v);

	case Q_IP:
		assert_maxval(cstate, "protocol number", v, UINT8_MAX);
		/*
		 * For FDDI, RFC 1188 says that SNAP encapsulation is used,
		 * not LLC encapsulation with LLCSAP_IP.
		 *
		 * For IEEE 802 networks - which includes 802.5 token ring
		 * (which is what DLT_IEEE802 means) and 802.11 - RFC 1042
		 * says that SNAP encapsulation is used, not LLC encapsulation
		 * with LLCSAP_IP.
		 *
		 * For LLC-encapsulated ATM/"Classical IP", RFC 1483 and
		 * RFC 2225 say that SNAP encapsulation is used, not LLC
		 * encapsulation with LLCSAP_IP.
		 *
		 * So we always check for ETHERTYPE_IP.
		 */
		b0 = gen_linktype(cstate, ETHERTYPE_IP);
		// 0 <= v <= UINT8_MAX
		b1 = gen_ip_proto(cstate, (uint8_t)v);
		gen_and(b0, b1);
		return b1;

	case Q_IPV6:
		assert_maxval(cstate, "protocol number", v, UINT8_MAX);
		b0 = gen_linktype(cstate, ETHERTYPE_IPV6);
		/*
		 * Also check for a fragment header before the final
		 * header.
		 */
		b2 = gen_ip6_proto(cstate, IPPROTO_FRAGMENT);
		b1 = gen_cmp(cstate, OR_LINKPL, 40, BPF_B, v);
		gen_and(b2, b1);
		// 0 <= v <= UINT8_MAX
		b2 = gen_ip6_proto(cstate, (uint8_t)v);
		gen_or(b2, b1);
		gen_and(b0, b1);
		return b1;

	case Q_ISO:
		assert_maxval(cstate, "ISO protocol", v, UINT8_MAX);
		switch (cstate->linktype) {

		case DLT_FRELAY:
			/*
			 * Frame Relay packets typically have an OSI
			 * NLPID at the beginning; "gen_linktype(cstate, LLCSAP_ISONS)"
			 * generates code to check for all the OSI
			 * NLPIDs, so calling it and then adding a check
			 * for the particular NLPID for which we're
			 * looking is bogus, as we can just check for
			 * the NLPID.
			 *
			 * What we check for is the NLPID and a frame
			 * control field value of UI, i.e. 0x03 followed
			 * by the NLPID.
			 *
			 * XXX - assumes a 2-byte Frame Relay header with
			 * DLCI and flags.  What if the address is longer?
			 *
			 * XXX - what about SNAP-encapsulated frames?
			 */
			return gen_cmp(cstate, OR_LINKHDR, 2, BPF_H, (0x03<<8) | v);
			/*NOTREACHED*/

		case DLT_C_HDLC:
		case DLT_HDLC:
			/*
			 * Cisco uses an Ethertype lookalike - for OSI,
			 * it's 0xfefe.
			 */
			b0 = gen_linktype(cstate, LLCSAP_ISONS<<8 | LLCSAP_ISONS);
			/* OSI in C-HDLC is stuffed with a fudge byte */
			b1 = gen_cmp(cstate, OR_LINKPL_NOSNAP, 1, BPF_B, v);
			gen_and(b0, b1);
			return b1;

		default:
			b0 = gen_linktype(cstate, LLCSAP_ISONS);
			b1 = gen_cmp(cstate, OR_LINKPL_NOSNAP, 0, BPF_B, v);
			gen_and(b0, b1);
			return b1;
		}

	case Q_ISIS:
		assert_maxval(cstate, "IS-IS PDU type", v, ISIS_PDU_TYPE_MAX);
		b0 = gen_proto(cstate, ISO10589_ISIS, Q_ISO);
		/*
		 * 4 is the offset of the PDU type relative to the IS-IS
		 * header.
		 * Except when it is not, see above.
		 */
		unsigned pdu_type_offset;
		switch (cstate->linktype) {
		case DLT_C_HDLC:
		case DLT_HDLC:
			pdu_type_offset = 5;
			break;
		default:
			pdu_type_offset = 4;
		}
		b1 = gen_mcmp(cstate, OR_LINKPL_NOSNAP, pdu_type_offset, BPF_B,
		    v, ISIS_PDU_TYPE_MAX);
		gen_and(b0, b1);
		return b1;
	}
	bpf_error(cstate, ERRSTR_INVALID_QUAL, pqkw(proto), "proto");
	/*NOTREACHED*/
}

/*
 * Convert a non-numeric name to a port number.
 */
static int
nametoport(compiler_state_t *cstate, const char *name, int ipproto)
{
	struct addrinfo hints, *res, *ai;
	int error;
	struct sockaddr_in *in4;
	struct sockaddr_in6 *in6;
	int port = -1;

	/*
	 * We check for both TCP and UDP in case there are
	 * ambiguous entries.
	 */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = (ipproto == IPPROTO_TCP) ? SOCK_STREAM : SOCK_DGRAM;
	hints.ai_protocol = ipproto;
	error = getaddrinfo(NULL, name, &hints, &res);
	if (error != 0) {
		switch (error) {

		case EAI_NONAME:
		case EAI_SERVICE:
			/*
			 * No such port.  Just return -1.
			 */
			break;

#ifdef EAI_SYSTEM
		case EAI_SYSTEM:
			/*
			 * We don't use strerror() because it's not
			 * guaranteed to be thread-safe on all platforms
			 * (probably because it might use a non-thread-local
			 * buffer into which to format an error message
			 * if the error code isn't one for which it has
			 * a canned string; three cheers for C string
			 * handling).
			 */
			bpf_set_error(cstate, "getaddrinfo(\"%s\" fails with system error: %d",
			    name, errno);
			port = -2;	/* a real error */
			break;
#endif

		default:
			/*
			 * This is a real error, not just "there's
			 * no such service name".
			 *
			 * We don't use gai_strerror() because it's not
			 * guaranteed to be thread-safe on all platforms
			 * (probably because it might use a non-thread-local
			 * buffer into which to format an error message
			 * if the error code isn't one for which it has
			 * a canned string; three cheers for C string
			 * handling).
			 */
			bpf_set_error(cstate, "getaddrinfo(\"%s\") fails with error: %d",
			    name, error);
			port = -2;	/* a real error */
			break;
		}
	} else {
		/*
		 * OK, we found it.  Did it find anything?
		 */
		for (ai = res; ai != NULL; ai = ai->ai_next) {
			/*
			 * Does it have an address?
			 */
			if (ai->ai_addr != NULL) {
				/*
				 * Yes.  Get a port number; we're done.
				 */
				if (ai->ai_addr->sa_family == AF_INET) {
					in4 = (struct sockaddr_in *)ai->ai_addr;
					port = ntohs(in4->sin_port);
					break;
				}
				if (ai->ai_addr->sa_family == AF_INET6) {
					in6 = (struct sockaddr_in6 *)ai->ai_addr;
					port = ntohs(in6->sin6_port);
					break;
				}
			}
		}
		freeaddrinfo(res);
	}
	return port;
}

/*
 * Convert a string to a port number.
 */
static bpf_u_int32
stringtoport(compiler_state_t *cstate, const char *string, size_t string_size,
    int *proto)
{
	stoulen_ret ret;
	char *cpy;
	bpf_u_int32 val;
	int tcp_port = -1;
	int udp_port = -1;

	/*
	 * See if it's a number.
	 */
	ret = stoulen(string, string_size, &val, cstate);
	switch (ret) {

	case STOULEN_OK:
		/* Unknown port type - it's just a number. */
		*proto = PROTO_UNDEF;
		break;

	case STOULEN_NOT_OCTAL_NUMBER:
	case STOULEN_NOT_HEX_NUMBER:
	case STOULEN_NOT_DECIMAL_NUMBER:
		/*
		 * Not a valid number; try looking it up as a port.
		 */
		cpy = malloc(string_size + 1);	/* +1 for terminating '\0' */
		memcpy(cpy, string, string_size);
		cpy[string_size] = '\0';
		tcp_port = nametoport(cstate, cpy, IPPROTO_TCP);
		if (tcp_port == -2) {
			/*
			 * We got a hard error; the error string has
			 * already been set.
			 */
			free(cpy);
			longjmp(cstate->top_ctx, 1);
			/*NOTREACHED*/
		}
		udp_port = nametoport(cstate, cpy, IPPROTO_UDP);
		if (udp_port == -2) {
			/*
			 * We got a hard error; the error string has
			 * already been set.
			 */
			free(cpy);
			longjmp(cstate->top_ctx, 1);
			/*NOTREACHED*/
		}

		/*
		 * We need to check /etc/services for ambiguous entries.
		 * If we find an ambiguous entry, and it has the
		 * same port number, change the proto to PROTO_UNDEF
		 * so both TCP and UDP will be checked.
		 */
		if (tcp_port >= 0) {
			val = (bpf_u_int32)tcp_port;
			*proto = IPPROTO_TCP;
			if (udp_port >= 0) {
				if (udp_port == tcp_port)
					*proto = PROTO_UNDEF;
#ifdef notdef
				else
					/* Can't handle ambiguous names that refer
					   to different port numbers. */
					warning("ambiguous port %s in /etc/services",
						cpy);
#endif
			}
			free(cpy);
			break;
		}
		if (udp_port >= 0) {
			val = (bpf_u_int32)udp_port;
			*proto = IPPROTO_UDP;
			free(cpy);
			break;
		}
		bpf_set_error(cstate, "'%s' is not a valid port", cpy);
		free(cpy);
		longjmp(cstate->top_ctx, 1);
		/*NOTREACHED*/
#ifdef _AIX
		PCAP_UNREACHABLE
#endif /* _AIX */

	case STOULEN_ERROR:
		/* Error already set. */
		longjmp(cstate->top_ctx, 1);
		/*NOTREACHED*/
#ifdef _AIX
		PCAP_UNREACHABLE
#endif /* _AIX */

	default:
		/* Should not happen */
		bpf_set_error(cstate, "stoulen returned %d - this should not happen", ret);
		longjmp(cstate->top_ctx, 1);
		/*NOTREACHED*/
	}
	return (val);
}

/*
 * Convert a string in the form PPP-PPP, which correspond to ports, to
 * a starting and ending port in a port range.
 */
static void
stringtoportrange(compiler_state_t *cstate, const char *string,
    bpf_u_int32 *port1, bpf_u_int32 *port2, int *proto)
{
	char *hyphen_off;
	const char *first, *second;
	size_t first_size, second_size;
	int save_proto;

	if ((hyphen_off = strchr(string, '-')) == NULL)
		bpf_error(cstate, "port range '%s' contains no hyphen", string);

	/*
	 * Make sure there are no other hyphens.
	 *
	 * XXX - we support named ports, but there are some port names
	 * in /etc/services that include hyphens, so this would rule
	 * that out.
	 */
	if (strchr(hyphen_off + 1, '-') != NULL)
		bpf_error(cstate, "port range '%s' contains more than one hyphen",
		    string);

	/*
	 * Get the length of the first port.
	 */
	first = string;
	first_size = hyphen_off - string;
	if (first_size == 0) {
		/* Range of "-port", which we don't support. */
		bpf_error(cstate, "port range '%s' has no starting port", string);
	}

	/*
	 * Try to convert it to a port.
	 */
	*port1 = stringtoport(cstate, first, first_size, proto);
	save_proto = *proto;

	/*
	 * Get the length of the second port.
	 */
	second = hyphen_off + 1;
	second_size = strlen(second);
	if (second_size == 0) {
		/* Range of "port-", which we don't support. */
		bpf_error(cstate, "port range '%s' has no ending port", string);
	}

	/*
	 * Try to convert it to a port.
	 */
	*port2 = stringtoport(cstate, second, second_size, proto);
	if (*proto != save_proto)
		*proto = PROTO_UNDEF;
}

struct block *
gen_scode(compiler_state_t *cstate, const char *name, struct qual q)
{
	int proto = q.proto;
	int dir = q.dir;
	bpf_u_int32 mask, addr;
	struct block *b;
	int port, real_proto;
	bpf_u_int32 port1, port2;

	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	if (q.proto == Q_DECNET) {
		/*
		 * A long time ago on Ultrix libpcap supported translation of
		 * DECnet host names into DECnet addresses, but this feature
		 * is history now.  The current implementation does not define
		 * any primitives that have "decnet" as the protocol qualifier
		 * and a name as the ID.
		 */
		bpf_error(cstate, ERRSTR_INVALID_QUAL, "decnet",
		          tqkw(q.addr == Q_DEFAULT ? Q_HOST : q.addr));
	}

	switch (q.addr) {

	case Q_NET:
		addr = pcap_nametonetaddr(name);
		if (addr == 0)
			bpf_error(cstate, "unknown network '%s'", name);
		/* Left justify network addr and calculate its network mask */
		mask = 0xffffffff;
		while (addr && (addr & 0xff000000) == 0) {
			addr <<= 8;
			mask <<= 8;
		}
		return gen_host(cstate, addr, mask, proto, dir, q.addr);

	case Q_DEFAULT:
	case Q_HOST:
		if (proto == Q_LINK) {
			return gen_mac48host_byname(cstate, name, q.dir, "link host NAME");
		} else {
			u_char tproto = q.proto;
			u_char tproto6 = q.proto;
			if (cstate->off_linktype.constant_part == OFFSET_NOT_SET &&
			    tproto == Q_DEFAULT) {
				/*
				 * For certain DLTs have "host NAME" mean
				 * "ip host NAME or ip6 host NAME", but not
				 * "arp host NAME or rarp host NAME" (here may
				 * be not the best place for this though).
				 */
				tproto = Q_IP;
				tproto6 = Q_IPV6;
			}
			return gen_host46_byname(cstate, name, tproto,
			    tproto6, q.dir);
		}

	case Q_PORT:
		(void)port_pq_to_ipproto(cstate, proto, "port"); // validate only
		if (pcap_nametoport(name, &port, &real_proto) == 0)
			bpf_error(cstate, "unknown port '%s'", name);
		if (proto == Q_UDP) {
			if (real_proto == IPPROTO_TCP)
				bpf_error(cstate, "port '%s' is tcp", name);
			else if (real_proto == IPPROTO_SCTP)
				bpf_error(cstate, "port '%s' is sctp", name);
			else
				/* override PROTO_UNDEF */
				real_proto = IPPROTO_UDP;
		}
		if (proto == Q_TCP) {
			if (real_proto == IPPROTO_UDP)
				bpf_error(cstate, "port '%s' is udp", name);

			else if (real_proto == IPPROTO_SCTP)
				bpf_error(cstate, "port '%s' is sctp", name);
			else
				/* override PROTO_UNDEF */
				real_proto = IPPROTO_TCP;
		}
		if (proto == Q_SCTP) {
			if (real_proto == IPPROTO_UDP)
				bpf_error(cstate, "port '%s' is udp", name);

			else if (real_proto == IPPROTO_TCP)
				bpf_error(cstate, "port '%s' is tcp", name);
			else
				/* override PROTO_UNDEF */
				real_proto = IPPROTO_SCTP;
		}

		/*
		 * These two checks are redundant at this point: here name is
		 * a string that the lexer does not recognize as a number
		 * hence did not attempt stoulen(), pcap_nametoport() does not
		 * use stoulen() and has successfully translated the string to
		 * an uint16_t value using getaddrinfo().
		 */
		if (port < 0)
			bpf_error(cstate, "illegal port number %d < 0", port);
		if (port > 65535)
			bpf_error(cstate, "illegal port number %d > 65535", port);

		// real_proto can be PROTO_UNDEF
		b = gen_port(cstate, (uint16_t)port, real_proto, dir);
		gen_or(gen_port6(cstate, (uint16_t)port, real_proto, dir), b);
		return b;

	case Q_PORTRANGE:
		(void)port_pq_to_ipproto(cstate, proto, "portrange"); // validate only
		stringtoportrange(cstate, name, &port1, &port2, &real_proto);
		if (proto == Q_UDP) {
			if (real_proto == IPPROTO_TCP)
				bpf_error(cstate, "port in range '%s' is tcp", name);
			else if (real_proto == IPPROTO_SCTP)
				bpf_error(cstate, "port in range '%s' is sctp", name);
			else
				/* override PROTO_UNDEF */
				real_proto = IPPROTO_UDP;
		}
		if (proto == Q_TCP) {
			if (real_proto == IPPROTO_UDP)
				bpf_error(cstate, "port in range '%s' is udp", name);
			else if (real_proto == IPPROTO_SCTP)
				bpf_error(cstate, "port in range '%s' is sctp", name);
			else
				/* override PROTO_UNDEF */
				real_proto = IPPROTO_TCP;
		}
		if (proto == Q_SCTP) {
			if (real_proto == IPPROTO_UDP)
				bpf_error(cstate, "port in range '%s' is udp", name);
			else if (real_proto == IPPROTO_TCP)
				bpf_error(cstate, "port in range '%s' is tcp", name);
			else
				/* override PROTO_UNDEF */
				real_proto = IPPROTO_SCTP;
		}

		/*
		 * When name is a string of the form "str1-str2", these two
		 * checks are redundant at this point: in both stringtoport()
		 * invocations stoulen() has rejected the argument and
		 * getaddrinfo() has successfully translated it to an uint16_t
		 * value.
		 *
		 * When name is a string of the form "num1-num2", "num-str" or
		 * "str-num", these two checks are necessary: in at least one
		 * stringtoport() invocation stoulen() can return any uint32_t
		 * value if it has accepted the argument.
		 */
		if (port1 > 65535)
			bpf_error(cstate, "illegal port number %d > 65535", port1);
		if (port2 > 65535)
			bpf_error(cstate, "illegal port number %d > 65535", port2);

		// real_proto can be PROTO_UNDEF
		b = gen_portrange(cstate, (uint16_t)port1, (uint16_t)port2,
		    real_proto, dir);
		gen_or(gen_portrange6(cstate, (uint16_t)port1, (uint16_t)port2,
		    real_proto, dir), b);
		return b;

	case Q_GATEWAY:
		return gen_gateway(cstate, name, q.proto);

	case Q_PROTO:
		return gen_proto(cstate, lookup_proto(cstate, name, q), proto);

#if !defined(NO_PROTOCHAIN)
	case Q_PROTOCHAIN:
		return gen_protochain(cstate, lookup_proto(cstate, name, q), proto);
#endif /* !defined(NO_PROTOCHAIN) */

	case Q_UNDEF:
		syntax(cstate);
		/*NOTREACHED*/
	}
	bpf_error(cstate, ERRSTR_FUNC_VAR_INT, __func__, "q.addr", q.addr);
	/*NOTREACHED*/
}

struct block *
gen_mcode(compiler_state_t *cstate, const char *s1, const char *s2,
    bpf_u_int32 masklen, struct qual q)
{
	int nlen, mlen;
	bpf_u_int32 n, m;
	uint64_t m64;

	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	if (q.proto == Q_DECNET) {
		/*
		 * libpcap has never defined any primitives that have "decnet"
		 * as the protocol qualifier and an IPv4 network with a
		 * netmask as the ID.
		 */
		bpf_error(cstate, ERRSTR_INVALID_QUAL, "decnet",
		          tqkw(q.addr == Q_DEFAULT ? Q_HOST : q.addr));
	}

	nlen = pcapint_atoin(s1, &n);
	if (nlen < 0)
		bpf_error(cstate, ERRSTR_INVALID_IPV4_ADDR, s1);
	/* Promote short ipaddr */
	n <<= 32 - nlen;

	if (s2 != NULL) {
		mlen = pcapint_atoin(s2, &m);
		if (mlen < 0)
			bpf_error(cstate, ERRSTR_INVALID_IPV4_ADDR, s2);
		/* Promote short ipaddr */
		m <<= 32 - mlen;
		if ((n & ~m) != 0)
			bpf_error(cstate, "non-network bits set in \"%s mask %s\"",
			    s1, s2);
	} else {
		/* Convert mask len to mask */
		if (masklen > 32)
			bpf_error(cstate, "mask length must be <= 32");
		m64 = UINT64_C(0xffffffff) << (32 - masklen);
		m = (bpf_u_int32)m64;
		if ((n & ~m) != 0)
			bpf_error(cstate, "non-network bits set in \"%s/%d\"",
			    s1, masklen);
	}

	switch (q.addr) {

	case Q_NET:
		return gen_host(cstate, n, m, q.proto, q.dir, q.addr);

	default:
		// Q_HOST and Q_GATEWAY only (see the grammar)
		bpf_error(cstate, "Mask syntax for networks only");
		/*NOTREACHED*/
	}
	/*NOTREACHED*/
}

struct block *
gen_ncode(compiler_state_t *cstate, const char *s, bpf_u_int32 v, struct qual q)
{
	bpf_u_int32 mask;
	int proto;
	int dir;
	int vlen;

	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	if (q.proto == Q_DECNET) {
		/*
		 * libpcap defines exactly one primitive that has "decnet" as
		 * the protocol qualifier: "decnet host AREANUMBER.NODENUMBER".
		 */
		if (q.addr != Q_DEFAULT && q.addr != Q_HOST)
			bpf_error(cstate, ERRSTR_INVALID_QUAL, "decnet",
			          tqkw(q.addr));

		if (s == NULL) {
			/*
			 * v contains a 32-bit unsigned parsed from a string
			 * of the form {N}, which could be decimal, hexadecimal
			 * or octal.  Although it would be possible to use the
			 * value as a raw 16-bit DECnet address when the value
			 * fits into 16 bits, this would be a questionable
			 * feature: DECnet address wire encoding is
			 * little-endian, so this would not work as intuitively
			 * as the same works for [big-endian] IPv4 addresses
			 * (0x01020304 means 1.2.3.4).
			 */
			bpf_error(cstate, "invalid DECnet address '%u'", v);
		}

		/*
		 * s points to a string of the form {N}.{N}, {N}.{N}.{N} or
		 * {N}.{N}.{N}.{N}, of which only the first potentially stands
		 * for a valid DECnet address.
		 */
		vlen = pcapint_atodn(s, &v);
		if (vlen == 0)
			bpf_error(cstate, "invalid DECnet address '%s'", s);

		return gen_host(cstate, v, 0, q.proto, q.dir, q.addr);
	}

	proto = q.proto;
	dir = q.dir;
	if (s == NULL) {
		/*
		 * v contains a 32-bit unsigned parsed from a string of the
		 * form {N}, which could be decimal, hexadecimal or octal.
		 * This is a valid IPv4 address, in the sense of inet_aton(3).
		 */
		vlen = 32;
	} else {
		/*
		 * s points to a string of the form {N}.{N}, {N}.{N}.{N} or
		 * {N}.{N}.{N}.{N}, all of which potentially stand for a valid
		 * IPv4 address, in the sense of inet_aton(3).
		 */
		vlen = pcapint_atoin(s, &v);
		if (vlen < 0)
			bpf_error(cstate, ERRSTR_INVALID_IPV4_ADDR, s);
	}

	struct block *b, *b6;
	switch (q.addr) {

	case Q_DEFAULT:
	case Q_HOST:
	case Q_NET:
		if (proto == Q_LINK) {
			if (s)
				// "link (host|net) IPV4ADDR" and variations thereof
				bpf_error(cstate, "illegal link-layer address '%s'", s);
			else
				// link host NUMBER
				bpf_error(cstate, "illegal link-layer address '%u'", v);
		} else {
			mask = 0xffffffff;
			if (s == NULL && q.addr == Q_NET) {
				/* Promote short net number */
				while (v && (v & 0xff000000) == 0) {
					v <<= 8;
					mask <<= 8;
				}
			} else {
				/* Promote short ipaddr */
				v <<= 32 - vlen;
				mask <<= 32 - vlen ;
			}
			return gen_host(cstate, v, mask, proto, dir, q.addr);
		}

	case Q_PORT:
		proto = port_pq_to_ipproto(cstate, proto, "port");

		// This check is necessary: v can hold any uint32_t value.
		if (v > 65535)
			bpf_error(cstate, "illegal port number %u > 65535", v);

		// proto can be PROTO_UNDEF
		b = gen_port(cstate, (uint16_t)v, proto, dir);
		b6 = gen_port6(cstate, (uint16_t)v, proto, dir);
		gen_or(b6, b);
		return b;

	case Q_PORTRANGE:
		proto = port_pq_to_ipproto(cstate, proto, "portrange");

		// This check is necessary: v can hold any uint32_t value.
		if (v > 65535)
			bpf_error(cstate, "illegal port number %u > 65535", v);

		// proto can be PROTO_UNDEF
		b = gen_portrange(cstate, (uint16_t)v, (uint16_t)v,
		    proto, dir);
		b6 = gen_portrange6(cstate, (uint16_t)v, (uint16_t)v,
		    proto, dir);
		gen_or(b6, b);
		return b;

	case Q_GATEWAY:
		bpf_error(cstate, "'gateway' requires a name");
		/*NOTREACHED*/

	case Q_PROTO:
		return gen_proto(cstate, v, proto);

#if !defined(NO_PROTOCHAIN)
	case Q_PROTOCHAIN:
		return gen_protochain(cstate, v, proto);
#endif

	case Q_UNDEF:
		syntax(cstate);
		/*NOTREACHED*/

	default:
		bpf_error(cstate, ERRSTR_FUNC_VAR_INT, __func__, "q.addr", q.addr);
		/*NOTREACHED*/
	}
	/*NOTREACHED*/
}

struct block *
gen_mcode6(compiler_state_t *cstate, const char *s, bpf_u_int32 masklen,
    struct qual q)
{
	struct in6_addr addr;
	struct in6_addr mask;
	bpf_u_int32 a[4], m[4]; /* Same as in gen_hostop6(). */

	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	/*
	 * If everything works correctly, this call never fails: a string that
	 * is valid for HID6 and the associated validating inet_pton() in the
	 * lexer is valid for inet_pton() here.
	 */
	if (1 != inet_pton(AF_INET6, s, &addr))
		bpf_error(cstate, "'%s' is not a valid IPv6 address", s);

	if (masklen > sizeof(mask.s6_addr) * 8)
		bpf_error(cstate, "mask length must be <= %zu", sizeof(mask.s6_addr) * 8);
	memset(&mask, 0, sizeof(mask));
	memset(&mask.s6_addr, 0xff, masklen / 8);
	if (masklen % 8) {
		mask.s6_addr[masklen / 8] =
			(0xff << (8 - masklen % 8)) & 0xff;
	}

	memcpy(a, &addr, sizeof(a));
	memcpy(m, &mask, sizeof(m));
	if ((a[0] & ~m[0]) || (a[1] & ~m[1])
	 || (a[2] & ~m[2]) || (a[3] & ~m[3])) {
		bpf_error(cstate, "non-network bits set in \"%s/%d\"", s, masklen);
	}

	char buf[INET6_ADDRSTRLEN + sizeof("/128")];
	switch (q.addr) {

	case Q_DEFAULT:
	case Q_HOST:
		if (masklen != 128) {
			snprintf(buf, sizeof(buf), "%s/%u", s, masklen);
			bpf_error(cstate, ERRSTR_INVALID_QUAL, "host", buf);
		}
		/* FALLTHROUGH */

	case Q_NET:
		return gen_host6(cstate, &addr, &mask, q.proto, q.dir, q.addr);

	default:
		// Q_GATEWAY only (see the grammar)
		if (masklen == 128)
			bpf_error(cstate, ERRSTR_INVALID_QUAL, tqkw(q.addr), s);
		else {
			snprintf(buf, sizeof(buf), "%s/%u", s, masklen);
			bpf_error(cstate, ERRSTR_INVALID_QUAL, tqkw(q.addr), buf);
		}
		/*NOTREACHED*/
	}
}

struct block *
gen_ecode(compiler_state_t *cstate, const char *s, struct qual q)
{
	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	const char *context = "link host XX:XX:XX:XX:XX:XX";

	if (! ((q.addr == Q_HOST || q.addr == Q_DEFAULT) && q.proto == Q_LINK))
		bpf_error(cstate, "ethernet address used in non-ether expression");
	if (! is_mac48_linktype(cstate->linktype))
		fail_kw_on_dlt(cstate, context);

	u_char *eaddrp = pcap_ether_aton(s);
	if (eaddrp == NULL)
		bpf_error(cstate, "malloc");
	u_char eaddr[6];
	memcpy(eaddr, eaddrp, sizeof(eaddr));
	free(eaddrp);

	return gen_mac48host(cstate, eaddr, q.dir, context);
}

// Process a regular primitive, the ID is a MAC-8 address string.
struct block *
gen_acode(compiler_state_t *cstate, const char *s, struct qual q)
{
	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	if (q.addr != Q_HOST && q.addr != Q_DEFAULT)
		bpf_error(cstate, ERRSTR_INVALID_QUAL, tqkw(q.addr), "$XX");
	if (q.proto != Q_LINK)
		bpf_error(cstate, "'link' is the only valid proto qualifier for 'host $XX'");

	uint8_t addr;
	/*
	 * The lexer currently defines the address format in a way that makes
	 * this error condition never true.  Let's check it anyway in case this
	 * part of the lexer changes in future.
	 */
	if (! pcapint_atoan(s, &addr))
	    bpf_error(cstate, "invalid MAC-8 address '%s'", s);

	return gen_mac8host(cstate, addr, q.dir, "link host $XX");
}

void
sappend(struct slist *s0, struct slist *s1)
{
	/*
	 * This is definitely not the best way to do this, but the
	 * lists will rarely get long.
	 */
	while (s0->next)
		s0 = s0->next;
	s0->next = s1;
}

static struct slist *
xfer_to_x(compiler_state_t *cstate, struct arth *a)
{
	struct slist *s;

	s = new_stmt(cstate, BPF_LDX|BPF_MEM);
	s->s.k = a->regno;
	return s;
}

static struct slist *
xfer_to_a(compiler_state_t *cstate, struct arth *a)
{
	struct slist *s;

	s = new_stmt(cstate, BPF_LD|BPF_MEM);
	s->s.k = a->regno;
	return s;
}

/*
 * Modify "index" to use the value stored into its register as an
 * offset relative to the beginning of the header for the protocol
 * "proto", and allocate a register and put an item "size" bytes long
 * (1, 2, or 4) at that offset into that register, making it the register
 * for "index".
 */
static struct arth *
gen_load_internal(compiler_state_t *cstate, int proto, struct arth *inst,
    bpf_u_int32 size)
{
	int size_code;
	struct slist *s, *tmp;
	struct block *b;
	int regno = alloc_reg(cstate);

	free_reg(cstate, inst->regno);
	switch (size) {

	default:
		bpf_error(cstate, "data size must be 1, 2, or 4");
		/*NOTREACHED*/

	case 1:
		size_code = BPF_B;
		break;

	case 2:
		size_code = BPF_H;
		break;

	case 4:
		size_code = BPF_W;
		break;
	}
	switch (proto) {
	default:
		bpf_error(cstate, "'%s' does not support the index operation", pqkw(proto));

	case Q_RADIO:
		/*
		 * The offset is relative to the beginning of the packet
		 * data, if we have a radio header.  (If we don't, this
		 * is an error.)
		 */
		if (cstate->linktype != DLT_IEEE802_11_RADIO_AVS &&
		    cstate->linktype != DLT_IEEE802_11_RADIO &&
		    cstate->linktype != DLT_PRISM_HEADER)
			bpf_error(cstate, "radio information not present in capture");

		/*
		 * Load into the X register the offset computed into the
		 * register specified by "index".
		 */
		s = xfer_to_x(cstate, inst);

		/*
		 * Load the item at that offset.
		 */
		tmp = new_stmt(cstate, BPF_LD|BPF_IND|size_code);
		sappend(s, tmp);
		sappend(inst->s, s);
		break;

	case Q_LINK:
		/*
		 * The offset is relative to the beginning of
		 * the link-layer header.
		 *
		 * XXX - what about ATM LANE?  Should the index be
		 * relative to the beginning of the AAL5 frame, so
		 * that 0 refers to the beginning of the LE Control
		 * field, or relative to the beginning of the LAN
		 * frame, so that 0 refers, for Ethernet LANE, to
		 * the beginning of the destination address?
		 */
		s = gen_abs_offset_varpart(cstate, &cstate->off_linkhdr);

		/*
		 * If "s" is non-null, it has code to arrange that the
		 * X register contains the length of the prefix preceding
		 * the link-layer header.  Add to it the offset computed
		 * into the register specified by "index", and move that
		 * into the X register.  Otherwise, just load into the X
		 * register the offset computed into the register specified
		 * by "index".
		 */
		if (s != NULL) {
			sappend(s, xfer_to_a(cstate, inst));
			sappend(s, new_stmt(cstate, BPF_ALU|BPF_ADD|BPF_X));
			sappend(s, new_stmt(cstate, BPF_MISC|BPF_TAX));
		} else
			s = xfer_to_x(cstate, inst);

		/*
		 * Load the item at the sum of the offset we've put in the
		 * X register and the offset of the start of the link
		 * layer header (which is 0 if the radio header is
		 * variable-length; that header length is what we put
		 * into the X register and then added to the index).
		 */
		tmp = new_stmt(cstate, BPF_LD|BPF_IND|size_code);
		tmp->s.k = cstate->off_linkhdr.constant_part;
		sappend(s, tmp);
		sappend(inst->s, s);
		break;

	case Q_IP:
	case Q_ARP:
	case Q_RARP:
	case Q_ATALK:
	case Q_DECNET:
	case Q_SCA:
	case Q_LAT:
	case Q_MOPRC:
	case Q_MOPDL:
	case Q_IPV6:
		/*
		 * The offset is relative to the beginning of
		 * the network-layer header.
		 * XXX - are there any cases where we want
		 * cstate->off_nl_nosnap?
		 */
		s = gen_abs_offset_varpart(cstate, &cstate->off_linkpl);

		/*
		 * If "s" is non-null, it has code to arrange that the
		 * X register contains the variable part of the offset
		 * of the link-layer payload.  Add to it the offset
		 * computed into the register specified by "index",
		 * and move that into the X register.  Otherwise, just
		 * load into the X register the offset computed into
		 * the register specified by "index".
		 */
		if (s != NULL) {
			sappend(s, xfer_to_a(cstate, inst));
			sappend(s, new_stmt(cstate, BPF_ALU|BPF_ADD|BPF_X));
			sappend(s, new_stmt(cstate, BPF_MISC|BPF_TAX));
		} else
			s = xfer_to_x(cstate, inst);

		/*
		 * Load the item at the sum of the offset we've put in the
		 * X register, the offset of the start of the network
		 * layer header from the beginning of the link-layer
		 * payload, and the constant part of the offset of the
		 * start of the link-layer payload.
		 */
		tmp = new_stmt(cstate, BPF_LD|BPF_IND|size_code);
		tmp->s.k = cstate->off_linkpl.constant_part + cstate->off_nl;
		sappend(s, tmp);
		sappend(inst->s, s);

		/*
		 * Do the computation only if the packet contains
		 * the protocol in question.
		 */
		b = gen_proto_abbrev_internal(cstate, proto);
		if (inst->b)
			gen_and(inst->b, b);
		inst->b = b;
		break;

	case Q_SCTP:
	case Q_TCP:
	case Q_UDP:
	case Q_ICMP:
	case Q_IGMP:
	case Q_IGRP:
	case Q_PIM:
	case Q_VRRP:
	case Q_CARP:
		/*
		 * The offset is relative to the beginning of
		 * the transport-layer header.
		 *
		 * Load the X register with the length of the IPv4 header
		 * (plus the offset of the link-layer header, if it's
		 * a variable-length header), in bytes.
		 *
		 * XXX - are there any cases where we want
		 * cstate->off_nl_nosnap?
		 * XXX - we should, if we're built with
		 * IPv6 support, generate code to load either
		 * IPv4, IPv6, or both, as appropriate.
		 */
		s = gen_loadx_iphdrlen(cstate);

		/*
		 * The X register now contains the sum of the variable
		 * part of the offset of the link-layer payload and the
		 * length of the network-layer header.
		 *
		 * Load into the A register the offset relative to
		 * the beginning of the transport layer header,
		 * add the X register to that, move that to the
		 * X register, and load with an offset from the
		 * X register equal to the sum of the constant part of
		 * the offset of the link-layer payload and the offset,
		 * relative to the beginning of the link-layer payload,
		 * of the network-layer header.
		 */
		sappend(s, xfer_to_a(cstate, inst));
		sappend(s, new_stmt(cstate, BPF_ALU|BPF_ADD|BPF_X));
		sappend(s, new_stmt(cstate, BPF_MISC|BPF_TAX));
		sappend(s, tmp = new_stmt(cstate, BPF_LD|BPF_IND|size_code));
		tmp->s.k = cstate->off_linkpl.constant_part + cstate->off_nl;
		sappend(inst->s, s);

		/*
		 * Do the computation only if the packet contains
		 * the protocol in question - which is true only
		 * if this is an IP datagram and is the first or
		 * only fragment of that datagram.
		 */
		gen_and(gen_proto_abbrev_internal(cstate, proto), b = gen_ipfrag(cstate));
		if (inst->b)
			gen_and(inst->b, b);
		gen_and(gen_proto_abbrev_internal(cstate, Q_IP), b);
		inst->b = b;
		break;
	case Q_ICMPV6:
		/*
		 * Do the computation only if the packet contains
		 * the protocol in question.
		 */
		b = gen_proto_abbrev_internal(cstate, Q_IPV6);
		if (inst->b)
			gen_and(inst->b, b);
		inst->b = b;

		/*
		 * Check if we have an icmp6 next header
		 */
		b = gen_ip6_proto(cstate, 58);
		if (inst->b)
			gen_and(inst->b, b);
		inst->b = b;

		s = gen_abs_offset_varpart(cstate, &cstate->off_linkpl);
		/*
		 * If "s" is non-null, it has code to arrange that the
		 * X register contains the variable part of the offset
		 * of the link-layer payload.  Add to it the offset
		 * computed into the register specified by "index",
		 * and move that into the X register.  Otherwise, just
		 * load into the X register the offset computed into
		 * the register specified by "index".
		 */
		if (s != NULL) {
			sappend(s, xfer_to_a(cstate, inst));
			sappend(s, new_stmt(cstate, BPF_ALU|BPF_ADD|BPF_X));
			sappend(s, new_stmt(cstate, BPF_MISC|BPF_TAX));
		} else
			s = xfer_to_x(cstate, inst);

		/*
		 * Load the item at the sum of the offset we've put in the
		 * X register, the offset of the start of the network
		 * layer header from the beginning of the link-layer
		 * payload, and the constant part of the offset of the
		 * start of the link-layer payload.
		 */
		tmp = new_stmt(cstate, BPF_LD|BPF_IND|size_code);
		tmp->s.k = cstate->off_linkpl.constant_part + cstate->off_nl + 40;

		sappend(s, tmp);
		sappend(inst->s, s);

		break;
	}
	inst->regno = regno;
	s = new_stmt(cstate, BPF_ST);
	s->s.k = regno;
	sappend(inst->s, s);

	return inst;
}

struct arth *
gen_load(compiler_state_t *cstate, int proto, struct arth *inst,
    bpf_u_int32 size)
{
	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	return gen_load_internal(cstate, proto, inst, size);
}

static struct block *
gen_relation_internal(compiler_state_t *cstate, int code, struct arth *a0,
    struct arth *a1, int reversed)
{
	struct slist *s0, *s1;
	struct block *b, *tmp;

	s0 = xfer_to_x(cstate, a1);
	s1 = xfer_to_a(cstate, a0);
	sappend(s0, s1);
	sappend(a1->s, s0);
	sappend(a0->s, a1->s);

	b = gen_jmp_x(cstate, code, a0->s);
	if (reversed)
		gen_not(b);

	free_reg(cstate, a0->regno);
	free_reg(cstate, a1->regno);

	/* 'and' together protocol checks */
	if (a0->b) {
		if (a1->b) {
			gen_and(a0->b, tmp = a1->b);
		}
		else
			tmp = a0->b;
	} else
		tmp = a1->b;

	if (tmp)
		gen_and(tmp, b);

	return b;
}

struct block *
gen_relation(compiler_state_t *cstate, int code, struct arth *a0,
    struct arth *a1, int reversed)
{
	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	return gen_relation_internal(cstate, code, a0, a1, reversed);
}

struct arth *
gen_loadlen(compiler_state_t *cstate)
{
	int regno;
	struct arth *a;
	struct slist *s;

	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	regno = alloc_reg(cstate);
	a = (struct arth *)newchunk(cstate, sizeof(*a));
	s = new_stmt(cstate, BPF_LD|BPF_LEN);
	s->next = new_stmt(cstate, BPF_ST);
	s->next->s.k = regno;
	a->s = s;
	a->regno = regno;

	return a;
}

static struct arth *
gen_loadi_internal(compiler_state_t *cstate, bpf_u_int32 val)
{
	struct arth *a;
	struct slist *s;
	int reg;

	a = (struct arth *)newchunk(cstate, sizeof(*a));

	reg = alloc_reg(cstate);

	s = new_stmt(cstate, BPF_LD|BPF_IMM);
	s->s.k = val;
	s->next = new_stmt(cstate, BPF_ST);
	s->next->s.k = reg;
	a->s = s;
	a->regno = reg;

	return a;
}

struct arth *
gen_loadi(compiler_state_t *cstate, bpf_u_int32 val)
{
	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	return gen_loadi_internal(cstate, val);
}

/*
 * The a_arg dance is to avoid annoying whining by compilers that
 * a might be clobbered by longjmp - yeah, it might, but *WHO CARES*?
 * It's not *used* after setjmp returns.
 */
struct arth *
gen_neg(compiler_state_t *cstate, struct arth *a_arg)
{
	struct arth *a = a_arg;
	struct slist *s;

	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	s = xfer_to_a(cstate, a);
	sappend(a->s, s);
	s = new_stmt(cstate, BPF_ALU|BPF_NEG);
	s->s.k = 0;
	sappend(a->s, s);
	s = new_stmt(cstate, BPF_ST);
	s->s.k = a->regno;
	sappend(a->s, s);

	return a;
}

/*
 * The a0_arg dance is to avoid annoying whining by compilers that
 * a0 might be clobbered by longjmp - yeah, it might, but *WHO CARES*?
 * It's not *used* after setjmp returns.
 */
struct arth *
gen_arth(compiler_state_t *cstate, int code, struct arth *a0_arg,
    struct arth *a1)
{
	struct arth *a0 = a0_arg;
	struct slist *s0, *s1, *s2;

	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	/*
	 * Disallow division by, or modulus by, zero; we do this here
	 * so that it gets done even if the optimizer is disabled.
	 *
	 * Also disallow shifts by a value greater than 31; we do this
	 * here, for the same reason.
	 */
	if (code == BPF_DIV) {
		if (a1->s->s.code == (BPF_LD|BPF_IMM) && a1->s->s.k == 0)
			bpf_error(cstate, "division by zero");
	} else if (code == BPF_MOD) {
		if (a1->s->s.code == (BPF_LD|BPF_IMM) && a1->s->s.k == 0)
			bpf_error(cstate, "modulus by zero");
	} else if (code == BPF_LSH || code == BPF_RSH) {
		if (a1->s->s.code == (BPF_LD|BPF_IMM) && a1->s->s.k > 31)
			bpf_error(cstate, "shift by more than 31 bits");
	}
	s0 = xfer_to_x(cstate, a1);
	s1 = xfer_to_a(cstate, a0);
	s2 = new_stmt(cstate, BPF_ALU|BPF_X|code);

	sappend(s1, s2);
	sappend(s0, s1);
	sappend(a1->s, s0);
	sappend(a0->s, a1->s);

	free_reg(cstate, a0->regno);
	free_reg(cstate, a1->regno);

	s0 = new_stmt(cstate, BPF_ST);
	a0->regno = s0->s.k = alloc_reg(cstate);
	sappend(a0->s, s0);

	return a0;
}

/*
 * Initialize the table of used registers and the current register.
 */
static void
init_regs(compiler_state_t *cstate)
{
	cstate->curreg = 0;
	memset(cstate->regused, 0, sizeof cstate->regused);
}

/*
 * Return the next free register.
 */
static int
alloc_reg(compiler_state_t *cstate)
{
	int n = BPF_MEMWORDS;

	while (--n >= 0) {
		if (cstate->regused[cstate->curreg])
			cstate->curreg = (cstate->curreg + 1) % BPF_MEMWORDS;
		else {
			cstate->regused[cstate->curreg] = 1;
			return cstate->curreg;
		}
	}
	bpf_error(cstate, "too many registers needed to evaluate expression");
	/*NOTREACHED*/
}

/*
 * Return a register to the table so it can
 * be used later.
 */
static void
free_reg(compiler_state_t *cstate, int n)
{
	cstate->regused[n] = 0;
}

static struct block *
gen_len(compiler_state_t *cstate, int jmp, int n)
{
	struct slist *s;

	s = new_stmt(cstate, BPF_LD|BPF_LEN);
	return gen_jmp_k(cstate, jmp, n, s);
}

struct block *
gen_greater(compiler_state_t *cstate, int n)
{
	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	return gen_len(cstate, BPF_JGE, n);
}

/*
 * Actually, this is less than or equal.
 */
struct block *
gen_less(compiler_state_t *cstate, int n)
{
	struct block *b;

	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	b = gen_len(cstate, BPF_JGT, n);
	gen_not(b);

	return b;
}

/*
 * This is for "byte {idx} {op} {val}"; "idx" is treated as relative to
 * the beginning of the link-layer header.
 * XXX - that means you can't test values in the radiotap header, but
 * as that header is difficult if not impossible to parse generally
 * without a loop, that might not be a severe problem.  A new keyword
 * "radio" could be added for that, although what you'd really want
 * would be a way of testing particular radio header values, which
 * would generate code appropriate to the radio header in question.
 */
struct block *
gen_byteop(compiler_state_t *cstate, int op, int idx, bpf_u_int32 val)
{
	struct block *b;
	struct slist *s;

	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	assert_maxval(cstate, "byte argument", val, UINT8_MAX);

	switch (op) {
	default:
		bpf_error(cstate, ERRSTR_FUNC_VAR_INT, __func__, "op", op);

	case '=':
		return gen_cmp(cstate, OR_LINKHDR, (u_int)idx, BPF_B, val);

	case '<':
		return gen_cmp_lt(cstate, OR_LINKHDR, (u_int)idx, BPF_B, val);

	case '>':
		return gen_cmp_gt(cstate, OR_LINKHDR, (u_int)idx, BPF_B, val);

	case '|':
		s = new_stmt(cstate, BPF_ALU|BPF_OR|BPF_K);
		break;

	case '&':
		s = new_stmt(cstate, BPF_ALU|BPF_AND|BPF_K);
		break;
	}
	s->s.k = val;
	// Load the required byte first.
	struct slist *s0 = gen_load_a(cstate, OR_LINKHDR, idx, BPF_B);
	sappend(s0, s);
	b = gen_jmp_k(cstate, BPF_JEQ, 0, s0);
	gen_not(b);

	return b;
}

struct block *
gen_broadcast(compiler_state_t *cstate, int proto)
{
	bpf_u_int32 hostmask;
	struct block *b0, *b1, *b2;
	static const u_char ebroadcast[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	switch (proto) {

	case Q_DEFAULT:
	case Q_LINK:
		switch (cstate->linktype) {
		case DLT_ARCNET:
		case DLT_ARCNET_LINUX:
			// ARCnet broadcast is [8-bit] destination address 0.
			return gen_mac8host(cstate, 0, Q_DST, "broadcast");
		case DLT_BACNET_MS_TP:
			// MS/TP broadcast is [8-bit] destination address 0xFF.
			return gen_mac8host(cstate, 0xFF, Q_DST, "broadcast");
		}
		return gen_mac48host(cstate, ebroadcast, Q_DST, "broadcast");
		/*NOTREACHED*/

	case Q_IP:
		/*
		 * We treat a netmask of PCAP_NETMASK_UNKNOWN (0xffffffff)
		 * as an indication that we don't know the netmask, and fail
		 * in that case.
		 */
		if (cstate->netmask == PCAP_NETMASK_UNKNOWN)
			bpf_error(cstate, "netmask not known, so 'ip broadcast' not supported");
		b0 = gen_linktype(cstate, ETHERTYPE_IP);
		hostmask = ~cstate->netmask;
		b1 = gen_mcmp(cstate, OR_LINKPL, 16, BPF_W, 0, hostmask);
		b2 = gen_mcmp(cstate, OR_LINKPL, 16, BPF_W, hostmask, hostmask);
		gen_or(b1, b2);
		gen_and(b0, b2);
		return b2;
	}
	bpf_error(cstate, ERRSTR_INVALID_QUAL, pqkw(proto), "broadcast");
	/*NOTREACHED*/
}

/*
 * Generate code to test the low-order bit of a MAC address (that's
 * the bottom bit of the *first* byte).
 */
static struct block *
gen_mac_multicast(compiler_state_t *cstate, int offset)
{
	struct slist *s;

	/* link[offset] & 1 != 0 */
	s = gen_load_a(cstate, OR_LINKHDR, offset, BPF_B);
	return gen_set(cstate, 1, s);
}

struct block *
gen_multicast(compiler_state_t *cstate, int proto)
{
	struct block *b0, *b1, *b2;
	struct slist *s;

	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	switch (proto) {

	case Q_DEFAULT:
	case Q_LINK:
		switch (cstate->linktype) {
		case DLT_ARCNET:
		case DLT_ARCNET_LINUX:
			// ARCnet multicast is the same as broadcast.
			return gen_mac8host(cstate, 0, Q_DST, "multicast");
		case DLT_EN10MB:
		case DLT_NETANALYZER:
		case DLT_NETANALYZER_TRANSPARENT:
			b1 = gen_prevlinkhdr_check(cstate);
			/* ether[0] & 1 != 0 */
			b0 = gen_mac_multicast(cstate, 0);
			if (b1 != NULL)
				gen_and(b1, b0);
			return b0;
		case DLT_FDDI:
			/*
			 * XXX TEST THIS: MIGHT NOT PORT PROPERLY XXX
			 *
			 * XXX - was that referring to bit-order issues?
			 */
			/* fddi[1] & 1 != 0 */
			return gen_mac_multicast(cstate, 1);
		case DLT_IEEE802:
			/* tr[2] & 1 != 0 */
			return gen_mac_multicast(cstate, 2);
		case DLT_IEEE802_11:
		case DLT_PRISM_HEADER:
		case DLT_IEEE802_11_RADIO_AVS:
		case DLT_IEEE802_11_RADIO:
		case DLT_PPI:
			/*
			 * Oh, yuk.
			 *
			 *	For control frames, there is no DA.
			 *
			 *	For management frames, DA is at an
			 *	offset of 4 from the beginning of
			 *	the packet.
			 *
			 *	For data frames, DA is at an offset
			 *	of 4 from the beginning of the packet
			 *	if To DS is clear and at an offset of
			 *	16 from the beginning of the packet
			 *	if To DS is set.
			 */

			/*
			 * Generate the tests to be done for data frames.
			 *
			 * First, check for To DS set, i.e. "link[1] & 0x01".
			 */
			s = gen_load_a(cstate, OR_LINKHDR, 1, BPF_B);
			b1 = gen_set(cstate, IEEE80211_FC1_DIR_TODS, s);

			/*
			 * If To DS is set, the DA is at 16.
			 */
			b0 = gen_mac_multicast(cstate, 16);
			gen_and(b1, b0);

			/*
			 * Now, check for To DS not set, i.e. check
			 * "!(link[1] & 0x01)".
			 */
			s = gen_load_a(cstate, OR_LINKHDR, 1, BPF_B);
			b2 = gen_unset(cstate, IEEE80211_FC1_DIR_TODS, s);

			/*
			 * If To DS is not set, the DA is at 4.
			 */
			b1 = gen_mac_multicast(cstate, 4);
			gen_and(b2, b1);

			/*
			 * Now OR together the last two checks.  That gives
			 * the complete set of checks for data frames.
			 */
			gen_or(b1, b0);

			/*
			 * Now check for a data frame.
			 * I.e, check "link[0] & 0x08".
			 */
			s = gen_load_a(cstate, OR_LINKHDR, 0, BPF_B);
			b1 = gen_set(cstate, IEEE80211_FC0_TYPE_DATA, s);

			/*
			 * AND that with the checks done for data frames.
			 */
			gen_and(b1, b0);

			/*
			 * If the high-order bit of the type value is 0, this
			 * is a management frame.
			 * I.e, check "!(link[0] & 0x08)".
			 */
			s = gen_load_a(cstate, OR_LINKHDR, 0, BPF_B);
			b2 = gen_unset(cstate, IEEE80211_FC0_TYPE_DATA, s);

			/*
			 * For management frames, the DA is at 4.
			 */
			b1 = gen_mac_multicast(cstate, 4);
			gen_and(b2, b1);

			/*
			 * OR that with the checks done for data frames.
			 * That gives the checks done for management and
			 * data frames.
			 */
			gen_or(b1, b0);

			/*
			 * If the low-order bit of the type value is 1,
			 * this is either a control frame or a frame
			 * with a reserved type, and thus not a
			 * frame with an SA.
			 *
			 * I.e., check "!(link[0] & 0x04)".
			 */
			s = gen_load_a(cstate, OR_LINKHDR, 0, BPF_B);
			b1 = gen_unset(cstate, IEEE80211_FC0_TYPE_CTL, s);

			/*
			 * AND that with the checks for data and management
			 * frames.
			 */
			gen_and(b1, b0);
			return b0;
		case DLT_IP_OVER_FC:
			return gen_mac_multicast(cstate, 2);
		default:
			break;
		}
		fail_kw_on_dlt(cstate, "multicast");
		/*NOTREACHED*/

	case Q_IP:
		b0 = gen_linktype(cstate, ETHERTYPE_IP);

		/*
		 * Compare address with 224.0.0.0/4
		 */
		b1 = gen_mcmp(cstate, OR_LINKPL, 16, BPF_B, 0xe0, 0xf0);

		gen_and(b0, b1);
		return b1;

	case Q_IPV6:
		b0 = gen_linktype(cstate, ETHERTYPE_IPV6);
		b1 = gen_cmp(cstate, OR_LINKPL, 24, BPF_B, 255);
		gen_and(b0, b1);
		return b1;
	}
	bpf_error(cstate, ERRSTR_INVALID_QUAL, pqkw(proto), "multicast");
	/*NOTREACHED*/
}

#ifdef __linux__
/*
 * This is Linux; we require PF_PACKET support.  If this is a *live* capture,
 * we can look at special meta-data in the filter expression; otherwise we
 * can't because it is either a savefile (rfile != NULL) or a pcap_t created
 * using pcap_open_dead() (rfile == NULL).  Thus check for a flag that
 * pcap_activate() conditionally sets.
 */
static void
require_basic_bpf_extensions(compiler_state_t *cstate, const char *keyword)
{
	if (cstate->bpf_pcap->bpf_codegen_flags & BPF_SPECIAL_BASIC_HANDLING)
		return;
	bpf_error(cstate, "not a live capture, '%s' not supported on %s",
	    keyword,
	    pcapint_datalink_val_to_string(cstate->linktype));
}
#endif // __linux__

struct block *
gen_ifindex(compiler_state_t *cstate, int ifindex)
{
	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	/*
	 * Only some data link types support ifindex qualifiers.
	 */
	switch (cstate->linktype) {
	case DLT_LINUX_SLL2:
		/* match packets on this interface */
		return gen_cmp(cstate, OR_LINKHDR, 4, BPF_W, ifindex);
	default:
#if defined(__linux__)
		require_basic_bpf_extensions(cstate, "ifindex");
		/* match ifindex */
		return gen_cmp(cstate, OR_LINKHDR, SKF_AD_OFF + SKF_AD_IFINDEX, BPF_W,
		             ifindex);
#else /* defined(__linux__) */
		fail_kw_on_dlt(cstate, "ifindex");
		/*NOTREACHED*/
#endif /* defined(__linux__) */
	}
}

/*
 * Filter on inbound (outbound == 0) or outbound (outbound == 1) traffic.
 * Outbound traffic is sent by this machine, while inbound traffic is
 * sent by a remote machine (and may include packets destined for a
 * unicast or multicast link-layer address we are not subscribing to).
 * These are the same definitions implemented by pcap_setdirection().
 * Capturing only unicast traffic destined for this host is probably
 * better accomplished using a higher-layer filter.
 */
struct block *
gen_inbound_outbound(compiler_state_t *cstate, const int outbound)
{
	struct block *b0;

	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	/*
	 * Only some data link types support inbound/outbound qualifiers.
	 */
	switch (cstate->linktype) {
	case DLT_SLIP:
		return gen_cmp(cstate, OR_LINKHDR, 0, BPF_B,
			  outbound ? SLIPDIR_OUT : SLIPDIR_IN);

	case DLT_IPNET:
		return gen_cmp(cstate, OR_LINKHDR, 2, BPF_H,
		    outbound ? IPNET_OUTBOUND : IPNET_INBOUND);

	case DLT_LINUX_SLL:
		/* match outgoing packets */
		b0 = gen_cmp(cstate, OR_LINKHDR, 0, BPF_H, LINUX_SLL_OUTGOING);
		if (! outbound) {
			/* to filter on inbound traffic, invert the match */
			gen_not(b0);
		}
		return b0;

	case DLT_LINUX_SLL2:
		/* match outgoing packets */
		b0 = gen_cmp(cstate, OR_LINKHDR, 10, BPF_B, LINUX_SLL_OUTGOING);
		if (! outbound) {
			/* to filter on inbound traffic, invert the match */
			gen_not(b0);
		}
		return b0;

	case DLT_PFLOG:
		return gen_cmp(cstate, OR_LINKHDR, offsetof(struct pfloghdr, dir), BPF_B,
		    outbound ? PF_OUT : PF_IN);

	case DLT_PPP_PPPD:
		return gen_cmp(cstate, OR_LINKHDR, 0, BPF_B, outbound ? PPP_PPPD_OUT : PPP_PPPD_IN);

	case DLT_JUNIPER_MFR:
	case DLT_JUNIPER_MLFR:
	case DLT_JUNIPER_MLPPP:
	case DLT_JUNIPER_ATM1:
	case DLT_JUNIPER_ATM2:
	case DLT_JUNIPER_PPPOE:
	case DLT_JUNIPER_PPPOE_ATM:
	case DLT_JUNIPER_GGSN:
	case DLT_JUNIPER_ES:
	case DLT_JUNIPER_MONITOR:
	case DLT_JUNIPER_SERVICES:
	case DLT_JUNIPER_ETHER:
	case DLT_JUNIPER_PPP:
	case DLT_JUNIPER_FRELAY:
	case DLT_JUNIPER_CHDLC:
	case DLT_JUNIPER_VP:
	case DLT_JUNIPER_ST:
	case DLT_JUNIPER_ISM:
	case DLT_JUNIPER_VS:
	case DLT_JUNIPER_SRX_E2E:
	case DLT_JUNIPER_FIBRECHANNEL:
	case DLT_JUNIPER_ATM_CEMIC:
		/* juniper flags (including direction) are stored
		 * the byte after the 3-byte magic number */
		return gen_mcmp(cstate, OR_LINKHDR, 3, BPF_B, outbound ? 0 : 1, 0x01);

	default:
		/*
		 * If we have packet meta-data indicating a direction,
		 * and that metadata can be checked by BPF code, check
		 * it.  Otherwise, give up, as this link-layer type has
		 * nothing in the packet data.
		 *
		 * Currently, the only platform where a BPF filter can
		 * check that metadata is Linux with the in-kernel
		 * BPF interpreter.  If other packet capture mechanisms
		 * and BPF filters also supported this, it would be
		 * nice.  It would be even better if they made that
		 * metadata available so that we could provide it
		 * with newer capture APIs, allowing it to be saved
		 * in pcapng files.
		 */
#if defined(__linux__)
		require_basic_bpf_extensions(cstate, outbound ? "outbound" : "inbound");
		/* match outgoing packets */
		b0 = gen_cmp(cstate, OR_LINKHDR, SKF_AD_OFF + SKF_AD_PKTTYPE, BPF_H,
		             PACKET_OUTGOING);
		if (! outbound) {
			/* to filter on inbound traffic, invert the match */
			gen_not(b0);
		}
		return b0;
#else /* defined(__linux__) */
		fail_kw_on_dlt(cstate, outbound ? "outbound" : "inbound");
		/*NOTREACHED*/
#endif /* defined(__linux__) */
	}
}

/* PF firewall log matched interface */
struct block *
gen_pf_ifname(compiler_state_t *cstate, const char *ifname)
{
	u_int len, off;

	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	assert_pflog(cstate, "ifname");

	len = sizeof(((struct pfloghdr *)0)->ifname);
	off = offsetof(struct pfloghdr, ifname);
	if (strlen(ifname) >= len) {
		bpf_error(cstate, "ifname interface names can only be %d characters",
		    len-1);
		/*NOTREACHED*/
	}
	return gen_bcmp(cstate, OR_LINKHDR, off, (u_int)strlen(ifname),
	    (const u_char *)ifname);
}

/* PF firewall log ruleset name */
struct block *
gen_pf_ruleset(compiler_state_t *cstate, char *ruleset)
{
	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	assert_pflog(cstate, "ruleset");

	if (strlen(ruleset) >= sizeof(((struct pfloghdr *)0)->ruleset)) {
		bpf_error(cstate, "ruleset names can only be %ld characters",
		    (long)(sizeof(((struct pfloghdr *)0)->ruleset) - 1));
		/*NOTREACHED*/
	}

	return gen_bcmp(cstate, OR_LINKHDR, offsetof(struct pfloghdr, ruleset),
	    (u_int)strlen(ruleset), (const u_char *)ruleset);
}

/* PF firewall log rule number */
struct block *
gen_pf_rnr(compiler_state_t *cstate, int rnr)
{
	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	assert_pflog(cstate, "rnr");

	return gen_cmp(cstate, OR_LINKHDR, offsetof(struct pfloghdr, rulenr), BPF_W,
		 (bpf_u_int32)rnr);
}

/* PF firewall log sub-rule number */
struct block *
gen_pf_srnr(compiler_state_t *cstate, int srnr)
{
	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	assert_pflog(cstate, "srnr");

	return gen_cmp(cstate, OR_LINKHDR, offsetof(struct pfloghdr, subrulenr), BPF_W,
	    (bpf_u_int32)srnr);
}

/* PF firewall log reason code */
struct block *
gen_pf_reason(compiler_state_t *cstate, int reason)
{
	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	assert_pflog(cstate, "reason");

	return gen_cmp(cstate, OR_LINKHDR, offsetof(struct pfloghdr, reason), BPF_B,
	    (bpf_u_int32)reason);
}

/* PF firewall log action */
struct block *
gen_pf_action(compiler_state_t *cstate, int action)
{
	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	assert_pflog(cstate, "action");

	return gen_cmp(cstate, OR_LINKHDR, offsetof(struct pfloghdr, action), BPF_B,
	    (bpf_u_int32)action);
}

/* IEEE 802.11 wireless header */
struct block *
gen_p80211_type(compiler_state_t *cstate, bpf_u_int32 type, bpf_u_int32 mask)
{
	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	switch (cstate->linktype) {

	case DLT_IEEE802_11:
	case DLT_PRISM_HEADER:
	case DLT_IEEE802_11_RADIO_AVS:
	case DLT_IEEE802_11_RADIO:
	case DLT_PPI:
		return gen_mcmp(cstate, OR_LINKHDR, 0, BPF_B, type, mask);

	default:
		fail_kw_on_dlt(cstate, "type/subtype");
		/*NOTREACHED*/
	}
}

struct block *
gen_p80211_fcdir(compiler_state_t *cstate, bpf_u_int32 fcdir)
{
	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	switch (cstate->linktype) {

	case DLT_IEEE802_11:
	case DLT_PRISM_HEADER:
	case DLT_IEEE802_11_RADIO_AVS:
	case DLT_IEEE802_11_RADIO:
	case DLT_PPI:
		return gen_mcmp(cstate, OR_LINKHDR, 1, BPF_B, fcdir,
		    IEEE80211_FC1_DIR_MASK);

	default:
		fail_kw_on_dlt(cstate, "dir");
		/*NOTREACHED*/
	}
}

static struct block *
gen_vlan_tpid_test(compiler_state_t *cstate)
{
	struct block *b0, *b1;

	/* check for VLAN, including 802.1ad and QinQ */
	b0 = gen_linktype(cstate, ETHERTYPE_8021Q);
	b1 = gen_linktype(cstate, ETHERTYPE_8021AD);
	gen_or(b0,b1);
	b0 = b1;
	b1 = gen_linktype(cstate, ETHERTYPE_8021QINQ);
	gen_or(b0,b1);

	return b1;
}

static struct block *
gen_vlan_vid_test(compiler_state_t *cstate, bpf_u_int32 vlan_num)
{
	assert_maxval(cstate, "VLAN tag", vlan_num, 0x0fff);
	return gen_mcmp(cstate, OR_LINKPL, 0, BPF_H, vlan_num, 0x0fff);
}

static struct block *
gen_vlan_no_bpf_extensions(compiler_state_t *cstate, bpf_u_int32 vlan_num,
    int has_vlan_tag)
{
	struct block *b0, *b1;

	b0 = gen_vlan_tpid_test(cstate);

	if (has_vlan_tag) {
		b1 = gen_vlan_vid_test(cstate, vlan_num);
		gen_and(b0, b1);
		b0 = b1;
	}

	/*
	 * Both payload and link header type follow the VLAN tags so that
	 * both need to be updated.
	 */
	cstate->off_linkpl.constant_part += 4;
	cstate->off_linktype.constant_part += 4;

	return b0;
}

#if defined(SKF_AD_VLAN_TAG_PRESENT)
/* add v to variable part of off */
static void
gen_vlan_vloffset_add(compiler_state_t *cstate, bpf_abs_offset *off,
    bpf_u_int32 v, struct slist *s)
{
	struct slist *s2;

	if (!off->is_variable)
		off->is_variable = 1;
	if (off->reg == -1)
		off->reg = alloc_reg(cstate);

	s2 = new_stmt(cstate, BPF_LD|BPF_MEM);
	s2->s.k = off->reg;
	sappend(s, s2);
	s2 = new_stmt(cstate, BPF_ALU|BPF_ADD|BPF_IMM);
	s2->s.k = v;
	sappend(s, s2);
	s2 = new_stmt(cstate, BPF_ST);
	s2->s.k = off->reg;
	sappend(s, s2);
}

/*
 * patch block b_tpid (VLAN TPID test) to update variable parts of link payload
 * and link type offsets first
 */
static void
gen_vlan_patch_tpid_test(compiler_state_t *cstate, struct block *b_tpid)
{
	struct slist s;

	/* offset determined at run time, shift variable part */
	s.next = NULL;
	cstate->is_vlan_vloffset = 1;
	gen_vlan_vloffset_add(cstate, &cstate->off_linkpl, 4, &s);
	gen_vlan_vloffset_add(cstate, &cstate->off_linktype, 4, &s);

	/* we get a pointer to a chain of or-ed blocks, patch first of them */
	sappend(s.next, b_tpid->head->stmts);
	b_tpid->head->stmts = s.next;
}

/*
 * patch block b_vid (VLAN id test) to load VID value either from packet
 * metadata (using BPF extensions) if SKF_AD_VLAN_TAG_PRESENT is true
 */
static void
gen_vlan_patch_vid_test(compiler_state_t *cstate, struct block *b_vid)
{
	struct slist *s, *s2, *sjeq;
	unsigned cnt;

	s = new_stmt(cstate, BPF_LD|BPF_B|BPF_ABS);
	s->s.k = (bpf_u_int32)(SKF_AD_OFF + SKF_AD_VLAN_TAG_PRESENT);

	/* true -> next instructions, false -> beginning of b_vid */
	sjeq = new_stmt(cstate, JMP(BPF_JEQ, BPF_K));
	sjeq->s.k = 1;
	sjeq->s.jf = b_vid->stmts;
	sappend(s, sjeq);

	s2 = new_stmt(cstate, BPF_LD|BPF_H|BPF_ABS);
	s2->s.k = (bpf_u_int32)(SKF_AD_OFF + SKF_AD_VLAN_TAG);
	sappend(s, s2);
	sjeq->s.jt = s2;

	/* Jump to the test in b_vid. We need to jump one instruction before
	 * the end of the b_vid block so that we only skip loading the TCI
	 * from packet data and not the 'and' instruction extracting VID.
	 */
	cnt = 0;
	for (s2 = b_vid->stmts; s2; s2 = s2->next)
		cnt++;
	s2 = new_stmt(cstate, JMP(BPF_JA, BPF_K));
	s2->s.k = cnt - 1;
	sappend(s, s2);

	/* insert our statements at the beginning of b_vid */
	sappend(s, b_vid->stmts);
	b_vid->stmts = s;
}

/*
 * Generate check for "vlan" or "vlan <id>" on systems with support for BPF
 * extensions.  Even if kernel supports VLAN BPF extensions, (outermost) VLAN
 * tag can be either in metadata or in packet data; therefore if the
 * SKF_AD_VLAN_TAG_PRESENT test is negative, we need to check link
 * header for VLAN tag. As the decision is done at run time, we need
 * update variable part of the offsets
 */
static struct block *
gen_vlan_bpf_extensions(compiler_state_t *cstate, bpf_u_int32 vlan_num,
    int has_vlan_tag)
{
	struct block *b0, *b_tpid, *b_vid = NULL;
	struct slist *s;

	/* generate new filter code based on extracting packet
	 * metadata */
	s = new_stmt(cstate, BPF_LD|BPF_B|BPF_ABS);
	s->s.k = (bpf_u_int32)(SKF_AD_OFF + SKF_AD_VLAN_TAG_PRESENT);

	b0 = gen_jmp_k(cstate, BPF_JEQ, 1, s);

	/*
	 * This is tricky. We need to insert the statements updating variable
	 * parts of offsets before the traditional TPID and VID tests so
	 * that they are called whenever SKF_AD_VLAN_TAG_PRESENT fails but
	 * we do not want this update to affect those checks. That's why we
	 * generate both test blocks first and insert the statements updating
	 * variable parts of both offsets after that. This wouldn't work if
	 * there already were variable length link header when entering this
	 * function but gen_vlan_bpf_extensions() isn't called in that case.
	 */
	b_tpid = gen_vlan_tpid_test(cstate);
	if (has_vlan_tag)
		b_vid = gen_vlan_vid_test(cstate, vlan_num);

	gen_vlan_patch_tpid_test(cstate, b_tpid);
	gen_or(b0, b_tpid);
	b0 = b_tpid;

	if (has_vlan_tag) {
		gen_vlan_patch_vid_test(cstate, b_vid);
		gen_and(b0, b_vid);
		b0 = b_vid;
	}

	return b0;
}
#endif

/*
 * support IEEE 802.1Q VLAN trunk over ethernet
 */
struct block *
gen_vlan(compiler_state_t *cstate, bpf_u_int32 vlan_num, int has_vlan_tag)
{
	struct	block	*b0;

	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	/* can't check for VLAN-encapsulated packets inside MPLS */
	if (cstate->label_stack_depth > 0)
		bpf_error(cstate, "no VLAN match after MPLS");

	/*
	 * Check for a VLAN packet, and then change the offsets to point
	 * to the type and data fields within the VLAN packet.  Just
	 * increment the offsets, so that we can support a hierarchy, e.g.
	 * "vlan 100 && vlan 200" to capture VLAN 200 encapsulated within
	 * VLAN 100.
	 *
	 * XXX - this is a bit of a kludge.  If we were to split the
	 * compiler into a parser that parses an expression and
	 * generates an expression tree, and a code generator that
	 * takes an expression tree (which could come from our
	 * parser or from some other parser) and generates BPF code,
	 * we could perhaps make the offsets parameters of routines
	 * and, in the handler for an "AND" node, pass to subnodes
	 * other than the VLAN node the adjusted offsets.
	 *
	 * This would mean that "vlan" would, instead of changing the
	 * behavior of *all* tests after it, change only the behavior
	 * of tests ANDed with it.  That would change the documented
	 * semantics of "vlan", which might break some expressions.
	 * However, it would mean that "(vlan and ip) or ip" would check
	 * both for VLAN-encapsulated IP and IP-over-Ethernet, rather than
	 * checking only for VLAN-encapsulated IP, so that could still
	 * be considered worth doing; it wouldn't break expressions
	 * that are of the form "vlan and ..." or "vlan N and ...",
	 * which I suspect are the most common expressions involving
	 * "vlan".  "vlan or ..." doesn't necessarily do what the user
	 * would really want, now, as all the "or ..." tests would
	 * be done assuming a VLAN, even though the "or" could be viewed
	 * as meaning "or, if this isn't a VLAN packet...".
	 */
	switch (cstate->linktype) {

	case DLT_EN10MB:
		/*
		 * Newer version of the Linux kernel pass around
		 * packets in which the VLAN tag has been removed
		 * from the packet data and put into metadata.
		 *
		 * This requires special treatment.
		 */
#if defined(SKF_AD_VLAN_TAG_PRESENT)
		/* Verify that this is the outer part of the packet and
		 * not encapsulated somehow. */
		if (cstate->vlan_stack_depth == 0 && !cstate->off_linkhdr.is_variable &&
		    cstate->off_linkhdr.constant_part ==
		    cstate->off_outermostlinkhdr.constant_part) {
			/*
			 * Do we need special VLAN handling?
			 */
			if (cstate->bpf_pcap->bpf_codegen_flags & BPF_SPECIAL_VLAN_HANDLING)
				b0 = gen_vlan_bpf_extensions(cstate, vlan_num,
				    has_vlan_tag);
			else
				b0 = gen_vlan_no_bpf_extensions(cstate,
				    vlan_num, has_vlan_tag);
		} else
#endif
			b0 = gen_vlan_no_bpf_extensions(cstate, vlan_num,
			    has_vlan_tag);
		break;

	case DLT_NETANALYZER:
	case DLT_NETANALYZER_TRANSPARENT:
	case DLT_IEEE802_11:
	case DLT_PRISM_HEADER:
	case DLT_IEEE802_11_RADIO_AVS:
	case DLT_IEEE802_11_RADIO:
		/*
		 * These are either Ethernet packets with an additional
		 * metadata header (the NetAnalyzer types), or 802.11
		 * packets, possibly with an additional metadata header.
		 *
		 * For the first of those, the VLAN tag is in the normal
		 * place, so the special-case handling above isn't
		 * necessary.
		 *
		 * For the second of those, we don't do the special-case
		 * handling for now.
		 */
		b0 = gen_vlan_no_bpf_extensions(cstate, vlan_num, has_vlan_tag);
		break;

	default:
		fail_kw_on_dlt(cstate, "vlan");
		/*NOTREACHED*/
	}

	cstate->vlan_stack_depth++;

	return (b0);
}

/*
 * support for MPLS
 *
 * The label_num_arg dance is to avoid annoying whining by compilers that
 * label_num might be clobbered by longjmp - yeah, it might, but *WHO CARES*?
 * It's not *used* after setjmp returns.
 */
static struct block *
gen_mpls_internal(compiler_state_t *cstate, bpf_u_int32 label_num,
    int has_label_num)
{
	struct	block	*b0, *b1;

	if (cstate->label_stack_depth > 0) {
		/* just match the bottom-of-stack bit clear */
		b0 = gen_mcmp(cstate, OR_PREVMPLSHDR, 2, BPF_B, 0, 0x01);
	} else {
		/*
		 * We're not in an MPLS stack yet, so check the link-layer
		 * type against MPLS.
		 */
		switch (cstate->linktype) {

		case DLT_C_HDLC: /* fall through */
		case DLT_HDLC:
		case DLT_EN10MB:
		case DLT_NETANALYZER:
		case DLT_NETANALYZER_TRANSPARENT:
			b0 = gen_linktype(cstate, ETHERTYPE_MPLS);
			break;

		case DLT_PPP:
			b0 = gen_linktype(cstate, PPP_MPLS_UCAST);
			break;

			/* FIXME add other DLT_s ...
			 * for Frame-Relay/and ATM this may get messy due to SNAP headers
			 * leave it for now */

		default:
			fail_kw_on_dlt(cstate, "mpls");
			/*NOTREACHED*/
		}
	}

	/* If a specific MPLS label is requested, check it */
	if (has_label_num) {
		assert_maxval(cstate, "MPLS label", label_num, 0xFFFFF);
		label_num = label_num << 12; /* label is shifted 12 bits on the wire */
		b1 = gen_mcmp(cstate, OR_LINKPL, 0, BPF_W, label_num,
		    0xfffff000); /* only compare the first 20 bits */
		gen_and(b0, b1);
		b0 = b1;
	}

	/*
	 * Change the offsets to point to the type and data fields within
	 * the MPLS packet.  Just increment the offsets, so that we
	 * can support a hierarchy, e.g. "mpls 100000 && mpls 1024" to
	 * capture packets with an outer label of 100000 and an inner
	 * label of 1024.
	 *
	 * Increment the MPLS stack depth as well; this indicates that
	 * we're checking MPLS-encapsulated headers, to make sure higher
	 * level code generators don't try to match against IP-related
	 * protocols such as Q_ARP, Q_RARP etc.
	 *
	 * XXX - this is a bit of a kludge.  See comments in gen_vlan().
	 */
	cstate->off_nl_nosnap += 4;
	cstate->off_nl += 4;
	cstate->label_stack_depth++;
	return (b0);
}

struct block *
gen_mpls(compiler_state_t *cstate, bpf_u_int32 label_num, int has_label_num)
{
	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	return gen_mpls_internal(cstate, label_num, has_label_num);
}

/*
 * Support PPPOE discovery and session.
 */
struct block *
gen_pppoed(compiler_state_t *cstate)
{
	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	/* check for PPPoE discovery */
	return gen_linktype(cstate, ETHERTYPE_PPPOED);
}

/*
 * RFC 2516 Section 4:
 *
 * The Ethernet payload for PPPoE is as follows:
 *
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  VER  | TYPE  |      CODE     |          SESSION_ID           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |            LENGTH             |           payload             ~
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct block *
gen_pppoes(compiler_state_t *cstate, bpf_u_int32 sess_num, int has_sess_num)
{
	struct block *b0, *b1;

	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	/*
	 * Test against the PPPoE session link-layer type.
	 */
	b0 = gen_linktype(cstate, ETHERTYPE_PPPOES);

	/* If a specific session is requested, check PPPoE session id */
	if (has_sess_num) {
		assert_maxval(cstate, "PPPoE session number", sess_num, UINT16_MAX);
		b1 = gen_cmp(cstate, OR_LINKPL, 2, BPF_H, sess_num);
		gen_and(b0, b1);
		b0 = b1;
	}

	/*
	 * Change the offsets to point to the type and data fields within
	 * the PPP packet, and note that this is PPPoE rather than
	 * raw PPP.
	 *
	 * XXX - this is a bit of a kludge.  See the comments in
	 * gen_vlan().
	 *
	 * The "network-layer" protocol is PPPoE, which has a 6-byte
	 * PPPoE header, followed by a PPP packet.
	 *
	 * There is no HDLC encapsulation for the PPP packet (it's
	 * encapsulated in PPPoES instead), so the link-layer type
	 * starts at the first byte of the PPP packet.  For PPPoE,
	 * that offset is relative to the beginning of the total
	 * link-layer payload, including any 802.2 LLC header, so
	 * it's 6 bytes past cstate->off_nl.
	 */
	PUSH_LINKHDR(cstate, DLT_PPP, cstate->off_linkpl.is_variable,
	    cstate->off_linkpl.constant_part + cstate->off_nl + 6, /* 6 bytes past the PPPoE header */
	    cstate->off_linkpl.reg);

	cstate->off_linktype = cstate->off_linkhdr;
	cstate->off_linkpl.constant_part = cstate->off_linkhdr.constant_part + 2;

	cstate->off_nl = 0;
	cstate->off_nl_nosnap = 0;	/* no 802.2 LLC */

	return b0;
}

/* Check that this is Geneve and the VNI is correct if
 * specified. Parameterized to handle both IPv4 and IPv6. */
static struct block *
gen_geneve_check(compiler_state_t *cstate,
    struct block *(*gen_portfn)(compiler_state_t *, uint16_t, int, int),
    enum e_offrel offrel, bpf_u_int32 vni, int has_vni)
{
	struct block *b0, *b1;

	b0 = gen_portfn(cstate, GENEVE_PORT, IPPROTO_UDP, Q_DST);

	/* Check that we are operating on version 0. Otherwise, we
	 * can't decode the rest of the fields. The version is 2 bits
	 * in the first byte of the Geneve header. */
	b1 = gen_mcmp(cstate, offrel, 8, BPF_B, 0, 0xc0);
	gen_and(b0, b1);
	b0 = b1;

	if (has_vni) {
		assert_maxval(cstate, "Geneve VNI", vni, 0xffffff);
		vni <<= 8; /* VNI is in the upper 3 bytes */
		b1 = gen_mcmp(cstate, offrel, 12, BPF_W, vni, 0xffffff00);
		gen_and(b0, b1);
		b0 = b1;
	}

	return b0;
}

/* The IPv4 and IPv6 Geneve checks need to do two things:
 * - Verify that this actually is Geneve with the right VNI.
 * - Place the IP header length (plus variable link prefix if
 *   needed) into register A to be used later to compute
 *   the inner packet offsets. */
static struct block *
gen_geneve4(compiler_state_t *cstate, bpf_u_int32 vni, int has_vni)
{
	struct block *b0, *b1;
	struct slist *s, *s1;

	b0 = gen_geneve_check(cstate, gen_port, OR_TRAN_IPV4, vni, has_vni);

	/* Load the IP header length into A. */
	s = gen_loadx_iphdrlen(cstate);

	s1 = new_stmt(cstate, BPF_MISC|BPF_TXA);
	sappend(s, s1);

	/* Forcibly append these statements to the true condition
	 * of the protocol check by creating a new block that is
	 * always true and ANDing them. */
	b1 = gen_jmp_x(cstate, BPF_JEQ, s);

	gen_and(b0, b1);

	return b1;
}

static struct block *
gen_geneve6(compiler_state_t *cstate, bpf_u_int32 vni, int has_vni)
{
	struct block *b0, *b1;
	struct slist *s, *s1;

	b0 = gen_geneve_check(cstate, gen_port6, OR_TRAN_IPV6, vni, has_vni);

	/* Load the IP header length. We need to account for a
	 * variable length link prefix if there is one. */
	s = gen_abs_offset_varpart(cstate, &cstate->off_linkpl);
	if (s) {
		s1 = new_stmt(cstate, BPF_LD|BPF_IMM);
		s1->s.k = 40;
		sappend(s, s1);

		s1 = new_stmt(cstate, BPF_ALU|BPF_ADD|BPF_X);
		s1->s.k = 0;
		sappend(s, s1);
	} else {
		s = new_stmt(cstate, BPF_LD|BPF_IMM);
		s->s.k = 40;
	}

	/* Forcibly append these statements to the true condition
	 * of the protocol check by creating a new block that is
	 * always true and ANDing them. */
	s1 = new_stmt(cstate, BPF_MISC|BPF_TAX);
	sappend(s, s1);

	b1 = gen_jmp_x(cstate, BPF_JEQ, s);

	gen_and(b0, b1);

	return b1;
}

/* We need to store three values based on the Geneve header::
 * - The offset of the linktype.
 * - The offset of the end of the Geneve header.
 * - The offset of the end of the encapsulated MAC header. */
static struct slist *
gen_geneve_offsets(compiler_state_t *cstate)
{
	struct slist *s, *s1, *s_proto;

	/* First we need to calculate the offset of the Geneve header
	 * itself. This is composed of the IP header previously calculated
	 * (include any variable link prefix) and stored in A plus the
	 * fixed sized headers (fixed link prefix, MAC length, and UDP
	 * header). */
	s = new_stmt(cstate, BPF_ALU|BPF_ADD|BPF_K);
	s->s.k = cstate->off_linkpl.constant_part + cstate->off_nl + 8;

	/* Stash this in X since we'll need it later. */
	s1 = new_stmt(cstate, BPF_MISC|BPF_TAX);
	sappend(s, s1);

	/* The EtherType in Geneve is 2 bytes in. Calculate this and
	 * store it. */
	s1 = new_stmt(cstate, BPF_ALU|BPF_ADD|BPF_K);
	s1->s.k = 2;
	sappend(s, s1);

	cstate->off_linktype.reg = alloc_reg(cstate);
	cstate->off_linktype.is_variable = 1;
	cstate->off_linktype.constant_part = 0;

	s1 = new_stmt(cstate, BPF_ST);
	s1->s.k = cstate->off_linktype.reg;
	sappend(s, s1);

	/* Load the Geneve option length and mask and shift to get the
	 * number of bytes. It is stored in the first byte of the Geneve
	 * header. */
	s1 = new_stmt(cstate, BPF_LD|BPF_IND|BPF_B);
	s1->s.k = 0;
	sappend(s, s1);

	s1 = new_stmt(cstate, BPF_ALU|BPF_AND|BPF_K);
	s1->s.k = 0x3f;
	sappend(s, s1);

	s1 = new_stmt(cstate, BPF_ALU|BPF_MUL|BPF_K);
	s1->s.k = 4;
	sappend(s, s1);

	/* Add in the rest of the Geneve base header. */
	s1 = new_stmt(cstate, BPF_ALU|BPF_ADD|BPF_K);
	s1->s.k = 8;
	sappend(s, s1);

	/* Add the Geneve header length to its offset and store. */
	s1 = new_stmt(cstate, BPF_ALU|BPF_ADD|BPF_X);
	s1->s.k = 0;
	sappend(s, s1);

	/* Set the encapsulated type as Ethernet. Even though we may
	 * not actually have Ethernet inside there are two reasons this
	 * is useful:
	 * - The linktype field is always in EtherType format regardless
	 *   of whether it is in Geneve or an inner Ethernet frame.
	 * - The only link layer that we have specific support for is
	 *   Ethernet. We will confirm that the packet actually is
	 *   Ethernet at runtime before executing these checks. */
	PUSH_LINKHDR(cstate, DLT_EN10MB, 1, 0, alloc_reg(cstate));

	s1 = new_stmt(cstate, BPF_ST);
	s1->s.k = cstate->off_linkhdr.reg;
	sappend(s, s1);

	/* Calculate whether we have an Ethernet header or just raw IP/
	 * MPLS/etc. If we have Ethernet, advance the end of the MAC offset
	 * and linktype by 14 bytes so that the network header can be found
	 * seamlessly. Otherwise, keep what we've calculated already. */

	/* We have a bare jmp so we can't use the optimizer. */
	cstate->no_optimize = 1;

	/* Load the EtherType in the Geneve header, 2 bytes in. */
	s1 = new_stmt(cstate, BPF_LD|BPF_IND|BPF_H);
	s1->s.k = 2;
	sappend(s, s1);

	/* Load X with the end of the Geneve header. */
	s1 = new_stmt(cstate, BPF_LDX|BPF_MEM);
	s1->s.k = cstate->off_linkhdr.reg;
	sappend(s, s1);

	/* Check if the EtherType is Transparent Ethernet Bridging. At the
	 * end of this check, we should have the total length in X. In
	 * the non-Ethernet case, it's already there. */
	s_proto = new_stmt(cstate, JMP(BPF_JEQ, BPF_K));
	s_proto->s.k = ETHERTYPE_TEB;
	sappend(s, s_proto);

	s1 = new_stmt(cstate, BPF_MISC|BPF_TXA);
	sappend(s, s1);
	s_proto->s.jt = s1;

	/* Since this is Ethernet, use the EtherType of the payload
	 * directly as the linktype. Overwrite what we already have. */
	s1 = new_stmt(cstate, BPF_ALU|BPF_ADD|BPF_K);
	s1->s.k = 12;
	sappend(s, s1);

	s1 = new_stmt(cstate, BPF_ST);
	s1->s.k = cstate->off_linktype.reg;
	sappend(s, s1);

	/* Advance two bytes further to get the end of the Ethernet
	 * header. */
	s1 = new_stmt(cstate, BPF_ALU|BPF_ADD|BPF_K);
	s1->s.k = 2;
	sappend(s, s1);

	/* Move the result to X. */
	s1 = new_stmt(cstate, BPF_MISC|BPF_TAX);
	sappend(s, s1);

	/* Store the final result of our linkpl calculation. */
	cstate->off_linkpl.reg = alloc_reg(cstate);
	cstate->off_linkpl.is_variable = 1;
	cstate->off_linkpl.constant_part = 0;

	s1 = new_stmt(cstate, BPF_STX);
	s1->s.k = cstate->off_linkpl.reg;
	sappend(s, s1);
	s_proto->s.jf = s1;

	cstate->off_nl = 0;

	return s;
}

/* Check to see if this is a Geneve packet. */
struct block *
gen_geneve(compiler_state_t *cstate, bpf_u_int32 vni, int has_vni)
{
	struct block *b0, *b1;
	struct slist *s;

	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	b0 = gen_geneve4(cstate, vni, has_vni);
	b1 = gen_geneve6(cstate, vni, has_vni);

	gen_or(b0, b1);
	b0 = b1;

	/* Later filters should act on the payload of the Geneve frame,
	 * update all of the header pointers. Attach this code so that
	 * it gets executed in the event that the Geneve filter matches. */
	s = gen_geneve_offsets(cstate);

	b1 = gen_true(cstate);
	sappend(s, b1->stmts);
	b1->stmts = s;

	gen_and(b0, b1);

	cstate->is_encap = 1;

	return b1;
}

/* Check that this is VXLAN and the VNI is correct if
 * specified. Parameterized to handle both IPv4 and IPv6. */
static struct block *
gen_vxlan_check(compiler_state_t *cstate,
    struct block *(*gen_portfn)(compiler_state_t *, uint16_t, int, int),
    enum e_offrel offrel, bpf_u_int32 vni, int has_vni)
{
	struct block *b0, *b1;

	b0 = gen_portfn(cstate, VXLAN_PORT, IPPROTO_UDP, Q_DST);

	/* Check that the VXLAN header has the flag bits set
	 * correctly. */
	b1 = gen_cmp(cstate, offrel, 8, BPF_B, 0x08);
	gen_and(b0, b1);
	b0 = b1;

	if (has_vni) {
		assert_maxval(cstate, "VXLAN VNI", vni, 0xffffff);
		vni <<= 8; /* VNI is in the upper 3 bytes */
		b1 = gen_mcmp(cstate, offrel, 12, BPF_W, vni, 0xffffff00);
		gen_and(b0, b1);
		b0 = b1;
	}

	return b0;
}

/* The IPv4 and IPv6 VXLAN checks need to do two things:
 * - Verify that this actually is VXLAN with the right VNI.
 * - Place the IP header length (plus variable link prefix if
 *   needed) into register A to be used later to compute
 *   the inner packet offsets. */
static struct block *
gen_vxlan4(compiler_state_t *cstate, bpf_u_int32 vni, int has_vni)
{
	struct block *b0, *b1;
	struct slist *s, *s1;

	b0 = gen_vxlan_check(cstate, gen_port, OR_TRAN_IPV4, vni, has_vni);

	/* Load the IP header length into A. */
	s = gen_loadx_iphdrlen(cstate);

	s1 = new_stmt(cstate, BPF_MISC|BPF_TXA);
	sappend(s, s1);

	/* Forcibly append these statements to the true condition
	 * of the protocol check by creating a new block that is
	 * always true and ANDing them. */
	b1 = gen_jmp_x(cstate, BPF_JEQ, s);

	gen_and(b0, b1);

	return b1;
}

static struct block *
gen_vxlan6(compiler_state_t *cstate, bpf_u_int32 vni, int has_vni)
{
	struct block *b0, *b1;
	struct slist *s, *s1;

	b0 = gen_vxlan_check(cstate, gen_port6, OR_TRAN_IPV6, vni, has_vni);

	/* Load the IP header length. We need to account for a
	 * variable length link prefix if there is one. */
	s = gen_abs_offset_varpart(cstate, &cstate->off_linkpl);
	if (s) {
		s1 = new_stmt(cstate, BPF_LD|BPF_IMM);
		s1->s.k = 40;
		sappend(s, s1);

		s1 = new_stmt(cstate, BPF_ALU|BPF_ADD|BPF_X);
		s1->s.k = 0;
		sappend(s, s1);
	} else {
		s = new_stmt(cstate, BPF_LD|BPF_IMM);
		s->s.k = 40;
	}

	/* Forcibly append these statements to the true condition
	 * of the protocol check by creating a new block that is
	 * always true and ANDing them. */
	s1 = new_stmt(cstate, BPF_MISC|BPF_TAX);
	sappend(s, s1);

	b1 = gen_jmp_x(cstate, BPF_JEQ, s);

	gen_and(b0, b1);

	return b1;
}

/* We need to store three values based on the VXLAN header:
 * - The offset of the linktype.
 * - The offset of the end of the VXLAN header.
 * - The offset of the end of the encapsulated MAC header. */
static struct slist *
gen_vxlan_offsets(compiler_state_t *cstate)
{
	struct slist *s, *s1;

	/* Calculate the offset of the VXLAN header itself. This
	 * includes the IP header computed previously (including any
	 * variable link prefix) and stored in A plus the fixed size
	 * headers (fixed link prefix, MAC length, UDP header). */
	s = new_stmt(cstate, BPF_ALU|BPF_ADD|BPF_K);
	s->s.k = cstate->off_linkpl.constant_part + cstate->off_nl + 8;

	/* Add the VXLAN header length to its offset and store */
	s1 = new_stmt(cstate, BPF_ALU|BPF_ADD|BPF_K);
	s1->s.k = 8;
	sappend(s, s1);

	/* Push the link header. VXLAN packets always contain Ethernet
	 * frames. */
	PUSH_LINKHDR(cstate, DLT_EN10MB, 1, 0, alloc_reg(cstate));

	s1 = new_stmt(cstate, BPF_ST);
	s1->s.k = cstate->off_linkhdr.reg;
	sappend(s, s1);

	/* As the payload is an Ethernet packet, we can use the
	 * EtherType of the payload directly as the linktype. */
	s1 = new_stmt(cstate, BPF_ALU|BPF_ADD|BPF_K);
	s1->s.k = 12;
	sappend(s, s1);

	cstate->off_linktype.reg = alloc_reg(cstate);
	cstate->off_linktype.is_variable = 1;
	cstate->off_linktype.constant_part = 0;

	s1 = new_stmt(cstate, BPF_ST);
	s1->s.k = cstate->off_linktype.reg;
	sappend(s, s1);

	/* Two bytes further is the end of the Ethernet header and the
	 * start of the payload. */
	s1 = new_stmt(cstate, BPF_ALU|BPF_ADD|BPF_K);
	s1->s.k = 2;
	sappend(s, s1);

	/* Move the result to X. */
	s1 = new_stmt(cstate, BPF_MISC|BPF_TAX);
	sappend(s, s1);

	/* Store the final result of our linkpl calculation. */
	cstate->off_linkpl.reg = alloc_reg(cstate);
	cstate->off_linkpl.is_variable = 1;
	cstate->off_linkpl.constant_part = 0;

	s1 = new_stmt(cstate, BPF_STX);
	s1->s.k = cstate->off_linkpl.reg;
	sappend(s, s1);

	cstate->off_nl = 0;

	return s;
}

/* Check to see if this is a VXLAN packet. */
struct block *
gen_vxlan(compiler_state_t *cstate, bpf_u_int32 vni, int has_vni)
{
	struct block *b0, *b1;
	struct slist *s;

	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	b0 = gen_vxlan4(cstate, vni, has_vni);
	b1 = gen_vxlan6(cstate, vni, has_vni);

	gen_or(b0, b1);
	b0 = b1;

	/* Later filters should act on the payload of the VXLAN frame,
	 * update all of the header pointers. Attach this code so that
	 * it gets executed in the event that the VXLAN filter matches. */
	s = gen_vxlan_offsets(cstate);

	b1 = gen_true(cstate);
	sappend(s, b1->stmts);
	b1->stmts = s;

	gen_and(b0, b1);

	cstate->is_encap = 1;

	return b1;
}

/* Check that the encapsulated frame has a link layer header
 * for Ethernet filters. */
static struct block *
gen_encap_ll_check(compiler_state_t *cstate)
{
	struct block *b0;
	struct slist *s, *s1;

	/* The easiest way to see if there is a link layer present
	 * is to check if the link layer header and payload are not
	 * the same. */

	/* Geneve always generates pure variable offsets so we can
	 * compare only the registers. */
	s = new_stmt(cstate, BPF_LD|BPF_MEM);
	s->s.k = cstate->off_linkhdr.reg;

	s1 = new_stmt(cstate, BPF_LDX|BPF_MEM);
	s1->s.k = cstate->off_linkpl.reg;
	sappend(s, s1);

	b0 = gen_jmp_x(cstate, BPF_JEQ, s);
	gen_not(b0);

	return b0;
}

static struct block *
gen_atmfield_code_internal(compiler_state_t *cstate, int atmfield,
    bpf_u_int32 jvalue, int jtype, int reverse)
{
	assert_atm(cstate, atmkw(atmfield));

	switch (atmfield) {

	case A_VPI:
		assert_maxval(cstate, "VPI", jvalue, UINT8_MAX);
		return gen_ncmp(cstate, OR_LINKHDR, cstate->off_vpi, BPF_B,
		    0xffffffffU, jtype, reverse, jvalue);

	case A_VCI:
		assert_maxval(cstate, "VCI", jvalue, UINT16_MAX);
		return gen_ncmp(cstate, OR_LINKHDR, cstate->off_vci, BPF_H,
		    0xffffffffU, jtype, reverse, jvalue);

	default:
		bpf_error(cstate, ERRSTR_FUNC_VAR_INT, __func__, "atmfield", atmfield);
	}
}

static struct block *
gen_atm_vpi(compiler_state_t *cstate, const uint8_t v)
{
	return gen_atmfield_code_internal(cstate, A_VPI, v, BPF_JEQ, 0);
}

static struct block *
gen_atm_vci(compiler_state_t *cstate, const uint16_t v)
{
	return gen_atmfield_code_internal(cstate, A_VCI, v, BPF_JEQ, 0);
}

static struct block *
gen_atm_prototype(compiler_state_t *cstate, const uint8_t v)
{
	return gen_mcmp(cstate, OR_LINKHDR, cstate->off_proto, BPF_B, v, 0x0fU);
}

static struct block *
gen_atmtype_llc(compiler_state_t *cstate)
{
	struct block *b0;

	b0 = gen_atm_prototype(cstate, PT_LLC);
	cstate->linktype = cstate->prevlinktype;
	return b0;
}

struct block *
gen_atmfield_code(compiler_state_t *cstate, int atmfield,
    bpf_u_int32 jvalue, int jtype, int reverse)
{
	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	return gen_atmfield_code_internal(cstate, atmfield, jvalue, jtype,
	    reverse);
}

struct block *
gen_atmtype_abbrev(compiler_state_t *cstate, int type)
{
	struct block *b0, *b1;

	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	assert_atm(cstate, atmkw(type));

	switch (type) {

	case A_METAC:
		/* Get all packets in Meta signalling Circuit */
		b0 = gen_atm_vpi(cstate, 0);
		b1 = gen_atm_vci(cstate, 1);
		gen_and(b0, b1);
		return b1;

	case A_BCC:
		/* Get all packets in Broadcast Circuit*/
		b0 = gen_atm_vpi(cstate, 0);
		b1 = gen_atm_vci(cstate, 2);
		gen_and(b0, b1);
		return b1;

	case A_OAMF4SC:
		/* Get all cells in Segment OAM F4 circuit*/
		b0 = gen_atm_vpi(cstate, 0);
		b1 = gen_atm_vci(cstate, 3);
		gen_and(b0, b1);
		return b1;

	case A_OAMF4EC:
		/* Get all cells in End-to-End OAM F4 Circuit*/
		b0 = gen_atm_vpi(cstate, 0);
		b1 = gen_atm_vci(cstate, 4);
		gen_and(b0, b1);
		return b1;

	case A_SC:
		/*  Get all packets in connection Signalling Circuit */
		b0 = gen_atm_vpi(cstate, 0);
		b1 = gen_atm_vci(cstate, 5);
		gen_and(b0, b1);
		return b1;

	case A_ILMIC:
		/* Get all packets in ILMI Circuit */
		b0 = gen_atm_vpi(cstate, 0);
		b1 = gen_atm_vci(cstate, 16);
		gen_and(b0, b1);
		return b1;

	case A_LANE:
		/* Get all LANE packets */
		b1 = gen_atm_prototype(cstate, PT_LANE);

		/*
		 * Arrange that all subsequent tests assume LANE
		 * rather than LLC-encapsulated packets, and set
		 * the offsets appropriately for LANE-encapsulated
		 * Ethernet.
		 *
		 * We assume LANE means Ethernet, not Token Ring.
		 */
		PUSH_LINKHDR(cstate, DLT_EN10MB, 0,
		    cstate->off_payload + 2,	/* Ethernet header */
		    -1);
		cstate->off_linktype.constant_part = cstate->off_linkhdr.constant_part + 12;
		cstate->off_linkpl.constant_part = cstate->off_linkhdr.constant_part + 14;	/* Ethernet */
		cstate->off_nl = 0;			/* Ethernet II */
		cstate->off_nl_nosnap = 3;		/* 802.3+802.2 */
		return b1;

	default:
		bpf_error(cstate, ERRSTR_FUNC_VAR_INT, __func__, "type", type);
	}
}

/*
 * Filtering for MTP2 messages based on li value
 * FISU, length is null
 * LSSU, length is 1 or 2
 * MSU, length is 3 or more
 * For MTP2_HSL, sequences are on 2 bytes, and length on 9 bits
 */
struct block *
gen_mtp2type_abbrev(compiler_state_t *cstate, int type)
{
	struct block *b0, *b1;

	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	assert_ss7(cstate, ss7kw(type));

	switch (type) {

	case M_FISU:
		return gen_ncmp(cstate, OR_PACKET, cstate->off_li, BPF_B,
		    0x3fU, BPF_JEQ, 0, 0U);

	case M_LSSU:
		b0 = gen_ncmp(cstate, OR_PACKET, cstate->off_li, BPF_B,
		    0x3fU, BPF_JGT, 1, 2U);
		b1 = gen_ncmp(cstate, OR_PACKET, cstate->off_li, BPF_B,
		    0x3fU, BPF_JGT, 0, 0U);
		gen_and(b1, b0);
		return b0;

	case M_MSU:
		return gen_ncmp(cstate, OR_PACKET, cstate->off_li, BPF_B,
		    0x3fU, BPF_JGT, 0, 2U);

	case MH_FISU:
		return gen_ncmp(cstate, OR_PACKET, cstate->off_li_hsl, BPF_H,
		    0xff80U, BPF_JEQ, 0, 0U);

	case MH_LSSU:
		b0 = gen_ncmp(cstate, OR_PACKET, cstate->off_li_hsl, BPF_H,
		    0xff80U, BPF_JGT, 1, 0x0100U);
		b1 = gen_ncmp(cstate, OR_PACKET, cstate->off_li_hsl, BPF_H,
		    0xff80U, BPF_JGT, 0, 0U);
		gen_and(b1, b0);
		return b0;

	case MH_MSU:
		return gen_ncmp(cstate, OR_PACKET, cstate->off_li_hsl, BPF_H,
		    0xff80U, BPF_JGT, 0, 0x0100U);

	default:
		bpf_error(cstate, ERRSTR_FUNC_VAR_INT, __func__, "type", type);
	}
}

/*
 * These maximum valid values are all-ones, so they double as the bitmasks
 * before any bitwise shifting.
 */
#define MTP2_SIO_MAXVAL UINT8_MAX
#define MTP3_PC_MAXVAL 0x3fffU
#define MTP3_SLS_MAXVAL 0xfU

static struct block *
gen_mtp3field_code_internal(compiler_state_t *cstate, int mtp3field,
    bpf_u_int32 jvalue, int jtype, int reverse)
{
	u_int newoff_sio;
	u_int newoff_opc;
	u_int newoff_dpc;
	u_int newoff_sls;

	newoff_sio = cstate->off_sio;
	newoff_opc = cstate->off_opc;
	newoff_dpc = cstate->off_dpc;
	newoff_sls = cstate->off_sls;

	assert_ss7(cstate, ss7kw(mtp3field));

	switch (mtp3field) {

	/*
	 * See UTU-T Rec. Q.703, Section 2.2, Figure 3/Q.703.
	 *
	 * SIO is the simplest field: the size is one byte and the offset is a
	 * multiple of bytes, so the only detail to get right is the value of
	 * the [right-to-left] field offset.
	 */
	case MH_SIO:
		newoff_sio += 3; /* offset for MTP2_HSL */
		/* FALLTHROUGH */

	case M_SIO:
		assert_maxval(cstate, ss7kw(mtp3field), jvalue, MTP2_SIO_MAXVAL);
		// Here the bitmask means "do not apply a bitmask".
		return gen_ncmp(cstate, OR_PACKET, newoff_sio, BPF_B, UINT32_MAX,
		    jtype, reverse, jvalue);

	/*
	 * See UTU-T Rec. Q.704, Section 2.2, Figure 3/Q.704.
	 *
	 * SLS, OPC and DPC are more complicated: none of these is sized in a
	 * multiple of 8 bits, MTP3 encoding is little-endian and MTP packet
	 * diagrams are meant to be read right-to-left.  This means in the
	 * diagrams within individual fields and concatenations thereof
	 * bitwise shifts and masks can be noted in the common left-to-right
	 * manner until each final value is ready to be byte-swapped and
	 * handed to gen_ncmp().  See also gen_dnhostop(), which solves a
	 * similar problem in a similar way.
	 *
	 * Offsets of fields within the packet header always have the
	 * right-to-left meaning.  Note that in DLT_MTP2 and possibly other
	 * DLTs the offset does not include the F (Flag) field at the
	 * beginning of each message.
	 *
	 * For example, if the 8-bit SIO field has a 3 byte [RTL] offset, the
	 * 32-bit standard routing header has a 4 byte [RTL] offset and could
	 * be tested entirely using a single BPF_W comparison.  In this case
	 * the 14-bit DPC field [LTR] bitmask would be 0x3FFF, the 14-bit OPC
	 * field [LTR] bitmask would be (0x3FFF << 14) and the 4-bit SLS field
	 * [LTR] bitmask would be (0xF << 28), all of which conveniently
	 * correlates with the [RTL] packet diagram until the byte-swapping is
	 * done before use.
	 *
	 * The code below uses this approach for OPC, which spans 3 bytes.
	 * DPC and SLS use shorter loads, SLS also uses a different offset.
	 */
	case MH_OPC:
		newoff_opc += 3;

		/* FALLTHROUGH */
	case M_OPC:
		assert_maxval(cstate, ss7kw(mtp3field), jvalue, MTP3_PC_MAXVAL);
		return gen_ncmp(cstate, OR_PACKET, newoff_opc, BPF_W,
		    SWAPLONG(MTP3_PC_MAXVAL << 14), jtype, reverse,
		    SWAPLONG(jvalue << 14));

	case MH_DPC:
		newoff_dpc += 3;
		/* FALLTHROUGH */

	case M_DPC:
		assert_maxval(cstate, ss7kw(mtp3field), jvalue, MTP3_PC_MAXVAL);
		return gen_ncmp(cstate, OR_PACKET, newoff_dpc, BPF_H,
		    SWAPSHORT(MTP3_PC_MAXVAL), jtype, reverse,
		    SWAPSHORT(jvalue));

	case MH_SLS:
		newoff_sls += 3;
		/* FALLTHROUGH */

	case M_SLS:
		assert_maxval(cstate, ss7kw(mtp3field), jvalue, MTP3_SLS_MAXVAL);
		return gen_ncmp(cstate, OR_PACKET, newoff_sls, BPF_B,
		    MTP3_SLS_MAXVAL << 4, jtype, reverse,
		    jvalue << 4);

	default:
		bpf_error(cstate, ERRSTR_FUNC_VAR_INT, __func__, "mtp3field", mtp3field);
	}
}

struct block *
gen_mtp3field_code(compiler_state_t *cstate, int mtp3field,
    bpf_u_int32 jvalue, int jtype, int reverse)
{
	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	return gen_mtp3field_code_internal(cstate, mtp3field, jvalue, jtype,
	    reverse);
}

static struct block *
gen_msg_abbrev(compiler_state_t *cstate, const uint8_t type)
{
	/*
	 * Q.2931 signalling protocol messages for handling virtual circuits
	 * establishment and teardown
	 */
	return gen_cmp(cstate, OR_LINKHDR, cstate->off_payload + MSG_TYPE_POS,
	    BPF_B, type);
}

struct block *
gen_atmmulti_abbrev(compiler_state_t *cstate, int type)
{
	struct block *b0, *b1;

	/*
	 * Catch errors reported by us and routines below us, and return NULL
	 * on an error.
	 */
	if (setjmp(cstate->top_ctx))
		return (NULL);

	assert_atm(cstate, atmkw(type));

	switch (type) {

	case A_OAM:
		/* OAM F4 type */
		b0 = gen_atm_vci(cstate, 3);
		b1 = gen_atm_vci(cstate, 4);
		gen_or(b0, b1);
		b0 = gen_atm_vpi(cstate, 0);
		gen_and(b0, b1);
		return b1;

	case A_OAMF4:
		/* OAM F4 type */
		b0 = gen_atm_vci(cstate, 3);
		b1 = gen_atm_vci(cstate, 4);
		gen_or(b0, b1);
		b0 = gen_atm_vpi(cstate, 0);
		gen_and(b0, b1);
		return b1;

	case A_CONNECTMSG:
		/*
		 * Get Q.2931 signalling messages for switched
		 * virtual connection
		 */
		b0 = gen_msg_abbrev(cstate, SETUP);
		b1 = gen_msg_abbrev(cstate, CALL_PROCEED);
		gen_or(b0, b1);
		b0 = gen_msg_abbrev(cstate, CONNECT);
		gen_or(b0, b1);
		b0 = gen_msg_abbrev(cstate, CONNECT_ACK);
		gen_or(b0, b1);
		b0 = gen_msg_abbrev(cstate, RELEASE);
		gen_or(b0, b1);
		b0 = gen_msg_abbrev(cstate, RELEASE_DONE);
		gen_or(b0, b1);
		b0 = gen_atmtype_abbrev(cstate, A_SC);
		gen_and(b0, b1);
		return b1;

	case A_METACONNECT:
		b0 = gen_msg_abbrev(cstate, SETUP);
		b1 = gen_msg_abbrev(cstate, CALL_PROCEED);
		gen_or(b0, b1);
		b0 = gen_msg_abbrev(cstate, CONNECT);
		gen_or(b0, b1);
		b0 = gen_msg_abbrev(cstate, RELEASE);
		gen_or(b0, b1);
		b0 = gen_msg_abbrev(cstate, RELEASE_DONE);
		gen_or(b0, b1);
		b0 = gen_atmtype_abbrev(cstate, A_METAC);
		gen_and(b0, b1);
		return b1;

	default:
		bpf_error(cstate, ERRSTR_FUNC_VAR_INT, __func__, "type", type);
	}
}
