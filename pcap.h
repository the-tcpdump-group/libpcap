/*
 * Copyright (c) 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the Computer Systems
 *	Engineering Group at Lawrence Berkeley Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * @(#) $Header: /tcpdump/master/libpcap/pcap.h,v 1.27 2000-09-18 05:08:02 guy Exp $ (LBL)
 */

#ifndef lib_pcap_h
#define lib_pcap_h

#include <sys/types.h>
#include <sys/time.h>

#include <net/bpf.h>

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4

#define PCAP_ERRBUF_SIZE 256

/*
 * Compatibility for systems that have a bpf.h that
 * predates the bpf typedefs for 64-bit support.
 */
#if BPF_RELEASE - 0 < 199406
typedef	int bpf_int32;
typedef	u_int bpf_u_int32;
#endif

typedef struct pcap pcap_t;
typedef struct pcap_dumper pcap_dumper_t;

/*
 * The first record in the file contains saved values for some
 * of the flags used in the printout phases of tcpdump.
 * Many fields here are 32 bit ints so compilers won't insert unwanted
 * padding; these files need to be interchangeable across architectures.
 *
 * Do not change the format of this structure, in any way (this includes
 * changes that only affect the length of fields in this structure).
 * Instead:
 *
 *	introduce a new structure for the new format;
 *
 *	send mail to "tcpdump-workers@tcpdump.org", requesting a new
 *	magic number for your new capture file format, and, when
 *	you get the new magic number, put it in "savefile.c";
 *
 *	use that magic number for save files with the changed file
 *	header;
 *
 *	make the code in "savefile.c" capable of reading files with
 *	the old file header as well as files with the new file header
 *	(using the magic number to determine the header format).
 *
 * Then supply the changes to "patches@tcpdump.org", so that future
 * versions of libpcap and programs that use it (such as tcpdump) will
 * be able to read your new capture file format.
 */
struct pcap_file_header {
	bpf_u_int32 magic;
	u_short version_major;
	u_short version_minor;
	bpf_int32 thiszone;	/* gmt to local correction */
	bpf_u_int32 sigfigs;	/* accuracy of timestamps */
	bpf_u_int32 snaplen;	/* max length saved portion of each pkt */
	bpf_u_int32 linktype;	/* data link type (PCAP_ENCAP_*) */
};

/*
 * Values for "linktype" in the file header.
 *
 * In the past, these have been DLT_ codes defined by <net/bpf.h>.
 * Those codes were used in two places:
 *
 *	inside BSD kernels, as the value returned by the BIOCGDLT ioctl
 *	for "/dev/bpfN" devices;
 *
 *	inside libpcap capture file headers.
 *
 * Unfortunately, the various flavors of BSD have not always used the same
 * numerical values for the same data types, and various patches to
 * libpcap for non-BSD OSes have added their own DLT_ codes for link
 * layer encapsulation types seen on those OSes, and those codes have had,
 * in some cases, values that were also used, on other platforms, for other
 * link layer encapsulation types.
 *
 * This means that capture files of a type whose numerical DLT_ code
 * means different things on different BSDs, or with different versions
 * of libpcap, can't always be read on systems other than those like
 * the one running on the machine on which the capture was made.
 *
 * We therefore now, in an attempt to decouple the values supplied by
 * BIOCGDLT from the values used in the libpcap file header, define
 * a set of PCAP_ENCAP_* codes to be used in the header; "pcap_open_live()"
 * in the various "pcap-bpf.c" files should set the "linktype" field of
 * the "pcap_t" it returns to a PCAP_ENCAP_* code, not to a DLT_* code.
 *
 * For those DLT_* codes that have, as far as we know, the same values on
 * all platforms (DLT_NULL through DLT_FDDI), we define PCAP_ENCAP_xxx as
 * DLT_xxx; this means that captures of those types will continue to use
 * the same "linktype" value, and thus will continue to be readable by
 * older versions of libpcap.
 *
 * The other PCAP_ENCAP_* codes are given values starting at 100, in the
 * hopes that no DLT_* code will be given one of those values.
 *
 * In order to ensure that a given PCAP_ENCAP_* code's value will refer to
 * the same encapsulation type on all platforms, you should not allocate
 * a new PCAP_ENCAP_* value without consulting "tcpdump-workers@tcpdump.org".
 * The tcpdump developers will allocate a value for you, and will not
 * subsequently allocate it to anybody else; that value will be added to
 * the "pcap.h" in the tcpdump.org CVS repository, so that a future
 * libpcap release will include it.
 *
 * You should, if possible, also contribute patches to libpcap and tcpdump
 * to handle the new encapsulation type, so that they can also be checked
 * into the tcpdump.org CVS repository and so that they will appear in
 * future libpcap and tcpdump releases.
 *
 * PCAP_ENCAP_* codes should not be used inside kernels; DLT_* codes
 * should be used inside kernels that support BSD's BPF mechanism (other
 * kernels may use other codes, e.g. ARPHRD_* codes in Linux kernels
 * and DL_* codes in kernels using DLPI).
 */
#define PCAP_ENCAP_NULL		DLT_NULL
#define PCAP_ENCAP_ETHERNET	DLT_EN10MB	/* also for 100Mb and up */
#define PCAP_ENCAP_EXP_ETHERNET	DLT_EN3MB	/* 3Mb experimental Ethernet */
#define PCAP_ENCAP_AX25		DLT_AX25
#define PCAP_ENCAP_PRONET	DLT_PRONET
#define PCAP_ENCAP_CHAOS	DLT_CHAOS
#define PCAP_ENCAP_TOKEN_RING	DLT_IEEE802	/* DLT_IEEE802 is used for Token Ring */
#define PCAP_ENCAP_ARCNET	DLT_ARCNET
#define PCAP_ENCAP_SLIP		DLT_SLIP
#define PCAP_ENCAP_PPP		DLT_PPP
#define PCAP_ENCAP_FDDI		DLT_FDDI

#define PCAP_ENCAP_ATM_RFC1483	100		/* LLC/SNAP-encapsulated ATM */
#define PCAP_ENCAP_RAW		101		/* raw IP */
#define PCAP_ENCAP_SLIP_BSDOS	102		/* BSD/OS SLIP BPF header */
#define PCAP_ENCAP_PPP_BSDOS	103		/* BSD/OS PPP BPF header */
#define PCAP_ENCAP_C_HDLC	104		/* Cisco HDLC */
#define PCAP_ENCAP_IEEE802_11	105		/* IEEE 802.11 (wireless) */
#define PCAP_ENCAP_ATM_CLIP	106		/* Linux Classical IP over ATM */

/*
 * PCAP_ENCAP_PPP is for use when there might, or might not, be an RFC 1662
 * PPP in HDLC-like framing header (with 0xff 0x03 before the PPP protocol
 * field) at the beginning of the packet.
 *
 * This is for use when there is always such a header; the address field
 * might be 0xff, for regular PPP, or it might be an address field for Cisco
 * point-to-point with HDLC framing as per section 4.3.1 of RFC 1547 ("Cisco
 * HDLC").  This is, for example, what you get with NetBSD's DLT_PPP_SERIAL.
 */
#define PCAP_ENCAP_PPP_HDLC	107		/* PPP in HDLC-like framing */

/*
 * Each packet in the dump file is prepended with this generic header.
 * This gets around the problem of different headers for different
 * packet interfaces.
 */
struct pcap_pkthdr {
	struct timeval ts;	/* time stamp */
	bpf_u_int32 caplen;	/* length of portion present */
	bpf_u_int32 len;	/* length this packet (off wire) */
};

/*
 * As returned by the pcap_stats()
 */
struct pcap_stat {
	u_int ps_recv;		/* number of packets received */
	u_int ps_drop;		/* number of packets dropped */
	u_int ps_ifdrop;	/* drops by interface XXX not yet supported */
};

typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *,
			     const u_char *);

char	*pcap_lookupdev(char *);
int	pcap_lookupnet(char *, bpf_u_int32 *, bpf_u_int32 *, char *);
pcap_t	*pcap_open_live(char *, int, int, int, char *);
pcap_t	*pcap_open_dead(int, int);
pcap_t	*pcap_open_offline(const char *, char *);
void	pcap_close(pcap_t *);
int	pcap_loop(pcap_t *, int, pcap_handler, u_char *);
int	pcap_dispatch(pcap_t *, int, pcap_handler, u_char *);
const u_char*
	pcap_next(pcap_t *, struct pcap_pkthdr *);
int	pcap_stats(pcap_t *, struct pcap_stat *);
int	pcap_setfilter(pcap_t *, struct bpf_program *);
void	pcap_perror(pcap_t *, char *);
char	*pcap_strerror(int);
char	*pcap_geterr(pcap_t *);
int	pcap_compile(pcap_t *, struct bpf_program *, char *, int,
	    bpf_u_int32);
int	pcap_compile_nopcap(int, int, struct bpf_program *,
	    char *, int, bpf_u_int32);
/* XXX */
int	pcap_freecode(pcap_t *, struct bpf_program *);
int	pcap_datalink(pcap_t *);
int	pcap_snapshot(pcap_t *);
int	pcap_is_swapped(pcap_t *);
int	pcap_major_version(pcap_t *);
int	pcap_minor_version(pcap_t *);

/* XXX */
FILE	*pcap_file(pcap_t *);
int	pcap_fileno(pcap_t *);

pcap_dumper_t *pcap_dump_open(pcap_t *, const char *);
void	pcap_dump_close(pcap_dumper_t *);
void	pcap_dump(u_char *, const struct pcap_pkthdr *, const u_char *);

/* XXX this guy lives in the bpf tree */
u_int	bpf_filter(struct bpf_insn *, u_char *, u_int, u_int);
int	bpf_validate(struct bpf_insn *f, int len);
char	*bpf_image(struct bpf_insn *, int);
void	bpf_dump(struct bpf_program *, int);

#ifdef __cplusplus
}
#endif

#endif
