/*
 * Copyright (c) 1993, 1994, 1995, 1996, 1997
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
 *
 * pcap-util.c - common code for various files
 */

#include <config.h>

#include <stddef.h>
#include <string.h>

#include <pcap-types.h>

#include "pcap/can_socketcan.h"
#include "pcap/sll.h"
#include "pcap/usb.h"
#include "pcap/nflog.h"

#include "pcap-int.h"
#include "extract.h"
#include "pcap-usb-linux-common.h"

#include "pcap-util.h"
#include "pflog.h"

/*
 * Most versions of the DLT_PFLOG pseudo-header have UID and PID fields
 * that are saved in host byte order.
 *
 * When reading a DLT_PFLOG packet, we need to convert those fields from
 * the byte order of the host that wrote the file to this host's byte
 * order.
 */
/*
 * Alignment-safe, bounds-checked in-place byte-swapping helpers.
 * Return 1 if the field fits within `limit` bytes and was swapped, 0 otherwise.
 */
static inline int
swap_u16_at(u_char *buf, size_t limit, size_t off)
{
	uint16_t v;

	if (off > limit || sizeof(v) > limit - off)
		return (0);
	memcpy(&v, buf + off, sizeof(v));
	v = PCAP_BSWAP_16(v);
	memcpy(buf + off, &v, sizeof(v));
	return (1);
}

static inline int
swap_u32_at(u_char *buf, size_t limit, size_t off)
{
	uint32_t v;

	if (off > limit || sizeof(v) > limit - off)
		return (0);
	memcpy(&v, buf + off, sizeof(v));
	v = PCAP_BSWAP_32(v);
	memcpy(buf + off, &v, sizeof(v));
	return (1);
}

static inline int
swap_u64_at(u_char *buf, size_t limit, size_t off)
{
	uint64_t v;

	if (off > limit || sizeof(v) > limit - off)
		return (0);
	memcpy(&v, buf + off, sizeof(v));
	v = PCAP_BSWAP_64(v);
	memcpy(buf + off, &v, sizeof(v));
	return (1);
}

static void
swap_pflog_header(const struct pcap_pkthdr *hdr, u_char *buf)
{
	size_t limit = hdr->caplen < hdr->len ? hdr->caplen : hdr->len;
	uint8_t pfloghdr_length;

	if (limit < offsetof(struct pfloghdr, length) + sizeof(pfloghdr_length))
		return;
	memcpy(&pfloghdr_length, buf + offsetof(struct pfloghdr, length),
	    sizeof(pfloghdr_length));
	if (pfloghdr_length < limit)
		limit = pfloghdr_length;

	if (!swap_u32_at(buf, limit, offsetof(struct pfloghdr, uid)))
		return;
	if (!swap_u32_at(buf, limit, offsetof(struct pfloghdr, pid)))
		return;
	if (!swap_u32_at(buf, limit, offsetof(struct pfloghdr, rule_uid)))
		return;
	(void)swap_u32_at(buf, limit, offsetof(struct pfloghdr, rule_pid));
}

/*
 * Linux cooked capture packets with a protocol type of LINUX_SLL_P_CAN or
 * LINUX_SLL_P_CANFD have SocketCAN CAN classic/CAN FD headers in front
 * of the payload,with the CAN ID being in the byte order of the host
 * that wrote the packet, and Linux cooked capture packets with a protocol
 * type of LINUX_SLL_P_CANXL have SocketCAN CAN XL headers in front of the
 * payload with the protocol/VCID field, the payload length, and the
 * acceptance field in the byte order of the host that wrote the packet.
 *
 * When reading a Linux cooked capture packet, we need to check for those
 * packets and, if the byte order host that wrote the packet, as
 * indicated by the byte order of the pcap file or pcapng section
 * containing the packet, is the opposite of our byte order, convert
 * the header files to our byte order by byte-swapping them.
 */
static void
swap_socketcan_header(uint16_t protocol, u_int caplen, u_int length,
    u_char *buf)
{
	size_t limit = caplen < length ? caplen : length;

	switch (protocol) {

	case LINUX_SLL_P_CAN:
	case LINUX_SLL_P_CANFD:
		(void)swap_u32_at(buf, limit,
		    offsetof(pcap_can_socketcan_hdr, can_id));
		break;

	case LINUX_SLL_P_CANXL:
		if (!swap_u32_at(buf, limit,
		    offsetof(pcap_can_socketcan_xl_hdr, priority_vcid)))
			return;
		if (!swap_u16_at(buf, limit,
		    offsetof(pcap_can_socketcan_xl_hdr, payload_length)))
			return;
		(void)swap_u32_at(buf, limit,
		    offsetof(pcap_can_socketcan_xl_hdr, acceptance_field));
		break;

	default:
		/*
		 * Not a CAN packet; nothing to do.
		 */
		break;
	}
}

/*
 * DLT_LINUX_SLL packets with a protocol type of LINUX_SLL_P_CAN or
 * LINUX_SLL_P_CANFD have SocketCAN headers in front of the payload,
 * with the CAN ID being in host byte order.
 *
 * When reading a DLT_LINUX_SLL packet, we need to check for those
 * packets and convert the CAN ID from the byte order of the host that
 * wrote the file to this host's byte order.
 */
static void
swap_linux_sll_socketcan_header(const struct pcap_pkthdr *hdr, u_char *buf)
{
	u_int caplen = hdr->caplen;
	u_int length = hdr->len;

	if (caplen < (u_int) sizeof(struct sll_header) ||
	    length < (u_int) sizeof(struct sll_header)) {
		/* Not enough data to have the protocol field */
		return;
	}

	/*
	 * Byte-swap what needs to be byte-swapped.
	 */
	swap_socketcan_header(
	    EXTRACT_BE_U_2(buf + offsetof(struct sll_header, sll_protocol)),
	    caplen - (u_int) sizeof(struct sll_header),
	    length - (u_int) sizeof(struct sll_header),
	    buf + sizeof(struct sll_header));
}

/*
 * The same applies for DLT_LINUX_SLL2.
 */
static void
swap_linux_sll2_socketcan_header(const struct pcap_pkthdr *hdr, u_char *buf)
{
	u_int caplen = hdr->caplen;
	u_int length = hdr->len;

	if (caplen < (u_int) sizeof(struct sll2_header) ||
	    length < (u_int) sizeof(struct sll2_header)) {
		/* Not enough data to have the protocol field */
		return;
	}

	/*
	 * Byte-swap what needs to be byte-swapped.
	 */
	swap_socketcan_header(
	    EXTRACT_BE_U_2(buf + offsetof(struct sll2_header, sll2_protocol)),
	    caplen - (u_int) sizeof(struct sll2_header),
	    length - (u_int) sizeof(struct sll2_header),
	    buf + sizeof(struct sll2_header));
}

/*
 * The DLT_USB_LINUX and DLT_USB_LINUX_MMAPPED headers are in host
 * byte order when capturing (it's supplied directly from a
 * memory-mapped buffer shared by the kernel).
 *
 * When reading a DLT_USB_LINUX or DLT_USB_LINUX_MMAPPED packet, we
 * need to convert it from the byte order of the host that wrote the
 * file to this host's byte order.
 */
static void
swap_linux_usb_header(const struct pcap_pkthdr *hdr, u_char *buf,
    int header_len_64_bytes)
{
	size_t caplen = hdr->caplen;
	size_t offset = 0;
	uint8_t transfer_type = 0;
	uint32_t ndesc = 0;

	if (!swap_u64_at(buf, caplen, offsetof(pcap_usb_header_mmapped, id)))
		return;
	if (caplen <= offsetof(pcap_usb_header_mmapped, transfer_type))
		return;
	transfer_type = buf[offsetof(pcap_usb_header_mmapped, transfer_type)];

	if (!swap_u16_at(buf, caplen, offsetof(pcap_usb_header_mmapped, bus_id)))
		return;
	if (!swap_u64_at(buf, caplen, offsetof(pcap_usb_header_mmapped, ts_sec)))
		return;
	if (!swap_u32_at(buf, caplen, offsetof(pcap_usb_header_mmapped, ts_usec)))
		return;
	if (!swap_u32_at(buf, caplen, offsetof(pcap_usb_header_mmapped, status)))
		return;
	if (!swap_u32_at(buf, caplen, offsetof(pcap_usb_header_mmapped, urb_len)))
		return;
	if (!swap_u32_at(buf, caplen, offsetof(pcap_usb_header_mmapped, data_len)))
		return;

	if (transfer_type == URB_ISOCHRONOUS) {
		if (!swap_u32_at(buf, caplen,
		    offsetof(pcap_usb_header_mmapped, s.iso.error_count)))
			return;
		if (!swap_u32_at(buf, caplen,
		    offsetof(pcap_usb_header_mmapped, s.iso.numdesc)))
			return;
	}

	if (header_len_64_bytes) {
		if (!swap_u32_at(buf, caplen,
		    offsetof(pcap_usb_header_mmapped, interval)))
			return;
		if (!swap_u32_at(buf, caplen,
		    offsetof(pcap_usb_header_mmapped, start_frame)))
			return;
		if (!swap_u32_at(buf, caplen,
		    offsetof(pcap_usb_header_mmapped, xfer_flags)))
			return;
		if (!swap_u32_at(buf, caplen,
		    offsetof(pcap_usb_header_mmapped, ndesc)))
			return;
		memcpy(&ndesc, buf + offsetof(pcap_usb_header_mmapped, ndesc),
		    sizeof(ndesc));

		if (transfer_type == URB_ISOCHRONOUS) {
			uint32_t i;

			offset = sizeof(pcap_usb_header_mmapped);
			for (i = 0; i < ndesc; i++) {
				if (!swap_u32_at(buf, caplen,
				    offset + offsetof(usb_isodesc, status)))
					return;
				if (!swap_u32_at(buf, caplen,
				    offset + offsetof(usb_isodesc, offset)))
					return;
				if (!swap_u32_at(buf, caplen,
				    offset + offsetof(usb_isodesc, len)))
					return;
				if (sizeof(usb_isodesc) > caplen - offset)
					return;
				offset += sizeof(usb_isodesc);
			}
		}
	}
}

/*
 * The DLT_NFLOG "packets" have a mixture of big-endian and host-byte-order
 * data.  They begin with a fixed-length header with big-endian fields,
 * followed by a set of TLVs, where the type and length are in host
 * byte order but the values are either big-endian or are a raw byte
 * sequence that's the same regardless of the host's byte order.
 *
 * When reading a DLT_NFLOG packet, we need to convert the type and
 * length values from the byte order of the host that wrote the file
 * to the byte order of this host.
 */
static void
swap_nflog_header(const struct pcap_pkthdr *hdr, u_char *buf)
{
	u_char *p = buf;
	nflog_hdr_t nfhdr;
	nflog_tlv_t tlv;
	size_t caplen = hdr->caplen;
	size_t length = hdr->len;
	size_t size;

	if (caplen < sizeof(nflog_hdr_t) || length < sizeof(nflog_hdr_t)) {
		/* Not enough data to have any TLVs. */
		return;
	}

	memcpy(&nfhdr, buf, sizeof(nfhdr));
	if (nfhdr.nflog_version != 0) {
		/* Unknown NFLOG version */
		return;
	}

	length -= sizeof(nflog_hdr_t);
	caplen -= sizeof(nflog_hdr_t);
	p += sizeof(nflog_hdr_t);

	while (caplen >= sizeof(nflog_tlv_t) && length >= sizeof(nflog_tlv_t)) {
		memcpy(&tlv, p, sizeof(tlv));

		/* Swap the type and length into host order before validating. */
		tlv.tlv_type = PCAP_BSWAP_16(tlv.tlv_type);
		tlv.tlv_length = PCAP_BSWAP_16(tlv.tlv_length);

		/* Get the 4-byte padded length of the TLV. */
		size = tlv.tlv_length;
		if (size % 4 != 0)
			size += 4 - size % 4;

		/* Is the TLV's length less than the minimum? */
		if (size < sizeof(nflog_tlv_t)) {
			/* Yes. Give up now without mutating malformed header. */
			return;
		}

		/* Write back swapped TLV header. */
		memcpy(p, &tlv, sizeof(tlv));

		/* Do we have enough data for the full TLV? */
		if (caplen < size || length < size) {
			/* No. */
			return;
		}

		/* Skip over the TLV. */
		length -= size;
		caplen -= size;
		p += size;
	}
}

static void
swap_pseudo_headers(int linktype, struct pcap_pkthdr *hdr, u_char *data)
{
	/*
	 * Convert pseudo-headers from the byte order of
	 * the host on which the file was saved to our
	 * byte order, as necessary.
	 */
	switch (linktype) {

	case DLT_PFLOG:
		swap_pflog_header(hdr, data);
		break;

	case DLT_LINUX_SLL:
		swap_linux_sll_socketcan_header(hdr, data);
		break;

	case DLT_LINUX_SLL2:
		swap_linux_sll2_socketcan_header(hdr, data);
		break;

	case DLT_USB_LINUX:
		swap_linux_usb_header(hdr, data, 0);
		break;

	case DLT_USB_LINUX_MMAPPED:
		swap_linux_usb_header(hdr, data, 1);
		break;

	case DLT_NFLOG:
		swap_nflog_header(hdr, data);
		break;
	}
}

static inline int
packet_length_might_be_wrong(struct pcap_pkthdr *hdr,
    const pcap_usb_header_mmapped *usb_hdr)
{
	uint32_t old_style_packet_length;

	/*
	 * Calculate the packet length the old way.
	 * We know that the multiplication won't overflow, but
	 * we don't know that the additions won't.  Calculate
	 * it with no overflow checks, as that's how it
	 * would have been calculated when it was captured.
	 */
	old_style_packet_length = iso_pseudo_header_len(usb_hdr) +
	    usb_hdr->urb_len;
	return (hdr->len == old_style_packet_length);
}

void
pcapint_post_process(int linktype, int swapped, struct pcap_pkthdr *hdr,
    u_char *data)
{
	if (swapped)
		swap_pseudo_headers(linktype, hdr, data);

	/*
	 * Is this a memory-mapped Linux USB capture?
	 */
	if (linktype == DLT_USB_LINUX_MMAPPED) {
		pcap_usb_header_mmapped usb_hdr_copy;
		const pcap_usb_header_mmapped *usb_hdr = &usb_hdr_copy;

		/*
		 * Yes.
		 *
		 * In older versions of libpcap, in memory-mapped Linux
		 * USB captures, the original length of completion events
		 * for incoming isochronous transfers was miscalculated;
		 * it needed to be calculated based on the offsets and
		 * lengths in the descriptors, not on the raw URB length,
		 * but it wasn't.
		 *
		 * If this packet contains transferred data (yes, data_flag
		 * is 0 if we *do* have data), it's a completion event
		 * for an incoming isochronous transfer, and the
		 * transfer length appears to have been calculated
		 * from the raw URB length, fix it.
		 *
		 * We only do this if we have the full USB pseudo-header,
		 * because we will have to look at that header and at
		 * all of the isochronous descriptors.
		 */
		if (hdr->caplen < sizeof (pcap_usb_header_mmapped)) {
			/*
			 * We don't have the full pseudo-header.
			 */
			return;
		}

		memcpy(&usb_hdr_copy, data, sizeof(usb_hdr_copy));

		/*
		 * Make sure the number of descriptors is sane.
		 *
		 * The Linux binary USB monitor code limits the number of
		 * isochronous descriptors to 128; if the number in the file
		 * is larger than that, either 1) the file's been damaged
		 * or 2) the file was produced after the number was raised
		 * in the kernel.
		 *
		 * In case 1), the number can't be trusted, so don't rely on
		 * it to attempt to fix the original length field in the pcap
		 * or pcapng header.
		 *
		 * In case 2), the system was probably running a version of
		 * libpcap that didn't miscalculate the original length, so
		 * it probably doesn't need to be fixed.
		 *
		 * This avoids the possibility of the product of the number of
		 * descriptors and the size of descriptors won't overflow an
		 * unsigned 32-bit integer.
		 */
		if (usb_hdr->ndesc > USB_MAXDESC)
			return;

		if (!usb_hdr->data_flag &&
		    is_isochronous_transfer_completion(usb_hdr) &&
		    packet_length_might_be_wrong(hdr, usb_hdr)) {
			u_int len;

			/*
			 * Make sure we have all of the descriptors,
			 * as we will have to look at all of them.
			 *
			 * If not, we don't bother trying to fix
			 * anything.
			 */
			if (hdr->caplen < iso_pseudo_header_len(usb_hdr))
				return;

			/*
			 * Calculate what the length should have been.
			 */
			len = incoming_isochronous_transfer_completed_len(hdr,
			    data);

			/*
			 * len is the smaller of UINT_MAX and the total
			 * header plus data length.  That's guaranteed
			 * to fit in a UINT_MAX.
			 *
			 * Don't reduce the original length to a value
			 * below the captured length, however, as that
			 * is bogus.
			 */
			if (len >= hdr->caplen)
				hdr->len = len;

			/*
			 * If the captured length is greater than the
			 * length, use the captured length.
			 *
			 * For completion events for incoming isochronous
			 * transfers, it's based on data_len, which is
			 * calculated the same way we calculated
			 * pre_truncation_data_len above, except that
			 * it has access to all the isochronous descriptors,
			 * not just the ones that the kernel were able to
			 * provide us or, for a capture file, that weren't
			 * sliced off by a snapshot length.
			 *
			 * However, it might have been reduced by the USB
			 * capture mechanism arbitrarily limiting the amount
			 * of data it provides to userland, or by the libpcap
			 * capture code limiting it to being no more than the
			 * snapshot, so we don't want to just use it all the
			 * time; we only do so to try to get a better estimate
			 * of the actual length - and to make sure the
			 * original length is always >= the captured length.
			 */
			if (hdr->caplen > hdr->len)
				hdr->len = hdr->caplen;
		}
	}
}
