/* SPDX-License-Identifier: BSD-3 */
/* Copyright (C) 2020  Linus Lüssing */

#ifndef _BATADV_PACKET_H_
#define _BATADV_PACKET_H_

/* For the definitive and most recent packet format definition,
 * see the batadv_packet.h in the Linux kernel.
 */

enum batadv_packettype {
	BATADV_IV_OGM           = 0x00,
	BATADV_BCAST            = 0x01,
	BATADV_CODED            = 0x02,
	BATADV_ELP		= 0x03,
	BATADV_OGM2		= 0x04,
	BATADV_UNICAST          = 0x40,
	BATADV_UNICAST_FRAG     = 0x41,
	BATADV_UNICAST_4ADDR    = 0x42,
	BATADV_ICMP             = 0x43,
	BATADV_UNICAST_TVLV     = 0x44,
};

#define ETH_ALEN	6

struct batadv_unicast_packet {
	uint8_t packet_type;
	uint8_t version;
	uint8_t ttl;
	uint8_t ttvn;
	uint8_t dest[ETH_ALEN];
};

struct batadv_unicast_4addr_packet {
	struct batadv_unicast_packet u;
	uint8_t src[ETH_ALEN];
	uint8_t subtype;
	uint8_t reserved;
};

struct batadv_frag_packet {
	uint8_t packet_type;
	uint8_t version;
	uint8_t ttl;
	uint8_t num_pri;	/* number and priority */
	uint8_t dest[ETH_ALEN];
	uint8_t orig[ETH_ALEN];
	uint8_t seqno[2];	/* 2-byte integral value */
	uint8_t total_size[2];	/* 2-byte integral value */
};

struct batadv_bcast_packet {
	uint8_t packet_type;
	uint8_t version;
	uint8_t ttl;
	uint8_t reserved;
	uint8_t seqno[4];	/* 4-byte integral value */
	uint8_t orig[ETH_ALEN];
};

struct batadv_coded_packet {
	uint8_t packet_type;
	uint8_t version;
	uint8_t ttl;
	uint8_t first_ttvn;
	uint8_t first_source[ETH_ALEN];
	uint8_t first_orig_dest[ETH_ALEN];
	uint8_t first_crc[4];	/* 4-byte integral value */
	uint8_t second_ttl;
	uint8_t second_ttvn;
	uint8_t second_dest[ETH_ALEN];
	uint8_t second_source[ETH_ALEN];
	uint8_t second_orig_dest[ETH_ALEN];
	uint8_t second_crc[4];	/* 4-byte integral value */
	uint8_t coded_len[2];	/* 2-byte integral value */
};

#endif /* _BATADV_PACKET_H_ */
