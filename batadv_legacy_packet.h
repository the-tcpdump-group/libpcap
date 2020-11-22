/* SPDX-License-Identifier: BSD-3 */
/* Copyright (C) 2020  Linus Lüssing */

#ifndef _BATADV_LEGACY_PACKET_H_
#define _BATADV_LEGACY_PACKET_H_

enum batadv_legacy_packettype {
	BATADV_LEGACY_IV_OGM		= 0x01,
	BATADV_LEGACY_ICMP		= 0x02,
	BATADV_LEGACY_UNICAST		= 0x03,
	BATADV_LEGACY_BCAST		= 0x04,
	BATADV_LEGACY_VIS		= 0x05,
	BATADV_LEGACY_UNICAST_FRAG	= 0x06,
	BATADV_LEGACY_TT_QUERY		= 0x07,
	BATADV_LEGACY_ROAM_ADV		= 0x08,
	BATADV_LEGACY_UNICAST_4ADDR	= 0x09,
	BATADV_LEGACY_CODED		= 0x0a,
};

#define ETH_ALEN	6

struct batadv_legacy_unicast_packet {
	uint8_t packet_type;
	uint8_t version;
	uint8_t ttl;
	uint8_t ttvn;
	uint8_t dest[ETH_ALEN];
};

struct batadv_legacy_unicast_4addr_packet {
	uint8_t packet_type;
	uint8_t version;
	uint8_t ttl;
	uint8_t src[ETH_ALEN];
	uint8_t subtype;
	uint8_t reserved;
};

struct batadv_legacy_unicast_frag_packet {
	uint8_t packet_type;
	uint8_t version;
	uint8_t ttl;
	uint8_t ttvn;
	uint8_t dest[ETH_ALEN];
	uint8_t flags;
	uint8_t align;
	uint8_t orig[ETH_ALEN];
	uint8_t seqno[2];		/* 2-byte integral value */
};

struct batadv_legacy_bcast_packet {
	uint8_t packet_type;
	uint8_t version;
	uint8_t ttl;
	uint8_t reserved;
	uint8_t seqno[4];		/* 4-byte integral value */
	uint8_t orig[ETH_ALEN];
};

struct batadv_legacy_coded_packet {
	uint8_t packet_type;
	uint8_t version;
	uint8_t ttl;
	uint8_t first_ttvn;
	uint8_t first_source[ETH_ALEN];
	uint8_t first_orig_dest[ETH_ALEN];
	uint8_t first_crc[4];		/* 4-byte integral value */
	uint8_t second_ttl;
	uint8_t second_ttvn;
	uint8_t second_dest[ETH_ALEN];
	uint8_t second_source[ETH_ALEN];
	uint8_t second_orig_dest[ETH_ALEN];
	uint8_t second_crc[4];		/* 4-byte integral value */
	uint8_t coded_len[2];		/* 2-byte integral value */
};

#endif /* _BATADV_LEGACY_PACKET_H_ */
