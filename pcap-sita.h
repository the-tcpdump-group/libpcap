/*
 * pcap-sita.h: Packet capture interface for SITA WAN devices
 *
 * Authors: Fulko Hew (fulko.hew@sita.aero) (+1 905 6815570);
 *
 * @(#) $Header: /tcpdump/master/libpcap/pcap-sita.h
 */

void pcap_close_acn(pcap_t *handle);
int pcap_stats_acn(pcap_t *handle, struct pcap_stat *ps);
int pcap_read_acn(pcap_t *handle, int max_packets, pcap_handler callback, u_char *user);

