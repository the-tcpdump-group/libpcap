/*
 * pcap-dag.c: Packet capture interface for Endace DAG card.
 *
 * The functionality of this code attempts to mimic that of pcap-linux as much
 * as possible.  This code is only needed when compiling in the DAG card code
 * at the same time as another type of device.
 *
 * Author: Richard Littin, Sean Irvine ({richard,sean}@reeltwo.com)
 *
 * @(#) $Header: /tcpdump/master/libpcap/pcap-dag.h,v 1.1 2003-07-23 05:29:21 guy Exp $ (LBL)
 */

int dag_stats(pcap_t *p, struct pcap_stat *ps);
int dag_read(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
pcap_t *dag_open_live(const char *device, int snaplen, int promisc, int to_ms, char *ebuf);
int dag_setfilter(pcap_t *p, struct bpf_program *fp);
void dag_platform_close(pcap_t *p);

