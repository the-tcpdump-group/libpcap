#ifndef dlpisubs_h
#define	dlpisubs_h

/*
 * Private data for capturing on DLPI devices.
 */
struct pcap_dlpi {
#ifdef HAVE_LIBDLPI
	dlpi_handle_t dlpi_hd;
#endif /* HAVE_LIBDLPI */
#ifdef DL_HP_RAWDLS
	int send_fd;
#endif /* DL_HP_RAWDLS */

	struct pcap_stat stat;
};

/*
 * Functions defined by dlpisubs.c.
 */
PCAP_UNEXPORTED_C_FUNC int pcap_stats_dlpi(pcap_t *, struct pcap_stat *);
PCAP_UNEXPORTED_C_FUNC int pcap_process_pkts(pcap_t *, pcap_handler, u_char *, int,
    u_char *, int);
PCAP_UNEXPORTED_C_FUNC int pcap_process_mactype(pcap_t *, u_int);
#ifdef HAVE_SYS_BUFMOD_H
PCAP_UNEXPORTED_C_FUNC int pcap_conf_bufmod(pcap_t *, int);
#endif
PCAP_UNEXPORTED_C_FUNC int pcap_alloc_databuf(pcap_t *);
PCAP_UNEXPORTED_C_FUNC int strioctl(int, int, int, char *);

#endif
