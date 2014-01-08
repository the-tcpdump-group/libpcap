/* common for all pcap-dvb-* implementation */
int dvb_findalldevs(pcap_if_t **alldevsp, char *err_str);
pcap_t *dvb_create(const char *device, char *ebuf, int *is_ours);
