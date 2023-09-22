/*
 * Prototypes for OpenVizsla-related functions
 */
int openvizsla_findalldevs(pcap_if_list_t *devlistp, char *err_str);
pcap_t *openvizsla_create(const char *device, char *ebuf, int *is_ours);
