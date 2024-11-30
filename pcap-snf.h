pcap_t *snf_create(const char *, char *, int *);
int snf_findalldevs(pcap_if_list_t *devlistp, char *errbuf);
int snf_get_if_flags(const char *, bpf_u_int32 *, char *);
