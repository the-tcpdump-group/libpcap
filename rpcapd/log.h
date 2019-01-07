#include "pcap/funcattrs.h"

extern void rpcapd_log_set(int, int);

typedef enum {
	LOGPRIO_DEBUG,
	LOGPRIO_INFO,
	LOGPRIO_WARNING,
	LOGPRIO_ERROR
} log_priority;

extern void rpcapd_log(log_priority priority,
    PCAP_FORMAT_STRING(const char *message), ...) PCAP_PRINTFLIKE(2, 3);
