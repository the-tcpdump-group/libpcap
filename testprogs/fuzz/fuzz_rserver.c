#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>

#include <pcap/pcap.h>
#include "rpcapd/daemon.h"

FILE * outfile = NULL;

void fuzz_openFile(const char * name) {
    if (outfile != NULL) {
        fclose(outfile);
    }
    outfile = fopen(name, "w");
}

typedef enum {
    LOGPRIO_DEBUG,
    LOGPRIO_INFO,
    LOGPRIO_WARNING,
    LOGPRIO_ERROR
} log_priority;

void rpcapd_log(log_priority priority, const char *message, ...)
{
    va_list ap;

    va_start(ap, message);
    fprintf(outfile, "rpcapd[%d]:", priority);
    vfprintf(outfile, message, ap);
    putc('\n', outfile);
    va_end(ap);
}

void sock_initfuzz(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    int sock;

    //initialization
    if (outfile == NULL) {
        fuzz_openFile("/dev/null");
    }

    sock_initfuzz(Data, Size);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        abort();
    }
    //dummy socket, active, null auth allowed, no data_port, no ssl
    daemon_serviceloop(sock, 1, malloc(0), 1, NULL, 0);

    return 0;
}
