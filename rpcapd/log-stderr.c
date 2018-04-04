#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include "log.h"

void
rpcapd_log_init(void)
{
}

void
rpcapd_log(log_priority priority, const char *message, ...)
{
	const char *tag;
	va_list ap;

	switch (priority) {

	case LOGPRIO_INFO:
		tag = "";
		break;

	case LOGPRIO_WARNING:
		tag = "warning: ";
		break;

	case LOGPRIO_ERROR:
		tag = "error: ";
		break;

	default:
		abort();
		/* NOTREACHED */
	}

	fprintf(stderr, "rpcapd: %s", tag);
	va_start(ap, message);
	vfprintf(stderr, message, ap);
	va_end(ap);
	putc('\n', stderr);
}
