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

	/*
	 * Squelch warnings from compilers that *don't* assume that
	 * priority always has a valid enum value and therefore don't
	 * assume that we'll always go through one of the case arms.
	 *
	 * If we have a default case, compilers that *do* assume that
	 * will then complain about the default case code being
	 * unreachable.
	 *
	 * Damned if you do, damned if you don't.
	 */
	tag = "";

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
	}

	fprintf(stderr, "rpcapd: %s", tag);
	va_start(ap, message);
	vfprintf(stderr, message, ap);
	va_end(ap);
	putc('\n', stderr);
}
