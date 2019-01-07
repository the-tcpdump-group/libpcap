#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <syslog.h>
#endif

#include "log.h"

static int log_to_systemlog;
static int log_debug_messages;

static void rpcapd_vlog_stderr(log_priority,
    PCAP_FORMAT_STRING(const char *), va_list) PCAP_PRINTFLIKE(2, 0);

static void rpcapd_vlog_stderr(log_priority priority, const char *message, va_list ap)
{
	const char *tag;

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

	case LOGPRIO_DEBUG:
		tag = "DEBUG: ";
		break;

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
	vfprintf(stderr, message, ap);
	putc('\n', stderr);
}

static void rpcapd_vlog_systemlog(log_priority,
    PCAP_FORMAT_STRING(const char *), va_list) PCAP_PRINTFLIKE(2, 0);

#ifdef _WIN32
static HANDLE log_handle = INVALID_HANDLE;

#define MESSAGE_SUBKEY \
    "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\rpcapd"

static void rpcapd_log_init(void)
{
	if (log_to_systemlog)
	{
		HKEY hey_handle;

		/*
		 * Register our message stuff in the Registry.
		 *
		 * First, create the registry key for us.  If the key
		 * already exists, this succeeds and returns a handle
		 * for it.
		 */
		if (RegCreateKey(HKEY_LOCAL_MACHINE, MESSAGE_SUBKEY,
		    &key_handle) != ERROR_SUCCESS) {
			/*
			 * Failed - give up and just log to the
			 * standard error.
			 */
			log_to_systemlog = 0;
			return;
		}
		log_handle = RegisterEventSource(NULL, "rpcapd");
	}
}

static void rpcapd_vlog_systemlog(log_priority priority, const char *message,
    va_list ap)
{
	WORD eventlog_type;
	DWORD event_id;
	char msgbuf[1024];
	char *strings[1];

	if (log_handle == INVALID_HANDLE) {
		/* Failed to initialize, or haven't tried */
		return;
	}

	switch (priority) {

	case LOGPRIO_DEBUG:
		//
		// XXX - what *should* we do about debug messages?
		//
		eventlog_type = EVENTLOG_INFORMATION_TYPE;
		event_id = RPCAPD_INFO_ID;
		break;

	case LOGPRIO_INFO:
		eventlog_type = EVENTLOG_INFORMATION_TYPE;
		event_id = RPCAPD_INFO_ID;
		break;

	case LOGPRIO_WARNING:
		eventlog_type = EVENTLOG_WARNING_TYPE;
		event_id = RPCAPD_WARNING_ID;
		break;

	case LOGPRIO_ERROR:
		eventlog_type = EVENTLOG_ERROR_TYPE;
		event_id = RPCAPD_ERROR_ID;
		break;

	default:
		/* Don't do this. */
		return;
	}

	vsprintf(msgbuf, message, ap);

	strings[0] = msgbuf;
	/*
	 * If this fails, how are we going to report it?
	 */
	(void) ReportEvent(log_handle, eventlog_type, 0, event_id, NULL, 1, 0,
	    strings, NULL);
}
#else
static void rpcapd_log_init(void)
{
	if (log_to_systemlog)
	{
		openlog("rpcapd", LOG_PID, LOG_DAEMON);
	}
}

static void rpcapd_vlog_systemlog(log_priority priority, const char *message,
    va_list ap)
{
	int syslog_priority;

	switch (priority) {

	case LOGPRIO_DEBUG:
		syslog_priority = LOG_DEBUG;
		break;

	case LOGPRIO_INFO:
		syslog_priority = LOG_INFO;
		break;

	case LOGPRIO_WARNING:
		syslog_priority = LOG_WARNING;
		break;

	case LOGPRIO_ERROR:
		syslog_priority = LOG_ERR;
		break;

	default:
		/* Don't do this. */
		return;
	}

	vsyslog(syslog_priority, message, ap);
}
#endif

void rpcapd_log_set(int log_to_systemlog_arg, int log_debug_messages_arg)
{
	log_debug_messages = log_debug_messages_arg;
	log_to_systemlog = log_to_systemlog_arg;
}

void rpcapd_log(log_priority priority, const char *message, ...)
{
	static int initialized = 0;
	va_list ap;

	if (!initialized) {
		//
		// Initialize the logging system.
		//
		rpcapd_log_init();
		initialized = 1;
	}

	if (priority != LOGPRIO_DEBUG || log_debug_messages) {
		va_start(ap, message);
		if (log_to_systemlog)
		{
			rpcapd_vlog_systemlog(priority, message, ap);
		}
		else
		{
			rpcapd_vlog_stderr(priority, message, ap);
		}
		va_end(ap);
	}
}
