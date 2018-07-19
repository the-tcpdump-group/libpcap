/*
 * Copyright (c) 2002 - 2003
 * NetGroup, Politecnico di Torino (Italy)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "ftmacros.h"
#include "varattrs.h"

#include <errno.h>		// for the errno variable
#include <stdlib.h>		// for malloc(), free(), ...
#include <string.h>		// for strlen(), ...

#ifdef _WIN32
  #include <process.h>		// for threads
#else
  #include <unistd.h>
  #include <pthread.h>
  #include <sys/time.h>
  #include <sys/types.h>	// for select() and such
  #include <pwd.h>		// for password management
#endif

#ifdef HAVE_GETSPNAM
#include <shadow.h>		// for password management
#endif

#include <pcap.h>		// for libpcap/WinPcap calls

#include "fmtutils.h"
#include "sockutils.h"		// for socket calls
#include "portability.h"
#include "rpcap-protocol.h"
#include "daemon.h"
#include "log.h"

#define RPCAP_TIMEOUT_INIT 90		/* Initial timeout for RPCAP connections (default: 90 sec) */
#define RPCAP_TIMEOUT_RUNTIME 180	/* Run-time timeout for RPCAP connections (default: 3 min) */
#define RPCAP_SUSPEND_WRONGAUTH 1	/* If the authentication is wrong, stops 1 sec before accepting a new auth message */

// Parameters for the service loop.
struct daemon_slpars
{
	SOCKET sockctrl_in;	//!< SOCKET ID of the input side of the control connection
	SOCKET sockctrl_out;	//!< SOCKET ID of the output side of the control connection
	uint8 protocol_version;	//!< negotiated protocol version
	int isactive;		//!< Not null if the daemon has to run in active mode
	int nullAuthAllowed;	//!< '1' if we permit NULL authentication, '0' otherwise
};

/*
 * Data for a session managed by a thread.
 */
struct session {
	SOCKET sockctrl_out;
	SOCKET sockdata;
	uint8 protocol_version;
	pcap_t *fp;
	unsigned int TotCapt;
};

//
// Structure to refer to a thread.
// It includes both a Boolean indicating whether we *have* a thread,
// and a platform-dependent (UN*X vs. Windows) identifier for the
// thread; on Windows, we could use an invalid handle to indicate
// that we don't have a thread, but there *is* no portable "no thread"
// value for a pthread_t on UN*X.
//
struct thread_handle {
	int	have_thread;
#ifdef _WIN32
	HANDLE thread;
#else
	pthread_t thread;
#endif
};

// Locally defined functions
static int daemon_msg_err(SOCKET sockctrl_in, uint32 plen);
static int daemon_msg_auth_req(struct daemon_slpars *pars, uint32 plen);
static int daemon_AuthUserPwd(char *username, char *password, char *errbuf);

static int daemon_msg_findallif_req(struct daemon_slpars *pars, uint32 plen);

static int daemon_msg_open_req(struct daemon_slpars *pars, uint32 plen, char *source, size_t sourcelen);
static int daemon_msg_startcap_req(struct daemon_slpars *pars, uint32 plen, struct thread_handle *threaddata, char *source, struct session **sessionp, struct rpcap_sampling *samp_param);
static int daemon_msg_endcap_req(struct daemon_slpars *pars, struct session *session, struct thread_handle *threaddata);

static int daemon_msg_updatefilter_req(struct daemon_slpars *pars, struct session *session, uint32 plen);
static int daemon_unpackapplyfilter(SOCKET sockctrl_in, struct session *session, uint32 *plenp, char *errbuf);

static int daemon_msg_stats_req(struct daemon_slpars *pars, struct session *session, uint32 plen, struct pcap_stat *stats, unsigned int svrcapt);

static int daemon_msg_setsampling_req(struct daemon_slpars *pars, uint32 plen, struct rpcap_sampling *samp_param);

static void daemon_seraddr(struct sockaddr_storage *sockaddrin, struct rpcap_sockaddr *sockaddrout);
#ifdef _WIN32
static unsigned __stdcall daemon_thrdatamain(void *ptr);
#else
static void *daemon_thrdatamain(void *ptr);
#endif

static int rpcapd_recv_msg_header(SOCKET sock, struct rpcap_header *headerp);
static int rpcapd_recv(SOCKET sock, char *buffer, size_t toread, uint32 *plen, char *errmsgbuf);
static int rpcapd_discard(SOCKET sock, uint32 len);

int
daemon_serviceloop(SOCKET sockctrl_in, SOCKET sockctrl_out, int isactive, int nullAuthAllowed)
{
	struct daemon_slpars pars;		// service loop parameters
	char errbuf[PCAP_ERRBUF_SIZE + 1];	// keeps the error string, prior to be printed
	char errmsgbuf[PCAP_ERRBUF_SIZE + 1];	// buffer for errors to send to the client
	int nrecv;
	struct rpcap_header header;		// RPCAP message general header
	uint32 plen;				// payload length from header
	int authenticated = 0;			// 1 if the client has successfully authenticated
	char source[PCAP_BUF_SIZE+1];		// keeps the string that contains the interface to open
	int got_source = 0;			// 1 if we've gotten the source from an open request
	struct session *session = NULL;		// struct session main variable
	const char *msg_type_string;		// string for message type
	int client_told_us_to_close = 0;	// 1 if the client told us to close the capture

	struct thread_handle threaddata;	// 'read from daemon and send to client' thread

	// needed to save the values of the statistics
	struct pcap_stat stats;
	unsigned int svrcapt;

	struct rpcap_sampling samp_param;	// in case sampling has been requested

	// Structures needed for the select() call
	fd_set rfds;				// set of socket descriptors we have to check
	struct timeval tv;			// maximum time the select() can block waiting for data
	int retval;				// select() return value

	// Set parameters structure
	pars.sockctrl_in = sockctrl_in;
	pars.sockctrl_out = sockctrl_out;
	pars.protocol_version = 0;		// not yet known
	pars.isactive = isactive;		// active mode
	pars.nullAuthAllowed = nullAuthAllowed;

	// We don't have a thread yet.
	threaddata.have_thread = 0;
	//
	// We *shouldn't* have to initialize the thread indicator
	// itself, because the compiler *should* realize that we
	// only use this if have_thread isn't 0, but we *do* have
	// to do it, because not all compilers *do* realize that.
	//
	// There is no "invalid thread handle" value for a UN*X
	// pthread_t, so we just zero it out.
	//
#ifdef _WIN32
	threaddata.thread = INVALID_HANDLE_VALUE;
#else
	memset(&threaddata.thread, 0, sizeof(threaddata.thread));
#endif

	*errbuf = 0;	// Initialize errbuf

	//
	// The client must first authenticate; loop until they send us a
	// message with a version we support and credentials we accept,
	// they send us a close message indicating that they're giving up,
	// or we get a network error or other fatal error.
	//
	while (!authenticated)
	{
		//
		// If we're in active mode, we have to check for the
		// initial timeout.
		//
		// XXX - do this on *every* trip through the loop?
		//
		if (!pars.isactive)
		{
			FD_ZERO(&rfds);
			// We do not have to block here
			tv.tv_sec = RPCAP_TIMEOUT_INIT;
			tv.tv_usec = 0;

			FD_SET(pars.sockctrl_in, &rfds);

			retval = select(pars.sockctrl_in + 1, &rfds, NULL, NULL, &tv);
			if (retval == -1)
			{
				sock_geterror("select failed: ", errmsgbuf, PCAP_ERRBUF_SIZE);
				if (rpcap_senderror(pars.sockctrl_out, 0, PCAP_ERR_NETW, errmsgbuf, errbuf) == -1)
					rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
				goto end;
			}

			// The timeout has expired
			// So, this was a fake connection. Drop it down
			if (retval == 0)
			{
				if (rpcap_senderror(pars.sockctrl_out, 0, PCAP_ERR_INITTIMEOUT, "The RPCAP initial timeout has expired", errbuf) == -1)
					rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
				goto end;
			}
		}

		//
		// Read the message header from the client.
		//
		nrecv = rpcapd_recv_msg_header(pars.sockctrl_in, &header);
		if (nrecv == -1)
		{
			// Fatal error.
			goto end;
		}
		if (nrecv == -2)
		{
			// Client closed the connection.
			goto end;
		}

		plen = header.plen;

		//
		// Did the client specify a version we can handle?
		//
		if (!RPCAP_VERSION_IS_SUPPORTED(header.ver))
		{
			//
			// Tell them it's not a valid protocol version.
			//
			uint8 reply_version;

			//
			// If RPCAP_MIN_VERSION is 0, no version is too
			// old, as the oldest supported version is 0,
			// and there are no negative versions.
			//
#if RPCAP_MIN_VERSION != 0
			if (header.ver < RPCAP_MIN_VERSION)
			{
				//
				// Their maximum version is too old;
				// there *is* no version we can both
				// handle, and they might reject
				// an error with a version they don't
				// understand, so reply with the
				// version they sent.  That may
				// make them retry with that version,
				// but they'll give up on that
				// failure.
				//
				reply_version = header.ver;
			}
			else
#endif
			{
				//
				// Their maximum version is too new,
				// but they might be able to handle
				// *our* maximum version, so reply
				// with that version.
				//
				reply_version = RPCAP_MAX_VERSION;
			}
			if (rpcap_senderror(pars.sockctrl_out, reply_version,
			    PCAP_ERR_WRONGVER, "RPCAP version number mismatch",
			    errbuf) == -1)
			{
				// That failed; log a message and give up.
				rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
				goto end;
			}

			// Discard the rest of the message.
			if (rpcapd_discard(pars.sockctrl_in, plen) == -1)
			{
				// Network error.
				goto end;
			}

			// Let them try again.
			continue;
		}

		//
		// OK, we use the version the client specified.
		//
		pars.protocol_version = header.ver;

		switch (header.type)
		{
			case RPCAP_MSG_AUTH_REQ:
				retval = daemon_msg_auth_req(&pars, plen);
				if (retval == -1)
				{
					// Fatal error; a message has
					// been logged, so just give up.
					goto end;
				}
				if (retval == -2)
				{
					// Non-fatal error; we sent back
					// an error message, so let them
					// try again.
					continue;
				}

				// OK, we're authenticated; we sent back
				// a reply, so start serving requests.
				authenticated = 1;
				break;

			case RPCAP_MSG_CLOSE:
				//
				// The client is giving up.
				// Discard the rest of the message, if
				// there is anything more.
				//
				(void)rpcapd_discard(pars.sockctrl_in, plen);
				// We're done with this client.
				goto end;

			case RPCAP_MSG_ERROR:
				// Log this and close the connection?
				// XXX - is this what happens in active
				// mode, where *we* initiate the
				// connection, and the client gives us
				// an error message rather than a "let
				// me log in" message, indicating that
				// we're not allowed to connect to them?
				(void)daemon_msg_err(pars.sockctrl_in, plen);
				goto end;

			case RPCAP_MSG_FINDALLIF_REQ:
			case RPCAP_MSG_OPEN_REQ:
			case RPCAP_MSG_STARTCAP_REQ:
			case RPCAP_MSG_UPDATEFILTER_REQ:
			case RPCAP_MSG_STATS_REQ:
			case RPCAP_MSG_ENDCAP_REQ:
			case RPCAP_MSG_SETSAMPLING_REQ:
				//
				// These requests can't be sent until
				// the client is authenticated.
				//
				msg_type_string = rpcap_msg_type_string(header.type);
				if (msg_type_string != NULL)
				{
					pcap_snprintf(errmsgbuf, PCAP_ERRBUF_SIZE, "%s request sent before authentication was completed", msg_type_string);
				}
				else
				{
					pcap_snprintf(errmsgbuf, PCAP_ERRBUF_SIZE, "Message of type %u sent before authentication was completed", header.type);
				}
				if (rpcap_senderror(pars.sockctrl_out,
				    pars.protocol_version, PCAP_ERR_WRONGMSG,
				    errmsgbuf, errbuf) == -1)
				{
					rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
					goto end;
				}
				// Discard the rest of the message.
				if (rpcapd_discard(pars.sockctrl_in, plen) == -1)
				{
					// Network error.
					goto end;
				}
				break;

			case RPCAP_MSG_PACKET:
			case RPCAP_MSG_FINDALLIF_REPLY:
			case RPCAP_MSG_OPEN_REPLY:
			case RPCAP_MSG_STARTCAP_REPLY:
			case RPCAP_MSG_UPDATEFILTER_REPLY:
			case RPCAP_MSG_AUTH_REPLY:
			case RPCAP_MSG_STATS_REPLY:
			case RPCAP_MSG_ENDCAP_REPLY:
			case RPCAP_MSG_SETSAMPLING_REPLY:
				//
				// These are server-to-client messages.
				//
				msg_type_string = rpcap_msg_type_string(header.type);
				if (msg_type_string != NULL)
				{
					pcap_snprintf(errmsgbuf, PCAP_ERRBUF_SIZE, "Server-to-client message %s received from client", msg_type_string);
				}
				else
				{
					pcap_snprintf(errmsgbuf, PCAP_ERRBUF_SIZE, "Server-to-client message of type %u received from client", header.type);
				}
				if (rpcap_senderror(pars.sockctrl_out,
				    pars.protocol_version, PCAP_ERR_WRONGMSG,
				    errmsgbuf, errbuf) == -1)
				{
					rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
					goto end;
				}
				// Discard the rest of the message.
				if (rpcapd_discard(pars.sockctrl_in, plen) == -1)
				{
					// Fatal error.
					goto end;
				}
				break;

			default:
				//
				// Unknown message type.
				//
				pcap_snprintf(errmsgbuf, PCAP_ERRBUF_SIZE, "Unknown message type %u", header.type);
				if (rpcap_senderror(pars.sockctrl_out,
				    pars.protocol_version, PCAP_ERR_WRONGMSG,
				    errmsgbuf, errbuf) == -1)
				{
					rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
					goto end;
				}
				// Discard the rest of the message.
				if (rpcapd_discard(pars.sockctrl_in, plen) == -1)
				{
					// Fatal error.
					goto end;
				}
				break;
		}
	}

	//
	// OK, the client has authenticated itself, and we can start
	// processing regular requests from it.
	//

	//
	// We don't have any statistics yet.
	//
	stats.ps_ifdrop = 0;
	stats.ps_recv = 0;
	stats.ps_drop = 0;
	svrcapt = 0;

	//
	// Service requests.
	//
	for (;;)
	{
		errbuf[0] = 0;	// clear errbuf

		// Avoid zombies connections; check if the connection is opens but no commands are performed
		// from more than RPCAP_TIMEOUT_RUNTIME
		// Conditions:
		// - I have to be in normal mode (no active mode)
		// - if the device is open, I don't have to be in the middle of a capture (session->sockdata)
		// - if the device is closed, I have always to check if a new command arrives
		//
		// Be carefully: the capture can have been started, but an error occurred (so session != NULL, but
		//  sockdata is 0
		if ((!pars.isactive) &&  ((session == NULL) || ((session != NULL) && (session->sockdata == 0))))
		{
			// Check for the initial timeout
			FD_ZERO(&rfds);
			// We do not have to block here
			tv.tv_sec = RPCAP_TIMEOUT_RUNTIME;
			tv.tv_usec = 0;

			FD_SET(pars.sockctrl_in, &rfds);

			retval = select(pars.sockctrl_in + 1, &rfds, NULL, NULL, &tv);
			if (retval == -1)
			{
				sock_geterror("select failed: ", errmsgbuf, PCAP_ERRBUF_SIZE);
				if (rpcap_senderror(pars.sockctrl_out,
				    pars.protocol_version, PCAP_ERR_NETW,
				    errmsgbuf, errbuf) == -1)
					rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
				goto end;
			}

			// The timeout has expired
			// So, this was a fake connection. Drop it down
			if (retval == 0)
			{
				if (rpcap_senderror(pars.sockctrl_out,
				    pars.protocol_version,
				    PCAP_ERR_INITTIMEOUT,
				    "The RPCAP initial timeout has expired",
				    errbuf) == -1)
					rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
				goto end;
			}
		}

		//
		// Read the message header from the client.
		//
		nrecv = rpcapd_recv_msg_header(pars.sockctrl_in, &header);
		if (nrecv == -1)
		{
			// Fatal error.
			goto end;
		}
		if (nrecv == -2)
		{
			// Client closed the connection.
			goto end;
		}

		plen = header.plen;

		//
		// Did the client specify the version we negotiated?
		//
		// For now, there's only one version.
		//
		if (header.ver != pars.protocol_version)
		{
			//
			// Tell them it's not the negotiated version.
			// Send the error message with their version,
			// so they don't reject it as having the wrong
			// version.
			//
			if (rpcap_senderror(pars.sockctrl_out,
			    header.ver, PCAP_ERR_WRONGVER,
			    "RPCAP version in message isn't the negotiated version",
			    errbuf) == -1)
			{
				// That failed; log a message and give up.
				rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
				goto end;
			}

			// Discard the rest of the message.
			(void)rpcapd_discard(pars.sockctrl_in, plen);
			// Give up on them.
			goto end;
		}

		switch (header.type)
		{
			case RPCAP_MSG_ERROR:		// The other endpoint reported an error
			{
				(void)daemon_msg_err(pars.sockctrl_in, plen);
				// Do nothing; just exit; the error code is already into the errbuf
				// XXX - actually exit....
				break;
			}

			case RPCAP_MSG_FINDALLIF_REQ:
			{
				if (daemon_msg_findallif_req(&pars, plen) == -1)
				{
					// Fatal error; a message has
					// been logged, so just give up.
					goto end;
				}
				break;
			}

			case RPCAP_MSG_OPEN_REQ:
			{
				//
				// Process the open request, and keep
				// the source from it, for use later
				// when the capture is started.
				//
				// XXX - we don't care if the client sends
				// us multiple open requests, the last
				// one wins.
				//
				retval = daemon_msg_open_req(&pars, plen, source, sizeof(source));
				if (retval == -1)
				{
					// Fatal error; a message has
					// been logged, so just give up.
					goto end;
				}
				got_source = 1;
				break;
			}

			case RPCAP_MSG_STARTCAP_REQ:
			{
				if (!got_source)
				{
					// They never told us what device
					// to capture on!
					if (rpcap_senderror(pars.sockctrl_out,
					    pars.protocol_version,
					    PCAP_ERR_STARTCAPTURE,
					    "No capture device was specified",
					    errbuf) == -1)
					{
						// Fatal error; log an
						// error and  give up.
						rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
						goto end;
					}
					if (rpcapd_discard(pars.sockctrl_in, plen) == -1)
					{
						goto end;
					}
					break;
				}

				if (daemon_msg_startcap_req(&pars, plen, &threaddata, source, &session, &samp_param) == -1)
				{
					// Fatal error; a message has
					// been logged, so just give up.
					goto end;
				}
				break;
			}

			case RPCAP_MSG_UPDATEFILTER_REQ:
			{
				if (session)
				{
					if (daemon_msg_updatefilter_req(&pars, session, plen) == -1)
					{
						// Fatal error; a message has
						// been logged, so just give up.
						goto end;
					}
				}
				else
				{
					if (rpcap_senderror(pars.sockctrl_out,
					    pars.protocol_version,
					    PCAP_ERR_UPDATEFILTER,
					    "Device not opened. Cannot update filter",
					    errbuf) == -1)
					{
						// That failed; log a message and give up.
						rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
						goto end;
					}
				}
				break;
			}

			case RPCAP_MSG_CLOSE:		// The other endpoint close the pcap session
			{
				//
				// Indicate to our caller that the client
				// closed the control connection.
				// This is used only in case of active mode.
				//
				client_told_us_to_close = 1;
				SOCK_DEBUG_MESSAGE("The other end system asked to close the connection.");
				goto end;
			}

			case RPCAP_MSG_STATS_REQ:
			{
				if (daemon_msg_stats_req(&pars, session, plen, &stats, svrcapt) == -1)
				{
					// Fatal error; a message has
					// been logged, so just give up.
					goto end;
				}
				break;
			}

			case RPCAP_MSG_ENDCAP_REQ:		// The other endpoint close the current capture session
			{
				if (session)
				{
					// Save statistics (we can need them in the future)
					if (pcap_stats(session->fp, &stats))
					{
						svrcapt = session->TotCapt;
					}
					else
					{
						stats.ps_ifdrop = 0;
						stats.ps_recv = 0;
						stats.ps_drop = 0;
						svrcapt = 0;
					}

					if (daemon_msg_endcap_req(&pars, session, &threaddata) == -1)
					{
						free(session);
						session = NULL;
						// Fatal error; a message has
						// been logged, so just give up.
						goto end;
					}
					free(session);
					session = NULL;
				}
				else
				{
					rpcap_senderror(pars.sockctrl_out,
					    pars.protocol_version,
					    PCAP_ERR_ENDCAPTURE,
					    "Device not opened. Cannot close the capture",
					    errbuf);
				}
				break;
			}

			case RPCAP_MSG_SETSAMPLING_REQ:
			{
				if (daemon_msg_setsampling_req(&pars, plen, &samp_param) == -1)
				{
					// Fatal error; a message has
					// been logged, so just give up.
					goto end;
				}
				break;
			}

			case RPCAP_MSG_AUTH_REQ:
			{
				//
				// We're already authenticated; you don't
				// get to reauthenticate.
				//
				rpcapd_log(LOGPRIO_INFO, "The client sent an RPCAP_MSG_AUTH_REQ message after authentication was completed");
				if (rpcap_senderror(pars.sockctrl_out,
				    pars.protocol_version,
				    PCAP_ERR_WRONGMSG,
				    "RPCAP_MSG_AUTH_REQ request sent after authentication was completed",
				    errbuf) == -1)
				{
					rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
					goto end;
				}
				// Discard the rest of the message.
				if (rpcapd_discard(pars.sockctrl_in, plen) == -1)
				{
					// Fatal error.
					goto end;
				}
				goto end;

			case RPCAP_MSG_PACKET:
			case RPCAP_MSG_FINDALLIF_REPLY:
			case RPCAP_MSG_OPEN_REPLY:
			case RPCAP_MSG_STARTCAP_REPLY:
			case RPCAP_MSG_UPDATEFILTER_REPLY:
			case RPCAP_MSG_AUTH_REPLY:
			case RPCAP_MSG_STATS_REPLY:
			case RPCAP_MSG_ENDCAP_REPLY:
			case RPCAP_MSG_SETSAMPLING_REPLY:
				//
				// These are server-to-client messages.
				//
				msg_type_string = rpcap_msg_type_string(header.type);
				if (msg_type_string != NULL)
				{
					rpcapd_log(LOGPRIO_INFO, "The client sent a %s server-to-client message", msg_type_string);
					pcap_snprintf(errmsgbuf, PCAP_ERRBUF_SIZE, "Server-to-client message %s received from client", msg_type_string);
				}
				else
				{
					rpcapd_log(LOGPRIO_INFO, "The client sent a server-to-client message of type %u", header.type);
					pcap_snprintf(errmsgbuf, PCAP_ERRBUF_SIZE, "Server-to-client message of type %u received from client", header.type);
				}
				if (rpcap_senderror(pars.sockctrl_out,
				    pars.protocol_version, PCAP_ERR_WRONGMSG,
				    errmsgbuf, errbuf) == -1)
				{
					rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
					goto end;
				}
				// Discard the rest of the message.
				if (rpcapd_discard(pars.sockctrl_in, plen) == -1)
				{
					// Fatal error.
					goto end;
				}
				goto end;

			default:
				//
				// Unknown message type.
				//
				rpcapd_log(LOGPRIO_INFO, "The client sent a message of type %u", header.type);
				pcap_snprintf(errmsgbuf, PCAP_ERRBUF_SIZE, "Unknown message type %u", header.type);
				if (rpcap_senderror(pars.sockctrl_out,
				    pars.protocol_version, PCAP_ERR_WRONGMSG,
				    errbuf, errmsgbuf) == -1)
				{
					rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
					goto end;
				}
				// Discard the rest of the message.
				if (rpcapd_discard(pars.sockctrl_in, plen) == -1)
				{
					// Fatal error.
					goto end;
				}
				goto end;
			}
		}
	}

end:
	// The child thread is about to end

	// perform pcap_t cleanup, in case it has not been done
	if (session)
	{
		if (threaddata.have_thread)
		{
#ifdef _WIN32
			//
			// Tell the data connection thread main capture
			// loop to break out of that loop.
			//
			pcap_breakloop(session->fp);

			//
			// If it's currently blocked waiting for packets
			// to arrive, try to wake it up, so it can see
			// the "break out of the loop" indication.
			//
			SetEvent(pcap_getevent(session->fp));

			//
			// Wait for the thread to exit, so we don't close
			// sockets out from under it.
			//
			// XXX - have a timeout, so we don't wait forever?
			//
			WaitForSingleObject(threaddata.thread, INFINITE);

			//
			// Release the thread handle, as we're done with
			// it.
			//
			CloseHandle(threaddata.thread);
#else
			pthread_cancel(threaddata.thread);
#endif
			threaddata.have_thread = 0;
		}
		if (session->sockdata)
		{
			sock_close(session->sockdata, NULL, 0);
			session->sockdata = 0;
		}
		pcap_close(session->fp);
		free(session);
		session = NULL;
	}

	// Print message and return
	SOCK_DEBUG_MESSAGE("I'm exiting from the child loop");
	SOCK_DEBUG_MESSAGE(errbuf);

	return client_told_us_to_close;
}

/*
 * This handles the RPCAP_MSG_ERR message.
 */
static int
daemon_msg_err(SOCKET sockctrl_in, uint32 plen)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char remote_errbuf[PCAP_ERRBUF_SIZE];

	if (plen >= PCAP_ERRBUF_SIZE)
	{
		/*
		 * Message is too long; just read as much of it as we
		 * can into the buffer provided, and discard the rest.
		 */
		if (sock_recv(sockctrl_in, remote_errbuf, PCAP_ERRBUF_SIZE - 1,
		    SOCK_RECEIVEALL_YES|SOCK_EOF_IS_ERROR, errbuf,
		    PCAP_ERRBUF_SIZE) == -1)
		{
			// Network error.
			rpcapd_log(LOGPRIO_ERROR, "Read from client failed: %s", errbuf);
			return -1;
		}
		if (rpcapd_discard(sockctrl_in, plen - (PCAP_ERRBUF_SIZE - 1)) == -1)
		{
			// Network error.
			return -1;
		}

		/*
		 * Null-terminate it.
		 */
		remote_errbuf[PCAP_ERRBUF_SIZE - 1] = '\0';
	}
	else if (plen == 0)
	{
		/* Empty error string. */
		remote_errbuf[0] = '\0';
	}
	else
	{
		if (sock_recv(sockctrl_in, remote_errbuf, plen,
		    SOCK_RECEIVEALL_YES|SOCK_EOF_IS_ERROR, errbuf,
		    PCAP_ERRBUF_SIZE) == -1)
		{
			// Network error.
			rpcapd_log(LOGPRIO_ERROR, "Read from client failed: %s", errbuf);
			return -1;
		}

		/*
		 * Null-terminate it.
		 */
		remote_errbuf[plen] = '\0';
	}
	// Log the message
	rpcapd_log(LOGPRIO_ERROR, "Error from client: %s", remote_errbuf);
	return 0;
}

/*
 * This handles the RPCAP_MSG_AUTH_REQ message.
 * It checks if the authentication credentials supplied by the user are valid.
 *
 * This function is called if the daemon receives a RPCAP_MSG_AUTH_REQ
 * message in its authentication loop.  It reads the body of the
 * authentication message from the network and checks whether the
 * credentials are valid.
 *
 * \param sockctrl: the socket for the control connection.
 *
 * \param nullAuthAllowed: '1' if the NULL authentication is allowed.
 *
 * \param errbuf: a user-allocated buffer in which the error message
 * (if one) has to be written.  It must be at least PCAP_ERRBUF_SIZE
 * bytes long.
 *
 * \return '0' if everything is fine, '-1' if an unrecoverable error occurred,
 * or '-2' if the authentication failed.  For errors, an error message is
 * returned in the 'errbuf' variable; this gives a message for the
 * unrecoverable error or for the authentication failure.
 */
static int
daemon_msg_auth_req(struct daemon_slpars *pars, uint32 plen)
{
	char errbuf[PCAP_ERRBUF_SIZE];		// buffer for network errors
	char errmsgbuf[PCAP_ERRBUF_SIZE];	// buffer for errors to send to the client
	struct rpcap_header header;		// RPCAP message general header
	int status;
	struct rpcap_auth auth;			// RPCAP authentication header

	status = rpcapd_recv(pars->sockctrl_in, (char *) &auth, sizeof(struct rpcap_auth), &plen, errmsgbuf);
	if (status == -1)
	{
		return -1;
	}
	if (status == -2)
	{
		goto error;
	}

	switch (ntohs(auth.type))
	{
		case RPCAP_RMTAUTH_NULL:
		{
			if (!pars->nullAuthAllowed)
			{
				// Send the client an error reply.
				pcap_snprintf(errmsgbuf, PCAP_ERRBUF_SIZE, "Authentication failed; NULL authentication not permitted.");
				goto error;
			}
			break;
		}

		case RPCAP_RMTAUTH_PWD:
		{
			char *username, *passwd;
			uint32 usernamelen, passwdlen;

			usernamelen = ntohs(auth.slen1);
			username = (char *) malloc (usernamelen + 1);
			if (username == NULL)
			{
				pcap_fmt_errmsg_for_errno(errmsgbuf,
				    PCAP_ERRBUF_SIZE, errno, "malloc() failed");
				goto error;
			}
			status = rpcapd_recv(pars->sockctrl_in, username, usernamelen, &plen, errmsgbuf);
			if (status == -1)
			{
				free(username);
				return -1;
			}
			if (status == -2)
			{
				free(username);
				goto error;
			}
			username[usernamelen] = '\0';

			passwdlen = ntohs(auth.slen2);
			passwd = (char *) malloc (passwdlen + 1);
			if (passwd == NULL)
			{
				pcap_fmt_errmsg_for_errno(errmsgbuf,
				    PCAP_ERRBUF_SIZE, errno, "malloc() failed");
				free(username);
				goto error;
			}
			status = rpcapd_recv(pars->sockctrl_in, passwd, passwdlen, &plen, errmsgbuf);
			if (status == -1)
			{
				free(username);
				free(passwd);
				return -1;
			}
			if (status == -2)
			{
				free(username);
				free(passwd);
				goto error;
			}
			passwd[passwdlen] = '\0';

			if (daemon_AuthUserPwd(username, passwd, errmsgbuf))
			{
				//
				// Authentication failed.  Let the client
				// know.
				//
				free(username);
				free(passwd);
				if (rpcap_senderror(pars->sockctrl_out,
				    pars->protocol_version,
				    PCAP_ERR_AUTH, errmsgbuf, errbuf) == -1)
				{
					// That failed; log a message and give up.
					rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
					return -1;
				}

				//
				// Suspend for 1 second, so that they can't
				// hammer us with repeated tries with an
				// attack such as a dictionary attack.
				//
				// WARNING: this delay is inserted only
				// at this point; if the client closes the
				// connection and reconnects, the suspension
				// time does not have any effect.
				//
				sleep_secs(RPCAP_SUSPEND_WRONGAUTH);
				goto error_noreply;
			}

			free(username);
			free(passwd);
			break;
			}

		default:
			pcap_snprintf(errmsgbuf, PCAP_ERRBUF_SIZE, "Authentication type not recognized.");
			goto error;
	}

	// The authentication succeeded; let the client know.
	rpcap_createhdr(&header, pars->protocol_version, RPCAP_MSG_AUTH_REPLY, 0, 0);

	// Send the ok message back
	if (sock_send(pars->sockctrl_out, (char *) &header, sizeof (struct rpcap_header), errbuf, PCAP_ERRBUF_SIZE) == -1)
	{
		// That failed; log a messsage and give up.
		rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
		return -1;
	}

	// Check if all the data has been read; if not, discard the data in excess
	if (rpcapd_discard(pars->sockctrl_in, plen) == -1)
	{
		return -1;
	}

	return 0;

error:
	if (rpcap_senderror(pars->sockctrl_out, pars->protocol_version,
	    PCAP_ERR_AUTH, errmsgbuf, errbuf) == -1)
	{
		// That failed; log a message and give up.
		rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
		return -1;
	}

error_noreply:
	// Check if all the data has been read; if not, discard the data in excess
	if (rpcapd_discard(pars->sockctrl_in, plen) == -1)
	{
		return -1;
	}

	return -2;
}

static int
daemon_AuthUserPwd(char *username, char *password, char *errbuf)
{
#ifdef _WIN32
	/*
	 * Warning: the user which launches the process must have the
	 * SE_TCB_NAME right.
	 * This corresponds to have the "Act as part of the Operating System"
	 * turned on (administrative tools, local security settings, local
	 * policies, user right assignment)
	 * However, it seems to me that if you run it as a service, this
	 * right should be provided by default.
	 */
	HANDLE Token;
	if (LogonUser(username, ".", password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &Token) == 0)
	{
		int error;

		error = GetLastError();
		FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, error, 0, errbuf,
			PCAP_ERRBUF_SIZE, NULL);

		return -1;
	}

	// This call should change the current thread to the selected user.
	// I didn't test it.
	if (ImpersonateLoggedOnUser(Token) == 0)
	{
		int error;

		error = GetLastError();
		FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, error, 0, errbuf,
			PCAP_ERRBUF_SIZE, NULL);

		CloseHandle(Token);
		return -1;
	}

	CloseHandle(Token);
	return 0;

#else
	/*
	 * See
	 *
	 *	http://www.unixpapa.com/incnote/passwd.html
	 *
	 * We use the Solaris/Linux shadow password authentication if
	 * we have getspnam(), otherwise we just do traditional
	 * authentication, which, on some platforms, might work, even
	 * with shadow passwords, if we're running as root.  Traditional
	 * authenticaion won't work if we're not running as root, as
	 * I think these days all UN*Xes either won't return the password
	 * at all with getpwnam() or will only do so if you're root.
	 *
	 * XXX - perhaps what we *should* be using is PAM, if we have
	 * it.  That might hide all the details of username/password
	 * authentication, whether it's done with a visible-to-root-
	 * only password database or some other authentication mechanism,
	 * behind its API.
	 */
	struct passwd *user;
	char *user_password;
#ifdef HAVE_GETSPNAM
	struct spwd *usersp;
#endif

	// This call is needed to get the uid
	if ((user = getpwnam(username)) == NULL)
	{
		pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "Authentication failed: no such user");
		return -1;
	}

#ifdef HAVE_GETSPNAM
	// This call is needed to get the password; otherwise 'x' is returned
	if ((usersp = getspnam(username)) == NULL)
	{
		pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "Authentication failed: no such user");
		return -1;
	}
	user_password = usersp->sp_pwdp;
#else
	/*
	 * XXX - what about other platforms?
	 * The unixpapa.com page claims this Just Works on *BSD if you're
	 * running as root - it's from 2000, so it doesn't indicate whether
	 * macOS (which didn't come out until 2001, under the name Mac OS
	 * X) behaves like the *BSDs or not, and might also work on AIX.
	 * HP-UX does something else.
	 *
	 * Again, hopefully PAM hides all that.
	 */
	user_password = user->pw_passwd;
#endif

	if (strcmp(user_password, (char *) crypt(password, user_password)) != 0)
	{
		pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "Authentication failed: password incorrect");
		return -1;
	}

	if (setuid(user->pw_uid))
	{
		pcap_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE,
		    errno, "setuid");
		return -1;
	}

/*	if (setgid(user->pw_gid))
	{
		pcap_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE,
		    errno, "setgid");
		return -1;
	}
*/
	return 0;

#endif

}

static int
daemon_msg_findallif_req(struct daemon_slpars *pars, uint32 plen)
{
	char errbuf[PCAP_ERRBUF_SIZE];		// buffer for network errors
	char errmsgbuf[PCAP_ERRBUF_SIZE];	// buffer for errors to send to the client
	char sendbuf[RPCAP_NETBUF_SIZE];	// temporary buffer in which data to be sent is buffered
	int sendbufidx = 0;			// index which keeps the number of bytes currently buffered
	pcap_if_t *alldevs = NULL;		// pointer to the header of the interface chain
	pcap_if_t *d;				// temp pointer needed to scan the interface chain
	struct pcap_addr *address;		// pcap structure that keeps a network address of an interface
	struct rpcap_findalldevs_if *findalldevs_if;// rpcap structure that packet all the data of an interface together
	uint16 nif = 0;				// counts the number of interface listed

	// Discard the rest of the message; there shouldn't be any payload.
	if (rpcapd_discard(pars->sockctrl_in, plen) == -1)
	{
		// Network error.
		return -1;
	}

	// Retrieve the device list
	if (pcap_findalldevs(&alldevs, errmsgbuf) == -1)
		goto error;

	if (alldevs == NULL)
	{
		if (rpcap_senderror(pars->sockctrl_out, pars->protocol_version,
			PCAP_ERR_NOREMOTEIF,
			"No interfaces found! Make sure libpcap/WinPcap is properly installed"
			" and you have the right to access to the remote device.",
			errbuf) == -1)
		{
			rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
			return -1;
		}
		return 0;
	}

	// checks the number of interfaces and it computes the total length of the payload
	for (d = alldevs; d != NULL; d = d->next)
	{
		nif++;

		if (d->description)
			plen+= strlen(d->description);
		if (d->name)
			plen+= strlen(d->name);

		plen+= sizeof(struct rpcap_findalldevs_if);

		for (address = d->addresses; address != NULL; address = address->next)
		{
			/*
			 * Send only IPv4 and IPv6 addresses over the wire.
			 */
			switch (address->addr->sa_family)
			{
			case AF_INET:
#ifdef AF_INET6
			case AF_INET6:
#endif
				plen+= (sizeof(struct rpcap_sockaddr) * 4);
				break;

			default:
				break;
			}
		}
	}

	// RPCAP findalldevs command
	if (sock_bufferize(NULL, sizeof(struct rpcap_header), NULL,
	    &sendbufidx, RPCAP_NETBUF_SIZE, SOCKBUF_CHECKONLY, errmsgbuf,
	    PCAP_ERRBUF_SIZE) == -1)
		goto error;

	rpcap_createhdr((struct rpcap_header *) sendbuf, pars->protocol_version,
	    RPCAP_MSG_FINDALLIF_REPLY, nif, plen);

	// send the interface list
	for (d = alldevs; d != NULL; d = d->next)
	{
		uint16 lname, ldescr;

		findalldevs_if = (struct rpcap_findalldevs_if *) &sendbuf[sendbufidx];

		if (sock_bufferize(NULL, sizeof(struct rpcap_findalldevs_if), NULL,
		    &sendbufidx, RPCAP_NETBUF_SIZE, SOCKBUF_CHECKONLY, errmsgbuf, PCAP_ERRBUF_SIZE) == -1)
			goto error;

		memset(findalldevs_if, 0, sizeof(struct rpcap_findalldevs_if));

		if (d->description) ldescr = (short) strlen(d->description);
		else ldescr = 0;
		if (d->name) lname = (short) strlen(d->name);
		else lname = 0;

		findalldevs_if->desclen = htons(ldescr);
		findalldevs_if->namelen = htons(lname);
		findalldevs_if->flags = htonl(d->flags);

		for (address = d->addresses; address != NULL; address = address->next)
		{
			/*
			 * Send only IPv4 and IPv6 addresses over the wire.
			 */
			switch (address->addr->sa_family)
			{
			case AF_INET:
#ifdef AF_INET6
			case AF_INET6:
#endif
				findalldevs_if->naddr++;
				break;

			default:
				break;
			}
		}
		findalldevs_if->naddr = htons(findalldevs_if->naddr);

		if (sock_bufferize(d->name, lname, sendbuf, &sendbufidx,
		    RPCAP_NETBUF_SIZE, SOCKBUF_BUFFERIZE, errmsgbuf,
		    PCAP_ERRBUF_SIZE) == -1)
			goto error;

		if (sock_bufferize(d->description, ldescr, sendbuf, &sendbufidx,
		    RPCAP_NETBUF_SIZE, SOCKBUF_BUFFERIZE, errmsgbuf,
		    PCAP_ERRBUF_SIZE) == -1)
			goto error;

		// send all addresses
		for (address = d->addresses; address != NULL; address = address->next)
		{
			struct rpcap_sockaddr *sockaddr;

			/*
			 * Send only IPv4 and IPv6 addresses over the wire.
			 */
			switch (address->addr->sa_family)
			{
			case AF_INET:
#ifdef AF_INET6
			case AF_INET6:
#endif
				sockaddr = (struct rpcap_sockaddr *) &sendbuf[sendbufidx];
				if (sock_bufferize(NULL, sizeof(struct rpcap_sockaddr), NULL,
				    &sendbufidx, RPCAP_NETBUF_SIZE, SOCKBUF_CHECKONLY, errmsgbuf, PCAP_ERRBUF_SIZE) == -1)
					goto error;
				daemon_seraddr((struct sockaddr_storage *) address->addr, sockaddr);

				sockaddr = (struct rpcap_sockaddr *) &sendbuf[sendbufidx];
				if (sock_bufferize(NULL, sizeof(struct rpcap_sockaddr), NULL,
				    &sendbufidx, RPCAP_NETBUF_SIZE, SOCKBUF_CHECKONLY, errmsgbuf, PCAP_ERRBUF_SIZE) == -1)
					goto error;
				daemon_seraddr((struct sockaddr_storage *) address->netmask, sockaddr);

				sockaddr = (struct rpcap_sockaddr *) &sendbuf[sendbufidx];
				if (sock_bufferize(NULL, sizeof(struct rpcap_sockaddr), NULL,
				    &sendbufidx, RPCAP_NETBUF_SIZE, SOCKBUF_CHECKONLY, errmsgbuf, PCAP_ERRBUF_SIZE) == -1)
					goto error;
				daemon_seraddr((struct sockaddr_storage *) address->broadaddr, sockaddr);

				sockaddr = (struct rpcap_sockaddr *) &sendbuf[sendbufidx];
				if (sock_bufferize(NULL, sizeof(struct rpcap_sockaddr), NULL,
				    &sendbufidx, RPCAP_NETBUF_SIZE, SOCKBUF_CHECKONLY, errmsgbuf, PCAP_ERRBUF_SIZE) == -1)
					goto error;
				daemon_seraddr((struct sockaddr_storage *) address->dstaddr, sockaddr);
				break;

			default:
				break;
			}
		}
	}

	// We no longer need the device list. Free it.
	pcap_freealldevs(alldevs);

	// Send a final command that says "now send it!"
	if (sock_send(pars->sockctrl_out, sendbuf, sendbufidx, errbuf, PCAP_ERRBUF_SIZE) == -1)
	{
		rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
		return -1;
	}

	return 0;

error:
	if (alldevs)
		pcap_freealldevs(alldevs);

	if (rpcap_senderror(pars->sockctrl_out, pars->protocol_version,
	    PCAP_ERR_FINDALLIF, errmsgbuf, errbuf) == -1)
	{
		rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
		return -1;
	}
	return 0;
}

/*
	\param plen: the length of the current message (needed in order to be able
	to discard excess data in the message, if present)
*/
static int
daemon_msg_open_req(struct daemon_slpars *pars, uint32 plen, char *source, size_t sourcelen)
{
	char errbuf[PCAP_ERRBUF_SIZE];		// buffer for network errors
	char errmsgbuf[PCAP_ERRBUF_SIZE];	// buffer for errors to send to the client
	pcap_t *fp;				// pcap_t main variable
	int nread;
	char sendbuf[RPCAP_NETBUF_SIZE];	// temporary buffer in which data to be sent is buffered
	int sendbufidx = 0;			// index which keeps the number of bytes currently buffered
	struct rpcap_openreply *openreply;	// open reply message

	if (plen > sourcelen - 1)
	{
		pcap_snprintf(errmsgbuf, PCAP_ERRBUF_SIZE, "Source string too long");
		goto error;
	}

	nread = sock_recv(pars->sockctrl_in, source, plen,
	    SOCK_RECEIVEALL_YES|SOCK_EOF_IS_ERROR, errbuf, PCAP_ERRBUF_SIZE);
	if (nread == -1)
	{
		rpcapd_log(LOGPRIO_ERROR, "Read from client failed: %s", errbuf);
		return -1;
	}
	source[nread] = '\0';
	plen -= nread;

	// XXX - make sure it's *not* a URL; we don't support opening
	// remote devices here.

	// Open the selected device
	// This is a fake open, since we do that only to get the needed parameters, then we close the device again
	if ((fp = pcap_open_live(source,
			1500 /* fake snaplen */,
			0 /* no promis */,
			1000 /* fake timeout */,
			errmsgbuf)) == NULL)
		goto error;

	// Now, I can send a RPCAP open reply message
	if (sock_bufferize(NULL, sizeof(struct rpcap_header), NULL, &sendbufidx,
	    RPCAP_NETBUF_SIZE, SOCKBUF_CHECKONLY, errmsgbuf, PCAP_ERRBUF_SIZE) == -1)
		goto error;

	rpcap_createhdr((struct rpcap_header *) sendbuf, pars->protocol_version,
	    RPCAP_MSG_OPEN_REPLY, 0, sizeof(struct rpcap_openreply));

	openreply = (struct rpcap_openreply *) &sendbuf[sendbufidx];

	if (sock_bufferize(NULL, sizeof(struct rpcap_openreply), NULL, &sendbufidx,
	    RPCAP_NETBUF_SIZE, SOCKBUF_CHECKONLY, errmsgbuf, PCAP_ERRBUF_SIZE) == -1)
		goto error;

	memset(openreply, 0, sizeof(struct rpcap_openreply));
	openreply->linktype = htonl(pcap_datalink(fp));
	openreply->tzoff = 0; /* This is always 0 for live captures */

	// We're done with the pcap_t.
	pcap_close(fp);

	// Send the reply.
	if (sock_send(pars->sockctrl_out, sendbuf, sendbufidx, errbuf, PCAP_ERRBUF_SIZE) == -1)
	{
		rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
		return -1;
	}
	return 0;

error:
	if (rpcap_senderror(pars->sockctrl_out, pars->protocol_version,
	    PCAP_ERR_OPEN, errmsgbuf, errbuf) == -1)
	{
		// That failed; log a message and give up.
		rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
		return -1;
	}

	// Check if all the data has been read; if not, discard the data in excess
	if (rpcapd_discard(pars->sockctrl_in, plen) == -1)
	{
		return -1;
	}
	return 0;
}

/*
	\param plen: the length of the current message (needed in order to be able
	to discard excess data in the message, if present)
*/
static int
daemon_msg_startcap_req(struct daemon_slpars *pars, uint32 plen, struct thread_handle *threaddata, char *source, struct session **sessionp, struct rpcap_sampling *samp_param _U_)
{
	char errbuf[PCAP_ERRBUF_SIZE];		// buffer for network errors
	char errmsgbuf[PCAP_ERRBUF_SIZE];	// buffer for errors to send to the client
	char portdata[PCAP_BUF_SIZE];		// temp variable needed to derive the data port
	char peerhost[PCAP_BUF_SIZE];		// temp variable needed to derive the host name of our peer
	struct session *session = NULL;		// saves state of session
	int status;
	char sendbuf[RPCAP_NETBUF_SIZE];	// temporary buffer in which data to be sent is buffered
	int sendbufidx = 0;			// index which keeps the number of bytes currently buffered

	// socket-related variables
	SOCKET sockdata = INVALID_SOCKET;	// socket descriptor of the data connection
	struct addrinfo hints;			// temp, needed to open a socket connection
	struct addrinfo *addrinfo;		// temp, needed to open a socket connection
	struct sockaddr_storage saddr;		// temp, needed to retrieve the network data port chosen on the local machine
	socklen_t saddrlen;			// temp, needed to retrieve the network data port chosen on the local machine
	int ret;				// return value from functions

#ifndef _WIN32
	pthread_attr_t detachedAttribute;	// temp, needed to set the created thread as detached
#endif

	// RPCAP-related variables
	struct rpcap_startcapreq startcapreq;		// start capture request message
	struct rpcap_startcapreply *startcapreply;	// start capture reply message
	int serveropen_dp;							// keeps who is going to open the data connection

	addrinfo = NULL;

	status = rpcapd_recv(pars->sockctrl_in, (char *) &startcapreq,
	    sizeof(struct rpcap_startcapreq), &plen, errmsgbuf);
	if (status == -1)
	{
		goto fatal_error;
	}
	if (status == -2)
	{
		goto error;
	}

	startcapreq.flags = ntohs(startcapreq.flags);

	// Create a session structure
	session = malloc(sizeof(struct session));
	if (session == NULL)
	{
		pcap_snprintf(errmsgbuf, PCAP_ERRBUF_SIZE, "Can't allocate session structure");
		goto error;
	}

	// Open the selected device
	if ((session->fp = pcap_open_live(source,
			ntohl(startcapreq.snaplen),
			(startcapreq.flags & RPCAP_STARTCAPREQ_FLAG_PROMISC) ? 1 : 0 /* local device, other flags not needed */,
			ntohl(startcapreq.read_timeout),
			errmsgbuf)) == NULL)
		goto error;

#if 0
	// Apply sampling parameters
	fp->rmt_samp.method = samp_param->method;
	fp->rmt_samp.value = samp_param->value;
#endif

	/*
	We're in active mode if:
	- we're using TCP, and the user wants us to be in active mode
	- we're using UDP
	*/
	serveropen_dp = (startcapreq.flags & RPCAP_STARTCAPREQ_FLAG_SERVEROPEN) || (startcapreq.flags & RPCAP_STARTCAPREQ_FLAG_DGRAM) || pars->isactive;

	/*
	Gets the sockaddr structure referred to the other peer in the ctrl connection

	We need that because:
	- if we're in passive mode, we need to know the address family we want to use
	(the same used for the ctrl socket)
	- if we're in active mode, we need to know the network address of the other host
	we want to connect to
	*/
	saddrlen = sizeof(struct sockaddr_storage);
	if (getpeername(pars->sockctrl_in, (struct sockaddr *) &saddr, &saddrlen) == -1)
	{
		sock_geterror("getpeername(): ", errmsgbuf, PCAP_ERRBUF_SIZE);
		goto error;
	}

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_socktype = (startcapreq.flags & RPCAP_STARTCAPREQ_FLAG_DGRAM) ? SOCK_DGRAM : SOCK_STREAM;
	hints.ai_family = saddr.ss_family;

	// Now we have to create a new socket to send packets
	if (serveropen_dp)		// Data connection is opened by the server toward the client
	{
		pcap_snprintf(portdata, sizeof portdata, "%d", ntohs(startcapreq.portdata));

		// Get the name of the other peer (needed to connect to that specific network address)
		if (getnameinfo((struct sockaddr *) &saddr, saddrlen, peerhost,
				sizeof(peerhost), NULL, 0, NI_NUMERICHOST))
		{
			sock_geterror("getnameinfo(): ", errmsgbuf, PCAP_ERRBUF_SIZE);
			goto error;
		}

		if (sock_initaddress(peerhost, portdata, &hints, &addrinfo, errmsgbuf, PCAP_ERRBUF_SIZE) == -1)
			goto error;

		if ((sockdata = sock_open(addrinfo, SOCKOPEN_CLIENT, 0, errmsgbuf, PCAP_ERRBUF_SIZE)) == INVALID_SOCKET)
			goto error;
	}
	else		// Data connection is opened by the client toward the server
	{
		hints.ai_flags = AI_PASSIVE;

		// Let's the server socket pick up a free network port for us
		if (sock_initaddress(NULL, "0", &hints, &addrinfo, errmsgbuf, PCAP_ERRBUF_SIZE) == -1)
			goto error;

		if ((sockdata = sock_open(addrinfo, SOCKOPEN_SERVER, 1 /* max 1 connection in queue */, errmsgbuf, PCAP_ERRBUF_SIZE)) == INVALID_SOCKET)
			goto error;

		// get the complete sockaddr structure used in the data connection
		saddrlen = sizeof(struct sockaddr_storage);
		if (getsockname(sockdata, (struct sockaddr *) &saddr, &saddrlen) == -1)
		{
			sock_geterror("getsockname(): ", errmsgbuf, PCAP_ERRBUF_SIZE);
			goto error;
		}

		// Get the local port the system picked up
		if (getnameinfo((struct sockaddr *) &saddr, saddrlen, NULL,
				0, portdata, sizeof(portdata), NI_NUMERICSERV))
		{
			sock_geterror("getnameinfo(): ", errmsgbuf, PCAP_ERRBUF_SIZE);
			goto error;
		}
	}

	// addrinfo is no longer used
	freeaddrinfo(addrinfo);
	addrinfo = NULL;

	// Needed to send an error on the ctrl connection
	session->sockctrl_out = pars->sockctrl_out;
	session->protocol_version = pars->protocol_version;

	// Now I can set the filter
	ret = daemon_unpackapplyfilter(pars->sockctrl_in, session, &plen, errmsgbuf);
	if (ret == -1)
	{
		// Fatal error.  A message has been logged; just give up.
		goto fatal_error;
	}
	if (ret == -2)
	{
		// Non-fatal error.  Send an error message to the client.
		goto error;
	}

	// Now, I can send a RPCAP start capture reply message
	if (sock_bufferize(NULL, sizeof(struct rpcap_header), NULL, &sendbufidx,
	    RPCAP_NETBUF_SIZE, SOCKBUF_CHECKONLY, errmsgbuf, PCAP_ERRBUF_SIZE) == -1)
		goto error;

	rpcap_createhdr((struct rpcap_header *) sendbuf, pars->protocol_version,
	    RPCAP_MSG_STARTCAP_REPLY, 0, sizeof(struct rpcap_startcapreply));

	startcapreply = (struct rpcap_startcapreply *) &sendbuf[sendbufidx];

	if (sock_bufferize(NULL, sizeof(struct rpcap_startcapreply), NULL,
	    &sendbufidx, RPCAP_NETBUF_SIZE, SOCKBUF_CHECKONLY, errmsgbuf, PCAP_ERRBUF_SIZE) == -1)
		goto error;

	memset(startcapreply, 0, sizeof(struct rpcap_startcapreply));
	startcapreply->bufsize = htonl(pcap_bufsize(session->fp));

	if (!serveropen_dp)
	{
		unsigned short port = (unsigned short)strtoul(portdata,NULL,10);
		startcapreply->portdata = htons(port);
	}

	if (sock_send(pars->sockctrl_out, sendbuf, sendbufidx, errbuf, PCAP_ERRBUF_SIZE) == -1)
	{
		// That failed; log a message and give up.
		rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
		goto fatal_error;
	}

	if (!serveropen_dp)
	{
		SOCKET socktemp;	// We need another socket, since we're going to accept() a connection

		// Connection creation
		saddrlen = sizeof(struct sockaddr_storage);

		socktemp = accept(sockdata, (struct sockaddr *) &saddr, &saddrlen);

		if (socktemp == INVALID_SOCKET)
		{
			sock_geterror("accept(): ", errbuf, PCAP_ERRBUF_SIZE);
			rpcapd_log(LOGPRIO_ERROR, "Accept of data connection failed: %s",
			    errbuf);
			goto error;
		}

		// Now that I accepted the connection, the server socket is no longer needed
		sock_close(sockdata, NULL, 0);
		sockdata = socktemp;
	}

	session->sockdata = sockdata;

	// Now we have to create a new thread to receive packets
#ifdef _WIN32
	threaddata->thread = (HANDLE)_beginthreadex(NULL, 0, daemon_thrdatamain,
	    (void *) session, 0, NULL);
	if (threaddata->thread == 0)
	{
		pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "Error creating the data thread");
		goto error;
	}
#else
	/* GV we need this to create the thread as detached. */
	/* GV otherwise, the thread handle is not destroyed  */
	pthread_attr_init(&detachedAttribute);
	pthread_attr_setdetachstate(&detachedAttribute, PTHREAD_CREATE_DETACHED);
	ret = pthread_create(&threaddata->thread, &detachedAttribute,
	    daemon_thrdatamain, (void *) session);
	if (ret != 0)
	{
		pcap_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE,
		    ret, "Error creating the data thread");
		pthread_attr_destroy(&detachedAttribute);
		goto error;
	}
	pthread_attr_destroy(&detachedAttribute);
#endif
	threaddata->have_thread = 1;

	// Check if all the data has been read; if not, discard the data in excess
	if (rpcapd_discard(pars->sockctrl_in, plen) == -1)
		goto fatal_error;

	*sessionp = session;
	return 0;

error:
	//
	// Not a fatal error, so send the client an error message and
	// keep serving client requests.
	//
	*sessionp = NULL;

	if (addrinfo)
		freeaddrinfo(addrinfo);

	if (threaddata->have_thread)
	{
#ifdef _WIN32
		if (session->fp)
		{
			pcap_breakloop(session->fp);
			SetEvent(pcap_getevent(session->fp));
		}
		CloseHandle(threaddata->thread);
#else
		pthread_cancel(threaddata->thread);
#endif
		threaddata->have_thread = 0;
	}

	if (sockdata != INVALID_SOCKET)
		sock_close(sockdata, NULL, 0);

	if (session)
	{
		if (session->fp)
			pcap_close(session->fp);
		free(session);
	}

	if (rpcap_senderror(pars->sockctrl_out, pars->protocol_version,
	    PCAP_ERR_STARTCAPTURE, errmsgbuf, errbuf) == -1)
	{
		// That failed; log a message and give up.
		rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
		return -1;
	}

	// Check if all the data has been read; if not, discard the data in excess
	if (rpcapd_discard(pars->sockctrl_in, plen) == -1)
	{
		// Network error.
		return -1;
	}

	return 0;

fatal_error:
	//
	// Fatal network error, so don't try to communicate with
	// the client, just give up.
	//
	*sessionp = NULL;

	if (threaddata->have_thread)
	{
#ifdef _WIN32
		if (session && session->fp)
		{
			//
			// Tell the data connection thread main capture
			// loop to break out of that loop.
			//
			pcap_breakloop(session->fp);

			//
			// If it's currently blocked waiting for packets
			// to arrive, try to wake it up, so it can see
			// the "break out of the loop" indication.
			//
			SetEvent(pcap_getevent(session->fp));
		}

		//
		// Wait for the thread to exit, so we don't close
		// sockets out from under it.
		//
		// XXX - have a timeout, so we don't wait forever?
		//
		WaitForSingleObject(threaddata->thread, INFINITE);

		//
		// Release the thread handle, as we're done with
		// it.
		//
		CloseHandle(threaddata->thread);
#else
		pthread_cancel(threaddata->thread);
#endif
		threaddata->have_thread = 0;
	}

	if (sockdata != INVALID_SOCKET)
		sock_close(sockdata, NULL, 0);

	if (session)
	{
		if (session->fp)
			pcap_close(session->fp);
		free(session);
	}

	return -1;
}

static int
daemon_msg_endcap_req(struct daemon_slpars *pars, struct session *session, struct thread_handle *threaddata)
{
	char errbuf[PCAP_ERRBUF_SIZE];		// buffer for network errors
	struct rpcap_header header;

	if (threaddata->have_thread)
	{
#ifdef _WIN32
		//
		// Tell the data connection thread main capture loop to
		// break out of that loop.
		//
		pcap_breakloop(session->fp);

		//
		// If it's currently blocked waiting for packets to
		// arrive, try to wake it up, so it can see the "break
		// out of the loop" indication.
		//
		SetEvent(pcap_getevent(session->fp));

		//
		// Wait for the thread to exit, so we don't close
		// sockets out from under it.
		//
		// XXX - have a timeout, so we don't wait forever?
		//
		WaitForSingleObject(threaddata->thread, INFINITE);

		//
		// Release the thread handle, as we're done with
		// it.
		//
		CloseHandle(threaddata->thread);
#else
		pthread_cancel(threaddata->thread);
#endif
		threaddata->have_thread = 0;
	}
	if (session->sockdata)
	{
		sock_close(session->sockdata, NULL, 0);
		session->sockdata = 0;
	}

	pcap_close(session->fp);

	rpcap_createhdr(&header, pars->protocol_version,
	    RPCAP_MSG_ENDCAP_REPLY, 0, 0);

	if (sock_send(pars->sockctrl_out, (char *) &header, sizeof(struct rpcap_header), errbuf, PCAP_ERRBUF_SIZE) == -1)
	{
		// That failed; log a message and give up.
		rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
		return -1;
	}

	return 0;
}

static int
daemon_unpackapplyfilter(SOCKET sockctrl_in, struct session *session, uint32 *plenp, char *errmsgbuf)
{
	int status;
	struct rpcap_filter filter;
	struct rpcap_filterbpf_insn insn;
	struct bpf_insn *bf_insn;
	struct bpf_program bf_prog;
	unsigned int i;

	status = rpcapd_recv(sockctrl_in, (char *) &filter,
	    sizeof(struct rpcap_filter), plenp, errmsgbuf);
	if (status == -1)
	{
		return -1;
	}
	if (status == -2)
	{
		return -2;
	}

	bf_prog.bf_len = ntohl(filter.nitems);

	if (ntohs(filter.filtertype) != RPCAP_UPDATEFILTER_BPF)
	{
		pcap_snprintf(errmsgbuf, PCAP_ERRBUF_SIZE, "Only BPF/NPF filters are currently supported");
		return -2;
	}

	bf_insn = (struct bpf_insn *) malloc (sizeof(struct bpf_insn) * bf_prog.bf_len);
	if (bf_insn == NULL)
	{
		pcap_fmt_errmsg_for_errno(errmsgbuf, PCAP_ERRBUF_SIZE,
		    errno, "malloc() failed");
		return -2;
	}

	bf_prog.bf_insns = bf_insn;

	for (i = 0; i < bf_prog.bf_len; i++)
	{
		status = rpcapd_recv(sockctrl_in, (char *) &insn,
		    sizeof(struct rpcap_filterbpf_insn), plenp, errmsgbuf);
		if (status == -1)
		{
			return -1;
		}
		if (status == -2)
		{
			return -2;
		}

		bf_insn->code = ntohs(insn.code);
		bf_insn->jf = insn.jf;
		bf_insn->jt = insn.jt;
		bf_insn->k = ntohl(insn.k);

		bf_insn++;
	}

	if (bpf_validate(bf_prog.bf_insns, bf_prog.bf_len) == 0)
	{
		pcap_snprintf(errmsgbuf, PCAP_ERRBUF_SIZE, "The filter contains bogus instructions");
		return -2;
	}

	if (pcap_setfilter(session->fp, &bf_prog))
	{
		pcap_snprintf(errmsgbuf, PCAP_ERRBUF_SIZE, "RPCAP error: %s", pcap_geterr(session->fp));
		return -2;
	}

	return 0;
}

static int
daemon_msg_updatefilter_req(struct daemon_slpars *pars, struct session *session, uint32 plen)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char errmsgbuf[PCAP_ERRBUF_SIZE];	// buffer for errors to send to the client
	int ret;				// status of daemon_unpackapplyfilter()
	struct rpcap_header header;		// keeps the answer to the updatefilter command

	ret = daemon_unpackapplyfilter(pars->sockctrl_in, session, &plen, errmsgbuf);
	if (ret == -1)
	{
		// Fatal error.  A message has been logged; just give up.
		return -1;
	}
	if (ret == -2)
	{
		// Non-fatal error.  Send an error reply to the client.
		goto error;
	}

	// Check if all the data has been read; if not, discard the data in excess
	if (rpcapd_discard(pars->sockctrl_in, plen) == -1)
	{
		// Network error.
		return -1;
	}

	// A response is needed, otherwise the other host does not know that everything went well
	rpcap_createhdr(&header, pars->protocol_version,
	    RPCAP_MSG_UPDATEFILTER_REPLY, 0, 0);

	if (sock_send(pars->sockctrl_out, (char *) &header, sizeof (struct rpcap_header), pcap_geterr(session->fp), PCAP_ERRBUF_SIZE))
	{
		// That failed; log a messsage and give up.
		rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
		return -1;
	}

	return 0;

error:
	if (rpcapd_discard(pars->sockctrl_in, plen) == -1)
	{
		return -1;
	}
	rpcap_senderror(pars->sockctrl_out, pars->protocol_version,
	    PCAP_ERR_UPDATEFILTER, errmsgbuf, NULL);

	return 0;
}

/*!
	\brief Received the sampling parameters from remote host and it stores in the pcap_t structure.
*/
static int
daemon_msg_setsampling_req(struct daemon_slpars *pars, uint32 plen, struct rpcap_sampling *samp_param)
{
	char errbuf[PCAP_ERRBUF_SIZE];		// buffer for network errors
	char errmsgbuf[PCAP_ERRBUF_SIZE];
	struct rpcap_header header;
	struct rpcap_sampling rpcap_samp;
	int status;

	status = rpcapd_recv(pars->sockctrl_in, (char *) &rpcap_samp, sizeof(struct rpcap_sampling), &plen, errmsgbuf);
	if (status == -1)
	{
		return -1;
	}
	if (status == -2)
	{
		goto error;
	}

	// Save these settings in the pcap_t
	samp_param->method = rpcap_samp.method;
	samp_param->value = ntohl(rpcap_samp.value);

	// A response is needed, otherwise the other host does not know that everything went well
	rpcap_createhdr(&header, pars->protocol_version,
	    RPCAP_MSG_SETSAMPLING_REPLY, 0, 0);

	if (sock_send(pars->sockctrl_out, (char *) &header, sizeof (struct rpcap_header), errbuf, PCAP_ERRBUF_SIZE) == -1)
	{
		// That failed; log a messsage and give up.
		rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
		return -1;
	}

	if (rpcapd_discard(pars->sockctrl_in, plen) == -1)
	{
		return -1;
	}

	return 0;

error:
	if (rpcap_senderror(pars->sockctrl_out, pars->protocol_version,
	    PCAP_ERR_AUTH, errmsgbuf, errbuf) == -1)
	{
		// That failed; log a message and give up.
		rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
		return -1;
	}

	// Check if all the data has been read; if not, discard the data in excess
	if (rpcapd_discard(pars->sockctrl_in, plen) == -1)
	{
		return -1;
	}

	return 0;
}

static int
daemon_msg_stats_req(struct daemon_slpars *pars, struct session *session, uint32 plen, struct pcap_stat *stats, unsigned int svrcapt)
{
	char errbuf[PCAP_ERRBUF_SIZE];		// buffer for network errors
	char errmsgbuf[PCAP_ERRBUF_SIZE];	// buffer for errors to send to the client
	char sendbuf[RPCAP_NETBUF_SIZE];	// temporary buffer in which data to be sent is buffered
	int sendbufidx = 0;			// index which keeps the number of bytes currently buffered
	struct rpcap_stats *netstats;		// statistics sent on the network

	// Checks that the header does not contain other data; if so, discard it
	if (rpcapd_discard(pars->sockctrl_in, plen) == -1)
	{
		// Network error.
		return -1;
	}

	if (sock_bufferize(NULL, sizeof(struct rpcap_header), NULL,
	    &sendbufidx, RPCAP_NETBUF_SIZE, SOCKBUF_CHECKONLY, errmsgbuf, PCAP_ERRBUF_SIZE) == -1)
		goto error;

	rpcap_createhdr((struct rpcap_header *) sendbuf, pars->protocol_version,
	    RPCAP_MSG_STATS_REPLY, 0, (uint16) sizeof(struct rpcap_stats));

	netstats = (struct rpcap_stats *) &sendbuf[sendbufidx];

	if (sock_bufferize(NULL, sizeof(struct rpcap_stats), NULL,
	    &sendbufidx, RPCAP_NETBUF_SIZE, SOCKBUF_CHECKONLY, errmsgbuf, PCAP_ERRBUF_SIZE) == -1)
		goto error;

	if (session && session->fp)
	{
		if (pcap_stats(session->fp, stats) == -1)
		{
			pcap_snprintf(errmsgbuf, PCAP_ERRBUF_SIZE, "%s", pcap_geterr(session->fp));
			goto error;
		}

		netstats->ifdrop = htonl(stats->ps_ifdrop);
		netstats->ifrecv = htonl(stats->ps_recv);
		netstats->krnldrop = htonl(stats->ps_drop);
		netstats->svrcapt = htonl(session->TotCapt);
	}
	else
	{
		// We have to keep compatibility with old applications,
		// which ask for statistics also when the capture has
		// already stopped.
		netstats->ifdrop = htonl(stats->ps_ifdrop);
		netstats->ifrecv = htonl(stats->ps_recv);
		netstats->krnldrop = htonl(stats->ps_drop);
		netstats->svrcapt = htonl(svrcapt);
	}

	// Send the packet
	if (sock_send(pars->sockctrl_out, sendbuf, sendbufidx, errbuf, PCAP_ERRBUF_SIZE) == -1)
	{
		rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
		return -1;
	}

	return 0;

error:
	rpcap_senderror(pars->sockctrl_out, pars->protocol_version,
	    PCAP_ERR_GETSTATS, errmsgbuf, NULL);
	return 0;
}

#ifdef _WIN32
static unsigned __stdcall
#else
static void *
#endif
daemon_thrdatamain(void *ptr)
{
	char errbuf[PCAP_ERRBUF_SIZE + 1];	// error buffer
	struct session *session;		// pointer to the struct session for this session
	int retval;							// general variable used to keep the return value of other functions
	struct rpcap_pkthdr *net_pkt_header;// header of the packet
	struct pcap_pkthdr *pkt_header;		// pointer to the buffer that contains the header of the current packet
	u_char *pkt_data;					// pointer to the buffer that contains the current packet
	size_t sendbufsize;			// size for the send buffer
	char *sendbuf;						// temporary buffer in which data to be sent is buffered
	int sendbufidx;						// index which keeps the number of bytes currently buffered
	int status;

	session = (struct session *) ptr;

	session->TotCapt = 0;			// counter which is incremented each time a packet is received

	// Initialize errbuf
	memset(errbuf, 0, sizeof(errbuf));

	//
	// We need a buffer large enough to hold a buffer large enough
	// for a maximum-size packet for this pcap_t.
	//
	if (pcap_snapshot(session->fp) < 0)
	{
		//
		// The snapshot length is negative.
		// This "should not happen".
		//
		rpcapd_log(LOGPRIO_ERROR,
		    "Unable to allocate the buffer for this child thread: snapshot length of %d is negative",
		        pcap_snapshot(session->fp));
		sendbuf = NULL;	// we can't allocate a buffer, so nothing to free
		goto error;
	}
	//
	// size_t is unsigned, and the result of pcap_snapshot() is signed;
	// on no platform that we support is int larger than size_t.
	// This means that, unless the extra information we prepend to
	// a maximum-sized packet is impossibly large, the sum of the
	// snapshot length and the size of that extra information will
	// fit in a size_t.
	//
	// So we don't need to make sure that sendbufsize will overflow.
	//
	sendbufsize = sizeof(struct rpcap_header) + sizeof(struct rpcap_pkthdr) + pcap_snapshot(session->fp);
	sendbuf = (char *) malloc (sendbufsize);
	if (sendbuf == NULL)
	{
		rpcapd_log(LOGPRIO_ERROR,
		    "Unable to allocate the buffer for this child thread");
		goto error;
	}

#ifndef _WIN32
	// Modify thread params so that it can be killed at any time
	retval = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	if (retval != 0)
	{
		pcap_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE,
		    retval, "pthread_setcancelstate");
		rpcapd_log(LOGPRIO_ERROR,
		    "Can't set cancel state on data thread: %s", errbuf);
		goto error;
	}
	retval = pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	if (retval != 0)
	{
		pcap_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE,
		    retval, "pthread_setcanceltype");
		rpcapd_log(LOGPRIO_ERROR,
		    "Can't set cancel type on data thread: %s", errbuf);
		goto error;
	}
#endif

	// Retrieve the packets
	while ((retval = pcap_next_ex(session->fp, &pkt_header, (const u_char **) &pkt_data)) >= 0)	// cast to avoid a compiler warning
	{
		if (retval == 0)	// Read timeout elapsed
			continue;

		sendbufidx = 0;

		// Bufferize the general header
		if (sock_bufferize(NULL, sizeof(struct rpcap_header), NULL,
		    &sendbufidx, sendbufsize, SOCKBUF_CHECKONLY, errbuf,
		    PCAP_ERRBUF_SIZE) == -1)
		{
			rpcapd_log(LOGPRIO_ERROR,
			    "sock_bufferize() error sending packet message: %s",
			    errbuf);
			goto error;
		}

		rpcap_createhdr((struct rpcap_header *) sendbuf,
		    session->protocol_version, RPCAP_MSG_PACKET, 0,
		    (uint16) (sizeof(struct rpcap_pkthdr) + pkt_header->caplen));

		net_pkt_header = (struct rpcap_pkthdr *) &sendbuf[sendbufidx];

		// Bufferize the pkt header
		if (sock_bufferize(NULL, sizeof(struct rpcap_pkthdr), NULL,
		    &sendbufidx, sendbufsize, SOCKBUF_CHECKONLY, errbuf,
		    PCAP_ERRBUF_SIZE) == -1)
		{
			rpcapd_log(LOGPRIO_ERROR,
			    "sock_bufferize() error sending packet message: %s",
			    errbuf);
			goto error;
		}

		net_pkt_header->caplen = htonl(pkt_header->caplen);
		net_pkt_header->len = htonl(pkt_header->len);
		net_pkt_header->npkt = htonl(++(session->TotCapt));
		net_pkt_header->timestamp_sec = htonl(pkt_header->ts.tv_sec);
		net_pkt_header->timestamp_usec = htonl(pkt_header->ts.tv_usec);

		// Bufferize the pkt data
		if (sock_bufferize((char *) pkt_data, pkt_header->caplen,
		    sendbuf, &sendbufidx, sendbufsize, SOCKBUF_BUFFERIZE,
		    errbuf, PCAP_ERRBUF_SIZE) == -1)
		{
			rpcapd_log(LOGPRIO_ERROR,
			    "sock_bufferize() error sending packet message: %s",
			    errbuf);
			goto error;
		}

		// Send the packet
		// If the client dropped the connection, don't report an
		// error, just quit.
		status = sock_send(session->sockdata, sendbuf, sendbufidx, errbuf, PCAP_ERRBUF_SIZE);
		if (status < 0)
		{
			if (status == -1)
			{
				//
				// Error other than "client closed the
				// connection out from under us"; report
				// it.
				//
				rpcapd_log(LOGPRIO_ERROR,
				    "Send of packet to client failed: %s",
				    errbuf);
			}

			//
			// Give up in either case.
			//
			goto error;
		}
	}

	if (retval == -1)
	{
		pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "Error reading the packets: %s", pcap_geterr(session->fp));
		rpcap_senderror(session->sockctrl_out, session->protocol_version,
		    PCAP_ERR_READEX, errbuf, NULL);
		goto error;
	}

error:
 	closesocket(session->sockdata);
	session->sockdata = 0;

	free(sendbuf);

	return 0;
}

/*!
	\brief It serializes a network address.

	It accepts a 'sockaddr_storage' structure as input, and it converts it appropriately into a format
	that can be used to be sent on the network. Basically, it applies all the hton()
	conversion required to the input variable.

	\param sockaddrin a 'sockaddr_storage' pointer to the variable that has to be
	serialized. This variable can be both a 'sockaddr_in' and 'sockaddr_in6'.

	\param sockaddrout an 'rpcap_sockaddr' pointer to the variable that will contain
	the serialized data. This variable has to be allocated by the user.

	\warning This function supports only AF_INET and AF_INET6 address families.
*/
static void
daemon_seraddr(struct sockaddr_storage *sockaddrin, struct rpcap_sockaddr *sockaddrout)
{
	memset(sockaddrout, 0, sizeof(struct sockaddr_storage));

	// There can be the case in which the sockaddrin is not available
	if (sockaddrin == NULL) return;

	// Warning: we support only AF_INET and AF_INET6
	switch (sockaddrin->ss_family)
	{
	case AF_INET:
		{
		struct sockaddr_in *sockaddrin_ipv4;
		struct rpcap_sockaddr_in *sockaddrout_ipv4;

		sockaddrin_ipv4 = (struct sockaddr_in *) sockaddrin;
		sockaddrout_ipv4 = (struct rpcap_sockaddr_in *) sockaddrout;
		sockaddrout_ipv4->family = htons(RPCAP_AF_INET);
		sockaddrout_ipv4->port = htons(sockaddrin_ipv4->sin_port);
		memcpy(&sockaddrout_ipv4->addr, &sockaddrin_ipv4->sin_addr, sizeof(sockaddrout_ipv4->addr));
		memset(sockaddrout_ipv4->zero, 0, sizeof(sockaddrout_ipv4->zero));
		break;
		}

#ifdef AF_INET6
	case AF_INET6:
		{
		struct sockaddr_in6 *sockaddrin_ipv6;
		struct rpcap_sockaddr_in6 *sockaddrout_ipv6;

		sockaddrin_ipv6 = (struct sockaddr_in6 *) sockaddrin;
		sockaddrout_ipv6 = (struct rpcap_sockaddr_in6 *) sockaddrout;
		sockaddrout_ipv6->family = htons(RPCAP_AF_INET6);
		sockaddrout_ipv6->port = htons(sockaddrin_ipv6->sin6_port);
		sockaddrout_ipv6->flowinfo = htonl(sockaddrin_ipv6->sin6_flowinfo);
		memcpy(&sockaddrout_ipv6->addr, &sockaddrin_ipv6->sin6_addr, sizeof(sockaddrout_ipv6->addr));
		sockaddrout_ipv6->scope_id = htonl(sockaddrin_ipv6->sin6_scope_id);
		break;
		}
#endif
	}
}


/*!
	\brief Suspends a thread for secs seconds.
*/
void sleep_secs(int secs)
{
#ifdef _WIN32
	Sleep(secs*1000);
#else
	unsigned secs_remaining;

	if (secs <= 0)
		return;
	secs_remaining = secs;
	while (secs_remaining != 0)
		secs_remaining = sleep(secs_remaining);
#endif
}

/*
 * Read the header of a message.
 */
static int
rpcapd_recv_msg_header(SOCKET sock, struct rpcap_header *headerp)
{
	int nread;
	char errbuf[PCAP_ERRBUF_SIZE];		// buffer for network errors

	nread = sock_recv(sock, (char *) headerp, sizeof(struct rpcap_header),
	    SOCK_RECEIVEALL_YES|SOCK_EOF_ISNT_ERROR, errbuf, PCAP_ERRBUF_SIZE);
	if (nread == -1)
	{
		// Network error.
		rpcapd_log(LOGPRIO_ERROR, "Read from client failed: %s", errbuf);
		return -1;
	}
	if (nread == 0)
	{
		// Immediate EOF; that's treated like a close message.
		return -2;
	}
	headerp->plen = ntohl(headerp->plen);
	return 0;
}

/*
 * Read data from a message.
 * If we're trying to read more data that remains, puts an error
 * message into errmsgbuf and returns -2.  Otherwise, tries to read
 * the data and, if that succeeds, subtracts the amount read from
 * the number of bytes of data that remains.
 * Returns 0 on success, logs a message and returns -1 on a network
 * error.
 */
static int
rpcapd_recv(SOCKET sock, char *buffer, size_t toread, uint32 *plen, char *errmsgbuf)
{
	int nread;
	char errbuf[PCAP_ERRBUF_SIZE];		// buffer for network errors

	if (toread > *plen)
	{
		// Tell the client and continue.
		pcap_snprintf(errmsgbuf, PCAP_ERRBUF_SIZE, "Message payload is too short");
		return -2;
	}
	nread = sock_recv(sock, buffer, toread,
	    SOCK_RECEIVEALL_YES|SOCK_EOF_IS_ERROR, errbuf, PCAP_ERRBUF_SIZE);
	if (nread == -1)
	{
		rpcapd_log(LOGPRIO_ERROR, "Read from client failed: %s", errbuf);
		return -1;
	}
	*plen -= nread;
	return 0;
}

/*
 * Discard data from a connection.
 * Mostly used to discard wrong-sized messages.
 * Returns 0 on success, logs a message and returns -1 on a network
 * error.
 */
static int
rpcapd_discard(SOCKET sock, uint32 len)
{
	char errbuf[PCAP_ERRBUF_SIZE + 1];	// keeps the error string, prior to be printed

	if (len != 0)
	{
		if (sock_discard(sock, len, errbuf, PCAP_ERRBUF_SIZE) == -1)
		{
			// Network error.
			rpcapd_log(LOGPRIO_ERROR, "Read from client failed: %s", errbuf);
			return -1;
		}
	}
	return 0;
}
