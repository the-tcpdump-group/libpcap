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
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "ftmacros.h"

#include <errno.h>		// for the errno variable
#include <string.h>		// for strtok, etc
#include <stdlib.h>		// for malloc(), free(), ...
#include <pcap.h>		// for PCAP_ERRBUF_SIZE
#include <signal.h>		// for signal()

#include "fmtutils.h"
#include "sockutils.h"		// for socket calls
#include "portability.h"
#include "rpcapd.h"
#include "fileconf.h"		// for the configuration file management
#include "rpcap-protocol.h"
#include "daemon.h"		// the true main() method of this daemon
#include "log.h"

#ifdef _WIN32
  #include <process.h>		// for thread stuff
  #include "win32-svc.h"	// for Win32 service stuff
  #include "getopt.h"		// for getopt()-for-Windows
#else
  #include <unistd.h>		// for exit()
  #include <sys/wait.h>		// waitpid()
#endif


// Global variables
char hostlist[MAX_HOST_LIST + 1];		//!< Keeps the list of the hosts that are allowed to connect to this server
struct active_pars activelist[MAX_ACTIVE_LIST];		//!< Keeps the list of the hosts (host, port) on which I want to connect to (active mode)
int nullAuthAllowed;				//!< '1' if we permit NULL authentication, '0' otherwise
static SOCKET sockmain;				//!< keeps the main socket identifier
char loadfile[MAX_LINE + 1];			//!< Name of the file from which we have to load the configuration
int passivemode = 1;				//!< '1' if we want to run in passive mode as well
struct addrinfo mainhints;			//!< temporary struct to keep settings needed to open the new socket
char address[MAX_LINE + 1];			//!< keeps the network address (either numeric or literal) to bind to
char port[MAX_LINE + 1];			//!< keeps the network port to bind to

extern char *optarg;	// for getopt()

// Function definition
#ifdef _WIN32
static unsigned __stdcall main_passive(void *ptr);
static unsigned __stdcall main_active(void *ptr);
#else
static void *main_passive(void *ptr);
static void *main_active(void *ptr);
#endif

static void main_terminate(int sign);
#ifdef _WIN32
static void main_abort(int sign);
#else
static void main_reap_children(int sign);
#endif

#define RPCAP_ACTIVE_WAIT 30		/* Waiting time between two attempts to open a connection, in active mode (default: 30 sec) */

/*!
	\brief Prints the usage screen if it is launched in console mode.
*/
static void printusage(void)
{
	char *usagetext =
	"USAGE:"
	" "  PROGRAM_NAME " [-b <address>] [-p <port>] [-4] [-l <host_list>] [-a <host,port>]\n"
	"              [-n] [-v] [-d] [-s <file>] [-f <file>]\n\n"
	"  -b <address>    the address to bind to (either numeric or literal).\n"
	"                  Default: binds to all local IPv4 and IPv6 addresses\n\n"
	"  -p <port>       the port to bind to.\n"
	"                  Default: binds to port " RPCAP_DEFAULT_NETPORT "\n\n"
	"  -4              use only IPv4.\n"
	"                  Default: use both IPv4 and IPv6 waiting sockets\n\n"
	"  -l <host_list>  a file that contains a list of hosts that are allowed\n"
	"                  to connect to this server (if more than one, list them one per line).\n"
	"                  We suggest to use literal names (instead of numeric ones) in\n"
	"                  order to avoid problems with different address families.\n\n"
	"  -n              permit NULL authentication (usually used with '-l')\n\n"
	"  -a <host,port>  run in active mode when connecting to 'host' on port 'port'\n"
	"                  In case 'port' is omitted, the default port (" RPCAP_DEFAULT_NETPORT_ACTIVE ") is used\n\n"
	"  -v              run in active mode only (default: if '-a' is specified, it accepts\n"
	"                  passive connections as well\n\n"
	"  -d              run in daemon mode (UNIX only) or as a service (Win32 only)\n"
	"                  Warning (Win32): this switch is provided automatically when the service\n"
	"                  is started from the control panel\n\n"
	"  -s <file>       save the current configuration to file\n\n"
	"  -f <file>       load the current configuration from file; all switches\n"
	"                  specified from the command line are ignored\n\n"
	"  -h              print this help screen\n\n";

	(void)fprintf(stderr, "RPCAPD, a remote packet capture daemon.\n"
	"Compiled with %s\n\n", pcap_lib_version());
	printf("%s", usagetext);
}



//! Program main
int main(int argc, char *argv[], char *envp[])
{
	char savefile[MAX_LINE + 1];		// name of the file on which we have to save the configuration
	int isdaemon = 0;			// Not null if the user wants to run this program as a daemon
	int retval;				// keeps the returning value from several functions
	char errbuf[PCAP_ERRBUF_SIZE + 1];	// keeps the error string, prior to be printed

	savefile[0] = 0;
	loadfile[0] = 0;
	hostlist[0] = 0;

	// Initialize errbuf
	memset(errbuf, 0, sizeof(errbuf));

	if (sock_init(errbuf, PCAP_ERRBUF_SIZE) == -1)
	{
		SOCK_ASSERT(errbuf, 1);
		exit(-1);
	}

	strncpy(address, RPCAP_DEFAULT_NETADDR, MAX_LINE);
	strncpy(port, RPCAP_DEFAULT_NETPORT, MAX_LINE);

	// Prepare to open a new server socket
	memset(&mainhints, 0, sizeof(struct addrinfo));

	mainhints.ai_family = PF_UNSPEC;
	mainhints.ai_flags = AI_PASSIVE;	// Ready to a bind() socket
	mainhints.ai_socktype = SOCK_STREAM;

	// Getting the proper command line options
	while ((retval = getopt(argc, argv, "b:dhp:4l:na:s:f:v")) != -1)
	{
		switch (retval)
		{
			case 'b':
				strncpy(address, optarg, MAX_LINE);
				break;
			case 'p':
				strncpy(port, optarg, MAX_LINE);
				break;
			case '4':
				mainhints.ai_family = PF_INET;		// IPv4 server only
				break;
			case 'd':
				isdaemon = 1;
				break;
			case 'n':
				nullAuthAllowed = 1;
				break;
			case 'v':
				passivemode = 0;
				break;
			case 'l':
			{
				strncpy(hostlist, optarg, sizeof(hostlist));
				break;
			}
			case 'a':
			{
				char *tmpaddress, *tmpport;
				char *lasts;
				int i = 0;

				tmpaddress = pcap_strtok_r(optarg, RPCAP_HOSTLIST_SEP, &lasts);

				while ((tmpaddress != NULL) && (i < MAX_ACTIVE_LIST))
				{
					tmpport = pcap_strtok_r(NULL, RPCAP_HOSTLIST_SEP, &lasts);

					strlcpy(activelist[i].address, tmpaddress, MAX_LINE);

					if ((tmpport == NULL) || (strcmp(tmpport, "DEFAULT") == 0)) // the user choose a custom port
						strlcpy(activelist[i].port, RPCAP_DEFAULT_NETPORT_ACTIVE, MAX_LINE);
					else
						strlcpy(activelist[i].port, tmpport, MAX_LINE);

					tmpaddress = pcap_strtok_r(NULL, RPCAP_HOSTLIST_SEP, &lasts);

					i++;
				}

				if (i > MAX_ACTIVE_LIST)
					SOCK_ASSERT("Only MAX_ACTIVE_LIST active connections are currently supported.", 1);

				// I don't initialize the remaining part of the structure, since
				// it is already zeroed (it is a global var)
				break;
			}
			case 'f':
				strlcpy(loadfile, optarg, MAX_LINE);
				break;
			case 's':
				strlcpy(savefile, optarg, MAX_LINE);
				break;
			case 'h':
				printusage();
				exit(0);
			default:
				break;
		}
	}

	if (savefile[0])
	{
		if (fileconf_save(savefile))
			SOCK_ASSERT("Error when saving the configuration to file", 1);
	}

	// If the file does not exist, it keeps the settings provided by the command line
	if (loadfile[0])
		fileconf_read(0);

#ifndef _WIN32
	// SIGTERM (i.e. kill -15) is not generated in Win32, although it is included for ANSI compatibility
	signal(SIGTERM, main_terminate);
	signal(SIGCHLD, main_reap_children);
#endif

	// forking a daemon, if it is needed
	if (isdaemon)
	{
#ifndef _WIN32
		int pid;

		// Unix Network Programming, pg 336
		if ((pid = fork()) != 0)
			exit(0);		// Parent terminates

		// First child continues
		// Set daemon mode
		setsid();

		// generated under unix with 'kill -HUP', needed to reload the configuration
		signal(SIGHUP, fileconf_read);

		if ((pid = fork()) != 0)
			exit(0);		// First child terminates

		// LINUX WARNING: the current linux implementation of pthreads requires a management thread
		// to handle some hidden stuff. So, as soon as you create the first thread, two threads are
		// created. Fom this point on, the number of threads active are always one more compared
		// to the number you're expecting

		// Second child continues
//		umask(0);
//		chdir("/");
#else
		// We use the SIGABRT signal to kill the Win32 service
		signal(SIGABRT, main_abort);

		// If this call succeeds, it is blocking on Win32
		if (svc_start() != 1)
			SOCK_ASSERT("Unable to start the service", 1);

		// When the previous call returns, the entire application has to be stopped.
		exit(0);
#endif
	}
	else	// Console mode
	{
		// Enable the catching of Ctrl+C
		signal(SIGINT, main_terminate);

#ifndef _WIN32
		// generated under unix with 'kill -HUP', needed to reload the configuration
		// We do not have this kind of signal in Win32
		signal(SIGHUP, fileconf_read);
#endif

		printf("Press CTRL + C to stop the server...\n");
	}

	// If we're a Win32 service, we have already called this function in the service_main
	main_startup();

	// The code should never arrive here (since the main_startup is blocking)
	//  however this avoids a compiler warning
	exit(0);
}

void main_startup(void)
{
	char errbuf[PCAP_ERRBUF_SIZE + 1];	// keeps the error string, prior to be printed
	struct addrinfo *addrinfo;		// keeps the addrinfo chain; required to open a new socket
	int i;
#ifdef _WIN32
	HANDLE threadId;			// handle for the subthread
#else
	pid_t pid;
#endif

	i = 0;
	addrinfo = NULL;
	memset(errbuf, 0, sizeof(errbuf));

	// Starts all the active threads
	while ((i < MAX_ACTIVE_LIST) && (activelist[i].address[0] != 0))
	{
		activelist[i].ai_family = mainhints.ai_family;

#ifdef _WIN32
		threadId = (HANDLE)_beginthreadex(NULL, 0, main_active,
		    (void *)&activelist[i], 0, NULL);
		if (threadId == 0)
		{
			SOCK_ASSERT("Error creating the active child threads", 1);
			continue;
		}
		CloseHandle(threadId);
#else
		if ((pid = fork()) == 0)	// I am the child
		{
			main_active((void *) &activelist[i]);
			exit(0);
		}
#endif
		i++;
	}

	/*
	 * The code that manages the active connections is not blocking;
	 * the code that manages the passive connection is blocking.
	 * So, if the user does not want to run in passive mode, we have
	 * to block the main thread here, otherwise the program ends and
	 * all threads are stopped.
	 *
	 * WARNING: this means that in case we have only active mode,
	 * the program does not terminate even if all the child thread
	 * terminates. The user has always to press Ctrl+C (or send a
	 * SIGTERM) to terminate the program.
	 */
	if (passivemode)
	{
		struct addrinfo *tempaddrinfo;

		// Do the work
		if (sock_initaddress((address[0]) ? address : NULL, port, &mainhints, &addrinfo, errbuf, PCAP_ERRBUF_SIZE) == -1)
		{
			SOCK_ASSERT(errbuf, 1);
			return;
		}

		tempaddrinfo = addrinfo;

		while (tempaddrinfo)
		{
			SOCKET *socktemp;

			if ((sockmain = sock_open(tempaddrinfo, SOCKOPEN_SERVER, SOCKET_MAXCONN, errbuf, PCAP_ERRBUF_SIZE)) == INVALID_SOCKET)
			{
				SOCK_ASSERT(errbuf, 1);
				tempaddrinfo = tempaddrinfo->ai_next;
				continue;
			}

			//
			// This trick is needed in order to allow the child
			// thread to save the 'sockmain' variable without
			// getting it overwritten by the sock_open, in case
			// we want to open more than one waiting socket.
			//
			// For instance, the rpcapd_thread_create() will
			// accept the socktemp variable, and it will
			// immediately deallocate that variable.
			//
			// XXX - this shouldn't be necessary if we're
			// using subprocesses rather than threads, as
			// the use and overwrite would be done in
			// separate processes; we should be able to
			// pass a pointer to sockmain in the child
			// process.
			//
			socktemp = (SOCKET *) malloc (sizeof (SOCKET));
			if (socktemp == NULL)
				exit(0);

			*socktemp = sockmain;

#ifdef _WIN32
			threadId = (HANDLE)_beginthreadex(NULL, 0, main_passive,
			    (void *) socktemp, 0, NULL);
			if (threadId == 0)
			{
				SOCK_ASSERT("Error creating the passive child thread", 1);
				free(socktemp);
				continue;
			}
			CloseHandle(threadId);
#else
			if ((pid = fork()) == 0)	// I am the child
			{
				freeaddrinfo(addrinfo);
				main_passive((void *) socktemp);
				return;
			}
			free(socktemp);
#endif
			tempaddrinfo = tempaddrinfo->ai_next;
		}

		freeaddrinfo(addrinfo);
	}

	// All the previous calls are no blocking, so the main line of execution goes here
	// and I have to avoid that the program terminates
	while (1)
	{
#ifdef _WIN32
		Sleep(INFINITE);
#else
		pause();
#endif
	}
}


/*
	\brief Closes gracefully (more or less) the program.

	This function is called:
	- when we're running in console and are terminated with ^C;
	- on UN*X, when we're terminated with SIGTERM.
*/
static void main_terminate(int sign)
{
	SOCK_ASSERT(PROGRAM_NAME " is closing.\n", 1);

#ifndef _WIN32
	//
	// Sends a KILL signal to all the processes in this process's
	// process group; i.e., it kills all the child processes
	// we've created.
	//
	// XXX - that also includes us, so we will be killed as well;
	// that may cause a message to be printed or logged.
	//
	kill(0, SIGKILL);
#endif

	//
	// Just leave.  We shouldn't need to clean up sockets or
	// anything else, and if we try to do so, we'll could end
	// up closing sockets, or shutting Winsock down, out from
	// under service loops, causing all sorts of noisy error
	// messages.
	//
	// We shouldn't need to worry about cleaning up any resources
	// such as handles, sockets, threads, etc. - exit() should
	// terminate the process, causing all those resources to be
	// cleaned up.
	//
	// Note that, on Windows, this will happen only for ^C, and
	// thus will happen on a thread created to run the ^C handler,
	// which is how it manages to cause the aforementioned service
	// loop issues in service loops in other threads.
	//
	exit(0);
}

#ifdef _WIN32
static void main_abort(int sign)
{
	SOCK_ASSERT(PROGRAM_NAME " is closing due to a SIGABRT.\n", 1);

	//
	// XXX - there should be a way to poke the main thread to get
	// it to shut down the service.
	//

	// FULVIO (bug)
	// Here we close only the latest 'sockmain' created; if we opened more than one waiting sockets,
	// only the latest one is closed correctly.
	if (sockmain)
		closesocket(sockmain);
	sock_cleanup();

	/*
	 * This is a Win32 service, so we're a child thread, and we want
	 * just to terminate ourself. This is because the exit(0) will
	 * be invoked by the main thread, which is blocked waiting that
	 * all childs terminates. We are forced to call exit from the
	 * main thread, otherwise the Win32 service control manager
	 * (SCM) does not work well.
	 */
}
#endif

#ifndef _WIN32
static void main_reap_children(int sign)
{
	pid_t pid;
	int exitstat;

	// Reap all child processes that have exited.
	// For reference, Stevens, pg 128

	while ((pid = waitpid(-1, &exitstat, WNOHANG)) > 0)
		SOCK_ASSERT("Child terminated", 1);

	return;
}
#endif

/*!
	\brief 'true' main of the program.

	It must be in a separate function because:
	- if we're in 'console' mode, we have to put the main thread waiting for a Ctrl+C
	(in order to be able to stop everything)
	- if we're in daemon mode, the main program must terminate and a new child must be
	created in order to create the daemon

	\param ptr: it keeps the main socket handler (what's called
	'sockmain' in the main()), that represents the socket used in
	the main connection. It is a 'void *' just because the thread
	APIs want this format.
*/
#ifdef _WIN32
static unsigned __stdcall
#else
static void *
#endif
main_passive(void *ptr)
{
	char errbuf[PCAP_ERRBUF_SIZE + 1];	// keeps the error string, prior to be printed
	SOCKET sockctrl;			// keeps the socket ID for this control connection
	struct sockaddr_storage from;		// generic sockaddr_storage variable
	socklen_t fromlen;			// keeps the length of the sockaddr_storage variable
	SOCKET sockmain;

#ifndef _WIN32
	pid_t pid;
#endif

	sockmain = *((SOCKET *) ptr);

	// Delete the pointer (which has been allocated in the main)
	free(ptr);

	// Initialize errbuf
	memset(errbuf, 0, sizeof(errbuf));

	// main thread loop
	while (1)
	{
#ifdef _WIN32
		HANDLE threadId;		// handle for the subthread
#endif
		struct daemon_slpars *pars;	// parameters needed by the daemon_serviceloop()

		// Connection creation
		fromlen = sizeof(struct sockaddr_storage);

		sockctrl = accept(sockmain, (struct sockaddr *) &from, &fromlen);

		if (sockctrl == INVALID_SOCKET)
		{
			// The accept() call can return this error when a signal is catched
			// In this case, we have simply to ignore this error code
			// Stevens, pg 124
#ifdef _WIN32
			if (WSAGetLastError() == WSAEINTR)
#else
			if (errno == EINTR)
#endif
				continue;

			// Don't check for errors here, since the error can be due to the fact that the thread
			// has been killed
			sock_geterror("accept(): ", errbuf, PCAP_ERRBUF_SIZE);
			rpcapd_log(LOGPRIO_ERROR, "Accept of control connection from client failed: %s",
			    errbuf);
			continue;
		}

		// checks if the connecting host is among the ones allowed
		if (sock_check_hostlist(hostlist, RPCAP_HOSTLIST_SEP, &from, errbuf, PCAP_ERRBUF_SIZE) < 0)
		{
			rpcap_senderror(sockctrl, 0, PCAP_ERR_HOSTNOAUTH, errbuf, NULL);
			sock_close(sockctrl, NULL, 0);
			continue;
		}


#ifdef _WIN32
		// in case of passive mode, this variable is deallocated by the daemon_serviceloop()
		pars = (struct daemon_slpars *) malloc (sizeof(struct daemon_slpars));
		if (pars == NULL)
		{
			pcap_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE,
			    errno, "malloc() failed");
			rpcap_senderror(sockctrl, 0, PCAP_ERR_OPEN, errbuf, NULL);
			sock_close(sockctrl, NULL, 0);
			continue;
		}

		pars->sockctrl = sockctrl;
		pars->activeclose = 0;		// useless in passive mode
		pars->isactive = 0;
		pars->nullAuthAllowed = nullAuthAllowed;

		threadId = (HANDLE)_beginthreadex(NULL, 0, daemon_serviceloop,
		    (void *) pars, 0, NULL);
		if (threadId == 0)
		{
			pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "Error creating the child thread");
			rpcap_senderror(sockctrl, 0, PCAP_ERR_OPEN, errbuf, NULL);
			sock_close(sockctrl, NULL, 0);
			continue;
		}
		CloseHandle(threadId);
#else
		if ((pid = fork()) == 0)	// I am the child
		{
			// in case of passive mode, this variable is deallocated by the daemon_serviceloop()
			pars = (struct daemon_slpars *) malloc (sizeof(struct daemon_slpars));
			if (pars == NULL)
			{
				pcap_fmt_errmsg_for_errno(errbuf,
				    PCAP_ERRBUF_SIZE, errno, "malloc() failed");
				exit(0);
			}

			pars->sockctrl = sockctrl;
			pars->activeclose = 0;		// useless in passive mode
			pars->isactive = 0;
			pars->nullAuthAllowed = nullAuthAllowed;

			// Close the main socket (must be open only in the parent)
			closesocket(sockmain);

			daemon_serviceloop((void *) pars);
			exit(0);
		}

		// I am the parent
		// Close the childsocket (must be open only in the child)
		closesocket(sockctrl);
#endif

		// loop forever, until interrupted
	}
	return 0;
}

/*!
	\brief 'true' main of the program in case the active mode is turned on.

	This function loops forever trying to connect to the remote host, until the
	daemon is turned down.

	\param ptr: it keeps the 'activepars' parameters.  It is a 'void *'
	just because the thread APIs want this format.
*/
#ifdef _WIN32
static unsigned __stdcall
#else
static void *
#endif
main_active(void *ptr)
{
	char errbuf[PCAP_ERRBUF_SIZE + 1];	// keeps the error string, prior to be printed
	SOCKET sockctrl;			// keeps the socket ID for this control connection
	struct addrinfo hints;			// temporary struct to keep settings needed to open the new socket
	struct addrinfo *addrinfo;		// keeps the addrinfo chain; required to open a new socket
	struct active_pars *activepars;
	struct daemon_slpars *pars;		// parameters needed by the daemon_serviceloop()

	activepars = (struct active_pars *) ptr;

	// Prepare to open a new server socket
	memset(&hints, 0, sizeof(struct addrinfo));
						// WARNING Currently it supports only ONE socket family among IPv4 and IPv6
	hints.ai_family = AF_INET;		// PF_UNSPEC to have both IPv4 and IPv6 server
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = activepars->ai_family;

	pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "Connecting to host %s, port %s, using protocol %s",
			activepars->address, activepars->port, (hints.ai_family == AF_INET) ? "IPv4":
			(hints.ai_family == AF_INET6) ? "IPv6" : "Unspecified");
	SOCK_ASSERT(errbuf, 1);

	// Initialize errbuf
	memset(errbuf, 0, sizeof(errbuf));

	// Do the work
	if (sock_initaddress(activepars->address, activepars->port, &hints, &addrinfo, errbuf, PCAP_ERRBUF_SIZE) == -1)
	{
		SOCK_ASSERT(errbuf, 1);
		return 0;
	}

	while (1)
	{
		int activeclose;

		if ((sockctrl = sock_open(addrinfo, SOCKOPEN_CLIENT, 0, errbuf, PCAP_ERRBUF_SIZE)) == INVALID_SOCKET)
		{
			SOCK_ASSERT(errbuf, 1);

			pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "Error connecting to host %s, port %s, using protocol %s",
					activepars->address, activepars->port, (hints.ai_family == AF_INET) ? "IPv4":
					(hints.ai_family == AF_INET6) ? "IPv6" : "Unspecified");

			SOCK_ASSERT(errbuf, 1);

			sleep_secs(RPCAP_ACTIVE_WAIT);

			continue;
		}

		pars = (struct daemon_slpars *) malloc (sizeof(struct daemon_slpars));
		if (pars == NULL)
		{
			pcap_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE,
			    errno, "malloc() failed");
			continue;
		}

		pars->sockctrl = sockctrl;
		pars->activeclose = 0;
		pars->isactive = 1;
		pars->nullAuthAllowed = nullAuthAllowed;

		daemon_serviceloop((void *) pars);

		activeclose = pars->activeclose;

		free(pars);

		// If the connection is closed by the user explicitely, don't try to connect to it again
		// just exit the program
		if (activeclose == 1)
			break;
	}

	freeaddrinfo(addrinfo);
	return 0;
}
