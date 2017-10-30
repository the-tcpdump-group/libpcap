/*
 * Copyright (c) 2002 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2008 CACE Technologies, Davis (California)
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
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies
 * nor the names of its contributors may be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
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

#include <string.h>		/* for strlen(), ... */
#include <stdlib.h>		/* for malloc(), free(), ... */
#include <stdarg.h>		/* for functions with variable number of arguments */
#include <errno.h>		/* for the errno variable */
#include "sockutils.h"
#include "portability.h"
#include "rpcap-protocol.h"
#include <pcap/pcap.h>

/*
 * This file contains functions used both by the rpcap client and the
 * rpcap daemon.
 */

/*
 * This function sends a RPCAP error to our peer.
 *
 * It has to be called when the main program detects an error.
 * It will send to our peer the 'buffer' specified by the user.
 * This function *does not* request a RPCAP CLOSE connection. A CLOSE
 * command must be sent explicitly by the program, since we do not know
 * whether the error can be recovered in some way or if it is a
 * non-recoverable one.
 *
 * \param sock: the socket we are currently using.
 *
 * \param error: an user-allocated (and '0' terminated) buffer that contains
 * the error description that has to be transmitted to our peer. The
 * error message cannot be longer than PCAP_ERRBUF_SIZE.
 *
 * \param errcode: a integer which tells the other party the type of error
 * we had; currently is is not too much used.
 *
 * \param errbuf: a pointer to a user-allocated buffer (of size
 * PCAP_ERRBUF_SIZE) that will contain the error message (in case there
 * is one). It could be network problem.
 *
 * \return '0' if everything is fine, '-1' if some errors occurred. The
 * error message is returned in the 'errbuf' variable.
 */
int
rpcap_senderror(SOCKET sock, char *error, unsigned short errcode, char *errbuf)
{
	char sendbuf[RPCAP_NETBUF_SIZE];	/* temporary buffer in which data to be sent is buffered */
	int sendbufidx = 0;			/* index which keeps the number of bytes currently buffered */
	uint16 length;

	length = (uint16)strlen(error);

	if (length > PCAP_ERRBUF_SIZE)
		length = PCAP_ERRBUF_SIZE;

	rpcap_createhdr((struct rpcap_header *) sendbuf, RPCAP_MSG_ERROR, errcode, length);

	if (sock_bufferize(NULL, sizeof(struct rpcap_header), NULL, &sendbufidx,
		RPCAP_NETBUF_SIZE, SOCKBUF_CHECKONLY, errbuf, PCAP_ERRBUF_SIZE))
		return -1;

	if (sock_bufferize(error, length, sendbuf, &sendbufidx,
		RPCAP_NETBUF_SIZE, SOCKBUF_BUFFERIZE, errbuf, PCAP_ERRBUF_SIZE))
		return -1;

	if (sock_send(sock, sendbuf, sendbufidx, errbuf, PCAP_ERRBUF_SIZE))
		return -1;

	return 0;
}

/*
 * This function fills in a structure of type rpcap_header.
 *
 * It is provided just because the creation of an rpcap header is a common
 * task. It accepts all the values that appears into an rpcap_header, and
 * it puts them in place using the proper hton() calls.
 *
 * \param header: a pointer to a user-allocated buffer which will contain
 * the serialized header, ready to be sent on the network.
 *
 * \param type: a value (in the host by order) which will be placed into the
 * header.type field and that represents the type of the current message.
 *
 * \param value: a value (in the host by order) which will be placed into
 * the header.value field and that has a message-dependent meaning.
 *
 * \param length: a value (in the host by order) which will be placed into
 * the header.length field, representing the payload length of the message.
 *
 * \return Nothing. The serialized header is returned into the 'header'
 * variable.
 */
void
rpcap_createhdr(struct rpcap_header *header, uint8 type, uint16 value, uint32 length)
{
	memset(header, 0, sizeof(struct rpcap_header));

	header->ver = RPCAP_VERSION;
	header->type = type;
	header->value = htons(value);
	header->plen = htonl(length);
}

/*
 * Convert a message type to a string containing the type name.
 */
static const char *requests[] =
{
	NULL,				/* not a valid message type */
	"RPCAP_MSG_ERROR",
	"RPCAP_MSG_FINDALLIF_REQ",
	"RPCAP_MSG_OPEN_REQ",
	"RPCAP_MSG_STARTCAP_REQ",
	"RPCAP_MSG_UPDATEFILTER_REQ",
	"RPCAP_MSG_CLOSE",
	"RPCAP_MSG_PACKET",
	"RPCAP_MSG_AUTH_REQ",
	"RPCAP_MSG_STATS_REQ",
	"RPCAP_MSG_ENDCAP_REQ",
	"RPCAP_MSG_SETSAMPLING_REQ",
};
#define NUM_REQ_TYPES	(sizeof requests / sizeof requests[0])

static const char *replies[] =
{
	NULL,
	NULL,			/* this would be a reply to RPCAP_MSG_ERROR */
	"RPCAP_MSG_FINDALLIF_REPLY",
	"RPCAP_MSG_OPEN_REPLY",
	"RPCAP_MSG_STARTCAP_REPLY",
	"RPCAP_MSG_UPDATEFILTER_REPLY",
	NULL,			/* this would be a reply to RPCAP_MSG_CLOSE */
	NULL,			/* this would be a reply to RPCAP_MSG_PACKET */
	"RPCAP_MSG_AUTH_REPLY",
	"RPCAP_MSG_STATS_REPLY",
	"RPCAP_MSG_ENDCAP_REPLY",
	"RPCAP_MSG_SETSAMPLING_REPLY",
};
#define NUM_REPLY_TYPES	(sizeof replies / sizeof replies[0])

const char *
rpcap_msg_type_string(uint8 type)
{
	if (type & RPCAP_MSG_IS_REPLY) {
		type &= ~RPCAP_MSG_IS_REPLY;
		if (type >= NUM_REPLY_TYPES)
			return NULL;
		return replies[type];
	} else {
		if (type > NUM_REQ_TYPES)
			return NULL;
		return requests[type];
	}
}

/*
 * This function checks whether the header of the received message is correct.
 *
 * It is a way to easily check if the message received, in a certain state
 * of the RPCAP protocol Finite State Machine, is valid. This function accepts,
 * as a parameter, the list of message types that are allowed in a certain
 * situation, and it returns the one that occurs.
 *
 * \param errbuf: a pointer to a user-allocated buffer (of size
 * PCAP_ERRBUF_SIZE) that will contain the error message (in case there
 * is one). It could either be a problem that occurred inside this function
 * (e.g. a network problem in case it tries to send an error to our peer
 * and the send() call fails), an error message thathas been sent to us
 * from the other party, or a version error (the message received has a
 * version number that is incompatible with ours).
 *
 * \param sock: the socket that has to be used to receive data. This
 * function can read data from socket in case the version contained into
 * the message is not compatible with ours. In that case, all the message
 * is purged from the socket, so that the following recv() calls will
 * return a new message.
 *
 * \param header: a pointer to and 'rpcap_header' structure that keeps
 * the data received from the network (still in network byte order) and
 * that has to be checked.
 *
 * \param first: this function has a variable number of parameters. From
 * this point on, all the messages that are valid in this context must be
 * passed as parameters.  The message type list must be terminated with a
 * '0' value, the null message type, which means 'no more types to check'.
 * The RPCAP protocol does not define anything with message type equal to
 * zero, so there is no ambiguity in using this value as a list terminator.
 *
 * \return The message type of the message that has been detected. In case
 * of errors (e.g. the header contains a type that is not listed among the
 * allowed types), this function will return the following codes:
 * - (-1) if the version is incompatible.
 * - (-2) if the code is not among the one listed into the parameters list
 * - (-3) if a network error (connection reset, ...)
 * - RPCAP_MSG_ERROR if the message is an error message (it follows that
 * the RPCAP_MSG_ERROR could not be present in the allowed message-types
 * list, because this function checks for errors anyway)
 *
 * In case either the version is incompatible or nothing matches (i.e. it
 * returns '-1' or '-2'), it discards the message body (i.e. it reads the
 * remaining part of the message from the network and it discards it) so
 * that the application is ready to receive a new message.
 */
int
rpcap_checkmsg(char *errbuf, SOCKET sock, struct rpcap_header *header, uint8 first, ...)
{
	va_list ap;
	uint8 type;
	int32 len;
	char remote_errbuf[PCAP_ERRBUF_SIZE];

	/* Check if the present version of the protocol can handle this message */
	if (header->ver != RPCAP_VERSION)
	{
		pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "Incompatible version number: message discarded.");

		/*
		 * Discard the rest of the packet.
		 */
		if (sock_discard(sock, ntohl(header->plen), NULL, 0) == -1) {
			/*
			 * Network error.
			 */
			return -3;
		}
		return -1;
	}

	va_start(ap, first);

	type = first;

	while (type != 0)
	{
		/*
		 * The message matches with one of the types listed
		 * There is no need of conversions since both values are uint8
		 *
		 * Check if the other side reported an error.
		 * If yes, it retrieves it and it returns it back to the caller
		 */
		if (header->type == RPCAP_MSG_ERROR)
		{
			len = ntohl(header->plen);

			if (len >= PCAP_ERRBUF_SIZE)
			{
				if (sock_recv(sock, remote_errbuf, PCAP_ERRBUF_SIZE - 1, SOCK_RECEIVEALL_YES, errbuf, PCAP_ERRBUF_SIZE) == -1)
				{
					va_end(ap);
					return -3;
				}

				sock_discard(sock, len - (PCAP_ERRBUF_SIZE - 1), NULL, 0);

				/*
				 * Copy the received string to errbuf, and
				 * null-terminate it.
				 */
				memcpy(errbuf, remote_errbuf, PCAP_ERRBUF_SIZE - 1);
				errbuf[PCAP_ERRBUF_SIZE - 1] = '\0';
			}
			else if (len == 0)
			{
				/* Empty error string. */
				errbuf[0] = '\0';
			}
			else
			{
				if (sock_recv(sock, remote_errbuf, len, SOCK_RECEIVEALL_YES, errbuf, PCAP_ERRBUF_SIZE) == -1)
				{
					va_end(ap);
					return -3;
				}

				/*
				 * Copy the received string to errbuf, and
				 * null-terminate it.
				 */
				memcpy(errbuf, remote_errbuf, len - 1);
				errbuf[len] = '\0';
			}

			va_end(ap);
			return header->type;
		}

		if (header->type == type)
		{
			va_end(ap);
			return header->type;
		}

		/* get next argument */
		type = va_arg(ap, int);
	}

	/* we already have an error, so please discard this one */
	sock_discard(sock, ntohl(header->plen), NULL, 0);

	pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "The other endpoint sent a message that is not allowed here.");
	SOCK_ASSERT(errbuf, 1);

	va_end(ap);
	return -2;
}
