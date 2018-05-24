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

#ifdef HAVE_OPENSSL
#include <stdlib.h>

#include "portability.h"
#include "sslutils.h"
#include "pcap/pcap.h"

int uses_ssl; //!< '1' to use TLS over the data socket
char ssl_keyfile[PATH_MAX]; //!< file containing the private key in PEM format
char ssl_certfile[PATH_MAX];  //!< file containing the server's certificate in PEM format
char ssl_rootfile[PATH_MAX];  //!< file containing the list of CAs trusted by the client
// TODO: a way to set ssl_rootfile from the command line, or an envvar?

// TODO: lock?
static SSL_CTX *ctx;

static int ssl_init_once(int is_server, char *errbuf, size_t errbuflen)
{
	static int inited = 0;
	if (inited) return 0;

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();

	SSL_METHOD const *meth = SSLv23_method();
	ctx = SSL_CTX_new(meth);
	if (! ctx)
	{
		pcap_snprintf(errbuf, errbuflen, "Cannot get a new SSL context: %s", ERR_error_string(ERR_get_error(), NULL));
		goto die;
	}

	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

	if (is_server)
	{
		char const *certfile = ssl_certfile[0] ? ssl_certfile : "cert.pem";
		if (1 != SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM))
		{
			pcap_snprintf(errbuf, errbuflen, "Cannot read certificate file %s: %s", certfile, ERR_error_string(ERR_get_error(), NULL));
			goto die;
		}

		char const *keyfile = ssl_keyfile[0] ? ssl_keyfile : "key.pem";
		if (1 != SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM))
		{
			pcap_snprintf(errbuf, errbuflen, "Cannot read private key file %s: %s", keyfile, ERR_error_string(ERR_get_error(), NULL));
			goto die;
		}
	}
	else
	{
		if (ssl_rootfile[0])
		{
			if (! SSL_CTX_load_verify_locations(ctx, ssl_rootfile, 0))
			{
				pcap_snprintf(errbuf, errbuflen, "Cannot read CA list from %s", ssl_rootfile);
				goto die;
			}
		}
		else
		{
			SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
		}
	}

#if 0
	if (! RAND_load_file(RANDOM, 1024*1024))
	{
		pcap_snprintf(errbuf, errbuflen, "Cannot init random");
		goto die;
	}

	if (is_server)
	{
		SSL_CTX_set_session_id_context(ctx, (void *)&s_server_session_id_context, sizeof(s_server_session_id_context));
	}
#endif

	inited = 1;
	return 0;

die:
	return -1;
}

void init_ssl_or_die(int is_server)
{
	char errbuf[PCAP_ERRBUF_SIZE];

	if (ssl_init_once(is_server, errbuf, sizeof errbuf) < 0)
	{
		fprintf(stderr, "%s\n", errbuf);
		exit(3);
	}
}

SSL *ssl_promotion(int is_server, SOCKET s, char *errbuf, size_t errbuflen)
{
	if (ssl_init_once(is_server, errbuf, errbuflen) < 0)
	{
		return NULL;
	}

	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, s);

	if (is_server)
	{
		if (SSL_accept(ssl) <= 0)
		{
			pcap_snprintf(errbuf, errbuflen, "SSL_accept(): %s",
					ERR_error_string(ERR_get_error(), NULL));
			return NULL;
		}
	}
	else
	{
		if (SSL_connect(ssl) <= 0)
		{
			pcap_snprintf(errbuf, errbuflen, "SSL_connect(): %s",
					ERR_error_string(ERR_get_error(), NULL));
			return NULL;
		}
	}

	return ssl;
}

// Same return value as sock_send:
// 0 on OK, -1 on error but closed connection (-2).
int ssl_send(SSL *ssl, char const *buffer, size_t size, char *errbuf, size_t errbuflen)
{
	int status = SSL_write(ssl, buffer, size);
	if (status > 0)
	{
		// "SSL_write() will only return with success, when the complete contents (...) has been written."
		return 0;
	}
	else
	{
		int ssl_err = SSL_get_error(ssl, status); // TODO: does it pop the error?
		if (ssl_err == SSL_ERROR_ZERO_RETURN)
		{
			return -2;
		}
		else if (ssl_err == SSL_ERROR_SYSCALL)
		{
#ifndef _WIN32
			if (errno == ECONNRESET || errno == EPIPE) return -2;
#endif
		}
		pcap_snprintf(errbuf, errbuflen, "SSL_write(): %s",
		    ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
}

// Same return status as sock_recv(SOCK_EOF_IS_ERROR):
// -3 for EINTR, -1 on error and EOF, or number of bytes read
int ssl_recv(SSL *ssl, unsigned char *buffer, size_t size, char *errbuf, size_t errbuflen)
{
	int status = SSL_read(ssl, buffer, size);
	if (status <= 0)
	{
		int ssl_err = SSL_get_error(ssl, status);
		if (ssl_err == SSL_ERROR_ZERO_RETURN)
		{
			pcap_snprintf(errbuf, errbuflen, "The other host terminated the connection.");
			return -1;
		}
		else if (ssl_err == SSL_ERROR_SYSCALL)
		{
#ifndef _WIN32
			if (errno == EINTR)
			{
				return -3;
			}
			else
			{
				pcap_snprintf(errbuf, errbuflen, "SSL_read(): %s",
				    ERR_error_string(ERR_get_error(), NULL));
				return -1;
			}
#endif
		}
	}
	return status;
}

#endif // HAVE_OPENSSL
