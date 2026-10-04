#include <config.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>

#ifdef HAVE_OPENSSL
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#endif

#include "varattrs.h"

/* RPCAP message types (rpcap-protocol.h) */
#define RPCAP_MSG_ERROR		0x01
#define RPCAP_MSG_OPEN_REQ	0x03
#define RPCAP_MSG_STARTCAP_REQ	0x04
#define RPCAP_MSG_AUTH_REQ	0x08
#define RPCAP_MSG_IS_REPLY	0x80

/*
 * Largest descriptor number we expect the library to use; the tests scan
 * below this to find the control socket it opened.
 */
#define FD_MAX	256

/*
 * A minimal RPCAP reply header; value and plen are big-endian on the wire.
 */
struct wire_header {
	uint8_t ver;
	uint8_t type;
	uint16_t value;
	uint32_t plen;
};

/*
 * The byte stream a stub speaks the handshake over: a plain socket, or a TLS
 * session on top of one.  The ssl member only exists when the library was
 * built with OpenSSL, which is also the only time the active-mode case uses
 * it.
 */
struct chan {
	int fd;
#ifdef HAVE_OPENSSL
	SSL *ssl;
#endif
};

static int
chan_write(struct chan *c, const void *buf, size_t len)
{
	const char *cp = (const char *)buf;
	size_t done = 0;

	while (done < len) {
#ifdef HAVE_OPENSSL
		if (c->ssl != NULL) {
			int n = SSL_write(c->ssl, cp + done,
			    (int)(len - done));
			if (n <= 0)
				return -1;
			done += (size_t)n;
			continue;
		}
#endif
		{
			ssize_t n = write(c->fd, cp + done, len - done);
			if (n < 0 && errno == EINTR)
				continue;
			if (n <= 0)
				return -1;
			done += (size_t)n;
		}
	}
	return 0;
}

static int
chan_read(struct chan *c, void *buf, size_t len)
{
	char *cp = (char *)buf;
	size_t got = 0;

	while (got < len) {
#ifdef HAVE_OPENSSL
		if (c->ssl != NULL) {
			int n = SSL_read(c->ssl, cp + got, (int)(len - got));
			if (n <= 0)
				return -1;
			got += (size_t)n;
			continue;
		}
#endif
		{
			ssize_t n = read(c->fd, cp + got, len - got);
			if (n < 0 && errno == EINTR)
				continue;
			if (n <= 0)
				return -1;
			got += (size_t)n;
		}
	}
	return 0;
}

static int
send_header(struct chan *c, uint8_t type, uint16_t value, uint32_t plen)
{
	struct wire_header h;

	h.ver = 0;
	h.type = type;
	h.value = htons(value);
	h.plen = htonl(plen);
	return chan_write(c, &h, sizeof h);
}

static int
read_header(struct chan *c, uint8_t *type, uint16_t *value, uint32_t *plen)
{
	struct wire_header h;

	if (chan_read(c, &h, sizeof h) < 0)
		return -1;
	*type = h.type;
	*value = ntohs(h.value);
	*plen = ntohl(h.plen);
	return 0;
}

static int
skip_payload(struct chan *c, uint32_t plen)
{
	char buf[4096];

	while (plen > 0) {
		size_t chunk = plen > sizeof buf ? sizeof buf : plen;
		if (chan_read(c, buf, chunk) < 0)
			return -1;
		plen -= (uint32_t)chunk;
	}
	return 0;
}

/*
 * Speak the part of the handshake that pcap_open() expects: answer AUTH_REQ
 * with AUTH_REPLY and OPEN_REQ with OPEN_REPLY.  When "startcap_fails" is
 * set, also answer STARTCAP_REQ with RPCAP_MSG_ERROR so that
 * pcap_startcapture_remote() fails.
 */
static int
stub_handshake(struct chan *c, int startcap_fails)
{
	uint8_t type;
	uint16_t value;
	uint32_t plen;
	uint32_t openreply[2];		/* linktype, tzoff */

	/* AUTH_REQ -> AUTH_REPLY (plen 0: protocol version 0 only) */
	if (read_header(c, &type, &value, &plen) < 0 ||
	    type != RPCAP_MSG_AUTH_REQ || skip_payload(c, plen) < 0)
		return -1;
	if (send_header(c, RPCAP_MSG_AUTH_REQ | RPCAP_MSG_IS_REPLY, 0, 0) < 0)
		return -1;

	/* OPEN_REQ -> OPEN_REPLY */
	if (read_header(c, &type, &value, &plen) < 0 ||
	    type != RPCAP_MSG_OPEN_REQ || skip_payload(c, plen) < 0)
		return -1;
	openreply[0] = htonl(1);	/* DLT_EN10MB */
	openreply[1] = 0;
	if (send_header(c, RPCAP_MSG_OPEN_REQ | RPCAP_MSG_IS_REPLY, 0,
	    sizeof openreply) < 0 ||
	    chan_write(c, openreply, sizeof openreply) < 0)
		return -1;

	if (startcap_fails) {
		/* STARTCAP_REQ -> RPCAP_MSG_ERROR */
		if (read_header(c, &type, &value, &plen) < 0 ||
		    type != RPCAP_MSG_STARTCAP_REQ ||
		    skip_payload(c, plen) < 0)
			return -1;
		if (send_header(c, RPCAP_MSG_ERROR, 1, 0) < 0)
			return -1;
	}
	return 0;
}

static void
sleep_ms(long ms)
{
	struct timespec ts;

	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (ms % 1000) * 1000000;
	(void)nanosleep(&ts, NULL);
}

#ifdef HAVE_OPENSSL
/*
 * Build an ephemeral SSL context holding a throwaway self-signed certificate.
 * libpcap's rpcap client does not verify the peer certificate unless a CA file
 * was configured (sslutils.c sets SSL_VERIFY_NONE otherwise), so any
 * certificate is accepted, and generating one in memory keeps the test free
 * of checked-in key material and of a dependency on the openssl(1) tool.
 */
static SSL_CTX *
make_server_ctx(void)
{
	SSL_CTX *ctx;
	EVP_PKEY *pkey;
	X509 *cert;
	X509_NAME *name;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
	pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
#else
	{
		BIGNUM *e = BN_new();
		RSA *rsa = RSA_new();

		pkey = NULL;
		if (e != NULL && rsa != NULL &&
		    BN_set_word(e, RSA_F4) == 1 &&
		    RSA_generate_key_ex(rsa, 2048, e, NULL) == 1) {
			pkey = EVP_PKEY_new();
			if (pkey == NULL || EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
				EVP_PKEY_free(pkey);
				pkey = NULL;
			} else {
				rsa = NULL;	/* now owned by pkey */
			}
		}
		RSA_free(rsa);
		BN_free(e);
	}
#endif
	if (pkey == NULL)
		return NULL;

	cert = X509_new();
	if (cert == NULL) {
		EVP_PKEY_free(pkey);
		return NULL;
	}
	if (X509_set_version(cert, 2) != 1 ||
	    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) != 1 ||
	    X509_gmtime_adj(X509_get_notBefore(cert), 0) == NULL ||
	    X509_gmtime_adj(X509_get_notAfter(cert), 3600) == NULL ||
	    X509_set_pubkey(cert, pkey) != 1) {
		X509_free(cert);
		EVP_PKEY_free(pkey);
		return NULL;
	}
	name = X509_get_subject_name(cert);
	if (name == NULL ||
	    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
		(const unsigned char *)"127.0.0.1", -1, -1, 0) != 1 ||
	    X509_set_issuer_name(cert, name) != 1 ||
	    X509_sign(cert, pkey, EVP_sha256()) == 0) {
		X509_free(cert);
		EVP_PKEY_free(pkey);
		return NULL;
	}

	ctx = SSL_CTX_new(SSLv23_server_method());
	if (ctx == NULL ||
	    SSL_CTX_use_certificate(ctx, cert) != 1 ||
	    SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
		SSL_CTX_free(ctx);
		X509_free(cert);
		EVP_PKEY_free(pkey);
		return NULL;
	}
	X509_free(cert);
	EVP_PKEY_free(pkey);
	return ctx;
}
#endif /* HAVE_OPENSSL */

/*
 * Stub for passive mode: listen on a free loopback port, tell the parent
 * which port that is, accept the library's connection and serve it.
 */
static void PCAP_NORETURN
stub_listen_and_serve(int ready_fd)
{
	struct sockaddr_in sa;
	socklen_t salen;
	struct chan c;
	int lfd, cfd;
	int one = 1;
	uint16_t port;

	lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0)
		_exit(1);
	(void)setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = 0;
	if (bind(lfd, (struct sockaddr *)&sa, sizeof sa) < 0 ||
	    listen(lfd, 1) < 0)
		_exit(1);
	salen = sizeof sa;
	if (getsockname(lfd, (struct sockaddr *)&sa, &salen) < 0)
		_exit(1);
	port = sa.sin_port;
	if (chan_write(&(struct chan){ .fd = ready_fd }, &port,
	    sizeof port) < 0)
		_exit(1);
	close(ready_fd);

	cfd = accept(lfd, NULL, NULL);
	if (cfd < 0)
		_exit(1);
	memset(&c, 0, sizeof c);
	c.fd = cfd;
	(void)stub_handshake(&c, 1);
	sleep_ms(2000);
	close(cfd);
	close(lfd);
	_exit(0);
}

/*
 * Stub for active mode: connect to the library's active-mode listener and
 * serve the handshake over a plain socket, or over TLS when "use_tls" is set
 * and the build has OpenSSL.  It must be started before
 * pcap_remoteact_accept() blocks in accept().
 */
static void PCAP_NORETURN
stub_connect_and_serve(uint16_t port, int use_tls)
{
	struct sockaddr_in sa;
	struct chan c;
	int fd = -1;
	int i;

	(void)use_tls;

	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = htons(port);

	for (i = 0; i < 100; i++) {
		fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd < 0)
			_exit(1);
		if (connect(fd, (struct sockaddr *)&sa, sizeof sa) == 0)
			break;
		close(fd);
		fd = -1;
		sleep_ms(50);
	}
	if (fd < 0)
		_exit(1);

	memset(&c, 0, sizeof c);
	c.fd = fd;
	if (use_tls) {
#ifdef HAVE_OPENSSL
		SSL_CTX *ctx = make_server_ctx();
		SSL *ssl;

		if (ctx == NULL) {
			fprintf(stderr, "stub: cannot generate a TLS "
			    "certificate\n");
			_exit(1);
		}
		ssl = SSL_new(ctx);
		if (ssl == NULL) {
			_exit(1);
		}
		SSL_set_fd(ssl, fd);
		if (SSL_accept(ssl) <= 0) {
			fprintf(stderr, "stub: TLS handshake failed\n");
			_exit(1);
		}
		/* The SSL handle holds its own reference to the context. */
		SSL_CTX_free(ctx);
		c.ssl = ssl;
#else
		_exit(1);
#endif
	}

	if (stub_handshake(&c, 0) < 0) {
		fprintf(stderr, "stub: rpcap handshake failed\n");
		_exit(1);
	}
	sleep_ms(2000);
#ifdef HAVE_OPENSSL
	if (c.ssl != NULL) {
		SSL_shutdown(c.ssl);
		SSL_free(c.ssl);
	}
#endif
	close(fd);
	_exit(0);
}

/*
 * Record which descriptors are open, so that the control socket the library
 * opens can be found afterwards.
 */
static void
snapshot_fds(char *open_before)
{
	int fd;

	for (fd = 0; fd < FD_MAX; fd++)
		open_before[fd] = fcntl(fd, F_GETFD) != -1;
}

static int
find_new_fd(const char *open_before)
{
	int fd;

	for (fd = 0; fd < FD_MAX; fd++) {
		if (!open_before[fd] && fcntl(fd, F_GETFD) != -1)
			return fd;
	}
	return -1;
}

/*
 * Place one end of a fresh AF_UNIX socketpair at exactly "fdnum", which the
 * library has just closed, and return the peer end.  Anything the library
 * still does to that descriptor number (send, shutdown or close) is then
 * visible at the peer.
 */
static int
place_probe(int fdnum, int *peerp)
{
	int sv[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
		return -1;
	if (sv[0] == fdnum) {
		*peerp = sv[1];
		return sv[0];
	}
	if (sv[1] == fdnum) {
		*peerp = sv[0];
		return sv[1];
	}
	if (dup2(sv[0], fdnum) < 0) {
		close(sv[0]);
		close(sv[1]);
		return -1;
	}
	close(sv[0]);
	*peerp = sv[1];
	return fdnum;
}

/*
 * The verify half: the probe must still be open and its peer must not have
 * seen any data or end-of-file.  Returns 0 when the descriptor was left
 * alone, -1 otherwise.
 */
static int
probe_untouched(int probe, int peer, const char *what)
{
	unsigned char buf[64];
	ssize_t n;
	int i;

	if (fcntl(probe, F_GETFD) == -1) {
		printf("FAIL: %s: libpcap closed the recycled descriptor\n",
		    what);
		return -1;
	}
	n = recv(peer, buf, sizeof buf, MSG_DONTWAIT);
	if (n > 0) {
		printf("FAIL: %s: libpcap wrote %zd bytes into the recycled "
		    "descriptor:", what, n);
		for (i = 0; i < n; i++)
			printf(" %02x", buf[i]);
		printf("\n");
		return -1;
	}
	if (n == 0) {
		printf("FAIL: %s: libpcap shut down the recycled descriptor\n",
		    what);
		return -1;
	}
	printf("PASS: %s\n", what);
	return 0;
}

/*
 * Passive mode: the server refuses STARTCAP_REQ, so the lazy startcapture
 * fails and closes the sockets.  Neither the retry of pcap_next_ex() nor
 * pcap_close() may operate on the recycled descriptor number.
 */
static int
test_passive_startcapture_failure(void)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[128];
	char open_before[FD_MAX];
	struct sockaddr_in sa;
	socklen_t salen;
	struct pcap_pkthdr *hdr;
	const u_char *data;
	struct bpf_program fprog;
	pcap_t *p;
	pid_t child;
	int pfd[2];
	int ctrl, probe, peer;
	int rc = -1;
	ssize_t got;
	uint16_t port;

	if (pipe(pfd) < 0) {
		perror("pipe");
		return -1;
	}
	child = fork();
	if (child < 0) {
		perror("fork");
		return -1;
	}
	if (child == 0) {
		close(pfd[0]);
		stub_listen_and_serve(pfd[1]);
	}
	close(pfd[1]);
	got = read(pfd[0], &port, sizeof port);
	close(pfd[0]);
	if (got != (ssize_t)sizeof port) {
		printf("FAIL: rpcap passive: stub did not report a port\n");
		goto out;
	}
	snprintf(source, sizeof source, "rpcap://127.0.0.1:%u/eth0",
	    (unsigned)ntohs(port));

	snapshot_fds(open_before);
	p = pcap_open(source, 65535, 0, 1000, NULL, errbuf);
	if (p == NULL) {
		printf("FAIL: rpcap passive: pcap_open failed: %s\n", errbuf);
		goto out;
	}
	ctrl = find_new_fd(open_before);
	salen = sizeof sa;
	if (ctrl < 0 || getsockname(ctrl, (struct sockaddr *)&sa, &salen) < 0) {
		printf("FAIL: rpcap passive: control socket not found\n");
		pcap_close(p);
		goto out;
	}

	/* Install a filter, so that the startcapture request carries a
	 * compiled program rather than the empty one. */
	if (pcap_compile(p, &fprog, "ip", 0, PCAP_NETMASK_UNKNOWN) < 0) {
		printf("FAIL: rpcap passive: pcap_compile failed: %s\n",
		    pcap_geterr(p));
		pcap_close(p);
		goto out;
	}
	if (pcap_setfilter(p, &fprog) < 0) {
		printf("FAIL: rpcap passive: pcap_setfilter failed: %s\n",
		    pcap_geterr(p));
		pcap_freecode(&fprog);
		pcap_close(p);
		goto out;
	}
	pcap_freecode(&fprog);

	/* The capture cannot start: the server answers STARTCAP_REQ
	 * with an error. */
	if (pcap_next_ex(p, &hdr, &data) != -1) {
		printf("FAIL: rpcap passive: expected startcapture to fail\n");
		pcap_close(p);
		goto out;
	}

	/* The library closed the control socket; put our probe at that
	 * exact descriptor number. */
	probe = place_probe(ctrl, &peer);
	if (probe < 0) {
		printf("FAIL: rpcap passive: cannot place probe\n");
		pcap_close(p);
		goto out;
	}

	/* Tear down; pcap_close() may not touch the recycled number. */
	pcap_close(p);

	rc = probe_untouched(probe, peer,
	    "rpcap passive: startcapture failure");
	close(probe);
	close(peer);

out:
	(void)kill(child, SIGKILL);
	(void)waitpid(child, NULL, 0);
	return rc;
}

/*
 * Active mode: pcap_open() borrows the control socket and the SSL handle of
 * the activeHosts entry.  After pcap_remoteact_close() has removed the entry
 * and freed them, pcap_close() must not touch them any more.  When the build
 * has OpenSSL the connection runs over TLS, so that the stale SSL handle that
 * the old teardown wrote to and freed again is actually present.
 */
static int
test_active_remoteact_close(void)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char portstr[16];
	char connectinghost[RPCAP_HOSTLIST_SIZE];
	struct sockaddr_in sa;
	socklen_t salen;
	PCAP_SOCKET s;
	pcap_t *p;
	pid_t child;
	int lfd, probe, peer;
	int rc = -1;
	int use_tls;
	unsigned attempt;
	uint16_t port;

#ifdef HAVE_OPENSSL
	use_tls = 1;
#else
	use_tls = 0;
#endif

	/* Find a free loopback port for our active-mode listener. */
	lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0) {
		perror("socket");
		return -1;
	}
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = 0;
	if (bind(lfd, (struct sockaddr *)&sa, sizeof sa) < 0) {
		perror("bind");
		close(lfd);
		return -1;
	}
	salen = sizeof sa;
	if (getsockname(lfd, (struct sockaddr *)&sa, &salen) < 0) {
		perror("getsockname");
		close(lfd);
		return -1;
	}
	port = ntohs(sa.sin_port);
	close(lfd);
	snprintf(portstr, sizeof portstr, "%u", (unsigned)port);

	for (attempt = 0; attempt < 5; attempt++) {
		child = fork();
		if (child < 0) {
			perror("fork");
			return -1;
		}
		if (child == 0) {
			stub_connect_and_serve(port, use_tls);
		}
		s = pcap_remoteact_accept_ex("127.0.0.1", portstr, NULL,
		    connectinghost, NULL, use_tls, errbuf);
		if (s != (PCAP_SOCKET)-1 && s != (PCAP_SOCKET)-2 &&
		    s != (PCAP_SOCKET)-3)
			break;
		(void)kill(child, SIGKILL);
		(void)waitpid(child, NULL, 0);
		sleep_ms(50);
	}
	if (attempt == 5) {
		printf("FAIL: rpcap active: pcap_remoteact_accept_ex failed: "
		    "%s\n", errbuf);
		return -1;
	}

	p = pcap_open("rpcap://127.0.0.1/eth0", 65535, 0, 1000, NULL,
	    errbuf);
	if (p == NULL) {
		printf("FAIL: rpcap active: pcap_open failed: %s\n", errbuf);
		goto out;
	}

	/* Drop the active entry: it frees the socket and the SSL handle
	 * that the pcap_t borrowed. */
	if (pcap_remoteact_close("127.0.0.1", errbuf) == -1) {
		printf("FAIL: rpcap active: pcap_remoteact_close failed: "
		    "%s\n", errbuf);
		pcap_close(p);
		goto out;
	}

	probe = place_probe((int)s, &peer);
	if (probe < 0) {
		printf("FAIL: rpcap active: cannot place probe\n");
		pcap_close(p);
		goto out;
	}

	pcap_close(p);

	rc = probe_untouched(probe, peer,
	    "rpcap active: pcap_remoteact_close then pcap_close");
	close(probe);
	close(peer);

out:
	(void)kill(child, SIGKILL);
	(void)waitpid(child, NULL, 0);
	return rc;
}

static void PCAP_NORETURN
on_alarm(int signo _U_)
{
	_exit(2);
}

int
main(void)
{
	int failures;

	(void)signal(SIGPIPE, SIG_IGN);
	(void)signal(SIGALRM, on_alarm);
	(void)alarm(60);

	failures = 0;
	if (test_passive_startcapture_failure() != 0)
		failures++;
	if (test_active_remoteact_close() != 0)
		failures++;

	if (failures != 0) {
		printf("rpcapownershiptest: %d test(s) failed\n", failures);
		return 1;
	}
	printf("rpcapownershiptest: all tests passed\n");
	return 0;
}
