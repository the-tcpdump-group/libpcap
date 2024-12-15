/* $OpenBSD: timeout.c,v 1.26 2023/11/03 19:16:31 cheloha Exp $ */

/*
 * Copyright (c) 2021 Job Snijders <job@openbsd.org>
 * Copyright (c) 2014 Baptiste Daroussin <bapt@FreeBSD.org>
 * Copyright (c) 2014 Vsevolod Stakhov <vsevolod@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pcap/funcattrs.h>

#define EXIT_TIMEOUT 124

static const char *program_name;

static volatile sig_atomic_t sig_chld = 0;
static volatile sig_atomic_t sig_term = 0;
static volatile sig_atomic_t sig_alrm = 0;
static volatile sig_atomic_t sig_ign = 0;

static void PCAP_NORETURN
usage(void)
{
	fprintf(stderr,
	    "usage: timeout [-fp] [-k time] [-s signal] duration command"
	    " [arg ...]\n");
	exit(1);
}

/* VARARGS */
static void PCAP_NORETURN PCAP_PRINTFLIKE(2, 3)
errx(int exit_status, PCAP_FORMAT_STRING(const char *fmt), ...)
{
	va_list ap;

	(void)fprintf(stderr, "%s: ", program_name);
	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
	exit(exit_status);
	/* NOTREACHED */
}

/* VARARGS */
static void PCAP_PRINTFLIKE(1, 2)
warn(PCAP_FORMAT_STRING(const char *fmt), ...)
{
	va_list ap;

	(void)fprintf(stderr, "%s: WARNING: ", program_name);
	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
}

static double
parse_duration(const char *duration)
{
	double	 ret;
	char	*suffix;

	ret = strtod(duration, &suffix);
	if (ret == 0 && suffix == duration)
		errx(1, "duration is not a number");
	if (ret < 0 || ret >= 100000000UL)
		errx(1, "duration out of range");

	if (suffix == NULL || *suffix == '\0')
		return (ret);

	if (suffix[1] != '\0')
		errx(1, "duration unit suffix too long");

	switch (*suffix) {
	case 's':
		break;
	case 'm':
		ret *= 60;
		break;
	case 'h':
		ret *= 60 * 60;
		break;
	case 'd':
		ret *= 60 * 60 * 24;
		break;
	default:
		errx(1, "duration unit suffix is invalid");
	}

	return (ret);
}

/*-
 * Copyright (c) 2004 Ted Unangst and Todd Miller
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * From:
 *	$OpenBSD: strtonum.c,v 1.7 2013/04/17 18:40:58 tedu Exp $
 */

#define	INVALID		1
#define	TOOSMALL	2
#define	TOOLARGE	3

static long long
our_strtonum(const char *numstr, long long minval, long long maxval,
    const char **errstrp)
{
	long long ll = 0;
	int error = 0;
	char *ep;
	struct errval {
		const char *errstr;
		int err;
	} ev[4] = {
		{ NULL,		0 },
		{ "invalid",	EINVAL },
		{ "too small",	ERANGE },
		{ "too large",	ERANGE },
	};

	ev[0].err = errno;
	errno = 0;
	if (minval > maxval) {
		error = INVALID;
	} else {
		ll = strtoll(numstr, &ep, 10);
		if (errno == EINVAL || numstr == ep || *ep != '\0')
			error = INVALID;
		else if ((ll == LLONG_MIN && errno == ERANGE) || ll < minval)
			error = TOOSMALL;
		else if ((ll == LLONG_MAX && errno == ERANGE) || ll > maxval)
			error = TOOLARGE;
	}
	if (errstrp != NULL)
		*errstrp = ev[error].errstr;
	errno = ev[error].err;
	if (error)
		ll = 0;

	return (ll);
}

struct sigentry {
	const char *name;
	int value;
};

static const struct sigentry signames[] = {
	{ "hup", SIGHUP },
	{ "int", SIGINT },
	{ "quit", SIGQUIT },
	{ "ill", SIGILL },
	{ "trap", SIGTRAP },
	{ "abrt", SIGABRT },
#ifdef SIGEMT
	{ "emt", SIGEMT },
#endif
	{ "fpe", SIGFPE },
	{ "kill", SIGKILL },
	{ "bus", SIGBUS },
	{ "segv", SIGSEGV },
	{ "sys", SIGSYS },
	{ "pipe", SIGPIPE },
	{ "alrm", SIGALRM },
	{ "term", SIGTERM },
	{ "urg", SIGURG },
	{ "stop", SIGSTOP },
	{ "tstp", SIGTSTP },
	{ "cont", SIGCONT },
	{ "chld", SIGCHLD },
	{ "ttin", SIGTTIN },
	{ "ttou", SIGTTOU },
#ifdef SIGIO
	{ "io", SIGIO },
#endif
	{ "xcpu", SIGXCPU },
	{ "xfsz", SIGXFSZ },
#ifdef SIGVTALRM
	{ "vtalrm", SIGVTALRM },
#endif
	{ "prof", SIGPROF },
#ifdef SIGWINCH
	{ "winch", SIGWINCH },
#endif
#ifdef SIGINFO
	{ "info", SIGINFO },
#endif
	{ "usr1", SIGUSR1 },
	{ "usr2", SIGUSR2 }
};

#define NUM_SIGNAMES	(sizeof (signames) / sizeof (signames[0]))

static int
parse_signal(const char *str)
{
	long long	 sig;
	const char	*errstr;

	if (isalpha((unsigned char)*str)) {
		if (strncasecmp(str, "SIG", 3) == 0)
			str += 3;
		for (size_t idx = 0; idx < NUM_SIGNAMES; idx++) {
			if (strcasecmp(str, signames[idx].name) == 0)
				return (signames[idx].value);
		}
		errx(1, "invalid signal name");
	}

	sig = our_strtonum(str, 1, NSIG, &errstr);
	if (errstr != NULL)
		errx(1, "signal %s %s", str, errstr);

	return (int)sig;
}

static void
sig_handler(int signo)
{
	if (sig_ign != 0 && signo == sig_ign) {
		sig_ign = 0;
		return;
	}

	switch (signo) {
	case SIGINT:
	case SIGHUP:
	case SIGQUIT:
	case SIGTERM:
		sig_term = signo;
		break;
	case SIGCHLD:
		sig_chld = 1;
		break;
	case SIGALRM:
		sig_alrm = 1;
		break;
	}
}

static void
set_interval(double iv)
{
	struct itimerval tim;

	memset(&tim, 0, sizeof(tim));
	tim.it_value.tv_sec = (time_t)iv;
	iv -= (double)tim.it_value.tv_sec;
	tim.it_value.tv_usec = (suseconds_t)(iv * 1000000UL);

	if (setitimer(ITIMER_REAL, &tim, NULL) == -1)
		errx(1, "setitimer: %s", strerror(errno));
}

int
main(int argc, char **argv)
{
	int		ch;
	unsigned long	i;
	int		foreground = 0, preserve = 0;
	int		pstat, status;
	int		killsig = SIGTERM;
	pid_t		pgid = 0, pid, cpid = 0;
	double		first_kill;
	double		second_kill = 0;
	bool		timedout = false;
	bool		do_second_kill = false;
	struct		sigaction signals;
	int		signums[] = {-1, SIGTERM, SIGINT, SIGHUP, SIGCHLD,
			    SIGALRM, SIGQUIT};

	const struct option longopts[] = {
		{ "preserve-status", no_argument,       NULL,        'p'},
		{ "foreground",      no_argument,       NULL,        'f'},
		{ "kill-after",      required_argument, NULL,        'k'},
		{ "signal",          required_argument, NULL,        's'},
		{ "help",            no_argument,       NULL,        'h'},
		{ NULL,              0,                 NULL,         0 }
	};

	program_name = argv[0];

	while ((ch = getopt_long(argc, argv, "+fk:ps:h", longopts, NULL))
	    != -1) {
		switch (ch) {
		case 'f':
			foreground = 1;
			break;
		case 'k':
			do_second_kill = true;
			second_kill = parse_duration(optarg);
			break;
		case 'p':
			preserve = 1;
			break;
		case 's':
			killsig = parse_signal(optarg);
			break;
		case 0:
			break;
		default:
			usage();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 2)
		usage();

	first_kill = parse_duration(argv[0]);
	argc--;
	argv++;

	if (!foreground) {
		pgid = setpgid(0, 0);

		if (pgid == -1)
			errx(1, "setpgid: %s", strerror(errno));
	}

	memset(&signals, 0, sizeof(signals));
	sigemptyset(&signals.sa_mask);

	if (killsig != SIGKILL && killsig != SIGSTOP)
		signums[0] = killsig;

	for (i = 0; i < sizeof(signums) / sizeof(signums[0]); i++)
		sigaddset(&signals.sa_mask, signums[i]);

	signals.sa_handler = sig_handler;
	signals.sa_flags = SA_RESTART;

	for (i = 0; i < sizeof(signums) / sizeof(signums[0]); i++) {
		if (signums[i] != -1 && signums[i] != 0 &&
		    sigaction(signums[i], &signals, NULL) == -1)
			errx(1, "sigaction: %s", strerror(errno));
	}

	signal(SIGTTIN, SIG_IGN);
	signal(SIGTTOU, SIG_IGN);

	pid = fork();
	if (pid == -1)
		errx(1, "fork: %s", strerror(errno));
	else if (pid == 0) {
		/* child process */
		signal(SIGTTIN, SIG_DFL);
		signal(SIGTTOU, SIG_DFL);

		execvp(argv[0], argv);
		warn("%s", argv[0]);
		_exit(errno == ENOENT ? 127 : 126);
	}

	/* parent continues here */

	if (sigprocmask(SIG_BLOCK, &signals.sa_mask, NULL) == -1)
		errx(1, "sigprocmask: %s", strerror(errno));

	set_interval(first_kill);

	for (;;) {
		sigemptyset(&signals.sa_mask);
		sigsuspend(&signals.sa_mask);

		if (sig_chld) {
			sig_chld = 0;
			while (((cpid = wait(&status)) < 0) && errno == EINTR)
				continue;

			if (cpid == pid) {
				pstat = status;
				break;
			}
		} else if (sig_alrm) {
			sig_alrm = 0;

			timedout = true;
			if (!foreground)
				killpg(pgid, killsig);
			else
				kill(pid, killsig);

			if (do_second_kill) {
				set_interval(second_kill);
				second_kill = 0;
				sig_ign = killsig;
				killsig = SIGKILL;
			} else
				break;

		} else if (sig_term) {
			if (!foreground)
				killpg(pgid, killsig);
			else
				kill(pid, (int)sig_term);

			if (do_second_kill) {
				set_interval(second_kill);
				second_kill = 0;
				sig_ign = killsig;
				killsig = SIGKILL;
			} else
				break;
		}
	}

	while (cpid != pid && wait(&pstat) == -1) {
		if (errno != EINTR)
			errx(1, "wait: %s", strerror(errno));
	}

	if (WEXITSTATUS(pstat))
		pstat = WEXITSTATUS(pstat);
	else if (WIFSIGNALED(pstat))
		pstat = 128 + WTERMSIG(pstat);

	if (timedout && !preserve)
		pstat = EXIT_TIMEOUT;

	return (pstat);
}
