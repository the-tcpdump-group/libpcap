/*
 * Copyright (c) 2026 Vincent Jardin, Free Mobile, Iliad
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS''AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * pcap-plugin: generic plugin loader for libpcap capture backends.
 *
 * Scans plugin directories for pcap-*.so shared modules, loads each
 * via pcapint_load_code(), and dispatches findalldevs/create calls to
 * loaded plugins.
 *
 * Security model (modeled after glibc/musl AT_SECURE behavior):
 *   - Privilege detection via getauxval(AT_SECURE) or uid/euid comparison.
 *   - $PCAP_PLUGIN_DIR is ignored under elevated privileges.
 *   - Plugin files are validated with lstat() before loading:
 *     symlinks rejected, group/world-writable rejected, ownership checked.
 *   - Plugin directories are validated the same way.
 *   - libpcap does NOT drop privileges itself; that is the app's job.
 *
 * Plugin search order:
 *   1. $PCAP_PLUGIN_DIR (colon-separated, skipped if AT_SECURE)
 *   2. PCAP_PLUGIN_DIR (compile-time --with-plugin-dir, if set)
 *   3. /usr/lib/pcap/plugins
 *   4. /usr/local/lib/pcap/plugins
 */

#include <config.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <dirent.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef HAVE_GETAUXVAL
#include <sys/auxv.h>
#endif
#endif /* _WIN32 */

#include "pcap-int.h"
#include "pcap-plugin.h"
#include <pcap/pcap-plugin.h>

#define MAX_PLUGINS	16

static struct pcap_plugin *plugins[MAX_PLUGINS];
static int n_plugins;
static int plugins_loaded;

#ifndef _WIN32
/*
 * Detect whether we are running with elevated privileges.
 *
 * Security checks:
 *   - getauxval(AT_SECURE) — Linux: covers setuid, setgid, file
 *     capabilities, and LSM domain transitions (e.g. SELinux).
 *   - issetugid() — BSD/macOS/Solaris: returns 1 when the process
 *     environment or memory address space is considered "tainted"
 *     (setuid/setgid exec, or explicit mark by the kernel).
 *   - uid/euid + gid/egid comparison — last resort fallback;
 *     misses some edge cases.
 */
static int
is_at_secure(void)
{
#ifdef HAVE_GETAUXVAL
	return (getauxval(AT_SECURE) != 0);
#elif defined(HAVE_ISSETUGID)
	return (issetugid());
#else
	return (getuid() != geteuid() || getgid() != getegid());
#endif
}

/*
 * Validate that a plugin directory is safe to load from.
 * Returns 0 if safe, -1 if not (with a warning on stderr).
 *
 * Rules:
 *   - Must exist and be a directory (lstat, S_ISDIR).
 *   - Must not be group-writable or world-writable.
 *   - Under AT_SECURE: must be owned by root (uid 0).
 *   - Under normal user: must be owned by current uid or root.
 */
static int
validate_dir(const char *dirpath, int secure)
{
	struct stat st;

	if (lstat(dirpath, &st) != 0)
		return (-1);	/* does not exist, silently skip */

	if (!S_ISDIR(st.st_mode)) {
		fprintf(stderr,
		    "libpcap: plugin directory \"%s\" is not a directory\n",
		    dirpath);
		return (-1);
	}

	if (st.st_mode & S_IWGRP) {
		fprintf(stderr,
		    "libpcap: plugin directory \"%s\" is group-writable, "
		    "skipping\n", dirpath);
		return (-1);
	}

	if (st.st_mode & S_IWOTH) {
		fprintf(stderr,
		    "libpcap: plugin directory \"%s\" is world-writable, "
		    "skipping\n", dirpath);
		return (-1);
	}

	if (secure) {
		if (st.st_uid != 0) {
			fprintf(stderr,
			    "libpcap: plugin directory \"%s\" not owned by "
			    "root (owner uid %u), skipping\n",
			    dirpath, (unsigned)st.st_uid);
			return (-1);
		}
	} else {
		uid_t myuid = getuid();
		if (st.st_uid != myuid && st.st_uid != 0) {
			fprintf(stderr,
			    "libpcap: plugin directory \"%s\" not owned by "
			    "current user or root (owner uid %u), skipping\n",
			    dirpath, (unsigned)st.st_uid);
			return (-1);
		}
	}

	return (0);
}

/*
 * Validate that a plugin file is safe to dlopen.
 * Returns 0 if safe, -1 if not (with a warning on stderr).
 *
 * Rules:
 *   1. Filename must not contain ".." (no path traversal).
 *   2. Must be a regular file (lstat — reject symlinks).
 *   3. Must not be group-writable.
 *   4. Must not be world-writable.
 *   5. Under AT_SECURE: must be owned by root (uid 0).
 *   6. Under normal user: must be owned by current uid or root.
 */
static int
validate_plugin_file(const char *path, const char *filename, int secure)
{
	struct stat st;

	/* Rule 1: reject path traversal */
	if (strstr(filename, "..") != NULL) {
		fprintf(stderr,
		    "libpcap: plugin filename \"%s\" contains \"..\", "
		    "skipping\n", filename);
		return (-1);
	}

	if (lstat(path, &st) != 0) {
		fprintf(stderr,
		    "libpcap: cannot lstat plugin \"%s\": %s\n",
		    path, strerror(errno));
		return (-1);
	}

	/* Rule 2: regular file, no symlinks */
	if (!S_ISREG(st.st_mode)) {
		fprintf(stderr,
		    "libpcap: plugin \"%s\" is not a regular file, "
		    "skipping\n", path);
		return (-1);
	}

	/* Rule 3: not group-writable */
	if (st.st_mode & S_IWGRP) {
		fprintf(stderr,
		    "libpcap: plugin \"%s\" is group-writable, "
		    "skipping\n", path);
		return (-1);
	}

	/* Rule 4: not world-writable */
	if (st.st_mode & S_IWOTH) {
		fprintf(stderr,
		    "libpcap: plugin \"%s\" is world-writable, "
		    "skipping\n", path);
		return (-1);
	}

	/* Rules 5 and 6: ownership */
	if (secure) {
		if (st.st_uid != 0) {
			fprintf(stderr,
			    "libpcap: plugin \"%s\" not owned by root "
			    "(owner uid %u), skipping\n",
			    path, (unsigned)st.st_uid);
			return (-1);
		}
	} else {
		uid_t myuid = getuid();
		if (st.st_uid != myuid && st.st_uid != 0) {
			fprintf(stderr,
			    "libpcap: plugin \"%s\" not owned by current "
			    "user or root (owner uid %u), skipping\n",
			    path, (unsigned)st.st_uid);
			return (-1);
		}
	}

	return (0);
}

static void
load_plugin(const char *path)
{
	pcap_code_handle_t handle;
	struct pcap_plugin *p;

	if (n_plugins >= MAX_PLUGINS) {
		fprintf(stderr,
		    "libpcap: too many plugins (max %d), skipping \"%s\"\n",
		    MAX_PLUGINS, path);
		return;
	}

	handle = pcapint_load_code(path);
	if (handle == NULL) {
		fprintf(stderr,
		    "libpcap: cannot load plugin \"%s\": %s\n",
		    path, dlerror());
		return;
	}

	p = pcapint_find_function(handle, "pcap_plugin_entry");
	if (p == NULL) {
		fprintf(stderr,
		    "libpcap: plugin \"%s\" has no pcap_plugin_entry "
		    "symbol\n", path);
		pcapint_unload_code(handle);
		return;
	}
	if (p->abi_version != PCAP_PLUGIN_ABI_VERSION) {
		fprintf(stderr,
		    "libpcap: plugin \"%s\" ABI version %d != expected %d\n",
		    path, p->abi_version, PCAP_PLUGIN_ABI_VERSION);
		pcapint_unload_code(handle);
		return;
	}
	if (p->name == NULL || p->create == NULL) {
		fprintf(stderr,
		    "libpcap: plugin \"%s\" has NULL name or create\n",
		    path);
		pcapint_unload_code(handle);
		return;
	}

	plugins[n_plugins++] = p;
	/*
	 * Intentionally leak the dlopen handle: the plugin stays loaded
	 * for the lifetime of the process.
	 */
}

static void
scan_dir(const char *dirpath, int secure)
{
	DIR *d;
	struct dirent *ent;

	if (validate_dir(dirpath, secure) != 0)
		return;

	d = opendir(dirpath);
	if (d == NULL)
		return;

	while ((ent = readdir(d)) != NULL) {
		const char *name = ent->d_name;
		size_t len = strlen(name);
		char path[4096];

		/* match pcap-*.so */
		if (len < 8)	/* strlen("pcap-.so") */
			continue;
		if (strncmp(name, "pcap-", 5) != 0)
			continue;
		if (strcmp(name + len - 3, ".so") != 0)
			continue;

		snprintf(path, sizeof(path), "%s/%s", dirpath, name);

		if (validate_plugin_file(path, name, secure) != 0)
			continue;

		load_plugin(path);
	}
	closedir(d);
}

static void
load_plugins(void)
{
	int secure;

	if (plugins_loaded)
		return;
	plugins_loaded = 1;

	secure = is_at_secure();

	/*
	 * $PCAP_PLUGIN_DIR is ignored when running with elevated
	 * privileges (AT_SECURE), matching ld-linux.so behavior
	 * for LD_LIBRARY_PATH under setuid.
	 */
	if (!secure) {
		const char *env;

		env = getenv("PCAP_PLUGIN_DIR");
		if (env != NULL && env[0] != '\0') {
			char *dirs, *dir, *saveptr;

			dirs = strdup(env);
			if (dirs != NULL) {
				for (dir = strtok_r(dirs, ":", &saveptr);
				     dir != NULL;
				     dir = strtok_r(NULL, ":", &saveptr)) {
					scan_dir(dir, secure);
				}
				free(dirs);
			}
		}
	}

#ifdef PCAP_PLUGIN_DIR
	scan_dir(PCAP_PLUGIN_DIR, secure);
#endif
	scan_dir("/usr/lib/pcap/plugins", secure);
	scan_dir("/usr/local/lib/pcap/plugins", secure);
}
#else /* _WIN32 */
static void
load_plugins(void)
{
	/*
	 * Windows plugin loading: not yet implemented.
	 *
	 * When implemented, this would use FindFirstFileA/FindNextFileA
	 * to scan a plugin directory for pcap-*.dll files, then call
	 * pcapint_load_code() and pcapint_find_function() for each.
	 *
	 * Note: the existing pcapint_load_code() on Windows prepends
	 * GetSystemDirectoryA(), which is not suitable for plugins in
	 * custom directories. A future implementation would need a
	 * variant that takes an absolute path.
	 */
}
#endif /* _WIN32 */

pcap_t *
pcap_plugin_dispatch_create(const char *device, char *errbuf, int *is_ours)
{
	int i;

	load_plugins();

	for (i = 0; i < n_plugins; i++) {
		pcap_t *p = plugins[i]->create(device, errbuf, is_ours);
		if (*is_ours)
			return p;
	}

	*is_ours = 0;
	return NULL;
}

int
pcap_plugin_dispatch_findalldevs(pcap_if_list_t *devlistp, char *errbuf)
{
	int i;

	load_plugins();

	for (i = 0; i < n_plugins; i++) {
		if (plugins[i]->findalldevs == NULL)
			continue;
		if (plugins[i]->findalldevs(devlistp, errbuf) == -1)
			return -1;
	}
	return 0;
}

/*
 * Plugin helper functions — exported wrappers around internal
 * libpcap functions and struct pcap accessors. These have PCAP_API
 * (default visibility) so plugins can call them from dlopen'd .so
 * modules without needing pcap-int.h.
 */

pcap_t *
pcap_plugin_create_handle(char *errbuf, size_t priv_size)
{
	return pcapint_create_common(errbuf,
	    sizeof(pcap_t) + priv_size, sizeof(pcap_t));
}

void *
pcap_plugin_priv(pcap_t *p)
{
	return p->priv;
}

void
pcap_plugin_set_activate(pcap_t *p, int (*activate_op)(pcap_t *))
{
	p->activate_op = activate_op;
}

void
pcap_plugin_set_ops(pcap_t *p, const struct pcap_plugin_ops *ops)
{
	if (ops->read != NULL)
		p->read_op = ops->read;
	if (ops->inject != NULL)
		p->inject_op = ops->inject;
	if (ops->setfilter != NULL)
		p->setfilter_op = ops->setfilter;
	if (ops->setdirection != NULL)
		p->setdirection_op = ops->setdirection;
	if (ops->set_datalink != NULL)
		p->set_datalink_op = ops->set_datalink;
	if (ops->getnonblock != NULL)
		p->getnonblock_op = ops->getnonblock;
	if (ops->setnonblock != NULL)
		p->setnonblock_op = ops->setnonblock;
	if (ops->stats != NULL)
		p->stats_op = ops->stats;
	if (ops->cleanup != NULL)
		p->cleanup_op = ops->cleanup;
	if (ops->breakloop_func != NULL)
		p->breakloop_op = ops->breakloop_func;
}

void
pcap_plugin_set_linktype(pcap_t *p, int linktype)
{
	p->linktype = linktype;
}

void
pcap_plugin_set_snapshot(pcap_t *p, int snaplen)
{
	p->snapshot = snaplen;
}

void
pcap_plugin_set_select_timeout(pcap_t *p, struct timeval *tv)
{
#ifndef _WIN32
	p->required_select_timeout = tv;
#endif
}

const char *
pcap_plugin_get_device(pcap_t *p)
{
	return p->opt.device;
}

int
pcap_plugin_get_snapshot(pcap_t *p)
{
	return p->snapshot;
}

int
pcap_plugin_get_timeout(pcap_t *p)
{
	return p->opt.timeout;
}

int
pcap_plugin_check_break_loop(pcap_t *p)
{
	if (p->break_loop) {
		p->break_loop = 0;
		return 1;
	}
	return 0;
}

struct bpf_insn *
pcap_plugin_get_filter(pcap_t *p)
{
	return p->fcode.bf_insns;
}

void
pcap_plugin_set_errbuf(pcap_t *p, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(p->errbuf, PCAP_ERRBUF_SIZE, fmt, ap);
	va_end(ap);
}

void
pcap_plugin_cleanup_live(pcap_t *p)
{
	pcapint_cleanup_live_common(p);
}

void
pcap_plugin_breakloop(pcap_t *p)
{
	pcapint_breakloop_common(p);
}

int
pcap_plugin_install_bpf(pcap_t *p, struct bpf_program *fp)
{
	return pcapint_install_bpf_program(p, fp);
}

unsigned int
pcap_plugin_filter(const struct bpf_insn *pc, const unsigned char *pkt,
    unsigned int wirelen, unsigned int caplen)
{
	return pcapint_filter(pc, pkt, wirelen, caplen);
}

pcap_if_t *
pcap_plugin_add_dev(pcap_if_list_t *devlistp, const char *name,
    unsigned int flags, const char *description, char *errbuf)
{
	return pcapint_add_dev(devlistp, name, (bpf_u_int32)flags,
	    description, errbuf);
}
