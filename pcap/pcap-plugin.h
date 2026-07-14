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

#ifndef pcap_plugin_h
#define pcap_plugin_h

/*
 * Public plugin ABI for libpcap capture backends.
 *
 * External projects can build shared modules (pcap-*.so) that libpcap
 * discovers and loads at runtime via dlopen(). This avoids compiling
 * backend-specific code into libpcap itself.
 *
 * Each plugin .so exports a single symbol "pcap_plugin_entry" of type
 * struct pcap_plugin. The loader (pcap-plugin.c) scans plugin directories,
 * dlopen's each pcap-*.so, and dispatches findalldevs/create calls.
 *
 * Plugins link against libpcap (-lpcap) and use the pcap_plugin_*
 * accessor/helper functions declared below instead of accessing the
 * pcap_t struct directly (which would require pcap-int.h). All
 * pcap_plugin_* functions have default visibility and are safe to call
 * from dlopen'd modules.
 */

#include <pcap/pcap.h>

/*
 * pcap_if_list_t is defined in pcap-int.h (not public).
 * Forward-declare it here so plugins can use the findalldevs callback
 * and pcap_plugin_add_dev() without including pcap-int.h.
 *
 * Guard against duplicate typedef when pcap-int.h is already included
 * (C99 does not allow duplicate typedefs; C11 does, but some compilers
 * reject it with -Werror,-Wtypedef-redefinition).
 */
#ifndef pcap_int_h
struct pcap_if_list;
typedef struct pcap_if_list pcap_if_list_t;
#endif

#define PCAP_PLUGIN_ABI_VERSION	1

/*
 * Maximum snapshot length. Same value as MAXIMUM_SNAPLEN in pcap-int.h.
 * Plugins should clamp snapshots to this value.
 */
#define PCAP_PLUGIN_SNAPLEN_MAX	262144

/*
 * Each plugin .so exports one instance of this struct as the symbol
 * "pcap_plugin_entry".
 */
struct pcap_plugin {
	int abi_version;	/* must be PCAP_PLUGIN_ABI_VERSION */
	const char *name;	/* short name, e.g. "grout" */
	int (*findalldevs)(pcap_if_list_t *, char *);
	pcap_t *(*create)(const char *device, char *errbuf, int *is_ours);
};

/*
 * Function pointer types for pcap operations.
 * These match the types used internally by libpcap.
 */
typedef int	(*pcap_plugin_read_op)(pcap_t *, int, pcap_handler, u_char *);
typedef int	(*pcap_plugin_inject_op)(pcap_t *, const void *, int);
typedef int	(*pcap_plugin_setfilter_op)(pcap_t *, struct bpf_program *);
typedef int	(*pcap_plugin_setdirection_op)(pcap_t *, pcap_direction_t);
typedef int	(*pcap_plugin_set_datalink_op)(pcap_t *, int);
typedef int	(*pcap_plugin_getnonblock_op)(pcap_t *);
typedef int	(*pcap_plugin_setnonblock_op)(pcap_t *, int);
typedef int	(*pcap_plugin_stats_op)(pcap_t *, struct pcap_stat *);
typedef void	(*pcap_plugin_cleanup_op)(pcap_t *);
typedef void	(*pcap_plugin_breakloop_op)(pcap_t *);

/*
 * Capture backend operations. Set all applicable fields, then call
 * pcap_plugin_set_ops() during activate.
 */
struct pcap_plugin_ops {
	pcap_plugin_read_op read;
	pcap_plugin_inject_op inject;
	pcap_plugin_setfilter_op setfilter;
	pcap_plugin_setdirection_op setdirection;
	pcap_plugin_set_datalink_op set_datalink;
	pcap_plugin_getnonblock_op getnonblock;
	pcap_plugin_setnonblock_op setnonblock;
	pcap_plugin_stats_op stats;
	pcap_plugin_cleanup_op cleanup;
	pcap_plugin_breakloop_op breakloop_func;
};

/* ---- Handle allocation ---- */

/*
 * Allocate a pcap_t with space for priv_size bytes of private data.
 * Returns NULL on failure (errbuf filled in).
 */
PCAP_API pcap_t *pcap_plugin_create_handle(char *errbuf, size_t priv_size);

/*
 * Get the private data pointer from a pcap_t.
 */
PCAP_API void *pcap_plugin_priv(pcap_t *p);

/* ---- Handle configuration (call during create/activate) ---- */

/*
 * Set the activate callback. Call from your create function.
 */
PCAP_API void pcap_plugin_set_activate(pcap_t *p,
    int (*activate_op)(pcap_t *));

/*
 * Install all capture operations at once. Call from your activate
 * function. NULL entries are left unchanged (libpcap defaults).
 */
PCAP_API void pcap_plugin_set_ops(pcap_t *p,
    const struct pcap_plugin_ops *ops);

/*
 * Set the link-layer type (e.g. DLT_EN10MB). Call from activate.
 */
PCAP_API void pcap_plugin_set_linktype(pcap_t *p, int linktype);

/*
 * Set the snapshot length. Call from activate if you need to override
 * the user-requested value.
 */
PCAP_API void pcap_plugin_set_snapshot(pcap_t *p, int snaplen);

/*
 * Set the required select timeout for poll-based plugins.
 * The pointer must remain valid for the lifetime of the pcap_t.
 */
PCAP_API void pcap_plugin_set_select_timeout(pcap_t *p, struct timeval *tv);

/* ---- Handle accessors (call during dispatch/activate) ---- */

/*
 * Get the device name string (e.g. "grout:p0").
 */
PCAP_API const char *pcap_plugin_get_device(pcap_t *p);

/*
 * Get the current snapshot length.
 */
PCAP_API int pcap_plugin_get_snapshot(pcap_t *p);

/*
 * Get the read timeout in milliseconds (0 = no timeout).
 */
PCAP_API int pcap_plugin_get_timeout(pcap_t *p);

/*
 * Check and clear the break_loop flag. Returns nonzero if a break
 * was requested. Plugins should call this in their dispatch loop.
 */
PCAP_API int pcap_plugin_check_break_loop(pcap_t *p);

/*
 * Get the compiled BPF filter instructions, or NULL if no filter
 * is installed. For plugins that do in-kernel/hardware filtering,
 * this is the fallback software filter.
 */
PCAP_API struct bpf_insn *pcap_plugin_get_filter(pcap_t *p);

/*
 * Format an error message into the pcap_t's error buffer.
 */
PCAP_API void pcap_plugin_set_errbuf(pcap_t *p,
    PCAP_FORMAT_STRING(const char *fmt), ...) PCAP_PRINTFLIKE(2, 3);

/*
 * Get the timestamp type requested by the user (e.g. PCAP_TSTAMP_ADAPTER).
 * Returns -1 (not set) if none was explicitly requested.
 * Call during activate to decide which clock source to use.
 */
PCAP_API int pcap_plugin_get_tstamp_type(pcap_t *p);

/*
 * Get the timestamp precision requested by the user.
 * Returns PCAP_TSTAMP_PRECISION_MICRO (default) or
 * PCAP_TSTAMP_PRECISION_NANO. Call during activate to decide
 * whether to provide nanosecond timestamps.
 */
PCAP_API int pcap_plugin_get_tstamp_precision(pcap_t *p);

/*
 * Get the promiscuous mode flag (nonzero = user requested promisc).
 * Call during activate.
 */
PCAP_API int pcap_plugin_get_promisc(pcap_t *p);

/*
 * Get the buffer size requested by the user (0 = platform default).
 * Call during activate to size ring buffers or mempools.
 */
PCAP_API int pcap_plugin_get_buffer_size(pcap_t *p);

/*
 * Get the immediate mode flag (nonzero = deliver packets ASAP,
 * don't wait to fill a buffer). Call during activate.
 */
PCAP_API int pcap_plugin_get_immediate(pcap_t *p);

/*
 * Advertise supported timestamp types to libpcap. Call during create
 * (before activate) so pcap_list_tstamp_types() works. The types
 * array is copied. Returns 0 on success, -1 on allocation failure.
 */
PCAP_API int pcap_plugin_set_tstamp_type_list(pcap_t *p,
    const int *types, int count);

/*
 * Advertise supported timestamp precisions. Call during create
 * so pcap_list_tstamp_precisions() works. The array is copied.
 * Returns 0 on success, -1 on allocation failure.
 */
PCAP_API int pcap_plugin_set_tstamp_precision_list(pcap_t *p,
    const int *precisions, int count);

/*
 * Advertise supported data link types. Call during activate
 * so pcap_list_datalinks() works. The array is copied.
 * Returns 0 on success, -1 on allocation failure.
 */
PCAP_API int pcap_plugin_set_datalink_list(pcap_t *p,
    const int *dlts, int count);

/*
 * Set the selectable file descriptor for poll/select/epoll.
 * Plugins that can provide a pollable fd (e.g. eventfd, unix socket)
 * should call this during activate. Set to -1 if not pollable
 * (then also set a required_select_timeout via
 * pcap_plugin_set_select_timeout).
 */
PCAP_API void pcap_plugin_set_selectable_fd(pcap_t *p, int fd);

/* ---- Helper functions ---- */

/*
 * Common cleanup for live captures. Call from your cleanup_op.
 */
PCAP_API void pcap_plugin_cleanup_live(pcap_t *p);

/*
 * Standard breakloop implementation. Use as breakloop_func in ops,
 * or call from your own breakloop.
 */
PCAP_API void pcap_plugin_breakloop(pcap_t *p);

/*
 * Install a BPF filter program (deep copy). Call from your setfilter_op
 * to install the filter locally for pcap_plugin_filter() fallback.
 */
PCAP_API int pcap_plugin_install_bpf(pcap_t *p, struct bpf_program *fp);

/*
 * Run a BPF filter on a packet. Returns nonzero if the packet matches.
 */
PCAP_API unsigned int pcap_plugin_filter(const struct bpf_insn *pc,
    const unsigned char *pkt, unsigned int wirelen, unsigned int caplen);

/*
 * Add a device entry to a device list (for findalldevs).
 */
PCAP_API pcap_if_t *pcap_plugin_add_dev(pcap_if_list_t *devlistp,
    const char *name, unsigned int flags, const char *description,
    char *errbuf);

#endif /* pcap_plugin_h */
