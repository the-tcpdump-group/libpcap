#define _GNU_SOURCE

/* XXX Hack not to include the Mach BPF interface */
#define _DEVICE_BPF_H_

#include <config.h>

#include <fcntl.h>
#include <hurd.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <device/device.h>
#include <device/device_types.h>
#include <device/net_status.h>
#include <hurd/ports.h>
#include <net/if_ether.h>

#include "pcap-int.h"

struct pcap_hurd {
	struct pcap_stat stat;
	device_t mach_dev;
	mach_port_t rcv_port;
	int filtering_in_kernel;
	pthread_t pipe_thread_id;
	int pipefd[2];
};

/* Accept all packets. */
static struct bpf_insn filter[] = {
	{ NETF_IN | NETF_OUT | NETF_BPF, 0, 0, 0 },
	{ BPF_RET | BPF_K, 0, 0, MAXIMUM_SNAPLEN },
};

/* device_set_filter calls net_set_filter which uses CSPF_BYTES which counts in
 * shorts, not elements, so using extra parenthesis to silence compilers which
 * believe we are computing wrong here. */
#define FILTER_COUNT (sizeof(filter) / (sizeof(short)))

/*
 * strerror() on GNU/Hurd maps Mach error messages to strings,
 * so we can use pcapint_fmt_errmsg_for_errno() to format
 * messages for them.
 */
#define pcapint_fmt_errmsg_for_kern_return_t	pcapint_fmt_errmsg_for_errno

static int
PCAP_WARN_UNUSED_RESULT
pcap_device_set_filter(pcap_t *p, filter_array_t filter_array,
                       const mach_msg_type_number_t filter_count)
{
	kern_return_t kr;
	struct pcap_hurd *ph = p->priv;
	kr = device_set_filter(ph->mach_dev, ph->rcv_port,
	                       MACH_MSG_TYPE_MAKE_SEND, 0,
	                       filter_array, filter_count);
	if (! kr)
		return 0;
	pcapint_fmt_errmsg_for_kern_return_t(p->errbuf, PCAP_ERRBUF_SIZE, kr,
	    "device_set_filter");
	return PCAP_ERROR;
}

static int
pcap_setfilter_hurd(pcap_t *p, struct bpf_program *program)
{
	if (! program || pcapint_install_bpf_program(p, program) < 0) {
		pcapint_strlcpy(p->errbuf, "setfilter: invalid program",
		                sizeof(p->errbuf));
		return PCAP_ERROR;
	}

	/*
	 * The bytecode is valid and the copy in p->fcode can be used for
	 * userland filtering if kernel filtering does not work out.
	 *
	 * The kernel BPF implementation supports neither BPF_MOD nor BPF_XOR,
	 * it also fails to reject unsupported bytecode properly, so the check
	 * must be done here.
	 */
	struct pcap_hurd *ph = p->priv;
	for (u_int i = 0; i < program->bf_len; i++) {
		u_short	c = program->bf_insns[i].code;
		if (BPF_CLASS(c) == BPF_ALU &&
		    (BPF_OP(c) == BPF_MOD || BPF_OP(c) == BPF_XOR))
			goto userland;
	}

	/*
	 * The kernel takes an array of 16-bit Hurd network filter commands, no
	 * more than NET_MAX_FILTER elements.  The first four commands form a
	 * header that says "BPF bytecode follows", the rest is a binary copy
	 * of 64-bit instructions of the required BPF bytecode.
	 */
	mach_msg_type_number_t cmdcount = 4 + 4 * program->bf_len;
	if (cmdcount > NET_MAX_FILTER)
		goto userland;

	filter_t cmdbuffer[NET_MAX_FILTER];
	memcpy(cmdbuffer, filter, sizeof(struct bpf_insn));
	memcpy(cmdbuffer + 4, program->bf_insns,
	       program->bf_len * sizeof(struct bpf_insn));
	if (pcap_device_set_filter(p, cmdbuffer, cmdcount))
		goto userland;
	ph->filtering_in_kernel = 1;
	return 0;

userland:
	/*
	 * Could not install a new kernel filter for a reason, so replace any
	 * previous kernel filter with one that accepts all packets and lets
	 * userland filtering do the job.  If that fails too, something is
	 * badly broken and even userland filtering would not work correctly,
	 * so expose the failure.
	 */
	ph->filtering_in_kernel = 0;
	return pcap_device_set_filter(p, (filter_array_t)filter, FILTER_COUNT);
}

static int
pcap_read_hurd(pcap_t *p, int cnt _U_, pcap_handler callback, u_char *user)
{
	struct net_rcv_msg *msg;
	struct pcap_hurd *ph;
	struct pcap_pkthdr h;
	struct timespec ts;
	int wirelen, caplen, rpipe, ret;
	u_char *pkt;

	ph = p->priv;
	rpipe = ph->pipefd[0];
	msg = (struct net_rcv_msg *)p->buffer;

retry:
	if (p->break_loop) {
		p->break_loop = 0;
		return PCAP_ERROR_BREAK;
	}

	ret = read(rpipe, &msg->msg_hdr, p->bufsize);
	if (ret < 0) {
		pcapint_fmt_errmsg_for_kern_return_t(p->errbuf,
			PCAP_ERRBUF_SIZE, errno, "read");
		return PCAP_ERROR;
	}
	if (ret == 0)
		/* Pipe closed, 0 packets read */
		return 0;
	clock_gettime(CLOCK_REALTIME, &ts);

	ph->stat.ps_recv++;

	/* XXX Ethernet support only */
	/*
	 * wirelen calculation assumes the following:
	 *   msg->packet_type.msgt_name == MACH_MSG_TYPE_BYTE
	 *   msg->packet_type.msgt_size == 8
	 *   msg->packet_type.msgt_number is a size in bytes
	 */
	wirelen = ETH_HLEN + msg->net_rcv_msg_packet_count
		  - sizeof(struct packet_header);
	pkt = p->buffer + offsetof(struct net_rcv_msg, packet)
	      + sizeof(struct packet_header) - ETH_HLEN;
	memmove(pkt, p->buffer + offsetof(struct net_rcv_msg, header),
		ETH_HLEN);

	/*
	 * It seems, kernel device filters treat the K in BPF_RET as a Boolean:
	 * so long as it is positive, the Mach message will contain the entire
	 * packet and wirelen will be set accordingly.  Thus the caplen value
	 * for the callback needs to be calculated for every packet no matter
	 * which type of filtering is in effect.
	 *
	 * For the userland filtering this calculated value is not an input:
	 * buflen always equals wirelen and a userland program can examine the
	 * entire packet, same way as a kernel program.  It is not an output
	 * either: pcapint_filter() returns either zero or MAXIMUM_SNAPLEN.
	 * The same principle applies to kernel filtering.
	 */
	caplen = (wirelen > p->snapshot) ? p->snapshot : wirelen;

	if (! ph->filtering_in_kernel &&
	    ! pcapint_filter(p->fcode.bf_insns, pkt, wirelen, wirelen)) {
		ph->stat.ps_drop++;
		return 0;
	}

	h.ts.tv_sec = ts.tv_sec;
	h.ts.tv_usec = ts.tv_nsec / 1000;
	h.len = wirelen;
	h.caplen = caplen;
	callback(user, &h, pkt);
	return 1;
}

static int
pcap_inject_hurd(pcap_t *p, const void *buf, int size)
{
	struct pcap_hurd *ph;
	kern_return_t kr;
	int count;

	ph = p->priv;
	kr = device_write(ph->mach_dev, D_NOWAIT, 0,
			  (io_buf_ptr_t)buf, size, &count);

	if (kr) {
		pcapint_fmt_errmsg_for_kern_return_t(p->errbuf, PCAP_ERRBUF_SIZE, kr,
		    "device_write");
		return PCAP_ERROR;
	}

	return count;
}

static int
pcap_stats_hurd(pcap_t *p, struct pcap_stat *ps)
{
	struct pcap_hurd *ph;

	ph = p->priv;
	*ps = ph->stat;
	return 0;
}

static void
pcap_cleanup_hurd(pcap_t *p)
{
	struct pcap_hurd *ph;
	int err;

	ph = p->priv;

	/* Cancel the thread */
	if (ph->pipe_thread_id != 0) {
		pthread_cancel(ph->pipe_thread_id);

		err = pthread_join(ph->pipe_thread_id, NULL);
		if (err != 0) {
			pcapint_fmt_errmsg_for_errno(p->errbuf,
				PCAP_ERRBUF_SIZE, err, "pthread_join");
		}
		ph->pipe_thread_id = 0;
	}

	/* Close the pipe ends */
	if (ph->pipefd[1] != -1) {
		close(ph->pipefd[1]);
		ph->pipefd[1] = -1;
	}

	if (ph->pipefd[0] != -1) {
		close(ph->pipefd[0]);
		ph->pipefd[0] = -1;
	}

	/* Release remaining resources */
	if (ph->rcv_port != MACH_PORT_NULL) {
		mach_port_deallocate(mach_task_self(), ph->rcv_port);
		ph->rcv_port = MACH_PORT_NULL;
	}

	if (ph->mach_dev != MACH_PORT_NULL) {
		device_close(ph->mach_dev);
		mach_port_deallocate(mach_task_self(), ph->mach_dev);
		ph->mach_dev = MACH_PORT_NULL;
	}

	pcapint_cleanup_live_common(p);
}

static void*
pipe_write_thread(void *arg) {
	pcap_t *p;
	struct pcap_hurd *ph;
	int wpipe, ret;
	struct net_rcv_msg msg;
	u_int msgsize;
	kern_return_t kr;
	mach_msg_timeout_t timeout_ms;
	sigset_t set;

	pthread_setname_np (pthread_self(), "pcap_hurd_pipe_thread");

	/* Block SIGPIPE for this thread */
	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	p = (pcap_t *)arg;
	ph = p->priv;
	wpipe = ph->pipefd[1];
	msgsize = sizeof(struct net_rcv_msg);
	timeout_ms = 100;

	while (1) {
		kr = mach_msg(&msg.msg_hdr,
			MACH_RCV_MSG | MACH_RCV_INTERRUPT| MACH_RCV_TIMEOUT,
			0, msgsize, ph->rcv_port, timeout_ms,
			MACH_PORT_NULL);

		if (kr) {
			if (kr == MACH_RCV_TIMED_OUT || kr == MACH_RCV_INTERRUPTED) {
				pthread_testcancel();
				continue;
			}

			pcapint_fmt_errmsg_for_kern_return_t(p->errbuf,
				PCAP_ERRBUF_SIZE, kr, "mach_msg");

			return NULL;
		}

		ret = write(wpipe, &msg, msgsize);
		if (ret < 0) {
			pcapint_fmt_errmsg_for_errno(p->errbuf,
				PCAP_ERRBUF_SIZE, errno, "write");
			return NULL;
		}
	}

	return NULL;
}

static int
init_pipe(pcap_t *p) {
	int err;
	struct pcap_hurd *ph;

	ph = p->priv;
	err = pipe(ph->pipefd);
	if (err < 0)
		return errno;

	err = pthread_create(&ph->pipe_thread_id, NULL, pipe_write_thread, p);
	if (err != 0)
		return err;

	return 0;
}

static int
pcap_activate_hurd(pcap_t *p)
{
	struct pcap_hurd *ph;
	mach_port_t master;
	kern_return_t kr;
	int ret = PCAP_ERROR;

	ph = p->priv;

	if (p->snapshot <= 0 || p->snapshot > MAXIMUM_SNAPLEN)
		p->snapshot = MAXIMUM_SNAPLEN;

	/* Try devnode first */
	master = file_name_lookup(p->opt.device, O_READ | O_WRITE, 0);

	if (master != MACH_PORT_NULL)
		kr = device_open(master, D_WRITE | D_READ, "eth", &ph->mach_dev);
	else {
		/* If unsuccessful, try Mach device */
		kr = get_privileged_ports(NULL, &master);

		if (kr) {
			pcapint_fmt_errmsg_for_kern_return_t(p->errbuf,
			    PCAP_ERRBUF_SIZE, kr, "get_privileged_ports");
			if (kr == EPERM)
				ret = PCAP_ERROR_PERM_DENIED;
			goto error;
		}

		kr = device_open(master, D_READ | D_WRITE, p->opt.device,
				 &ph->mach_dev);
	}

	mach_port_deallocate(mach_task_self(), master);

	if (kr) {
		pcapint_fmt_errmsg_for_kern_return_t(p->errbuf, PCAP_ERRBUF_SIZE, kr,
		    "device_open");
		if (kr == ED_NO_SUCH_DEVICE) /* not ENODEV */
			ret = PCAP_ERROR_NO_SUCH_DEVICE;
		goto error;
	}

	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
				&ph->rcv_port);

	if (kr) {
		pcapint_fmt_errmsg_for_kern_return_t(p->errbuf, PCAP_ERRBUF_SIZE, kr,
		    "mach_port_allocate");
		goto error;
	}

	p->bufsize = sizeof(struct net_rcv_msg);
	p->buffer = malloc(p->bufsize);

	if (p->buffer == NULL) {
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "malloc");
		goto error;
	}

	ret = init_pipe(p);
	if (ret != 0) {
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			ret, "init_pipe");
		goto error;
	}

	p->selectable_fd = ph->pipefd[0];

	/*
	 * XXX Ethernet only currently
	 *
	 * XXX - does "Ethernet only currently" mean "the only devices
	 * on which the Hurd supports packet capture are Ethernet
	 * devices", or "it supports other devices but makes them
	 * all provide Ethernet headers"?
	 *
	 * If the latter, is there a way to determine whether the
	 * device is a real Ethernet, so that we could offer DLT_DOCSIS,
	 * in case you're capturing DOCSIS traffic that a Cisco Cable
	 * Modem Termination System is putting out onto an Ethernet
	 * (it doesn't put an Ethernet header onto the wire, it puts
	 * raw DOCSIS frames out on the wire inside the low-level
	 * Ethernet framing)?
	 */
	p->linktype = DLT_EN10MB;

	p->read_op = pcap_read_hurd;
	p->inject_op = pcap_inject_hurd;
	p->setfilter_op = pcap_setfilter_hurd;
	p->stats_op = pcap_stats_hurd;
	p->cleanup_op = pcap_cleanup_hurd;

	return 0;

error:
	pcap_cleanup_hurd(p);
	return ret;
}

pcap_t *
pcapint_create_interface(const char *device _U_, char *ebuf)
{
	struct pcap_hurd *ph;
	pcap_t *p;

	p = PCAP_CREATE_COMMON(ebuf, struct pcap_hurd);
	if (p == NULL)
		return NULL;

	ph = p->priv;
	ph->mach_dev = MACH_PORT_NULL;
	ph->rcv_port = MACH_PORT_NULL;
	ph->pipefd[0] = -1;
	ph->pipefd[1] = -1;
	p->activate_op = pcap_activate_hurd;
	return p;
}

static int
can_be_bound(const char *name)
{
	/*
	 * On Hurd lo appears in the list of interfaces, but the call to
	 * device_open() fails with: "(os/device) no such device".
	 */
	if (! strcmp(name, "lo"))
		return 0;
	return 1;
}

static int
get_if_flags(const char *name _U_, bpf_u_int32 *flags, char *errbuf _U_)
{
	/*
	 * This would apply to the loopback interface if it worked.  Ethernet
	 * interfaces appear up and running regardless of the link status.
	 */
	*flags |= PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE;
	return 0;
}

int
pcapint_platform_finddevs(pcap_if_list_t *devlistp, char *errbuf)
{
	return pcapint_findalldevs_interfaces(devlistp, errbuf, can_be_bound,
	                                      get_if_flags);
}

/*
 * Libpcap version string.
 */
const char *
pcap_lib_version(void)
{
	return PCAP_VERSION_STRING;
}
