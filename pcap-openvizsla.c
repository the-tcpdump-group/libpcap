#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "pcap-int.h"
#include "pcap-openvizsla.h"

#include <openvizsla.h>

#define OPENVIZSLA_IFACE "openvizsla"

struct pcap_openvizsla {
	enum ov_usb_speed usb_speed;
	struct ov_device* ov;
};

struct pcap_openvizsla_read {
	pcap_handler callback;
	u_char *user;
};

static void openvizsla_read_cb(struct ov_packet* packet, void* data) {
	struct pcap_openvizsla_read* r = (struct pcap_openvizsla_read*)data;

	struct pcap_pkthdr pkth;
	pkth.caplen = ov_to_host_16(packet->size) + sizeof(struct ov_packet);
	pkth.len = pkth.caplen;
	pkth.ts.tv_sec = 0;
	pkth.ts.tv_usec = 0;

	r->callback(r->user, &pkth, (const u_char*)packet);
}

static int openvizsla_read(pcap_t *handle, int max_packets, pcap_handler callback, u_char *user)
{
	struct pcap_openvizsla* handlep = handle->priv;
	struct pcap_openvizsla_read r;

	r.callback = callback;
	r.user = user;

	int ret = 0;

	if ((ret = ov_capture_start(handlep->ov, handle->buffer, handle->bufsize, openvizsla_read_cb, &r)) < 0) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			"Can't start capture: %s", ov_get_error_string(handlep->ov));
		return PCAP_ERROR;
	}

	if ((ret = ov_capture_dispatch(handlep->ov, max_packets)) < 0) {
		if (handle->break_loop) {
			handle->break_loop = 0;

			ov_capture_stop(handlep->ov);

			return PCAP_ERROR_BREAK;
		}

		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			"An error occured during capturing: %s", ov_get_error_string(handlep->ov));
		return PCAP_ERROR;
	}

	ov_capture_stop(handlep->ov);

	return ret;
}

static void openvizsla_cleanup(pcap_t* handle)
{
	struct pcap_openvizsla* handlep = handle->priv;

	ov_free(handlep->ov);
	pcap_cleanup_live_common(handle);
}

static void openvizsla_breakloop(pcap_t* handle)
{
	struct pcap_openvizsla* handlep = handle->priv;

	ov_capture_breakloop(handlep->ov);
	pcap_breakloop_common(handle);
}

static int openvizsla_activate(pcap_t* handle)
{
	struct pcap_openvizsla* handlep = handle->priv;
	int ret = 0;

	if (handle->snapshot <= 0 || handle->snapshot > MAXIMUM_SNAPLEN)
		handle->snapshot = MAXIMUM_SNAPLEN;

	handle->bufsize = handle->snapshot;
	handle->offset = 0;
	handle->linktype = DLT_OPENVIZSLA;
	handle->buffer = malloc(handle->bufsize);
	if (!handle->buffer) {
		pcap_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE, errno, "malloc");
		goto fail_buffer_malloc;
	}

	handle->cleanup_op = openvizsla_cleanup;
	handle->read_op = openvizsla_read;
	handle->setfilter_op = install_bpf_program; /* no kernel filtering */
	handle->breakloop_op = openvizsla_breakloop;

	handlep->ov = ov_new(NULL);
	if (!handlep->ov) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			"Can't create OpenVizsla device handler");
		goto fail_ov_init;
	}

	ret = ov_open(handlep->ov);
	if (ret < 0) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			"Can't open device: %s", ov_get_error_string(handlep->ov));
		goto fail_ov_open;
	}

	ret = ov_set_usb_speed(handlep->ov, handlep->usb_speed);
	if (ret < 0) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			"Can't set USB speed: %s", ov_get_error_string(handlep->ov));
		goto fail_ov_set_usb_speed;
	}

	return 0;

fail_ov_set_usb_speed:
fail_ov_open:
	ov_free(handlep->ov);
fail_ov_init:
	free(handle->buffer);
	handle->buffer = NULL;
fail_buffer_malloc:
	return PCAP_ERROR;
}

int openvizsla_findalldevs(pcap_if_list_t *devlistp, char *err_str)
{
	/* Always find one device */
	return 0;
}

pcap_t *openvizsla_create(const char *device, char *ebuf, int *is_ours)
{
	const char *cp;
	char *cpend;
	long devnum;
	pcap_t *p;
	struct pcap_openvizsla* handlep;
	enum ov_usb_speed usb_speed;

	cp = strrchr(device, '/');
	if (cp == NULL)
		cp = device;

	if (strncmp(cp, OPENVIZSLA_IFACE, sizeof (OPENVIZSLA_IFACE - 1)) != 0) {
		*is_ours = 0;
		return NULL;
	}

	cp += sizeof OPENVIZSLA_IFACE - 1;
	devnum = strtol(cp, &cpend, 10);
	if (cpend == cp) {
		*is_ours = 0;
		return NULL;
	}
	if (devnum < 0) {
		*is_ours = 0;
		return NULL;
	}

	switch (*cpend) {
		case '\0': /* Fallback to 'l' */
		case 'l': {
			usb_speed = OV_LOW_SPEED;
		} break;
		case 'f': {
			usb_speed = OV_FULL_SPEED;
		} break;
		case 'h': {
			usb_speed = OV_HIGH_SPEED;
		} break;
		default: {
			*is_ours = 0;
			return NULL;
		}
	}

	*is_ours = 1;

	p = PCAP_CREATE_COMMON(ebuf, struct pcap_openvizsla);
	if (p == NULL)
		return NULL;

	p->activate_op = openvizsla_activate;

	handlep = p->priv;
	handlep->usb_speed = usb_speed;

	return p;
}
