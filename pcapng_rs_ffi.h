#ifndef PCAPNG_RS_FFI_H
#define PCAPNG_RS_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct pcapng_rs_state;

struct pcapng_rs_interface {
	uint32_t snaplen;
	uint64_t tsresol;
	int32_t scale_type;
	uint64_t scale_factor;
	int64_t tsoffset;
};

struct pcapng_rs_state *pcapng_rs_state_new(void);
void pcapng_rs_state_free(struct pcapng_rs_state *state);

int pcapng_rs_ensure_block_capacity(struct pcapng_rs_state *state,
    uint32_t required_len, uint32_t max_blocksize, char *errbuf,
    size_t errbuf_len);

uint8_t *pcapng_rs_block_buffer_ptr(struct pcapng_rs_state *state);
uint32_t pcapng_rs_block_buffer_len(const struct pcapng_rs_state *state);

void pcapng_rs_interfaces_clear(struct pcapng_rs_state *state);

int pcapng_rs_interface_push(struct pcapng_rs_state *state,
    uint32_t snaplen, uint64_t tsresol, int32_t scale_type,
    uint64_t scale_factor, int64_t tsoffset, char *errbuf,
    size_t errbuf_len);

uint32_t pcapng_rs_interface_count(const struct pcapng_rs_state *state);

int pcapng_rs_interface_get(const struct pcapng_rs_state *state,
    uint32_t index, struct pcapng_rs_interface *out_iface);

#ifdef __cplusplus
}
#endif

#endif