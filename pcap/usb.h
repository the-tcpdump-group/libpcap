/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
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
 * Basic USB data struct
 * By Paolo Abeni <paolo.abeni@email.com>
 *
 */
 
#ifndef _PCAP_USB_STRUCTS_H__
#define _PCAP_USB_STRUCTS_H__

typedef enum { 
  URB_CONTROL_INPUT,
  URB_CONTROL_OUTPUT,
  URB_ISOCHRONOUS_INPUT,
  URB_ISOCHRONOUS_OUTPUT,
  URB_INTERRUPT_INPUT,
  URB_INTERRUPT_OUTPUT,
  URB_BULK_INPUT,
  URB_BULK_OUTPUT,
  URB_UNKNOWN
} pcap_urb_type_t;

typedef struct _usb_header {
  bpf_u_int32 urb_type;  
  bpf_u_int32 device_address;
  bpf_u_int32 endpoint_number;
  bpf_u_int32 setup_packet;
} pcap_usb_header;


/*
 * defined in USB specification 
 */
typedef struct _usb_setup {
  u_int8_t bmRequestType;
  u_int8_t bRequest;
  u_int16_t wValue;
  u_int16_t wIndex;
  u_int16_t wLength;
} pcap_usb_setup;

#endif
