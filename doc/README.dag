# Compiling and using libpcap with Endace DAG capture cards.

## How to build

The following instructions apply if you have a Linux host and want libpcap to
support the DAG range of passive network monitoring cards from
[Endace](https://www.endace.com/) (see below for further contact details).

1. Install and build a recent version of the DAG software distribution by
   following the instructions supplied with that package.  Current Endace
   customers can download the DAG software distribution from
   [here](https://support.endace.com/).

2. Configure libcap.  The `configure` script detects a typical DAG software
   installation automatically.  In case you need to use the DAG software
   distribution from a custom location, use the `--with-dag` option:
   ```
   ./configure --with-dag=DIR
   ```
   Where `DIR` is the root of the DAG software distribution, for example
   `/var/src/dag`.  If the DAG software is correctly detected, `configure` will
   report:
   ```
   checking whether we have DAG API... yes
   ```
   If `configure` reports that there is no DAG API, the directory may have been
   incorrectly specified or the DAG software was not built before configuring
   libpcap (if the DAG package requires building before use).

3. Building libpcap at this stage will include support for both the usual Linux
   libpcap devices (network interfaces, USB, Bluetooth etc.) and for DAG cards.
   To build libpcap with only DAG support, specify the capture type as "dag"
   when configuring libpcap:
   ```
   ./configure [--with-dag=DIR] --with-pcap=dag
   ```
   Applications built with libpcap configured in this way will be able to use
   DAG cards only.

CMake builds support DAG too, see the
[libpcap installation notes](../INSTALL.md) for further libpcap configuration
options.

## Supported libpcap features

`pcap_set_timeout()` is supported. `pcap_dispatch()` will return after `to_ms`
milliseconds regardless of how many packets are received.  If `to_ms` is zero,
`pcap_dispatch()` will block waiting for data indefinitely.

`pcap_dispatch()` will block on and process a minimum of 64kB of data (before
filtering) for efficiency.  This can introduce high latencies on quiet
interfaces unless a timeout value is set.  The timeout expiring will override
the 64kB minimum causing `pcap_dispatch()` to process any available data and
return.

`pcap_setnonblock()` is supported.  When `nonblock` is set, `pcap_dispatch()`
will check once for available data, process any data available up to `cnt`
packets, then return immediately.

`pcap_findalldevs()` is supported.  At the time of this writing all supported
DAG cards implement capturing to multiple logical interfaces, called "streams".
This can be data from different physical ports, or separated by filtering
or load balancing mechanisms.  Receive (capture) streams on a given card have
even numbers (0, 2, 4 etc.) and are available via `pcap_findalldevs()` as
separate capture devices (`dag0:0`, `dag0:2`, `dag0:4` etc.).  `dag0:0` is
the same as `dag0`.  Specifying transmit streams for capture is not supported.

`pcap_setfilter()` is supported, BPF programs run in userspace.

`pcap_setdirection()` is not supported.  Only received traffic is captured.
DAG cards normally do not have IP or link-layer addresses assigned as they are
used to passively monitor links.

`pcap_set_promisc()` has no effect because DAG cards always capture packets in
promiscuous mode.

`pcap_breakloop()` is supported.

`pcap_datalink()` and `pcap_list_datalinks()` are supported.  `pcap_activate()`
attempts to set the correct datalink type automatically when the capture stream
supports more than one type.

`pcap_stats()` is supported.  `ps_drop` is the number of packets dropped due to
Rx stream buffer overflow, this count is before filters are applied (it will
include packets that would have been dropped by the filter).  The Rx stream
buffer size is user configurable outside libpcap, typically 16-512MB.

`pcap_get_selectable_fd()` is not supported, as DAG cards do not support
`poll()`/`select()` methods.

`pcap_inject()` and `pcap_sendpacket()` are not supported.

## Other considerations

libpcap now does **not** set the card's hardware snaplen (`slen`).  This must
now be set using `dagconfig`.  This is because the snaplen used to be shared
between all of the streams of a DAG card.  Newer hardware implements snaplen as
a per-stream parameter, but libpcap does not support that yet.

DAG cards by default capture entire packets including the L2 CRC/FCS.  If the
card is not configured to discard the CRC/FCS, this can confuse applications
that use libpcap if they're not prepared for packets to have an FCS.

Libpcap now reads the environment variable `ERF_FCS_BITS` to determine how many
bits of CRC/FCS to strip from the end of the captured frame.  This defaults to
32, which usually fits Ethernet.  If the card is configured to strip the
CRC/FCS, then set `ERF_FCS_BITS=0`.  If used with a HDLC/PoS/PPP/Frame Relay
link with 16-bit CRC/FCS, then set `ERF_FCS_BITS=16`.

If you wish to create a pcap file that **does** contain the Ethernet FCS,
specify the environment variable `ERF_DONT_STRIP_FCS=1`.  This will cause the
existing FCS to be captured into the pcap file.  Note some applications may
incorrectly report capture errors or oversize packets when reading these files.

## Endace contact details

Please submit DAG software distribution and hardware bug reports via
<support@endace.com>.

Please also visit [our web site](https://www.endace.com/).

For more information about Endace DAG cards contact <sales@endace.com>.
