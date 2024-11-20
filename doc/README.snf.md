# Compiling and using libpcap with Myricom network adapters

On Linux, a Myricom network adapter by default works as a regular network
interface using the `myri10ge.ko` kernel module.  To support such interfaces,
libpcap does not require any additional setup and the rest of this document
does not apply.

It is also possible to use the `myri_snf.ko` kernel module, which is a part of
the SNF software , which can be installed separately.  To support a Myricom
network adapter, the module requires it to have a valid SNF licence, then it
makes supported adapters available as both regular network interfaces and
capture-optimized SNF devices.  To support the SNF devices, libpcap needs to
be compiled in a specific way.

Two versions of the SNF software exist: SNFv3 and SNFv5.  Depending on the
hardware model, a Myricom adapter may be compatible with either SNFv3 or SNFv5.
This version of libpcap has been tested on Linux/AMD64 using SNFv3 version
3.0.26.50935 and a Myricom 10G-PCIE2-8C2-2S adapter.  Other operating systems
have not been tested.

## How to build

1. [Download](https://www.ariacybersecurity.com/support/downloads/) the SNF
   software and its documentation, unpack the software to a directory.
2. Build the `myri_snf.ko` kernel module in the unpacked SNF software
   directory, load it and verify that the module accepts the hardware as SNF
   device(s):
   ```
   cd /path/to/snf
   ./sbin/rebuild.sh
   rmmod myri10ge
   insmod ./sbin/myri_snf.ko
   ./bin/myri_nic_info
   ```
3. Configure and build libpcap.  For example, using Autoconf:
   ```
   cd /path/to/libpcap
   ./configure [--with-snf=DIR] [--with-pcap=snf]
   ```
   Here `DIR` is the directory with the unpacked SNF software if the directory
   is not the default `/opt/snf/`, and `--with-pcap=snf` would request an
   SNF-only build of libpcap if required.  If `configure` has detected the SNF
   software correctly, it will report:
   ```
   configure: using Myricom SNF API headers from /path/to/snf/include
   configure: using Myricom SNF API libraries from /path/to/snf/lib
   ```
	 Then run `make testprogs`.
4. Verify that the compiled libpcap detects the SNF device(s)s using the SNF
   API:
   ```
   LD_LIBRARY_PATH=/path/to/snf/lib ./testprogs/findalldevstest
   ```
   In the output of `findalldevstest` SNF devices should have "Myricom snf" in
   the description.

## Supported libpcap features
The only supported link-level header type is `DLT_EN10MB`.

[**pcap_findalldevs**](https://www.tcpdump.org/manpages/pcap_findalldevs.3pcap.html)(3PCAP)
is supported.  The connection status flags of each device reflect what the SNF
API reports for the device, not what the regular network interface reports.

[**pcap_setfilter**](https://www.tcpdump.org/manpages/pcap_setfilter.3pcap.html)(3PCAP)
is supported, BPF programs run in userspace.

[**pcap_inject**](https://www.tcpdump.org/manpages/pcap_inject.3pcap.html)(3PCAP)
is supported.

[**pcap_setnonblock**](https://www.tcpdump.org/manpages/pcap_setnonblock.3pcap.html)(3PCAP)
is supported.

[**pcap_get_selectable_fd**](https://www.tcpdump.org/manpages/pcap_get_selectable_fd.3pcap.html)(3PCAP)
is not supported.

[**pcap_setdirection**](https://www.tcpdump.org/manpages/pcap_setdirection.3pcap.html)(3PCAP)
is not supported.

## Vendor contact details
[Main web site](https://www.cspi.com/)

[Technical support](https://www.ariacybersecurity.com/support/)

aria_support@ariacybersecurity.com
