# Compiling and using libpcap on GNU/Hurd

libpcap on Hurd currently does not support packet capture on the loopback
network interface.  BPF works in kernel only if the filter length is not
greater that 31 BPF instructions and does not use `BPF_MOD` or `BPF_XOR`.
Packet timestamping always occurs in userland.  Wireless monitor mode is not
supported.  Packet capture sees only packets received on the interface.
[**pcap_set_buffer_size**](https://www.tcpdump.org/manpages/pcap_set_buffer_size.3pcap.html)(3PCAP)
has no effect.
[**pcap_setdirection**](https://www.tcpdump.org/manpages/pcap_setdirection.3pcap.html)(3PCAP)
is not supported.
[**pcap_set_promisc**](https://www.tcpdump.org/manpages/pcap_set_promisc.3pcap.html)(3PCAP)
has no effect.

## Debian GNU/Hurd unstable

* Autoconf 2.73 works.
* flex 2.6.4 and GNU Bison 3.8.2 work.
* CMake 4.4.5 works.
* GCC 16.2.0 and Clang 21.1.8 work.

For reference, the tests were done using a system installed from the 2026-03-14
snapshot from [here](https://cdimage.debian.org/cdimage/ports/latest/hurd-i386/).
