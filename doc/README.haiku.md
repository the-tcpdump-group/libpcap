# Compiling and using libpcap on Haiku

Haiku R1/beta4 and earlier versions do not support packet capture on the
loopback interface.  Using this version of libpcap, loopback capture works
since Haiku R1/beta5.  Packet timestamping and filtering always occur
in userland.  Wireless monitor mode is not supported.  The "any"
pseudo-interface is not supported.
[**pcap_set_buffer_size**](https://www.tcpdump.org/manpages/pcap_set_buffer_size.3pcap.html)(3PCAP)
has no effect.
[**pcap_setdirection**](https://www.tcpdump.org/manpages/pcap_setdirection.3pcap.html)(3PCAP)
is not supported.
[**pcap_inject**](https://www.tcpdump.org/manpages/pcap_inject.3pcap.html)(3PCAP)
is not supported.

The statistics reported by
[**pcap_stats**](https://www.tcpdump.org/manpages/pcap_stats.3pcap.html)(3PCAP)
on Haiku are as follows:
* `ps_recv` is the number of packets successfully delivered by the kernel,
  before libpcap applies a filter.
* `ps_drop` is the number of packets rejected by the filter.
* `ps_ifdrop` is the number of packets dropped by the network interface (as
  seen via `SIOCGIFSTATS`) since the capture handle became active.

## AMD64 R1/beta5

* Autoconf 2.72 works.
* CMake 3.28.3 works.
* GCC 13.3.0 works.
* Clang 18.1.7 works.
* flex 2.6.4 works.
* bison 3.8.2 works.

The following command will install respective non-default packages:
```
pkgman install cmake llvm18_clang
```

For reference, the tests were done using a system installed from
`haiku-r1beta5-x86_64-anyboot.iso`.
