# libpcap installation notes

Platform-specific notes:
* [AIX](doc/README.aix)
* [Haiku](doc/README.haiku.md)
* [HP-UX](doc/README.hpux)
* [GNU/Hurd](doc/README.hurd.md)
* [GNU/Linux](doc/README.linux)
* [macOS](doc/README.macos)
* [Solaris and related OSes](doc/README.solaris.md)
* [Windows](doc/README.windows.md)

Hardware-specific notes:
* [Endace DAG](doc/README.dag.md)
* [Intel Septel](doc/README.septel)

Libpcap can be built either with the configure script and `make`, or
with CMake and any build system supported by CMake.

To build libpcap with the configure script and `make`:

* If you build from a git clone rather than from a release archive,
run `./autogen.sh` (a shell script). The autogen.sh script will
build the `configure` and `config.h.in` files.

On some system, you may need to set the `AUTORECONF` variable, like:
`AUTORECONF=autoreconf-2.69 ./autogen.sh`
to select the `autoreconf` version you want to use.

* Run `./configure` (a shell script).  The configure script will
determine your system attributes and generate an appropriate `Makefile`
from `Makefile.in`.  The configure script has a number of options to
control the configuration of libpcap; `./configure --help` will show
them.

* Next, run `make`.  If everything goes well, you can
`su` to root and run `make install`.  However, you need not install
libpcap if you just want to build tcpdump; just make sure the tcpdump
and libpcap directory trees have the same parent directory.

On OpenBSD, you may need to set, before the `make`, the `AUTOCONF_VERSION`
variable like:
`AUTOCONF_VERSION=2.69 make`

To build libpcap with CMake and the build system of your choice, from
the command line:

* Create a build directory into which CMake will put the build files it
generates; CMake does not work as well with builds done in the source
code directory as does the configure script.  The build directory may be
created as a subdirectory of the source directory or as a directory
outside the source directory.

* Change to the build directory and run CMake with the path from the
build directory to the source directory as an argument.  The `-G` flag
can be used to select the CMake "generator" appropriate for the build
system you're using; various `-D` flags can be used to control the
configuration of libpcap.

* Run the build tool.  If everything goes well, you can `su` to root and
run the build tool with the `install` target.  Building tcpdump from a
libpcap in a build directory is not supported.

An `uninstall` target is supported with both `./configure` and CMake.

***DO NOT*** run the build as root; there is no need to do so, running
anything as root that doesn't need to be run as root increases the risk
of damaging your system, and running the build as root will put files in
the build directory that are owned by root and that probably cannot be
overwritten, removed, or replaced except by root, which could cause
permission errors in subsequent builds.

If configure says:

    configure: warning: cannot determine packet capture interface
    configure: warning: (see INSTALL.md file for more info)

or CMake says:

    cannot determine packet capture interface

    (see the INSTALL.md file for more info)

then your system either does not support packet capture or your system
does support packet capture but libpcap does not support that
particular type.  If your system uses a
packet capture not supported by libpcap, please send us patches; don't
forget to include an autoconf fragment suitable for use in
`configure.ac`.

It is possible to override the default packet capture type with the
`--with-pcap` option to `./configure` or the `-DPCAP_TYPE` option to
CMake, although the circumstances where this works are limited.  One
possible reason to do that would be to force a supported packet capture
type in the case where the configure or CMake scripts fails to detect
it.

You will need a C99 compiler to build libpcap. The configure script
will abort if your compiler is not C99 compliant. If this happens, use
the generally available GNU C compiler (GCC) or Clang.

You will need either Flex 2.5.31 or later, or a version of Lex
compatible with it (if any exist), to build libpcap.  The configure
script will abort if there isn't any such program; CMake fails if Flex
or Lex cannot be found, but doesn't ensure that it's compatible with
Flex 2.5.31 or later.  If you have an older version of Flex, or don't
have a compatible version of Lex, the current version of Flex is
available [here](https://github.com/westes/flex).

You will need either Bison, Berkeley YACC, or a version of YACC
compatible with them (if any exist), to build libpcap.  The configure
script will abort if there isn't any such program; CMake fails if Bison
or some form of YACC cannot be found, but doesn't ensure that it's
compatible with Bison or Berkeley YACC.  If you don't have any such
program, the current version of Bison can be found
[here](https://ftp.gnu.org/gnu/bison/) and the current version of
Berkeley YACC can be found [here](https://invisible-island.net/byacc/).

Sometimes the stock C compiler does not interact well with Flex and
Bison. The list of problems includes undefined references for alloca(3).
You can get around this by installing GCC.

## Description of files
	CHANGES		    - description of differences between releases
	ChmodBPF/*	    - macOS startup item to set ownership and permissions on /dev/bpf*
	CMakeLists.txt	    - CMake file
	CONTRIBUTING.md	    - guidelines for contributing
	CREDITS		    - people that have helped libpcap along
	INSTALL.md	    - this file
	LICENSE		    - the license under which libpcap is distributed
	Makefile.in	    - compilation rules (input to the configure script)
	README.md	    - description of distribution
	doc/README.aix	    - notes on using libpcap on AIX
	doc/README.dag.md   - notes on using libpcap to capture on Endace DAG devices
	doc/README.haiku.md - notes on using libpcap on Haiku
	doc/README.hpux	    - notes on using libpcap on HP-UX
	doc/README.hurd.md  - notes on using libpcap on GNU/Hurd
	doc/README.linux    - notes on using libpcap on Linux
	doc/README.macos    - notes on using libpcap on macOS
	doc/README.septel   - notes on using libpcap to capture on Intel/Septel devices
	doc/README.solaris.md - notes on using libpcap on Solaris
	doc/README.windows.md - notes on using libpcap on Windows systems (with Npcap)
	VERSION		    - version of this release
	aclocal.m4	    - autoconf macros
	autogen.sh	    - build configure and config.h.in (run this first)
	bpf_dump.c	    - BPF program printing routines
	bpf_filter.c	    - BPF filtering routines
	bpf_image.c	    - BPF disassembly routine
	charconv.c	    - Windows Unicode routines
	charconv.h	    - Windows Unicode prototypes
	config.guess	    - autoconf support
	config.sub	    - autoconf support
	configure.ac	    - configure script source
	diag-control.h	    - compiler diagnostics control macros
	dlpisubs.c	    - DLPI-related functions for pcap-dlpi.c and pcap-libdlpi.c
	dlpisubs.h	    - DLPI-related function declarations
	etherent.c	    - /etc/ethers support routines
	extract.h	    - Alignment definitions
	ethertype.h	    - Ethernet protocol types and names definitions
	fad-getad.c	    - pcap_findalldevs() for systems with getifaddrs()
	fad-gifc.c	    - pcap_findalldevs() for systems with only SIOCGIFLIST
	fad-glifc.c	    - pcap_findalldevs() for systems with SIOCGLIFCONF
	fmtutils.c	    - error message formatting routines
	fmtutils.h	    - error message formatting prototypes
	ftmacros.h	    - feature test macros
	testprogs/filtertest.c      - test program for BPF compiler
	testprogs/findalldevstest.c - test program for pcap_findalldevs()
	gencode.c	    - BPF code generation routines
	gencode.h	    - BPF code generation definitions
	grammar.y	    - filter string grammar
	ieee80211.h	    - 802.11 definitions
	install-sh	    - BSD style install script
	instrument-functions.c - functions instrumentation calls for entry/exit
	lbl/os-*.h	    - OS-dependent defines and prototypes (if any)
	llc.h		    - 802.2 LLC SAP definitions
	missing/*	    - replacements for missing library functions
	mkdep		    - construct Makefile dependency list
	nametoaddr.c	    - hostname to address routines
	nametoaddr.h	    - hostname to address prototypes
	optimize.c	    - BPF optimization routines
	optimize.h	    - BPF optimization prototypes
	pcap/bluetooth.h    - public definition of DLT_BLUETOOTH_HCI_H4_WITH_PHDR header
	pcap/bpf.h	    - BPF definitions
	pcap/can_socketcan.h - SocketCAN header
	pcap/compiler-tests.h - compiler version comparison and other macros
	pcap/dlt.h	    - Link-layer header type codes.
	pcap/funcattrs.h    - function attribute macros
	pcap/ipnet.h	    - Solaris IPnet definitions
	pcap/namedb.h	    - public libpcap name database definitions
	pcap/nflog.h	    - NFLOG-related definitions
	pcap/pcap.h	    - public libpcap definitions
	pcap/pcap-inttypes.h - header for OS-specific integer type includes
	pcap/sll.h	    - public definitions of DLT_LINUX_SLL and DLT_LINUX_SLL2 headers
	pcap/socket.h	    - IP sockets support for various OSes
	pcap/usb.h	    - public definition of DLT_USB header
	pcap/vlan.h	    - VLAN-specific definitions
	pcap-airpcap.c	    - AirPcap device capture support
	pcap-airpcap.h	    - AirPcap device capture support
	pcap-bpf.c	    - BSD Packet Filter support
	pcap-bpf.h	    - header for backwards compatibility
	pcap-bt-linux.c	    - Bluetooth capture support for Linux
	pcap-bt-linux.h	    - Bluetooth capture support for Linux
	pcap-bt-monitor-linux.c - Bluetooth monitor capture support for Linux
	pcap-bt-monitor-linux.h - Bluetooth monitor capture support for Linux
	pcap-common.c	    - common code for pcap and pcapng files
	pcap-common.h	    - common code for pcap and pcapng files
	pcap-dag.c	    - Endace DAG device capture support
	pcap-dag.h	    - Endace DAG device capture support
	pcap-dbus.c	    - D-Bus capture support
	pcap-dbus.h	    - D-Bus capture support
	pcap-dlpi.c	    - Data Link Provider Interface support
	pcap-dpdk.c	    - DPDK device support
	pcap-dpdk.h	    - DPDK device support
	pcap-haiku.c	    - Haiku capture support
	pcap-hurd.c	    - GNU Hurd support
	pcap-int.h	    - internal libpcap definitions
	pcap-libdlpi.c	    - Data Link Provider Interface support for systems with libdlpi
	pcap-linux.c	    - Linux packet socket support
	pcap-namedb.h	    - header for backwards compatibility
	pcap-netfilter-linux.c - Linux netfilter support
	pcap-netfilter-linux.h - Linux netfilter support
	pcap-netmap.c	    - netmap support
	pcap-netmap.h	    - netmap support
	pcap-npf.c	    - Npcap capture support
	pcap-null.c	    - dummy monitor support (allows offline use of libpcap)
	pcap-rdmasniff.c    - RDMA/InfiniBand capture support
	pcap-rdmasniff.h    - RDMA/InfiniBand capture support
	pcap-rpcap.c	    - RPCAP protocol capture support
	pcap-rpcap.h	    - RPCAP protocol capture support
	pcap-septel.c       - Intel/Septel device capture support
	pcap-septel.h       - Intel/Septel device capture support
	pcap-snf.c	    - Myricom SNF device capture support
	pcap-snf.h	    - Myricom SNF device capture support
	pcap-types.h	    - header for OS-specific type includes
	pcap-usb-linux.c    - USB capture support for Linux
	pcap-usb-linux.h    - USB capture support for Linux
	pcap-usb-linux-common.c - Linux USB common routines
	pcap-usb-linux-common.h - Linux USB common prototypes
	pcap-util.c	    - common code for various files
	pcap-util.h	    - common code for various files
	pcap.3pcap	    - manual entry for the library
	pcap.c		    - pcap utility routines
	pcap.h		    - header for backwards compatibility
	pcap_*.3pcap	    - manual entries for library functions
	pcap-filter.manmisc.in   - manual entry for filter syntax
	pcap-linktype.manmisc.in - manual entry for link-layer header types
	pflog.h		    - header for DLT_PFLOG handling in filter code
	portability.h	    - Portability declarations/definitions
	ppp.h		    - Point to Point Protocol definitions
	rpcap-protocol.c    - RPCAP client/server common routines
	rpcap-protocol.h    - RPCAP client/server common prototypes
	savefile.c	    - offline support
	scanner.l	    - filter string scanner
	sf-pcap.c	    - routines for .pcap savefiles
	sf-pcap.h	    - prototypes for .pcap savefiles
	sf-pcapng.c	    - routines for .pcapng savefiles
	sf-pcapng.h	    - prototypes for .pcapng savefiles
	sockutils.c	    - socket and name lookup API routines
	sockutils.h	    - socket and name lookup API prototypes
	sslutils.c	    - OpenSSL interface routines
	sslutils.h	    - OpenSSL interface prototypes
	varattrs.h	    - variable attribute macros
