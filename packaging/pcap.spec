%define prefix   /usr
%define version 2001.02.22 

Summary: packet capture library
Name: libpcap
Version: %version
Release: 1
Group: Development/Libraries
Copyright: BSD
Source: libpcap-current.tar.gz
BuildRoot: /tmp/%{name}-buildroot
URL: http://www.tcpdump.org

%description
Packet-capture library LIBPCAP 0.5
Now maintained by "The Tcpdump Group"
See http://www.tcpdump.org
Please send inquiries/comments/reports to tcpdump-workers@tcpdump.org

%prep
%setup

%post
ldconfig

%build
CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix=%prefix
make

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/{lib,include,man}
mkdir -p $RPM_BUILD_ROOT/usr/include/net
mkdir -p $RPM_BUILD_ROOT/usr/man/man3
install -m 755 -o root libpcap.a $RPM_BUILD_ROOT/usr/lib
install -m 644 -o root pcap.3 $RPM_BUILD_ROOT/usr/man/man3
install -m 644 -o root pcap.h $RPM_BUILD_ROOT/usr/include
install -m 644 -o root pcap-namedb.h $RPM_BUILD_ROOT/usr/include
install -m 644 -o root net/bpf.h $RPM_BUILD_ROOT/usr/include/net

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc LICENSE CHANGES INSTALL README.linux TODO VERSION CREDITS pcap.spec
/usr/lib/libpcap.a
/usr/include/pcap.h
/usr/include/pcap-namedb.h
/usr/include/net/bpf.h
