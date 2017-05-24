#! /bin/sh

stop()
{
	echo "$*"
	exit 0
}

cpp -dM -undef < /dev/null > /dev/null || stop "Compiler does not support \
'-undef'. Skipping def file generation."

# overriding user localization settings for sort
export LC_ALL=C

HEADER='LIBRARY wpcap.dll\nEXPORTS'
TMPFILE=DELETEME
DEF=Win32/Prj/wpcap.def

# Don't include anything and make sure that the names of all PCAP_API
# declarations come directly after the second space from the left.
# pcap/export-defs.h must come first.
sed -e "s/#include <.*>//g" \
	-e "s/#include ".*"//g" \
	-e "s/const char/constchar/g" \
	-e "s/const u_char/constu_char/g" \
	-e "s/**pcap/pcap/g" \
	-e "s/*pcap/pcap/g" \
	-e "s/*bpf/bpf/g" \
	-e "s/eproto_db\[\]/eproto_db/g" \
	-e "s/struct pcap_samp/structpcap_samp/g" \
	-e "s/struct pcap_stat/structpcap_statp/g" \
	-e "s/struct	pcap_etherent/structpcap_etherent/g" \
	-e "s/struct addrinfo/structaddrinfo/g" \
	pcap/export-defs.h pcap/pcap.h pcap/namedb.h nametoaddr.c > $TMPFILE

echo $HEADER > $DEF

# Run the preprocessor on $TMPFILE with *just* these things defined and do some
# command-line kung-fu with the result.
cpp -E -xc -undef -D_WIN32 -DBUILDING_PCAP -DINET6 $TMPFILE \
| grep '__declspec(dllexport)' \
| cut -c 3- \
| cut -f4 -d" " \
| cut -f1 -d"(" \
| sort \
| awk '$0="    "$0' >> $DEF

# Converting line breaks
awk 'BEGIN{RS="^$";ORS="";getline;gsub("\n","\r&");print>ARGV[1]}' $DEF

rm -f $TMPFILE
# EOF
