#! /bin/sh
#
# NOTE: this really is supposed to be static; importing a string
# from a shared library does not work very well on many
# versions of UNIX (Solaris, Linux, and the BSDs, for example),
# so we make the version string static and return it from
# a function, which does work.
#
if grep GIT "$1" >/dev/null
then
	read ver <"$1"
	echo $ver | tr -d '\012'
	date +_%Y_%m_%d
else
	cat "$1"
fi | sed -e 's/.*/static const char pcap_version_string[] = "libpcap version &";/' > "$2"
