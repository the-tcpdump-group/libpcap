#! /bin/sh
print_version_string()
{
	if grep GIT "$1" >/dev/null
	then
		read ver <"$1"
		echo $ver | tr -d '\012'
		date +_%Y_%m_%d
	else
		cat "$1"
	fi
}
if test $# != 2
then
	echo "Usage: gen_version_c.sh <version file> <output file>" 1>&2
	exit 1
fi
version_string=`print_version_string "$1"`
echo '#include <pcap/funcattrs.h>' > "$2"
echo 'PCAP_API_DEF' >> "$2"
echo "$version_string" | sed -e 's/.*/char pcap_version[] = "&";/' >> "$2"

