#!/bin/sh -e

# This script runs one build with setup environment variables: CC, CMAKE and
# REMOTE.
: "${CC:=gcc}"
: "${CMAKE:=no}"
: "${REMOTE:=no}"
: "${LIBPCAP_TAINTED:=no}"

. ./build_common.sh
# Install directory prefix
if [ -z "$PREFIX" ]; then
    # shellcheck disable=SC2006
    PREFIX=`mktempdir libpcap_build`
    echo "PREFIX set to '$PREFIX'"
    DELETE_PREFIX=yes
fi

print_cc_version

# The norm is to compile without any warnings, but libpcap builds on some OSes
# are not warning-free for one or another reason.  If you manage to fix one of
# these cases, please remember to remove respective exemption below to help any
# later warnings in the same matrix subset trigger an error.
# shellcheck disable=SC2006,SC2221,SC2222
case `cc_id`/`os_id` in
gcc-*/Linux-*)
    # This warning is a bit odd.  It is steadily present in Cirrus CI, but not
    # in Buildbot.  On my Linux system with the same exact distribution and GCC
    # as Cirrus CI it reproduces only if GCC receives the "-g" flag:
    # make CFLAGS=-g -- does not reproduce
    # CFLAGS=-g make -- reproduces
    # make -- reproduces
    # And even this way it does not make GCC exit with an error when it has
    # reported the warning and has received the "-Werror" flag.
    #
    # pcap-linux.c:947:8: warning: ignoring return value of 'write', declared
    # with attribute warn_unused_result [-Wunused-result]
    [ "$CMAKE" = no ] && LIBPCAP_TAINTED=yes
    ;;
clang-*/NetBSD-*)
    # pcap-bpf.c:1044:18: warning: implicit conversion loses integer precision:
    # 'uint64_t' (aka 'unsigned long') to 'u_int' (aka 'unsigned int')
    # [-Wshorten-64-to-32]
    # pcap-bpf.c:1045:18: warning: implicit conversion loses integer precision:
    # 'uint64_t' (aka 'unsigned long') to 'u_int' (aka 'unsigned int')
    # [-Wshorten-64-to-32]
    # pcap-bpf.c:1274:39: warning: implicit conversion loses integer precision:
    # 'long' to 'suseconds_t' (aka 'int') [-Wshorten-64-to-32]
    LIBPCAP_TAINTED=yes
    ;;
clang-*/NetBSD-*)
    # savefile.c:354:4: warning: code will never be executed
    # [-Wunreachable-code]
    LIBPCAP_TAINTED=yes
    ;;
clang-*/OpenBSD-*)
    # Same as the above.
    LIBPCAP_TAINTED=yes
    ;;
esac
# shellcheck disable=SC2006
[ "$LIBPCAP_TAINTED" != yes ] && CFLAGS=`cc_werr_cflags`

if [ "$CMAKE" = no ]; then
    run_after_echo ./configure --prefix="$PREFIX" --enable-remote="$REMOTE"
else
    # Remove the leftovers from any earlier in-source builds, so this
    # out-of-source build does not break because of that.
    # https://gitlab.kitware.com/cmake/community/-/wikis/FAQ#what-is-an-out-of-source-build
    run_after_echo rm -rf CMakeFiles/ CMakeCache.txt
    [ ! -d build ] && run_after_echo mkdir build
    run_after_echo cd build
    run_after_echo cmake ${CFLAGS:+-DEXTRA_CFLAGS="$CFLAGS"} \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" -DENABLE_REMOTE="$REMOTE" ..
fi
run_after_echo make -s clean
if [ "$CMAKE" = no ]; then
    run_after_echo make -s ${CFLAGS:+CFLAGS="$CFLAGS"}
    run_after_echo make -s testprogs ${CFLAGS:+CFLAGS="$CFLAGS"}
else
    # The "-s" flag is a no-op and CFLAGS is set using -DEXTRA_CFLAGS above.
    run_after_echo make
    run_after_echo make testprogs
fi
run_after_echo make install
if [ "$CMAKE" = no ]; then
    run_after_echo testprogs/findalldevstest
    run_after_echo make releasetar
else
    run_after_echo run/findalldevstest
fi
handle_matrix_debug
if [ "$DELETE_PREFIX" = yes ]; then
    run_after_echo rm -rf "$PREFIX"
fi
# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :
