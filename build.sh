#!/bin/sh -e

# This script runs one build with setup environment variables: CC, CMAKE, IPV6
# and REMOTE.
: "${CC:=gcc}"
: "${CMAKE:=no}"
: "${IPV6:=no}"
: "${REMOTE:=no}"
: "${LIBPCAP_TAINTED:=no}"
: "${LIBPCAP_CMAKE_TAINTED:=no}"
: "${MAKE_BIN:=make}"
# At least one OS (AIX 7) where this software can build does not have at least
# one command (mktemp) required for a successful run of "make releasetar".
: "${TEST_RELEASETAR:=yes}"

. ./build_common.sh
# Install directory prefix
if [ -z "$PREFIX" ]; then
    PREFIX=`mktempdir libpcap_build`
    echo "PREFIX set to '$PREFIX'"
    DELETE_PREFIX=yes
fi

print_cc_version

# The norm is to compile without any warnings, but libpcap builds on some OSes
# are not warning-free for one or another reason.  If you manage to fix one of
# these cases, please remember to remove respective exemption below to help any
# later warnings in the same matrix subset trigger an error.
# shellcheck disable=SC2221,SC2222
case `cc_id`/`os_id` in
clang-*/SunOS-5.11)
    # (Solaris 11 and OpenIndiana)
    # fad-getad.c:266:52: warning: implicit conversion loses integer precision:
    #   'uint64_t'(aka 'unsigned long') to 'bpf_u_int32' (aka 'unsigned int')
    #   [-Wshorten-64-to-32]
    # (OpenIndiana)
    # rpcapd.c:393:18: warning: this function declaration is not a prototype
    #   [-Wstrict-prototypes]
    [ "`uname -p`" = i386 ] && LIBPCAP_TAINTED=yes
    ;;
suncc-5.1[45]/SunOS-5.11)
    # "scanner.l", line 257: warning: statement not reached
    # (186 warnings for scanner.l)
    #
    # "./filtertest.c", line 259: warning: statement not reached
    # "./filtertest.c", line 276: warning: statement not reached
    # "./filtertest.c", line 281: warning: statement not reached
    LIBPCAP_TAINTED=yes
    ;;
esac
[ "$LIBPCAP_TAINTED" != yes ] && CFLAGS=`cc_werr_cflags`

# If necessary, set LIBPCAP_CMAKE_TAINTED here to exempt particular cmake from
# warnings. Use as specific terms as possible (e.g. some specific version and
# some specific OS).

[ "$LIBPCAP_CMAKE_TAINTED" != yes ] && CMAKE_OPTIONS='-Werror=dev'

if [ "$CMAKE" = no ]; then
    run_after_echo ./autogen.sh
    run_after_echo ./configure --prefix="$PREFIX" --enable-ipv6="$IPV6" --enable-remote="$REMOTE"
else
    # Remove the leftovers from any earlier in-source builds, so this
    # out-of-source build does not break because of that.
    # https://gitlab.kitware.com/cmake/community/-/wikis/FAQ#what-is-an-out-of-source-build
    # (The contents of build/ remaining after an earlier unsuccessful attempt
    # can fail subsequent build attempts too, sometimes in non-obvious ways,
    # so remove that directory as well.)
    run_after_echo rm -rf CMakeFiles/ CMakeCache.txt build/
    run_after_echo mkdir build
    run_after_echo cd build
    run_after_echo cmake ${CFLAGS:+-DEXTRA_CFLAGS="$CFLAGS"} \
        ${CMAKE_OPTIONS:+"$CMAKE_OPTIONS"} \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" -DINET6="$IPV6" -DENABLE_REMOTE="$REMOTE" ..
fi
run_after_echo "$MAKE_BIN" -s clean
if [ "$CMAKE" = no ]; then
    run_after_echo "$MAKE_BIN" -s ${CFLAGS:+CFLAGS="$CFLAGS"}
    run_after_echo "$MAKE_BIN" -s testprogs ${CFLAGS:+CFLAGS="$CFLAGS"}
else
    # The "-s" flag is a no-op and CFLAGS is set using -DEXTRA_CFLAGS above.
    run_after_echo "$MAKE_BIN"
    run_after_echo "$MAKE_BIN" testprogs
fi
run_after_echo "$MAKE_BIN" install

while read -r opts; do
    # opts is meant to expand
    # shellcheck disable=SC2086
    run_after_echo "$PREFIX/bin/pcap-config" $opts
done <<EOF
--help
--version
--cflags
--libs
--additional-libs
--libs --static
--additional-libs --static
--libs --static-pcap-only
--additional-libs --static-pcap-only
EOF

# VALGRIND_CMD is meant either to collapse or to expand.
# shellcheck disable=SC2086
if [ "$CMAKE" = no ]; then
    run_after_echo $VALGRIND_CMD testprogs/findalldevstest
    [ "$TEST_RELEASETAR" = yes ] && run_after_echo "$MAKE_BIN" releasetar
else
    run_after_echo $VALGRIND_CMD run/findalldevstest
fi
handle_matrix_debug
if [ "$DELETE_PREFIX" = yes ]; then
    run_after_echo rm -rf "$PREFIX"
fi
# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :
