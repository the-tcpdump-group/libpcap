#!/bin/sh -e

# This script runs one build with the setup environment variables below.
: "${CC:=gcc}"
: "${CMAKE:=no}"
: "${REMOTE:=no}"
: "${PROTOCHAIN:=yes}"
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
tcc-*/*)
    # At least one warning is expected because TCC does not implement
    # thread-local storage.
    LIBPCAP_TAINTED=yes
    ;;
clang-3.4/Linux-*)
    # pcap-netfilter-linux.c:427:10: error: will never be executed
    #   [-Werror,-Wunreachable-code]
    # pcap.c:3812:4: error: will never be executed
    #   [-Werror,-Wunreachable-code]
    # scanner.l:662:3: warning: will never be executed [-Wunreachable-code]
    # gencode.c:7061:3: warning: will never be executed [-Wunreachable-code]
    LIBPCAP_TAINTED=yes
    ;;
suncc-5.14/SunOS-5.10|suncc-5.15/SunOS-5.10)
    # (Sun C 5.15 on Solaris 11.4 does not generate any of these warnings.)
    # "./gencode.c", line 599: warning: function "bpf_error" marked as not
    #   returning, might return
    # "optimize.c", line 2409: warning: function "opt_error" marked as not
    #   returning, might return
    # "optimize.c", line 2915: warning: function "conv_error" marked as not
    #   returning, might return
    # "./can_set_rfmon_test.c", line 95: warning: function "error" marked as
    #   not returning, might return
    # "./capturetest.c", line 314: warning: function "usage" marked as not
    #   returning, might return
    # "./capturetest.c", line 333: warning: function "error" marked as not
    #   returning, might return
    # "./filtertest.c", line 163: warning: function "error" marked as not
    #   returning, might return
    # "./filtertest.c", line 478: warning: function "usage" marked as not
    #   returning, might return
    # "./opentest.c", line 222: warning: function "usage" marked as not
    #   returning, might return
    # "./opentest.c", line 241: warning: function "error" marked as not
    #   returning, might return
    # "./nonblocktest.c", line 69: warning: function "error" marked as not
    #   returning, might return
    # "./nonblocktest.c", line 94: warning: function "usage" marked as not
    #   returning, might return
    # "./reactivatetest.c", line 89: warning: function "error" marked as not
    #   returning, might return
    # "./selpolltest.c", line 375: warning: function "usage" marked as not
    #   returning, might return
    # "./selpolltest.c", line 394: warning: function "error" marked as not
    #   returning, might return
    # "./threadsignaltest.c", line 339: warning: function "usage" marked as
    #   not returning, might return
    # "./threadsignaltest.c", line 358: warning: function "error" marked as
    #   not returning, might return
    # "./writecaptest.c", line 490: warning: function "usage" marked as not
    #   returning, might return
    # "./writecaptest.c", line 509: warning: function "error" marked as not
    #   returning, might return
    LIBPCAP_TAINTED=yes
    ;;
*)
    ;;
esac
[ "$LIBPCAP_TAINTED" != yes ] && CFLAGS=`cc_werr_cflags`

case `cc_id`/`os_id` in
clang-*/SunOS-5.11)
    # Work around https://www.illumos.org/issues/16369
    [ "`uname -o`" = illumos ] && grep -Fq OpenIndiana /etc/release && CFLAGS="-Wno-fuse-ld-path${CFLAGS:+ $CFLAGS}"
    ;;
esac

# If necessary, set LIBPCAP_CMAKE_TAINTED here to exempt particular cmake from
# warnings. Use as specific terms as possible (e.g. some specific version and
# some specific OS).

[ "$LIBPCAP_CMAKE_TAINTED" != yes ] && CMAKE_OPTIONS='-Werror=dev'

if [ "$CMAKE" = no ]; then
    run_after_echo ./autogen.sh
    run_after_echo ./configure --prefix="$PREFIX" --enable-protochain="$PROTOCHAIN" --enable-remote="$REMOTE"
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
    run_after_echo cmake --version
    run_after_echo cmake ${CFLAGS:+-DEXTRA_CFLAGS="$CFLAGS"} \
        ${CMAKE_OPTIONS:+"$CMAKE_OPTIONS"} \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" -DENABLE_PROTOCHAIN="$PROTOCHAIN" -DENABLE_REMOTE="$REMOTE" ..
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

run_after_echo "$PREFIX/bin/pcap-config" --help
run_after_echo "$PREFIX/bin/pcap-config" --version
run_after_echo "$PREFIX/bin/pcap-config" --cflags
run_after_echo "$PREFIX/bin/pcap-config" --libs
run_after_echo "$PREFIX/bin/pcap-config" --additional-libs
run_after_echo "$PREFIX/bin/pcap-config" --libs --static
run_after_echo "$PREFIX/bin/pcap-config" --additional-libs --static
run_after_echo "$PREFIX/bin/pcap-config" --libs --static-pcap-only
run_after_echo "$PREFIX/bin/pcap-config" --additional-libs --static-pcap-only

[ "$REMOTE" = yes ] && print_so_deps "$PREFIX/sbin/rpcapd"
[ "$REMOTE" = yes ] && run_after_echo "$PREFIX/sbin/rpcapd" -h

# VALGRIND_CMD is meant either to collapse or to expand.
# shellcheck disable=SC2086
if [ "$CMAKE" = no ]; then
    FILTERTEST_BIN="$VALGRIND_CMD testprogs/filtertest"
    export FILTERTEST_BIN
    run_after_echo "$MAKE_BIN" -s check
    run_after_echo $VALGRIND_CMD testprogs/findalldevstest
    [ "$TEST_RELEASETAR" = yes ] && run_after_echo "$MAKE_BIN" releasetar
else
    FILTERTEST_BIN="$VALGRIND_CMD run/filtertest"
    export FILTERTEST_BIN
    run_after_echo "$MAKE_BIN" -s check
    run_after_echo $VALGRIND_CMD run/findalldevstest
fi
handle_matrix_debug
if [ "$DELETE_PREFIX" = yes ]; then
    run_after_echo rm -rf "$PREFIX"
fi
# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :
