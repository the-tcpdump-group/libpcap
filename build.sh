#!/bin/sh -e

# This script runs one build with setup environment variables: CC, CMAKE and
# REMOTE.
: "${CC:=gcc}"
: "${CMAKE:=no}"
: "${REMOTE:=no}"

. ./build_common.sh
# Install directory prefix
if [ -z "$PREFIX" ]; then
    # shellcheck disable=SC2006
    PREFIX=`mktempdir libpcap_build`
    echo "PREFIX set to '$PREFIX'"
    DELETE_PREFIX=yes
fi

print_cc_version
if [ "$CMAKE" = no ]; then
    run_after_echo ./configure --prefix="$PREFIX" --enable-remote="$REMOTE"
else
    # Remove the leftovers from any earlier in-source builds, so this
    # out-of-source build does not break because of that.
    # https://gitlab.kitware.com/cmake/community/-/wikis/FAQ#what-is-an-out-of-source-build
    run_after_echo rm -rf CMakeFiles/ CMakeCache.txt
    [ ! -d build ] && run_after_echo mkdir build
    run_after_echo cd build
    run_after_echo cmake -DCMAKE_INSTALL_PREFIX="$PREFIX" -DENABLE_REMOTE="$REMOTE" ..
fi
run_after_echo make -s clean
run_after_echo make -s
run_after_echo make -s testprogs
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
