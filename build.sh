#!/bin/sh -e

# This script runs one build with setup environment variables: CC, CMAKE and
# REMOTE (default: CC=gcc, CMAKE=no, REMOTE=no).

# CC: gcc or clang
CC=${CC:-gcc}
# GCC and Clang recognize --version and print to stdout. Sun compilers
# recognize -V and print to stderr.
"$CC" --version 2>/dev/null || "$CC" -V || :
# CMAKE: no or yes
CMAKE=${CMAKE:-no}
# REMOTE: no or yes
REMOTE=${REMOTE:-no}
# Install directory prefix
if [ -z "$PREFIX" ]; then
    PREFIX=$(mktemp -d -t libpcap_build_XXXXXXXX)
    echo "PREFIX set to '$PREFIX'"
    DELETE_PREFIX=yes
fi

# Run a command after displaying it
run_after_echo() {
    printf '$ '
    echo "$@"
    # shellcheck disable=SC2068
    $@
}

if [ "$CMAKE" = no ]; then
    echo '$ ./configure [...]'
    ./configure --prefix="$PREFIX" --enable-remote="$REMOTE"
else
    # Remove the leftovers from any earlier in-source builds, so this
    # out-of-source build does not break because of that.
    # https://gitlab.kitware.com/cmake/community/-/wikis/FAQ#what-is-an-out-of-source-build
    rm -rf CMakeFiles/ CMakeCache.txt
    [ ! -d build ] && mkdir build
    cd build
    echo '$ cmake [...]'
    cmake -DCMAKE_INSTALL_PREFIX="$PREFIX" -DENABLE_REMOTE="$REMOTE" ..
fi
run_after_echo "make -s clean"
run_after_echo "make -s"
run_after_echo "make -s testprogs"
echo '$ make install'
make install
if [ "$CMAKE" = no ]; then
    run_after_echo "testprogs/findalldevstest"
else
    run_after_echo "run/findalldevstest"
fi
if [ "$CMAKE" = no ]; then
    run_after_echo "make releasetar"
fi
if [ "$MATRIX_DEBUG" = true ]; then
    echo '$ cat Makefile [...]'
    sed '/^# DO NOT DELETE THIS LINE -- mkdep uses it.$/q' < Makefile
    echo '$ cat config.h'
    cat config.h
    if [ "$CMAKE" = no ]; then
        echo '$ cat config.log'
        cat config.log
    fi
fi
if [ "$DELETE_PREFIX" = yes ]; then
    rm -rf "$PREFIX"
fi
# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :
