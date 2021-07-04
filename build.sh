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

travis_fold() {
    tf_action=${1:?}
    tf_name=${2:?}
    if [ "$TRAVIS" != true ]; then return; fi
    printf 'travis_fold:%s:%s.script.%s\r' "$tf_action" "$LABEL" "$tf_name"
    sleep 1
}

# Run a command after displaying it
run_after_echo() {
    printf '$ '
    echo "$@"
    # shellcheck disable=SC2068
    $@
}

# LABEL is needed to build the travis fold labels
LABEL="$CC.$CMAKE.$REMOTE"
if [ "$CMAKE" = no ]; then
    echo '$ ./configure [...]'
    travis_fold start configure
    ./configure --prefix="$PREFIX" --enable-remote="$REMOTE"
    travis_fold end configure
else
    # Remove the leftovers from any earlier in-source builds, so this
    # out-of-source build does not break because of that.
    # https://gitlab.kitware.com/cmake/community/-/wikis/FAQ#what-is-an-out-of-source-build
    rm -rf CMakeFiles/ CMakeCache.txt
    [ ! -d build ] && mkdir build
    cd build
    echo '$ cmake [...]'
    travis_fold start cmake
    cmake -DCMAKE_INSTALL_PREFIX="$PREFIX" -DENABLE_REMOTE="$REMOTE" ..
    travis_fold end cmake
fi
run_after_echo "make -s clean"
run_after_echo "make -s"
run_after_echo "make -s testprogs"
echo '$ make install'
travis_fold start make_install
make install
travis_fold end make_install
if [ "$CMAKE" = no ]; then
    run_after_echo "testprogs/findalldevstest"
else
    run_after_echo "run/findalldevstest"
fi
if [ "$CMAKE" = no ]; then
    system=$(uname -s)
    if [ "$system" = Darwin ] || [ "$system" = Linux ]; then
        run_after_echo "make releasetar"
    fi
fi
if [ "$TRAVIS" = true ]; then
    echo '$ cat Makefile [...]'
    travis_fold start cat_makefile
    sed '/^# DO NOT DELETE THIS LINE -- mkdep uses it.$/q' < Makefile
    travis_fold end cat_makefile
    echo '$ cat config.h'
    travis_fold start cat_config_h
    cat config.h
    travis_fold end cat_config_h
    if [ "$CMAKE" = no ]; then
        echo '$ cat config.log'
        travis_fold start cat_config_log
        cat config.log
        travis_fold end cat_config_log
    fi
fi
if [ "$DELETE_PREFIX" = yes ]; then
    rm -rf "$PREFIX"
fi
# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :
