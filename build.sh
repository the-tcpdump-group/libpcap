#!/usr/bin/env bash

# This script runs one build with exported variables setup: CC, CMAKE and
# REMOTE (default: gcc, no (cmake), no (remote)).

set -e

# CC: gcc or clang
CC=${CC:-gcc}
# CMAKE: no or yes
CMAKE=${CMAKE:-no}
# REMOTE: no or yes
REMOTE=${REMOTE:-no}
# Install directory prefix
PREFIX=/tmp/local

travis_fold() {
    local action="$1"
    local name="$2"
    if [ "$TRAVIS" != true ]; then return; fi
    echo -ne "travis_fold:$action:$LABEL.script.$name\\r"
    sleep 1
}

# LABEL is needed to build the travis fold labels
LABEL="$CC.$CMAKE.$REMOTE"
if [ "$CMAKE" = no ]; then
    echo '$ ./configure [...]'
    travis_fold start configure
    ./configure --prefix=$PREFIX --enable-remote="$REMOTE"
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
    cmake -DCMAKE_INSTALL_PREFIX=$PREFIX -DENABLE_REMOTE="$REMOTE" ..
    travis_fold end cmake
fi
make -s
make -s testprogs
echo '$ make install'
travis_fold start make_install
make install
travis_fold end make_install
if [ "$CMAKE" = no ]; then
    testprogs/findalldevstest
else
    run/findalldevstest
fi
if [ "$CMAKE" = no ]; then
    system=$(uname -s)
    if [ "$system" = Darwin ] || [ "$system" = Linux ]; then
        echo '$ make releasetar'
        make releasetar
    fi
fi
if [ "$TRAVIS" = true ]; then
    echo '$ cat Makefile [...]'
    travis_fold start cat_makefile
    if [ "$CMAKE" = no ]; then
        sed -n '1,/DO NOT DELETE THIS LINE -- mkdep uses it/p' < Makefile
    else
        cat Makefile
    fi
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
# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :
