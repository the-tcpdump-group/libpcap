#!/usr/bin/env bash

# This script executes the matrix loops, exclude tests and cleaning.
# It calls the build.sh script which runs one build with exported variables
# setup: CC, CMAKE and REMOTE (default: gcc, no (cmake), no (remote)).

set -e

# ANSI color escape sequences
ANSI_MAGENTA="\\033[35;1m"
ANSI_RESET="\\033[0m"
# Install directory prefix
PREFIX=/tmp/local

travis_fold() {
    local action="$1"
    local name="$2"
    if [ "$TRAVIS" != true ]; then return; fi
    echo -ne "travis_fold:$action:$LABEL.script.$name\\r"
    sleep 1
}

# Display text in magenta
echo_magenta() {
    echo -ne "$ANSI_MAGENTA"
    echo "$@"
    echo -ne "$ANSI_RESET"
}

touch .devel configure
for CC in gcc clang; do
    export CC
    # Exclude gcc on OSX (it is just an alias for clang)
    if [ "$CC" = gcc ] && [ "$TRAVIS_OS_NAME" = osx ]; then continue; fi
    for CMAKE in no yes; do
        export CMAKE
        for REMOTE in no yes; do
            export REMOTE
            echo_magenta "===== SETUP: compiler:$CC cmake:$CMAKE remote:$REMOTE ====="
            # LABEL is needed to build the travis fold labels
            LABEL="$CC.$CMAKE.$REMOTE"
            # Run one build with exported variables setup: CC, CMAKE and REMOTE
            ./build.sh
            echo 'Cleaning...'
            travis_fold start cleaning
            if [ "$CMAKE" = yes ]; then rm -rf build; else make distclean; fi
            rm -rf $PREFIX
            git status -suall
            # Cancel changes in configure
            git checkout configure
            travis_fold end cleaning
        done
    done
done
# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :
