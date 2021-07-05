#!/bin/sh -e

# This script executes the matrix loops, exclude tests and cleaning.
# The matrix can be configured with environment variables MATRIX_CC,
# MATRIX_CMAKE and MATRIX_REMOTE (default: MATRIX_CC='gcc clang',
# MATRIX_CMAKE='no yes', MATRIX_REMOTE='no yes').
# It calls the build.sh script which runs one build with setup environment
# variables : CC, CMAKE and REMOTE (default: CC=gcc, CMAKE=no, REMOTE=no).

uname -a
date
# Install directory prefix
if [ -z "$PREFIX" ]; then
    PREFIX=$(mktemp -d -t libpcap_build_matrix_XXXXXXXX)
    echo "PREFIX set to '$PREFIX'"
    export PREFIX
fi
COUNT=0

# Display text in magenta
echo_magenta() {
    printf '\033[35;1m' # ANSI magenta
    echo "$@"
    printf '\033[0m' # ANSI reset
}

touch .devel configure
for CC in ${MATRIX_CC:-gcc clang}; do
    export CC
    # Exclude gcc on macOS (it is just an alias for clang).
    if [ "$CC" = gcc ] && [ "$(uname -s)" = Darwin ]; then
        echo '(skipped)'
        continue
    fi
    for CMAKE in ${MATRIX_CMAKE:-no yes}; do
        export CMAKE
        for REMOTE in ${MATRIX_REMOTE:-no yes}; do
            export REMOTE
            COUNT=$((COUNT+1))
            echo_magenta "===== SETUP $COUNT: CC=$CC CMAKE=$CMAKE REMOTE=$REMOTE ====="
            # Run one build with setup environment variables: CC, CMAKE and REMOTE
            ./build.sh
            echo 'Cleaning...'
            if [ "$CMAKE" = yes ]; then rm -rf build; else make distclean; fi
            rm -rf "${PREFIX:?}"/*
            git status -suall
            # Cancel changes in configure
            git checkout configure
        done
    done
done
rm -rf "$PREFIX"
echo_magenta "Tested setup count: $COUNT"
# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :
