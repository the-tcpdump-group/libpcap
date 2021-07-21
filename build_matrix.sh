#!/bin/sh -e

# This script executes the matrix loops, exclude tests and cleaning.
# The matrix can be configured with the following environment variables: MATRIX_CC,
# MATRIX_CMAKE and MATRIX_REMOTE.
: "${MATRIX_CC:=gcc clang}"
: "${MATRIX_CMAKE:=no yes}"
: "${MATRIX_REMOTE:=no yes}"
# It calls the build.sh script which runs one build with setup environment
# variables: CC, CMAKE and REMOTE.

. ./build_common.sh
print_sysinfo
# Install directory prefix
if [ -z "$PREFIX" ]; then
    # shellcheck disable=SC2006
    PREFIX=`mktempdir libpcap_build_matrix`
    echo "PREFIX set to '$PREFIX'"
    export PREFIX
fi
COUNT=0

touch .devel configure
for CC in $MATRIX_CC; do
    export CC
    # Exclude gcc on macOS (it is just an alias for clang).
    # shellcheck disable=SC2006
    if [ "$CC" = gcc ] && [ "`uname -s`" = Darwin ]; then
        echo '(skipped)'
        continue
    fi
    for CMAKE in $MATRIX_CMAKE; do
        export CMAKE
        for REMOTE in $MATRIX_REMOTE; do
            export REMOTE
            # shellcheck disable=SC2006
            COUNT=`increment $COUNT`
            echo_magenta "===== SETUP $COUNT: CC=$CC CMAKE=$CMAKE REMOTE=$REMOTE ====="
            # Run one build with setup environment variables: CC, CMAKE and REMOTE
            run_after_echo ./build.sh
            echo 'Cleaning...'
            if [ "$CMAKE" = yes ]; then rm -rf build; else make distclean; fi
            purge_directory "$PREFIX"
            run_after_echo git status -suall
            # Cancel changes in configure
            run_after_echo git checkout configure
        done
    done
done
run_after_echo rm -rf "$PREFIX"
echo_magenta "Tested setup count: $COUNT"
# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :
