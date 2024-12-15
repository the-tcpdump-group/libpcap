#! /bin/bash
#
# If we have Homebrew, set the environment variables for it.
#
brewpath=`which brew`
if [ ! -z "$brewpath" ]
then
	#
	# Yes, we have it.
	#
	brew --prefix
fi
env
exec ./build_matrix.sh
