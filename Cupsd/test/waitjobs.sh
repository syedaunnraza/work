#!/bin/sh
#
# "$Id: waitjobs.sh 7410 2008-03-29 00:34:23Z mike $"
#
# Script to wait for jobs to complete.
#
#   Copyright 2008 by Apple Inc.
#
#   These coded instructions, statements, and computer programs are the
#   property of Apple Inc. and are protected by Federal copyright
#   law.  Distribution and use rights are outlined in the file "LICENSE.txt"
#   which should have been included with this file.  If this file is
#   file is missing or damaged, see the license at "http://www.cups.org/".
#

# Get timeout from command-line
if test $# = 1; then
	timeout=$1
else
	timeout=60
fi

echo "Waiting for jobs to complete..."

while test $timeout -gt 0; do
	jobs=`../systemv/lpstat 2>/dev/null`
	if test "x$jobs" = "x"; then
		break
	fi

	sleep 5
	timeout=`expr $timeout - 5`
done

#
# End of "$Id: waitjobs.sh 7410 2008-03-29 00:34:23Z mike $".
#
