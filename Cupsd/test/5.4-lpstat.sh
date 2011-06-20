#!/bin/sh
#
# "$Id: 5.4-lpstat.sh 6649 2007-07-11 21:46:42Z mike $"
#
#   Test the lpstat command.
#
#   Copyright 2007 by Apple Inc.
#   Copyright 1997-2005 by Easy Software Products, all rights reserved.
#
#   These coded instructions, statements, and computer programs are the
#   property of Apple Inc. and are protected by Federal copyright
#   law.  Distribution and use rights are outlined in the file "LICENSE.txt"
#   which should have been included with this file.  If this file is
#   file is missing or damaged, see the license at "http://www.cups.org/".
#

echo "LPSTAT Test"
echo ""
echo "    lpstat -t"
../systemv/lpstat -t 2>&1
if test $? != 0; then
	echo "    FAILED"
	exit 1
else
	echo "    PASSED"
fi
echo ""

#
# End of "$Id: 5.4-lpstat.sh 6649 2007-07-11 21:46:42Z mike $".
#
