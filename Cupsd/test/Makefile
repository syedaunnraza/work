#
# "$Id: Makefile 6649 2007-07-11 21:46:42Z mike $"
#
#   IPP test makefile for the Common UNIX Printing System (CUPS).
#
#   Copyright 2007 by Apple Inc.
#   Copyright 1997-2006 by Easy Software Products, all rights reserved.
#
#   These coded instructions, statements, and computer programs are the
#   property of Apple Inc. and are protected by Federal copyright
#   law.  Distribution and use rights are outlined in the file "LICENSE.txt"
#   which should have been included with this file.  If this file is
#   file is missing or damaged, see the license at "http://www.cups.org/".
#

include ../Makedefs


#
# Make all targets...
#

all:	ipptest


#
# Clean all object files...
#

clean:
	$(RM) ipptest ipptest.o


#
# Update dependencies (without system header dependencies...)
#

depend:
	makedepend -Y -I.. -fDependencies ipptest.c >/dev/null 2>&1


#
# Install all targets...
#

install: all


#
# Unnstall all targets...
#

uninstall:


#
# ipptest
#

ipptest:	ipptest.o ../cups/libcups.a
	echo Linking $@...
	$(CC) $(LDFLAGS) -o ipptest ipptest.o  ../cups/libcups.a \
		$(LIBGSSAPI) $(SSLLIBS) $(COMMONLIBS) $(LIBZ)


#
# Dependencies...
#

include Dependencies


#
# End of "$Id: Makefile 6649 2007-07-11 21:46:42Z mike $".
#
