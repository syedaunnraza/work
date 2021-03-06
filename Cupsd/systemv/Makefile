#
# "$Id: Makefile 6649 2007-07-11 21:46:42Z mike $"
#
#   System V commands makefile for the Common UNIX Printing System (CUPS).
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

TARGETS	=	accept cancel cupsaddsmb cupsctl cupstestdsc cupstestppd \
		lp lpadmin lpinfo lpmove lpoptions lppasswd lpstat
OBJS	=	accept.o cancel.o cupsaddsmb.o cupsctl.o cupstestdsc.o \
		cupstestppd.o lp.o lpadmin.o lpinfo.o lpmove.o lpoptions.o \
		lppasswd.o lpstat.o


#
# Make all targets...
#

all:	$(TARGETS)


#
# Clean all object files...
#

clean:
	$(RM) $(OBJS) $(TARGETS) cupsdisable cupsenable reject


#
# Update dependencies (without system header dependencies...)
#

depend:
	makedepend -Y -I.. -fDependencies $(OBJS:.o=.c) >/dev/null 2>&1


#
# Install all targets...
#

install:	all
	$(INSTALL_DIR) -m 755 $(SBINDIR)
	$(INSTALL_BIN) accept $(SBINDIR)
	$(RM) $(SBINDIR)/reject
	$(LN) accept $(SBINDIR)/reject
	$(INSTALL_BIN) cupsaddsmb $(SBINDIR)
	$(INSTALL_BIN) cupsctl $(SBINDIR)
	$(INSTALL_BIN) lpadmin $(SBINDIR)
	$(INSTALL_BIN) lpinfo $(SBINDIR)
	$(INSTALL_BIN) lpmove $(SBINDIR)
	$(INSTALL_DIR) -m 755 $(BINDIR)
	$(INSTALL_BIN) cancel $(BINDIR)
	$(INSTALL_BIN) cupstestdsc $(BINDIR)
	$(INSTALL_BIN) cupstestppd $(BINDIR)
	$(RM) $(SBINDIR)/cupsdisable
	$(LN) accept $(SBINDIR)/cupsdisable
	$(RM) $(SBINDIR)/cupsenable
	$(LN) accept $(SBINDIR)/cupsenable
	$(INSTALL_BIN) lp $(BINDIR)
	$(INSTALL_BIN) lpoptions $(BINDIR)
	$(INSTALL_BIN) lpstat $(BINDIR)
	$(INSTALL_BIN) -m 4755 -o root lppasswd $(BINDIR) || $(INSTALL_BIN) lppasswd $(BINDIR)
	if test "x$(SYMROOT)" != "x"; then \
		$(INSTALL_DIR) $(SYMROOT); \
		for file in $(TARGETS); do \
			cp $$file $(SYMROOT); \
		done \
	fi


#
# Uninstall all targets...
#

uninstall:
	$(RM) $(BINDIR)/cancel
	$(RM) $(BINDIR)/cupstestdsc
	$(RM) $(BINDIR)/cupstestppd
	$(RM) $(BINDIR)/lp
	$(RM) $(BINDIR)/lpoptions
	$(RM) $(BINDIR)/lppasswd
	$(RM) $(BINDIR)/lpstat
	-$(RMDIR) $(BINDIR)
	$(RM) $(SBINDIR)/accept
	$(RM) $(SBINDIR)/cupsaddsmb
	$(RM) $(SBINDIR)/cupsdisable
	$(RM) $(SBINDIR)/cupsenable
	$(RM) $(SBINDIR)/lpadmin
	$(RM) $(SBINDIR)/lpinfo
	$(RM) $(SBINDIR)/lpmove
	$(RM) $(SBINDIR)/reject
	-$(RMDIR) $(SBINDIR)


#
# accept
#

accept:	accept.o ../cups/$(LIBCUPS)
	echo Linking $@...
	$(CC) $(LDFLAGS) -o accept accept.o $(LIBS)
	$(RM) reject cupsenable cupsdisable
	$(LN) accept reject
	$(LN) accept cupsenable
	$(LN) accept cupsdisable


#
# cancel
#

cancel:	cancel.o ../cups/$(LIBCUPS)
	echo Linking $@...
	$(CC) $(LDFLAGS) -o cancel cancel.o $(LIBS)


#
# cupsaddsmb
#

cupsaddsmb:	cupsaddsmb.o ../cups/$(LIBCUPS)
	echo Linking $@...
	$(CC) $(LDFLAGS) -o cupsaddsmb cupsaddsmb.o $(LIBS)


#
# cupsctl
#

cupsctl:	cupsctl.o ../cups/$(LIBCUPS)
	echo Linking $@...
	$(CC) $(LDFLAGS) -o cupsctl cupsctl.o $(LIBS)


#
# cupstestdsc
#

cupstestdsc:	cupstestdsc.o ../cups/$(LIBCUPS)
	echo Linking $@...
	$(CC) $(LDFLAGS) -o $@ cupstestdsc.o $(LIBS)


#
# cupstestppd
#

cupstestppd:	cupstestppd.o ../cups/$(LIBCUPS) ../filter/$(LIBCUPSIMAGE)
	echo Linking $@...
	$(CC) $(LDFLAGS) -o $@ cupstestppd.o $(LINKCUPSIMAGE) $(IMGLIBS) $(LIBS)


#
# lp
#

lp:	lp.o ../cups/$(LIBCUPS)
	echo Linking $@...
	$(CC) $(LDFLAGS) -o lp lp.o $(LIBS)


#
# lpadmin
#

lpadmin:	lpadmin.o ../cups/$(LIBCUPS)
	echo Linking $@...
	$(CC) $(LDFLAGS) -o lpadmin lpadmin.o $(LIBZ) $(LIBS)


#
# lpinfo
#

lpinfo:	lpinfo.o ../cups/$(LIBCUPS)
	echo Linking $@...
	$(CC) $(LDFLAGS) -o lpinfo lpinfo.o $(LIBS)


#
# lpmove
#

lpmove:	lpmove.o ../cups/$(LIBCUPS)
	echo Linking $@...
	$(CC) $(LDFLAGS) -o lpmove lpmove.o $(LIBS)


#
# lpoptions
#

lpoptions:	lpoptions.o ../cups/$(LIBCUPS)
	echo Linking $@...
	$(CC) $(LDFLAGS) -o lpoptions lpoptions.o $(LIBZ) $(LIBS)


#
# lppasswd
#

lppasswd:	lppasswd.o ../cups/$(LIBCUPS)
	echo Linking $@...
	$(CC) $(LDFLAGS) -o lppasswd lppasswd.o $(LIBZ) $(LIBS)


#
# lpstat
#

lpstat:	lpstat.o ../cups/$(LIBCUPS)
	echo Linking $@...
	$(CC) $(LDFLAGS) -o lpstat lpstat.o $(LIBS)


#
# Dependencies...
#

include Dependencies


#
# End of "$Id: Makefile 6649 2007-07-11 21:46:42Z mike $".
#
