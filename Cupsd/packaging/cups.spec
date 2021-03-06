#
# "$Id: cups.spec.in 7692 2008-06-25 17:06:24Z mike $"
#
#   RPM "spec" file for the Common UNIX Printing System (CUPS).
#
#   Original version by Jason McMullan <jmcc@ontv.com>.
#
#   Copyright 2007-2008 by Apple Inc.
#   Copyright 1999-2007 by Easy Software Products, all rights reserved.
#
#   These coded instructions, statements, and computer programs are the
#   property of Apple Inc. and are protected by Federal copyright
#   law.  Distribution and use rights are outlined in the file "LICENSE.txt"
#   which should have been included with this file.  If this file is
#   file is missing or damaged, see the license at "http://www.cups.org/".
#

# Conditional build options (--with name/--without name):
#
#   dbus     - Enable/disable DBUS support (default = enable)
#   php      - Enable/disable PHP support (default = enable)

%{!?_with_dbus: %{!?_without_dbus: %define _with_dbus --with-dbus}}
%{?_with_dbus: %define _dbus --enable-dbus}
%{!?_with_dbus: %define _dbus --disable-dbus}

%{!?_with_php: %{!?_without_php: %define _with_php --with-php}}
%{?_with_php: %define _php --with-php}
%{!?_with_php: %define _php --without-php}

%{!?_with_static: %{!?_without_static: %define _without_static --without-static}}
%{?_with_static: %define _static --enable-static}
%{!?_with_static: %define _static --disable-static}

Summary: Common UNIX Printing System
Name: cups
Version: 1.3.8
Release: 1
Epoch: 1
License: GPL
Group: System Environment/Daemons
Source: ftp://ftp.easysw.com/pub/cups/1.3.8/cups-1.3.8-source.tar.gz
Url: http://www.cups.org
Packager: Anonymous <anonymous@foo.com>
Vendor: Apple Inc.

# Use buildroot so as not to disturb the version already installed
BuildRoot: /tmp/%{name}-root

# Dependencies...
Requires: %{name}-libs = %{epoch}:%{version}
Obsoletes: lpd, lpr, LPRng
Provides: lpd, lpr, LPRng

%package devel
Summary: Common UNIX Printing System - development environment
Group: Development/Libraries
Requires: %{name}-libs = %{epoch}:%{version}

%package libs
Summary: Common UNIX Printing System - shared libraries
Group: System Environment/Libraries
Provides: libcups1

%package lpd
Summary: Common UNIX Printing System - LPD support
Group: System Environment/Daemons
Requires: %{name} = %{epoch}:%{version} xinetd

%package da
Summary: Common UNIX Printing System - Danish support
Group: System Environment/Daemons
Requires: %{name} = %{epoch}:%{version}

%package de
Summary: Common UNIX Printing System - German support
Group: System Environment/Daemons
Requires: %{name} = %{epoch}:%{version}

%package es
Summary: Common UNIX Printing System - Spanish support
Group: System Environment/Daemons
Requires: %{name} = %{epoch}:%{version}

%package et
Summary: Common UNIX Printing System - Estonian support
Group: System Environment/Daemons
Requires: %{name} = %{epoch}:%{version}

%package fi
Summary: Common UNIX Printing System - Finnish support
Group: System Environment/Daemons
Requires: %{name} = %{epoch}:%{version}

%package fr
Summary: Common UNIX Printing System - French support
Group: System Environment/Daemons
Requires: %{name} = %{epoch}:%{version}

%package he
Summary: Common UNIX Printing System - Hebrew support
Group: System Environment/Daemons
Requires: %{name} = %{epoch}:%{version}

%package id
Summary: Common UNIX Printing System - Indonesian support
Group: System Environment/Daemons
Requires: %{name} = %{epoch}:%{version}

%package it
Summary: Common UNIX Printing System - Italian support
Group: System Environment/Daemons
Requires: %{name} = %{epoch}:%{version}

%package ja
Summary: Common UNIX Printing System - Japanese support
Group: System Environment/Daemons
Requires: %{name} = %{epoch}:%{version}

%package ko
Summary: Common UNIX Printing System - Korean support
Group: System Environment/Daemons
Requires: %{name} = %{epoch}:%{version}

%package nl
Summary: Common UNIX Printing System - Dutch support
Group: System Environment/Daemons
Requires: %{name} = %{epoch}:%{version}

%package no
Summary: Common UNIX Printing System - Nowegian support
Group: System Environment/Daemons
Requires: %{name} = %{epoch}:%{version}

%package pl
Summary: Common UNIX Printing System - Polish support
Group: System Environment/Daemons
Requires: %{name} = %{epoch}:%{version}

%package pt
Summary: Common UNIX Printing System - Portuguese support
Group: System Environment/Daemons
Requires: %{name} = %{epoch}:%{version}

%package ru
Summary: Common UNIX Printing System - Russian support
Group: System Environment/Daemons
Requires: %{name} = %{epoch}:%{version}

%package sv
Summary: Common UNIX Printing System - Swedish support
Group: System Environment/Daemons
Requires: %{name} = %{epoch}:%{version}

%package zh
Summary: Common UNIX Printing System - Chinese support
Group: System Environment/Daemons
Requires: %{name} = %{epoch}:%{version}

%if %{?_with_php:1}%{!?_with_php:0}
%package php
Summary: Common UNIX Printing System - PHP support
Group: Development/Languages
Requires: %{name}-libs = %{epoch}:%{version}
%endif

%description
The Common UNIX Printing System provides a portable printing layer for 
UNIX� operating systems. It was developed by Easy Software Products 
to promote a standard printing solution for all UNIX vendors and users
and is now owned by Apple Inc.  CUPS provides the System V and Berkeley
command-line interfaces. 

%description devel
The Common UNIX Printing System provides a portable printing layer for 
UNIX� operating systems. This is the development package for creating
additional printer drivers and other CUPS services.

%description libs
The Common UNIX Printing System provides a portable printing layer for 
UNIX� operating systems. This package contains the CUPS shared libraries.

%description lpd
The Common UNIX Printing System provides a portable printing layer for 
UNIX� operating systems. This package provides LPD client support.

%description da
The Common UNIX Printing System provides a portable printing layer for 
UNIX� operating systems. This package provides Danish support.

%description de
The Common UNIX Printing System provides a portable printing layer for 
UNIX� operating systems. This package provides German support.

%description es
The Common UNIX Printing System provides a portable printing layer for 
UNIX� operating systems. This package provides Spanish support.

%description et
The Common UNIX Printing System provides a portable printing layer for 
UNIX� operating systems. This package provides Estonian support.

%description fi
The Common UNIX Printing System provides a portable printing layer for 
UNIX� operating systems. This package provides Finnish support.

%description fr
The Common UNIX Printing System provides a portable printing layer for 
UNIX� operating systems. This package provides French support.

%description he
The Common UNIX Printing System provides a portable printing layer for 
UNIX� operating systems. This package provides Hebrew support.

%description id
The Common UNIX Printing System provides a portable printing layer for 
UNIX� operating systems. This package provides Indonesian support.

%description it
The Common UNIX Printing System provides a portable printing layer for 
UNIX� operating systems. This package provides Italian support.

%description ja
The Common UNIX Printing System provides a portable printing layer for 
UNIX� operating systems. This package provides Japanese support.

%description ko
The Common UNIX Printing System provides a portable printing layer for 
UNIX� operating systems. This package provides Korean support.

%description nl
The Common UNIX Printing System provides a portable printing layer for 
UNIX� operating systems. This package provides Dutch support.

%description no
The Common UNIX Printing System provides a portable printing layer for 
UNIX� operating systems. This package provides Norwegian support.

%description pl
The Common UNIX Printing System provides a portable printing layer for 
UNIX� operating systems. This package provides Polish support.

%description pt
The Common UNIX Printing System provides a portable printing layer for 
UNIX� operating systems. This package provides Portuguese support.

%description ru
The Common UNIX Printing System provides a portable printing layer for 
UNIX� operating systems. This package provides Russian support.

%description sv
The Common UNIX Printing System provides a portable printing layer for 
UNIX� operating systems. This package provides Swedish support.

%description zh
The Common UNIX Printing System provides a portable printing layer for 
UNIX� operating systems. This package provides Chinese support.

%if %{?_with_php:1}%{!?_with_php:0}
%description php
The Common UNIX Printing System provides a portable printing layer for 
UNIX� operating systems. This package provides PHP support.
%endif

%prep
%setup

%build
%ifarch x86_64
./configure --enable-32bit %{_dbus} %{_php} %{_static}
%else
CFLAGS="$RPM_OPT_FLAGS" CXXFLAGS="$RPM_OPT_FLAGS" LDFLAGS="$RPM_OPT_FLAGS" \
    ./configure %{_dbus} %{_php} %{_static}
%endif
# If we got this far, all prerequisite libraries must be here.
make

%install
# Make sure the RPM_BUILD_ROOT directory exists.
rm -rf $RPM_BUILD_ROOT

make BUILDROOT=$RPM_BUILD_ROOT install

%post
/sbin/chkconfig --add cups
/sbin/chkconfig cups on

# Restart cupsd if we are upgrading...
if test $1 -gt 1; then
	/sbin/service cups stop
	/sbin/service cups start
fi

%post libs
/sbin/ldconfig

%preun
if test $1 = 0; then
	/sbin/service cups stop
	/sbin/chkconfig --del cups
fi

%postun
if test $1 -ge 1; then
	/sbin/service cups stop
	/sbin/service cups start
fi

%postun libs
/sbin/ldconfig

%clean
rm -rf $RPM_BUILD_ROOT

%files
%docdir /usr/share/doc/cups
%defattr(-,root,root)
%dir /etc/cups
%config(noreplace) /etc/cups/*.conf
/etc/cups/cupsd.conf.default
%dir /etc/cups/interfaces
/etc/cups/mime.types
/etc/cups/mime.convs
%dir /etc/cups/ppd
%attr(0700,root,root) %dir /etc/cups/ssl

%if %{?_with_dbus:1}%{!?_with_dbus:0}
# DBUS
/etc/dbus-1/system.d/*
%endif

# PAM
%dir /etc/pam.d
/etc/pam.d/*

# RC dirs are a pain under Linux...  Uncomment the appropriate ones if you
# don't use Red Hat or Mandrake...

/etc/init.d/*
/etc/rc0.d/*
/etc/rc2.d/*
/etc/rc3.d/*
/etc/rc5.d/*

# OLD RedHat/Mandrake
#/etc/rc.d/init.d/*
#/etc/rc.d/rc0.d/*
#/etc/rc.d/rc2.d/*
#/etc/rc.d/rc3.d/*
#/etc/rc.d/rc5.d/*

#/sbin/rc.d/*
#/sbin/rc.d/rc0.d/*
#/sbin/rc.d/rc2.d/*
#/sbin/rc.d/rc3.d/*
#/sbin/rc.d/rc5.d/*

/usr/bin/cancel
/usr/bin/cupstestdsc
/usr/bin/cupstestppd
/usr/bin/lp*
%dir /usr/lib/cups
%dir /usr/lib/cups/backend
/usr/lib/cups/backend/http
%attr(0700,root,root) /usr/lib/cups/backend/ipp
%attr(0700,root,root) /usr/lib/cups/backend/lpd
/usr/lib/cups/backend/parallel
/usr/lib/cups/backend/scsi
/usr/lib/cups/backend/serial
/usr/lib/cups/backend/snmp
/usr/lib/cups/backend/socket
/usr/lib/cups/backend/usb
%dir /usr/lib/cups/cgi-bin
/usr/lib/cups/cgi-bin/*
%dir /usr/lib/cups/daemon
/usr/lib/cups/daemon/cups-deviced
/usr/lib/cups/daemon/cups-driverd
/usr/lib/cups/daemon/cups-polld
%dir /usr/lib/cups/driver
%dir /usr/lib/cups/filter
/usr/lib/cups/filter/*
%dir /usr/lib/cups/monitor
/usr/lib/cups/monitor/*
%dir /usr/lib/cups/notifier
/usr/lib/cups/notifier/*

/usr/sbin/*
%dir /usr/share/cups
%dir /usr/share/cups/banners
/usr/share/cups/banners/*
%dir /usr/share/cups/charmaps
/usr/share/cups/charmaps/*
%dir /usr/share/cups/charsets
/usr/share/cups/charsets/*
%dir /usr/share/cups/data
/usr/share/cups/data/*
%dir /usr/share/cups/fonts
/usr/share/cups/fonts/*
%dir /usr/share/cups/model
/usr/share/cups/model/*
%dir /usr/share/cups/templates
/usr/share/cups/templates/*.tmpl
%dir /usr/share/doc/cups
/usr/share/doc/cups/*.*
%dir /usr/share/doc/cups/help
/usr/share/doc/cups/help/accounting.html
/usr/share/doc/cups/help/cgi.html
/usr/share/doc/cups/help/glossary.html
/usr/share/doc/cups/help/kerberos.html
/usr/share/doc/cups/help/license.html
/usr/share/doc/cups/help/man-*.html
/usr/share/doc/cups/help/network.html
/usr/share/doc/cups/help/options.html
/usr/share/doc/cups/help/overview.html
/usr/share/doc/cups/help/policies.html
/usr/share/doc/cups/help/ref-*.html
/usr/share/doc/cups/help/security.html
/usr/share/doc/cups/help/standard.html
/usr/share/doc/cups/help/translation.html
/usr/share/doc/cups/help/whatsnew.html
%dir /usr/share/doc/cups/images
/usr/share/doc/cups/images/*

%dir /usr/share/man/man1
/usr/share/man/man1/cancel.1.gz
/usr/share/man/man1/cupstestdsc.1.gz
/usr/share/man/man1/cupstestppd.1.gz
/usr/share/man/man1/lp.1.gz
/usr/share/man/man1/lpoptions.1.gz
/usr/share/man/man1/lppasswd.1.gz
/usr/share/man/man1/lpq.1.gz
/usr/share/man/man1/lpr.1.gz
/usr/share/man/man1/lprm.1.gz
/usr/share/man/man1/lpstat.1.gz
%dir /usr/share/man/man5
/usr/share/man/man5/*
%dir /usr/share/man/man8
/usr/share/man/man8/accept.8.gz
/usr/share/man/man8/cupsaddsmb.8.gz
/usr/share/man/man8/cupsctl.8.gz
/usr/share/man/man8/cupsfilter.8.gz
/usr/share/man/man8/cupsd.8.gz
/usr/share/man/man8/cupsdisable.8.gz
/usr/share/man/man8/cupsenable.8.gz
/usr/share/man/man8/cups-deviced.8.gz
/usr/share/man/man8/cups-driverd.8.gz
/usr/share/man/man8/cups-polld.8.gz
/usr/share/man/man8/lpadmin.8.gz
/usr/share/man/man8/lpc.8.gz
/usr/share/man/man8/lpinfo.8.gz
/usr/share/man/man8/lpmove.8.gz
/usr/share/man/man8/reject.8.gz

%dir /var/cache/cups
%attr(0775,root,sys) %dir /var/cache/cups/rss
%dir /var/log/cups
%dir /var/run/cups
%attr(0711,lp,sys) %dir /var/run/cups/certs
%attr(0710,lp,sys) %dir /var/spool/cups
%attr(1770,lp,sys) %dir /var/spool/cups/tmp

# Desktop files
/usr/share/applications/*
/usr/share/icons/*

%files devel
%defattr(-,root,root)
%dir /usr/share/man/man1
/usr/share/man/man1/cups-config.1.gz
%dir /usr/share/man/man7
/usr/share/man/man7/*

/usr/bin/cups-config
%dir /usr/include/cups
/usr/include/cups/*
/usr/lib*/*.so

%if %{?_with_static:1}%{!?_with_static:0}
/usr/lib*/*.a
%endif

%dir /usr/share/doc/cups/help
/usr/share/doc/cups/help/api*.html
/usr/share/doc/cups/help/spec*.html

%files libs
%defattr(-,root,root)
/usr/lib*/*.so.*

%files lpd
%defattr(-,root,root)
/etc/xinetd.d/cups-lpd
%dir /usr/lib/cups
%dir /usr/lib/cups/daemon
/usr/lib/cups/daemon/cups-lpd
%dir /usr/share/man/man8
/usr/share/man/man8/cups-lpd.8.gz

%files da
%defattr(-,root,root)
/usr/share/locale/da/cups_da.po

%files de
%defattr(-,root,root)
%dir /usr/share/doc/cups/de
/usr/share/doc/cups/de/index.html
%dir /usr/share/doc/cups/de/images
/usr/share/doc/cups/de/images/*
%dir /usr/share/cups/templates/de
/usr/share/cups/templates/de/*
/usr/share/locale/de/cups_de.po

%files es
%defattr(-,root,root)
%dir /usr/share/doc/cups/es
/usr/share/doc/cups/es/index.html
%dir /usr/share/doc/cups/es/images
/usr/share/doc/cups/es/images/*
%dir /usr/share/cups/templates/es
/usr/share/cups/templates/es/*
/usr/share/locale/es/cups_es.po

%files et
%defattr(-,root,root)
%dir /usr/share/doc/cups/et
/usr/share/doc/cups/et/index.html
%dir /usr/share/doc/cups/et/images
/usr/share/doc/cups/et/images/*
%dir /usr/share/cups/templates/et
/usr/share/cups/templates/et/*
/usr/share/locale/et/cups_et.po

%files fi
%defattr(-,root,root)
/usr/share/locale/fi/cups_fi.po

%files fr
%defattr(-,root,root)
%dir /usr/share/doc/cups/fr
/usr/share/doc/cups/fr/index.html
%dir /usr/share/doc/cups/fr/images
/usr/share/doc/cups/fr/images/*
%dir /usr/share/cups/templates/fr
/usr/share/cups/templates/fr/*
/usr/share/locale/fr/cups_fr.po

%files he
%defattr(-,root,root)
%dir /usr/share/doc/cups/he
/usr/share/doc/cups/he/index.html
/usr/share/doc/cups/he/cups.css
%dir /usr/share/doc/cups/he/images
/usr/share/doc/cups/he/images/*
%dir /usr/share/cups/templates/he
/usr/share/cups/templates/he/*
/usr/share/locale/he/cups_he.po

%files it
%defattr(-,root,root)
%dir /usr/share/doc/cups/it
/usr/share/doc/cups/it/index.html
%dir /usr/share/doc/cups/it/images
/usr/share/doc/cups/it/images/*
%dir /usr/share/cups/templates/it
/usr/share/cups/templates/it/*
/usr/share/locale/it/cups_it.po

%files id
%defattr(-,root,root)
%dir /usr/share/doc/cups/id
/usr/share/doc/cups/id/index.html
%dir /usr/share/doc/cups/id/images
/usr/share/doc/cups/id/images/*
%dir /usr/share/cups/templates/id
/usr/share/cups/templates/id/*
/usr/share/locale/id/cups_id.po

%files ja
%defattr(-,root,root)
%dir /usr/share/doc/cups/ja
/usr/share/doc/cups/ja/index.html
%dir /usr/share/doc/cups/ja/images
/usr/share/doc/cups/ja/images/*
%dir /usr/share/cups/templates/ja
/usr/share/cups/templates/ja/*
/usr/share/locale/ja/cups_ja.po

%files ko
%defattr(-,root,root)
/usr/share/locale/ko/cups_ko.po

%files nl
%defattr(-,root,root)
/usr/share/locale/nl/cups_nl.po

%files no
%defattr(-,root,root)
/usr/share/locale/no/cups_no.po

%files pl
%defattr(-,root,root)
%dir /usr/share/doc/cups/pl
/usr/share/doc/cups/pl/index.html
%dir /usr/share/doc/cups/pl/images
/usr/share/doc/cups/pl/images/*
%dir /usr/share/cups/templates/pl
/usr/share/cups/templates/pl/*
/usr/share/locale/pl/cups_pl.po

%files pt
%defattr(-,root,root)
/usr/share/locale/pt/cups_pt.po
/usr/share/locale/pt_BR/cups_pt_BR.po

%files ru
%defattr(-,root,root)
/usr/share/locale/ru/cups_ru.po

%files sv
%defattr(-,root,root)
%dir /usr/share/doc/cups/sv
/usr/share/doc/cups/sv/index.html
%dir /usr/share/doc/cups/sv/images
/usr/share/doc/cups/sv/images/*
%dir /usr/share/cups/templates/sv
/usr/share/cups/templates/sv/*
/usr/share/locale/sv/cups_sv.po

%files zh
%defattr(-,root,root)
%dir /usr/share/doc/cups/zh_TW
/usr/share/doc/cups/zh_TW/index.html
%dir /usr/share/doc/cups/zh_TW/images
/usr/share/doc/cups/zh_TW/images/*
%dir /usr/share/cups/templates/zh_TW
/usr/share/cups/templates/zh_TW/*
/usr/share/locale/zh/cups_zh.po
/usr/share/locale/zh_TW/cups_zh_TW.po

%if %{?_with_php:1}%{!?_with_php:0}
%files php
# PHP
/usr/lib*/php*
%endif


#
# End of "$Id: cups.spec.in 7692 2008-06-25 17:06:24Z mike $".
#
