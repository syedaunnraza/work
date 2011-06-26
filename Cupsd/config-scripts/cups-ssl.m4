dnl
dnl "$Id: cups-ssl.m4 6649 2007-07-11 21:46:42Z mike $"
dnl
dnl   OpenSSL/GNUTLS stuff for the Common UNIX Printing System (CUPS).
dnl
dnl   Copyright 2007 by Apple Inc.
dnl   Copyright 1997-2007 by Easy Software Products, all rights reserved.
dnl
dnl   These coded instructions, statements, and computer programs are the
dnl   property of Apple Inc. and are protected by Federal copyright
dnl   law.  Distribution and use rights are outlined in the file "LICENSE.txt"
dnl   which should have been included with this file.  If this file is
dnl   file is missing or damaged, see the license at "http://www.cups.org/".
dnl

AC_ARG_ENABLE(ssl, [  --enable-ssl            turn on SSL/TLS support, default=yes])
AC_ARG_ENABLE(cdsassl, [  --enable-cdsassl        use CDSA for SSL/TLS support, default=first])
AC_ARG_ENABLE(gnutls, [  --enable-gnutls         use GNU TLS for SSL/TLS support, default=second])
AC_ARG_ENABLE(openssl, [  --enable-openssl        use OpenSSL for SSL/TLS support, default=third])
AC_ARG_WITH(openssl-libs, [  --with-openssl-libs     set directory for OpenSSL library],
    LDFLAGS="-L$withval $LDFLAGS"
    DSOFLAGS="-L$withval $DSOFLAGS",)
AC_ARG_WITH(openssl-includes, [  --with-openssl-includes set directory for OpenSSL includes],
    CFLAGS="-I$withval $CFLAGS"
    CXXFLAGS="-I$withval $CXXFLAGS"
    CPPFLAGS="-I$withval $CPPFLAGS",)

SSLFLAGS=""
SSLLIBS=""
ENCRYPTION_REQUIRED=""

if test x$enable_ssl != xno; then
    dnl Look for CDSA...
    if test "x${SSLLIBS}" = "x" -a "x${enable_cdsassl}" != "xno"; then
	if test $uname = Darwin; then
	    AC_CHECK_HEADER(Security/SecureTransport.h, [
		SSLLIBS="-framework CoreFoundation -framework Security"
		# MacOS X doesn't (yet) come with pre-installed encryption
		# certificates for CUPS, so don't enable encryption on
		# /admin just yet...
		#ENCRYPTION_REQUIRED="  Encryption Required"
		AC_DEFINE(HAVE_SSL)
		AC_DEFINE(HAVE_CDSASSL)

		dnl Check for the various security headers...
		AC_CHECK_HEADER(Security/SecPolicy.h,
		    AC_DEFINE(HAVE_SECPOLICY_H))
		AC_CHECK_HEADER(Security/SecPolicyPriv.h,
		    AC_DEFINE(HAVE_SECPOLICYPRIV_H))
		AC_CHECK_HEADER(Security/SecBasePriv.h,
		    AC_DEFINE(HAVE_SECBASEPRIV_H))
		AC_CHECK_HEADER(Security/SecIdentitySearchPriv.h,
		    AC_DEFINE(HAVE_SECIDENTITYSEARCHPRIV_H))

		dnl Check for SecIdentitySearchCreateWithPolicy...
		AC_MSG_CHECKING(for SecIdentitySearchCreateWithPolicy)
		if test $uversion -ge 80; then
		    AC_DEFINE(HAVE_SECIDENTITYSEARCHCREATEWITHPOLICY)
		    AC_MSG_RESULT(yes)
		else
		    AC_MSG_RESULT(no)
		fi])
	fi
    fi

    dnl Then look for GNU TLS...
    if test "x${SSLLIBS}" = "x" -a "x${enable_gnutls}" != "xno"; then
    	AC_PATH_PROG(LIBGNUTLSCONFIG,libgnutls-config)
	if test "x$LIBGNUTLSCONFIG" != x; then
	    SSLLIBS=`$LIBGNUTLSCONFIG --libs`
	    SSLFLAGS=`$LIBGNUTLSCONFIG --cflags`
	    ENCRYPTION_REQUIRED="  Encryption Required"
	    AC_DEFINE(HAVE_SSL)
	    AC_DEFINE(HAVE_GNUTLS)
	fi
    fi

    dnl Check for the OpenSSL library last...
    if test "x${SSLLIBS}" = "x" -a "x${enable_openssl}" != "xno"; then
	AC_CHECK_HEADER(openssl/ssl.h,
	    dnl Save the current libraries so the crypto stuff isn't always
	    dnl included...
	    SAVELIBS="$LIBS"

	    dnl Some ELF systems can't resolve all the symbols in libcrypto
	    dnl if libcrypto was linked against RSAREF, and fail to link the
	    dnl test program correctly, even though a correct installation
	    dnl of OpenSSL exists.  So we test the linking three times in
	    dnl case the RSAREF libraries are needed.

	    for libcrypto in \
	        "-lcrypto" \
	        "-lcrypto -lrsaref" \
	        "-lcrypto -lRSAglue -lrsaref"
	    do
		AC_CHECK_LIB(ssl,SSL_new,
		    [SSLFLAGS="-DOPENSSL_DISABLE_OLD_DES_SUPPORT"
		     SSLLIBS="-lssl $libcrypto"
		     ENCRYPTION_REQUIRED="  Encryption Required"
		     AC_DEFINE(HAVE_SSL)
		     AC_DEFINE(HAVE_LIBSSL)],,
		    $libcrypto)

		if test "x${SSLLIBS}" != "x"; then
		    break
		fi
	    done

	    LIBS="$SAVELIBS")
    fi
fi

if test "x$SSLLIBS" != x; then
    AC_MSG_RESULT([    Using SSLLIBS="$SSLLIBS"])
    AC_MSG_RESULT([    Using SSLFLAGS="$SSLFLAGS"])
fi

AC_SUBST(SSLFLAGS)
AC_SUBST(SSLLIBS)
AC_SUBST(ENCRYPTION_REQUIRED)

EXPORT_SSLLIBS="$SSLLIBS"
AC_SUBST(EXPORT_SSLLIBS)


dnl
dnl End of "$Id: cups-ssl.m4 6649 2007-07-11 21:46:42Z mike $".
dnl
