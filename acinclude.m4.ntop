#
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
# local automake definitions for ntop
## (this file is processed with 'automake' to produce Makefile.in)
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
#
# Copyright (c) 1998, 2000 Luca Deri <deri@ntop.org>
# Updated 1Q 2000 Rocco Carbone <rocco@ntop.org>
#
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#

dnl>
dnl>  Check for an ANSI C typedef in a header
dnl>
dnl>  configure.in:
dnl>    AC_CHECK_TYPEDEF(<typedef>, <header>)
dnl>  acconfig.h:
dnl>    #undef HAVE_<typedef>
dnl>

AC_DEFUN(AC_CHECK_TYPEDEF,[dnl
AC_REQUIRE([AC_HEADER_STDC])dnl
AC_MSG_CHECKING(for typedef $1)
AC_CACHE_VAL(ac_cv_typedef_$1,
[AC_EGREP_CPP(dnl
changequote(<<,>>)dnl
<<(^|[^a-zA-Z_0-9])$1[^a-zA-Z_0-9]>>dnl
changequote([,]), [
#include <$2>
], ac_cv_typedef_$1=yes, ac_cv_typedef_$1=no)])dnl
AC_MSG_RESULT($ac_cv_typedef_$1)
if test $ac_cv_typedef_$1 = yes; then
    AC_DEFINE(HAVE_[]translit($1, [a-z], [A-Z]))
fi
])

dnl>
dnl>  Append a value to $LIBS -- allows us to encapsulate functionality
dnl>           for those OSes which DO NOT check subdirectories
dnl>

# NTOP_APPEND_LIBS(Lvalue, lvalue)
# ----------------------------------------------
AC_DEFUN([NTOP_APPEND_LIBS],  
[dnl
# Expansion of NTOP_APPEND_LIBS($1, $2)
    case "${DEFINEOS}" in
      DARWIN )
          LIBS="$LIBS -L$1 -L$1/lib"
          ;;
      * )
          LIBS="$LIBS -L$1"
          ;;
    esac
    if test ".$2" != "."; then
        LIBS="$LIBS -l$2"
    fi
# Finished expansion of NTOP_APPEND_LIBS()
])

dnl>
dnl> Test for a library we MUST have (pcap gdbm)
dnl>

# NTOP_TEST_MUSTHAVE(itemname, headername, functionname1, functionname2, VARNAME)
# ---------------------------------------------------------------
AC_DEFUN([NTOP_TEST_MUSTHAVE],
[dnl
# Expansion of NTOP_NTOP_TEST_MUSTHAVE($1, $2, $3, $4, $5)
dnl>setup our variables...
nt_ac_header=`echo "ac_cv_header_$2" | $as_tr_sh`
nt_ac_lib=`echo "ac_cv_lib_$3_$2" | $as_tr_sh`

AC_MSG_CHECKING([for $1])

if eval "test ""$${$nt_ac_lib}"" = yes" &&
   eval "test ""$${$nt_ac_header}"" = yes"; then
    if test ".${$5_ROOT}" != "."; then
        AC_MSG_RESULT(ok)
        echo
        echo "******************************************************************"
        echo "*"
        echo "* NOTE:  You specified --with-$1-root."
        echo "*        However, a version was found in a standard location."
        echo "*"
        echo "*       Since this version will be used anyway,"
        echo "*>>>    we've ignored your specified location."
        echo "*"
        echo "******************************************************************"
        echo
        $5=
    else
        AC_MSG_RESULT([ok (standard location)])
    fi
elif test ".${$5_ROOT}" = "."; then
    AC_MSG_RESULT([not found in standard location, no --with-$1-root, testing further...])
    AC_MSG_CHECKING([for $1 header $2])
    if eval "test ""$${$nt_ac_header}"" = yes"; then
         AC_MSG_RESULT([ok, found in standard location])
    elif test -d /usr &&
         test -d /usr/include &&
         test -r /usr/include/$2; then
         AC_MSG_RESULT([ok, found in /usr/include])
         INCS="${INCS} -I/usr/include"
         AC_DEFINE_UNQUOTED(HAVE_$5_H, 1, [Show we found $2 and set INCS])
    elif test -d /usr &&
         test -d /usr/include &&
         test -d /usr/include/$1 &&
         test -r /usr/include/$1/$2; then
         AC_MSG_RESULT([ok, found in /usr/include/$1])
         INCS="${INCS} -I/usr/include/$1"
         AC_DEFINE_UNQUOTED(HAVE_$5_H, 1, [Show we found $2 and set INCS])
    elif test -d /usr &&
         test -d /usr/local &&
         test -d /usr/local/include &&
         test -r /usr/local/include/$2; then
         AC_MSG_RESULT([ok, found in /usr/local/include])
         INCS="${INCS} -I/usr/local/include"
         AC_DEFINE_UNQUOTED(HAVE_$5_H, 1, [Show we found $2 and set INCS])
    elif test ".${DEFINEOS}" = ".SOLARIS" &&
         test -d /usr/local/tools/SunOS &&
         test -d /usr/local/tools/SunOS/include &&
         test -r /usr/local/tools/SunOS/include/$2; then
         AC_MSG_RESULT([ok, found in /usr/local/tools/SunOS/include])
         INCS="${INCS} -I/usr/local/tools/SunOS/include"
         AC_DEFINE_UNQUOTED(HAVE_$5_H, 1, [Show we found $2 and set INCS])
    elif test ".${DEFINEOS}" = ".DARWIN" &&
         test -d /sw &&
         test -d /sw/include &&
         test -r /sw/include/$2; then
         AC_MSG_RESULT([ok, found in /sw/include])
         INCS="${INCS} -I/sw/include"
         AC_DEFINE_UNQUOTED(HAVE_$5_H, 1, [Show we found $2 and set INCS])
    elif test -r $2; then
         AC_MSG_RESULT([ok, found in ntop directory])
         AC_DEFINE_UNQUOTED(HAVE_$5_H, 1, [Show we found $2])
    else
        AC_MSG_RESULT(error)
        echo
        echo "******************************************************************"
        echo "*"
        echo "* ERROR:  1. We were unable to find the header $2 in the"
        echo "*            standard location."
        echo "*"
        echo "*     and 2. You did not specify an alternate location"
        echo "*            via --with-$1-root."
        echo "*"
        echo "*     and 3. We also tested the following:"
        echo "*"
        echo "*                /usr/include"
        echo "*                /usr/include/$1"
        echo "*                /usr/local/include"
        if test ".${DEFINEOS}" = ".DARWIN"; then
            echo "*                /sw/include"
        fi
        if test ".${DEFINEOS}" = ".SOLARIS"; then
            echo "*                /usr/local/tools/SunOS/include"
        fi
        echo "*                ntop source directory"
        echo "*"
        echo "*>>> No way to proceed."
        echo "*"
        echo "*???     1. Rerun ./configure with a corrected --with-$1-root"
        echo "*???  or 2. Install lib$1 and rerun ./configure"
        echo "*"
        echo "******************************************************************"
        echo
        AC_MSG_ERROR(Unable to continue... aborting ./configure)
    fi
    AC_MSG_CHECKING([for $1 library lib$1])
    if eval "test ""$${$nt_ac_lib}"" = yes"; then
        AC_MSG_RESULT([ok, found in standard location, -l$1])
        AC_DEFINE_UNQUOTED(HAVE_$5, 1, [Show we found -l$1 and set LIBS])
    elif test -d /usr &&
         test -d /usr/lib &&
         (test -r /usr/lib/lib$1.so ||
          test -r /usr/lib/lib$1.a); then
        AC_MSG_RESULT([ok, found in /usr/lib])
        LIBS="${LIBS} -L/usr/lib -l$1"
        dnl>  /usr/lib should be automatically tested for as part of ld.so.conf...
        AC_DEFINE_UNQUOTED(HAVE_$5, 1, [Show we found -l$1 and set LIBS])
    elif test -d /usr &&
         test -d /usr/local &&
         test -d /usr/local/lib &&
         (test -r /usr/local/lib/lib$1.so ||
          test -r /usr/local/lib/lib$1.a); then
        AC_MSG_RESULT([ok, found in /usr/local/lib])
        LIBS="${LIBS} -L/usr/local/lib -l$1"
        AC_DEFINE_UNQUOTED(HAVE_$5, 1, [Show we found -l$1 and set LIBS])
    elif test ".${DEFINEOS}" = ".SOLARIS" &&
         test -d /usr/local/tools/SunOS &&
         test -d /usr/local/tools/SunOS/lib &&
         (test -r /usr/local/tools/SunOS/lib/lib$1.so ||
          test -r /usr/local/tools/SunOS/lib/lib$1.a); then
        LIBS="${LIBS} -L/usr/local/tools/SunOS/lib -l$1"
        AC_MSG_RESULT([ok, found in /usr/local/tools/SunOS/lib])
        AC_DEFINE_UNQUOTED(HAVE_$5, 1, [Show we found -l$1 and set LIBS])
    elif test ".${DEFINEOS}" = ".DARWIN" &&
         test -d /sw &&
         test -d /sw/lib &&
         test -r /sw/lib/lib$1.dylib; then
        LIBS="${LIBS} -L/sw/lib -l$1"
        AC_MSG_RESULT([ok, found in /sw/lib])
        AC_DEFINE_UNQUOTED(HAVE_$5, 1, [Show we found -l$1 and set LIBS])
    elif test -r $2.so ||
         test -r $2.a; then
         AC_MSG_RESULT([ok, found in ntop directory])
         AC_DEFINE_UNQUOTED(HAVE_$5_H, 1, [Show we found $2])
    else
        AC_MSG_RESULT(error)
        echo
        echo "*******************************************************************"
        echo "*"
        echo "* ERROR:  1. We were unable to compile a test program for"
        echo "*            $3() against -l$2."
        echo "*"
        echo "*     and 2. You did not specify an alternate location"
        echo "*            via --with-$1-root."
        echo "*"
        echo "*     and 3. We were unable to find lib$1.so or lib$1.a"
        echo "*            via a manual search of"
        echo "*"
        echo "*                /usr/lib"
        echo "*                /usr/local/lib"
        if test ".${DEFINEOS}" = ".DARWIN"; then
            echo "*                /sw/lib        (lib$1.dylib)"
        fi
        if test ".${DEFINEOS}" = ".SOLARIS"; then
            echo "*                /usr/local/tools/SunOS/lib"
        fi
        echo "*                ntop source directory"
        echo "*"
        echo "*>>> No way to proceed."
        echo "*"
        echo "*???     1. Install lib$1 and rerun ./configure"
        echo "*???  or 2. Rerun ./configure with a corrected --with-$1-root"
        echo "*"
        echo "******************************************************************"
        echo
        AC_MSG_ERROR(Unable to continue... aborting ./configure)
    fi
else
    AC_MSG_RESULT([not found in standard location, testing --with-$1-root...])
    AC_MSG_CHECKING([for $1 header, $2])
    if eval "test ""$${$nt_ac_header}"" = yes"; then
         AC_MSG_RESULT([ok, found in standard location])
    dnl> Can we find $2 and lib$1 where s/he told us?
    elif test -d ${$5_ROOT} &&
         test -r ${$5_ROOT}/$2; then
         AC_MSG_RESULT([ok, found in \${$5_ROOT}])
         INCS="${INCS} -I\${$5_ROOT}"
         AC_DEFINE_UNQUOTED(HAVE_$5_H, 1, [Show we found $2 and set INCS])
    elif test -d ${$5_ROOT} &&
       test -d ${$5_ROOT}/include &&
       test -r ${$5_ROOT}/include/$2; then
         AC_MSG_RESULT([ok, found in \${$5_ROOT}/include])
         INCS="${INCS} -I${$5_ROOT}/include"
         AC_DEFINE_UNQUOTED(HAVE_$5_H, 1, [Show we found $2 and set INCS])
    elif test -d ${$5_ROOT} &&
       test -d ${$5_ROOT}/include &&
       test -d ${$5_ROOT}/include/$1 &&
       test -r ${$5_ROOT}/include/$1/$2; then
         AC_MSG_RESULT([ok, found in ${$5_ROOT}/include/$1])
         INCS="${INCS} -I${$5_ROOT}/include/$1"
         AC_DEFINE_UNQUOTED(HAVE_$5_H, 1, [Show we found $2 and set INCS])
    else
        AC_MSG_RESULT(error)
        echo
        echo "******************************************************************"
        echo "*"
        echo "* ERROR:  1. We were unable to find the header $2 in the"
        echo "*            standard location or the alternate location you"
        echo "*            specified by --with-$1-root."
        echo "*"
        echo "*>>> No way to proceed."
        echo "*"
        echo "*???     1. Rerun ./configure with a corrected --with-$1-root"
        echo "*???  or 2. Install lib$1 and rerun ./configure"
        echo "*"
        echo "******************************************************************"
        echo
        AC_MSG_ERROR(Unable to continue... aborting ./configure)
    fi
    AC_MSG_CHECKING([for $1 library lib$1])
    if eval "test ""$${$nt_ac_lib}"" = yes"; then
        AC_MSG_RESULT([ok, found in standard location, -l$1])
        AC_DEFINE_UNQUOTED(HAVE_$5, 1, [Show we found -l$1 and set LIBS])
    else
        oLIBS="${LIBS}"
        NTOP_APPEND_LIBS([${$5_ROOT}])
        LIBS="${LIBS} -lgdbm"
        AC_CHECK_LIB([$1], [$3],
           [AC_DEFINE_UNQUOTED(HAVE_$5, 1, [Show we found -l$1 and set LIBS])],

           [LIBS="${oLIBS}"
            NTOP_APPEND_LIBS([${$5_ROOT}/lib])
            LIBS="${LIBS} -lgdbm"
            AC_CHECK_LIB([$1], [$4],
               [AC_DEFINE_UNQUOTED(HAVE_$5, 1, [Show we found -l$1 and set LIBS])],
               [AC_MSG_RESULT(error)
                LIBS="${oLIBS}"
                echo
                echo "******************************************************************"
                echo ""
                echo "* ERROR:  1. We were unable to compile a test program"
                echo "*            against -l$1 in the standard location"
                echo ""
                echo "*     and 2. We were unable to compile a test program for"
                echo "*            $3() against -l$1 in the alternate"
                echo "*            location specified by --with-$1-root."
                echo ""
                echo "*>>> No way to proceed."
                echo ""
                echo "*???     1. Rerun ./configure with a corrected --with-$1-root"
                echo "*???  or 2. Install lib$1 and rerun ./configure"
                echo ""
                echo "*****************************************************************"
                echo
                AC_MSG_ERROR(Unable to continue... aborting ./configure)
               ])
           ])
    fi
fi
# Finished expansion of NTOP_TEST_MUSTHAVE()
])]

# NTOP_OPENSSL_TESTS(where)
# ----------------------------------------------
AC_DEFUN([NTOP_OPENSSL_TESTS],
[dnl
# Expansion of NTOP_OPENSSL_TESTS($1)

           test -d $1          &&
           test -r $1/rsa.h    &&
           test -r $1/crypto.h &&
           test -r $1/x509.h   &&
           test -r $1/pem.h    &&
           test -r $1/ssl.h    &&
           test -r $1/err.h; then
            AC_MSG_RESULT([ok, openSSL .h files found in $1])
            INCS="${INCS} -I$1"
            AC_DEFINE_UNQUOTED(HAVE_RSA_H,    1, [Show we found rsa.h and set INCS])
            AC_DEFINE_UNQUOTED(HAVE_CRYPTO_H, 1, [Show we found crypto.h and set INCS])
            AC_DEFINE_UNQUOTED(HAVE_X509_H,   1, [Show we found x509.h and set INCS])
            AC_DEFINE_UNQUOTED(HAVE_PEM_H,    1, [Show we found pem.h and set INCS])
            AC_DEFINE_UNQUOTED(HAVE_SSL_H,    1, [Show we found ssl.h and set INCS])
            AC_DEFINE_UNQUOTED(HAVE_ERR_H,    1, [Show we found err.h and set INCS])

# Finished expansion of NTOP_OPENSSL_TESTS()
])]
