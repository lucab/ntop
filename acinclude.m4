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
    elif test -d /usr &&
         test -d /usr/lib64 &&
         (test -r /usr/lib64/lib$1.so ||
          test -r /usr/lib64/lib$1.a); then
        AC_MSG_RESULT([ok, found in /usr/lib64])
        LIBS="${LIBS} -L/usr/lib64 -l$1"
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
## libtool.m4 - Configure libtool for the target system. -*-Shell-script-*-
## Copyright (C) 1996-1999 Free Software Foundation, Inc.
## Originally by Gordon Matzigkeit <gord@gnu.ai.mit.edu>, 1996
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
##
## As a special exception to the GNU General Public License, if you
## distribute this file as part of a program that contains a
## configuration script generated by Autoconf, you may include it under
## the same distribution terms that you use for the rest of that program.

# serial 40 AC_PROG_LIBTOOL
AC_DEFUN(AC_PROG_LIBTOOL,
[AC_REQUIRE([AC_LIBTOOL_SETUP])dnl

# Save cache, so that ltconfig can load it
AC_CACHE_SAVE

# Actually configure libtool.  ac_aux_dir is where install-sh is found.
CC="$CC" CFLAGS="$CFLAGS" CPPFLAGS="$CPPFLAGS" \
LD="$LD" LDFLAGS="$LDFLAGS" LIBS="$LIBS" \
LN_S="$LN_S" NM="$NM" RANLIB="$RANLIB" \
DLLTOOL="$DLLTOOL" AS="$AS" OBJDUMP="$OBJDUMP" \
${CONFIG_SHELL-/bin/sh} $ac_aux_dir/ltconfig --no-reexec \
$libtool_flags --no-verify $ac_aux_dir/ltmain.sh $host \
|| AC_MSG_ERROR([libtool configure failed])

# Reload cache, that may have been modified by ltconfig
AC_CACHE_LOAD

# This can be used to rebuild libtool when needed
LIBTOOL_DEPS="$ac_aux_dir/ltconfig $ac_aux_dir/ltmain.sh"

# Always use our own libtool.
LIBTOOL='$(SHELL) $(top_builddir)/libtool'
AC_SUBST(LIBTOOL)dnl

# Redirect the config.log output again, so that the ltconfig log is not
# clobbered by the next message.
exec 5>>./config.log
])

AC_DEFUN(AC_LIBTOOL_SETUP,
[AC_PREREQ(2.13)dnl
AC_REQUIRE([AC_ENABLE_SHARED])dnl
AC_REQUIRE([AC_ENABLE_STATIC])dnl
AC_REQUIRE([AC_ENABLE_FAST_INSTALL])dnl
AC_REQUIRE([AC_CANONICAL_HOST])dnl
AC_REQUIRE([AC_CANONICAL_BUILD])dnl
AC_REQUIRE([AC_PROG_RANLIB])dnl
AC_REQUIRE([AC_PROG_CC])dnl
AC_REQUIRE([AC_PROG_LD])dnl
AC_REQUIRE([AC_PROG_NM])dnl
AC_REQUIRE([AC_PROG_LN_S])dnl
dnl

# Check for any special flags to pass to ltconfig.
libtool_flags="--cache-file=$cache_file"
test "$enable_shared" = no && libtool_flags="$libtool_flags --disable-shared"
test "$enable_static" = no && libtool_flags="$libtool_flags --disable-static"
test "$enable_fast_install" = no && libtool_flags="$libtool_flags --disable-fast-install"
test "$ac_cv_prog_gcc" = yes && libtool_flags="$libtool_flags --with-gcc"
test "$ac_cv_prog_gnu_ld" = yes && libtool_flags="$libtool_flags --with-gnu-ld"
ifdef([AC_PROVIDE_AC_LIBTOOL_DLOPEN],
[libtool_flags="$libtool_flags --enable-dlopen"])
ifdef([AC_PROVIDE_AC_LIBTOOL_WIN32_DLL],
[libtool_flags="$libtool_flags --enable-win32-dll"])
AC_ARG_ENABLE(libtool-lock,
  [  --disable-libtool-lock  avoid locking (might break parallel builds)])
test "x$enable_libtool_lock" = xno && libtool_flags="$libtool_flags --disable-lock"
test x"$silent" = xyes && libtool_flags="$libtool_flags --silent"

# Some flags need to be propagated to the compiler or linker for good
# libtool support.
case "$host" in
*-*-irix6*)
  # Find out which ABI we are using.
  echo '[#]line __oline__ "configure"' > conftest.$ac_ext
  if AC_TRY_EVAL(ac_compile); then
    case "`/usr/bin/file conftest.o`" in
    *32-bit*)
      LD="${LD-ld} -32"
      ;;
    *N32*)
      LD="${LD-ld} -n32"
      ;;
    *64-bit*)
      LD="${LD-ld} -64"
      ;;
    esac
  fi
  rm -rf conftest*
  ;;

*-*-sco3.2v5*)
  # On SCO OpenServer 5, we need -belf to get full-featured binaries.
  SAVE_CFLAGS="$CFLAGS"
  CFLAGS="$CFLAGS -belf"
  AC_CACHE_CHECK([whether the C compiler needs -belf], lt_cv_cc_needs_belf,
    [AC_TRY_LINK([],[],[lt_cv_cc_needs_belf=yes],[lt_cv_cc_needs_belf=no])])
  if test x"$lt_cv_cc_needs_belf" != x"yes"; then
    # this is probably gcc 2.8.0, egcs 1.0 or newer; no need for -belf
    CFLAGS="$SAVE_CFLAGS"
  fi
  ;;

ifdef([AC_PROVIDE_AC_LIBTOOL_WIN32_DLL],
[*-*-cygwin* | *-*-mingw*)
  AC_CHECK_TOOL(DLLTOOL, dlltool, false)
  AC_CHECK_TOOL(AS, as, false)
  AC_CHECK_TOOL(OBJDUMP, objdump, false)
  ;;
])
esac
])

# AC_LIBTOOL_DLOPEN - enable checks for dlopen support
AC_DEFUN(AC_LIBTOOL_DLOPEN, [AC_BEFORE([$0],[AC_LIBTOOL_SETUP])])

# AC_LIBTOOL_WIN32_DLL - declare package support for building win32 dll's
AC_DEFUN(AC_LIBTOOL_WIN32_DLL, [AC_BEFORE([$0], [AC_LIBTOOL_SETUP])])

# AC_ENABLE_SHARED - implement the --enable-shared flag
# Usage: AC_ENABLE_SHARED[(DEFAULT)]
#   Where DEFAULT is either `yes' or `no'.  If omitted, it defaults to
#   `yes'.
AC_DEFUN(AC_ENABLE_SHARED, [dnl
define([AC_ENABLE_SHARED_DEFAULT], ifelse($1, no, no, yes))dnl
AC_ARG_ENABLE(shared,
changequote(<<, >>)dnl
<<  --enable-shared[=PKGS]  build shared libraries [default=>>AC_ENABLE_SHARED_DEFAULT],
changequote([, ])dnl
[p=${PACKAGE-default}
case "$enableval" in
yes) enable_shared=yes ;;
no) enable_shared=no ;;
*)
  enable_shared=no
  # Look at the argument we got.  We use all the common list separators.
  IFS="${IFS= 	}"; ac_save_ifs="$IFS"; IFS="${IFS}:,"
  for pkg in $enableval; do
    if test "X$pkg" = "X$p"; then
      enable_shared=yes
    fi
  done
  IFS="$ac_save_ifs"
  ;;
esac],
enable_shared=AC_ENABLE_SHARED_DEFAULT)dnl
])

# AC_DISABLE_SHARED - set the default shared flag to --disable-shared
AC_DEFUN(AC_DISABLE_SHARED, [AC_BEFORE([$0],[AC_LIBTOOL_SETUP])dnl
AC_ENABLE_SHARED(no)])

# AC_ENABLE_STATIC - implement the --enable-static flag
# Usage: AC_ENABLE_STATIC[(DEFAULT)]
#   Where DEFAULT is either `yes' or `no'.  If omitted, it defaults to
#   `yes'.
AC_DEFUN(AC_ENABLE_STATIC, [dnl
define([AC_ENABLE_STATIC_DEFAULT], ifelse($1, no, no, yes))dnl
AC_ARG_ENABLE(static,
changequote(<<, >>)dnl
<<  --enable-static[=PKGS]  build static libraries [default=>>AC_ENABLE_STATIC_DEFAULT],
changequote([, ])dnl
[p=${PACKAGE-default}
case "$enableval" in
yes) enable_static=yes ;;
no) enable_static=no ;;
*)
  enable_static=no
  # Look at the argument we got.  We use all the common list separators.
  IFS="${IFS= 	}"; ac_save_ifs="$IFS"; IFS="${IFS}:,"
  for pkg in $enableval; do
    if test "X$pkg" = "X$p"; then
      enable_static=yes
    fi
  done
  IFS="$ac_save_ifs"
  ;;
esac],
enable_static=AC_ENABLE_STATIC_DEFAULT)dnl
])

# AC_DISABLE_STATIC - set the default static flag to --disable-static
AC_DEFUN(AC_DISABLE_STATIC, [AC_BEFORE([$0],[AC_LIBTOOL_SETUP])dnl
AC_ENABLE_STATIC(no)])


# AC_ENABLE_FAST_INSTALL - implement the --enable-fast-install flag
# Usage: AC_ENABLE_FAST_INSTALL[(DEFAULT)]
#   Where DEFAULT is either `yes' or `no'.  If omitted, it defaults to
#   `yes'.
AC_DEFUN(AC_ENABLE_FAST_INSTALL, [dnl
define([AC_ENABLE_FAST_INSTALL_DEFAULT], ifelse($1, no, no, yes))dnl
AC_ARG_ENABLE(fast-install,
changequote(<<, >>)dnl
<<  --enable-fast-install[=PKGS]  optimize for fast installation [default=>>AC_ENABLE_FAST_INSTALL_DEFAULT],
changequote([, ])dnl
[p=${PACKAGE-default}
case "$enableval" in
yes) enable_fast_install=yes ;;
no) enable_fast_install=no ;;
*)
  enable_fast_install=no
  # Look at the argument we got.  We use all the common list separators.
  IFS="${IFS= 	}"; ac_save_ifs="$IFS"; IFS="${IFS}:,"
  for pkg in $enableval; do
    if test "X$pkg" = "X$p"; then
      enable_fast_install=yes
    fi
  done
  IFS="$ac_save_ifs"
  ;;
esac],
enable_fast_install=AC_ENABLE_FAST_INSTALL_DEFAULT)dnl
])

# AC_ENABLE_FAST_INSTALL - set the default to --disable-fast-install
AC_DEFUN(AC_DISABLE_FAST_INSTALL, [AC_BEFORE([$0],[AC_LIBTOOL_SETUP])dnl
AC_ENABLE_FAST_INSTALL(no)])

# AC_PROG_LD - find the path to the GNU or non-GNU linker
AC_DEFUN(AC_PROG_LD,
[AC_ARG_WITH(gnu-ld,
[  --with-gnu-ld           assume the C compiler uses GNU ld [default=no]],
test "$withval" = no || with_gnu_ld=yes, with_gnu_ld=no)
AC_REQUIRE([AC_PROG_CC])dnl
AC_REQUIRE([AC_CANONICAL_HOST])dnl
AC_REQUIRE([AC_CANONICAL_BUILD])dnl
ac_prog=ld
if test "$ac_cv_prog_gcc" = yes; then
  # Check if gcc -print-prog-name=ld gives a path.
  AC_MSG_CHECKING([for ld used by GCC])
  ac_prog=`($CC -print-prog-name=ld) 2>&5`
  case "$ac_prog" in
    # Accept absolute paths.
changequote(,)dnl
    [\\/]* | [A-Za-z]:[\\/]*)
      re_direlt='/[^/][^/]*/\.\./'
changequote([,])dnl
      # Canonicalize the path of ld
      ac_prog=`echo $ac_prog| sed 's%\\\\%/%g'`
      while echo $ac_prog | grep "$re_direlt" > /dev/null 2>&1; do
	ac_prog=`echo $ac_prog| sed "s%$re_direlt%/%"`
      done
      test -z "$LD" && LD="$ac_prog"
      ;;
  "")
    # If it fails, then pretend we aren't using GCC.
    ac_prog=ld
    ;;
  *)
    # If it is relative, then search for the first ld in PATH.
    with_gnu_ld=unknown
    ;;
  esac
elif test "$with_gnu_ld" = yes; then
  AC_MSG_CHECKING([for GNU ld])
else
  AC_MSG_CHECKING([for non-GNU ld])
fi
AC_CACHE_VAL(ac_cv_path_LD,
[if test -z "$LD"; then
  IFS="${IFS= 	}"; ac_save_ifs="$IFS"; IFS="${IFS}${PATH_SEPARATOR-:}"
  for ac_dir in $PATH; do
    test -z "$ac_dir" && ac_dir=.
    if test -f "$ac_dir/$ac_prog" || test -f "$ac_dir/$ac_prog$ac_exeext"; then
      ac_cv_path_LD="$ac_dir/$ac_prog"
      # Check to see if the program is GNU ld.  I'd rather use --version,
      # but apparently some GNU ld's only accept -v.
      # Break only if it was the GNU/non-GNU ld that we prefer.
      if "$ac_cv_path_LD" -v 2>&1 < /dev/null | egrep '(GNU|with BFD)' > /dev/null; then
	test "$with_gnu_ld" != no && break
      else
	test "$with_gnu_ld" != yes && break
      fi
    fi
  done
  IFS="$ac_save_ifs"
else
  ac_cv_path_LD="$LD" # Let the user override the test with a path.
fi])
LD="$ac_cv_path_LD"
if test -n "$LD"; then
  AC_MSG_RESULT($LD)
else
  AC_MSG_RESULT(no)
fi
test -z "$LD" && AC_MSG_ERROR([no acceptable ld found in \$PATH])
AC_SUBST(LD)
AC_PROG_LD_GNU
])

AC_DEFUN(AC_PROG_LD_GNU,
[AC_CACHE_CHECK([if the linker ($LD) is GNU ld], ac_cv_prog_gnu_ld,
[# I'd rather use --version here, but apparently some GNU ld's only accept -v.
if $LD -v 2>&1 </dev/null | egrep '(GNU|with BFD)' 1>&5; then
  ac_cv_prog_gnu_ld=yes
else
  ac_cv_prog_gnu_ld=no
fi])
])

# AC_PROG_NM - find the path to a BSD-compatible name lister
AC_DEFUN(AC_PROG_NM,
[AC_MSG_CHECKING([for BSD-compatible nm])
AC_CACHE_VAL(ac_cv_path_NM,
[if test -n "$NM"; then
  # Let the user override the test.
  ac_cv_path_NM="$NM"
else
  IFS="${IFS= 	}"; ac_save_ifs="$IFS"; IFS="${IFS}${PATH_SEPARATOR-:}"
  for ac_dir in $PATH /usr/ccs/bin /usr/ucb /bin; do
    test -z "$ac_dir" && ac_dir=.
    if test -f $ac_dir/nm || test -f $ac_dir/nm$ac_exeext ; then
      # Check to see if the nm accepts a BSD-compat flag.
      # Adding the `sed 1q' prevents false positives on HP-UX, which says:
      #   nm: unknown option "B" ignored
      if ($ac_dir/nm -B /dev/null 2>&1 | sed '1q'; exit 0) | egrep /dev/null >/dev/null; then
	ac_cv_path_NM="$ac_dir/nm -B"
	break
      elif ($ac_dir/nm -p /dev/null 2>&1 | sed '1q'; exit 0) | egrep /dev/null >/dev/null; then
	ac_cv_path_NM="$ac_dir/nm -p"
	break
      else
	ac_cv_path_NM=${ac_cv_path_NM="$ac_dir/nm"} # keep the first match, but
	continue # so that we can try to find one that supports BSD flags
      fi
    fi
  done
  IFS="$ac_save_ifs"
  test -z "$ac_cv_path_NM" && ac_cv_path_NM=nm
fi])
NM="$ac_cv_path_NM"
AC_MSG_RESULT([$NM])
AC_SUBST(NM)
])

# AC_CHECK_LIBM - check for math library
AC_DEFUN(AC_CHECK_LIBM,
[AC_REQUIRE([AC_CANONICAL_HOST])dnl
LIBM=
case "$host" in
*-*-beos* | *-*-cygwin*)
  # These system don't have libm
  ;;
*-ncr-sysv4.3*)
  AC_CHECK_LIB(mw, _mwvalidcheckl, LIBM="-lmw")
  AC_CHECK_LIB(m, main, LIBM="$LIBM -lm")
  ;;
*)
  AC_CHECK_LIB(m, main, LIBM="-lm")
  ;;
esac
])

# AC_LIBLTDL_CONVENIENCE[(dir)] - sets LIBLTDL to the link flags for
# the libltdl convenience library, adds --enable-ltdl-convenience to
# the configure arguments.  Note that LIBLTDL is not AC_SUBSTed, nor
# is AC_CONFIG_SUBDIRS called.  If DIR is not provided, it is assumed
# to be `${top_builddir}/libltdl'.  Make sure you start DIR with
# '${top_builddir}/' (note the single quotes!) if your package is not
# flat, and, if you're not using automake, define top_builddir as
# appropriate in the Makefiles.
AC_DEFUN(AC_LIBLTDL_CONVENIENCE, [AC_BEFORE([$0],[AC_LIBTOOL_SETUP])dnl
  case "$enable_ltdl_convenience" in
  no) AC_MSG_ERROR([this package needs a convenience libltdl]) ;;
  "") enable_ltdl_convenience=yes
      ac_configure_args="$ac_configure_args --enable-ltdl-convenience" ;;
  esac
  LIBLTDL=ifelse($#,1,$1,['${top_builddir}/libltdl'])/libltdlc.la
  INCLTDL=ifelse($#,1,-I$1,['-I${top_builddir}/libltdl'])
])

# AC_LIBLTDL_INSTALLABLE[(dir)] - sets LIBLTDL to the link flags for
# the libltdl installable library, and adds --enable-ltdl-install to
# the configure arguments.  Note that LIBLTDL is not AC_SUBSTed, nor
# is AC_CONFIG_SUBDIRS called.  If DIR is not provided, it is assumed
# to be `${top_builddir}/libltdl'.  Make sure you start DIR with
# '${top_builddir}/' (note the single quotes!) if your package is not
# flat, and, if you're not using automake, define top_builddir as
# appropriate in the Makefiles.
# In the future, this macro may have to be called after AC_PROG_LIBTOOL.
AC_DEFUN(AC_LIBLTDL_INSTALLABLE, [AC_BEFORE([$0],[AC_LIBTOOL_SETUP])dnl
  AC_CHECK_LIB(ltdl, main,
  [test x"$enable_ltdl_install" != xyes && enable_ltdl_install=no],
  [if test x"$enable_ltdl_install" = xno; then
     AC_MSG_WARN([libltdl not installed, but installation disabled])
   else
     enable_ltdl_install=yes
   fi
  ])
  if test x"$enable_ltdl_install" = x"yes"; then
    ac_configure_args="$ac_configure_args --enable-ltdl-install"
    LIBLTDL=ifelse($#,1,$1,['${top_builddir}/libltdl'])/libltdl.la
    INCLTDL=ifelse($#,1,-I$1,['-I${top_builddir}/libltdl'])
  else
    ac_configure_args="$ac_configure_args --enable-ltdl-install=no"
    LIBLTDL="-lltdl"
    INCLTDL=
  fi
])

dnl old names
AC_DEFUN(AM_PROG_LIBTOOL, [indir([AC_PROG_LIBTOOL])])dnl
AC_DEFUN(AM_ENABLE_SHARED, [indir([AC_ENABLE_SHARED], $@)])dnl
AC_DEFUN(AM_ENABLE_STATIC, [indir([AC_ENABLE_STATIC], $@)])dnl
AC_DEFUN(AM_DISABLE_SHARED, [indir([AC_DISABLE_SHARED], $@)])dnl
AC_DEFUN(AM_DISABLE_STATIC, [indir([AC_DISABLE_STATIC], $@)])dnl
AC_DEFUN(AM_PROG_LD, [indir([AC_PROG_LD])])dnl
AC_DEFUN(AM_PROG_NM, [indir([AC_PROG_NM])])dnl

dnl This is just to silence aclocal about the macro not being used
ifelse([AC_DISABLE_FAST_INSTALL])dnl
