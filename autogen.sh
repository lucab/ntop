#!/bin/sh
#
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
# Run this to generate all the initial makefiles, etc. for ntop
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


# The name of this program.
progname=`echo "$0" | sed 's%^.*/%%'`

# Constants
PACKAGE=ntop
VERSION=2.0


GNU_OR_DIE=1

help="Try \`$progname --help' for more information"

disable_configure="no"

for arg
do
  case "$arg" in
  -h | --help)
    cat <<EOF
Usage: $progname [option]...


This script should help you to configure $PACKAGE

-h, --help             display this message and exit
-v, --version          print version information and exit
-d, --debug            enable verbose shell tracing
-1, --dontrunconfigure generate all files (step 1) but do not run configure (step 2)
-p, --purge            purge all files automatically generated files
                       (not strictly making part of the source package)

EOF
    exit 0
    ;;

  -v | --version)
    echo "$PACKAGE $VERSION"
    exit 0
    ;;

  -d | --debug)
    echo "$progname: enabling shell trace mode"
    set -x
    ;;

  -1 | --dontrunconfigure)
    disable_configure="yes"
    ;;

  esac
done

if test "$GNU_OR_DIE" -eq 0; then
  exit 1
fi

if [ -f /usr/bin/glibtool ]; then
(glibtool --version) < /dev/null > /dev/null 2>&1 ||
{
  echo
  echo "You must have glibtool installed to compile $PACKAGE."
  echo "Download the appropriate package for your distribution, or get the"
  echo "source tarball at ftp://ftp.gnu.org/gnu/libtool/"
  GNU_OR_DIE=0
}
else
(libtool --version) < /dev/null > /dev/null 2>&1 ||
{
  echo
  echo "You must have libtool installed to compile $PACKAGE."
  echo "Download the appropriate package for your distribution, or get the"
  echo "source tarball at ftp://ftp.gnu.org/gnu/libtool/"
  GNU_OR_DIE=0
}
fi

(automake --version) < /dev/null > /dev/null 2>&1 ||
{
  echo
  echo "You must have automake installed to compile $PACKAGE."
  echo "Download the appropriate package for your distribution, or get the"
  echo "source tarball at ftp://ftp.gnu.org/gnu/automake/"
  GNU_OR_DIE=0
}

(m4 --version) < /dev/null > /dev/null 2>&1 ||
{
  echo
  echo "You must have GNU m4 installed to compile $PACKAGE."
  echo "Download the appropriate package for your distribution, or get the"
  echo "source tarball at ftp://ftp.gnu.org/gnu/m4/"
  GNU_OR_DIE=0
}

(autoconf --version) < /dev/null > /dev/null 2>&1 ||
{
  echo
  echo "You must have autoconf installed to compile $PACKAGE."
  echo "Download the appropriate package for your distribution, or get the"
  echo "source tarball at ftp://ftp.gnu.org/gnu/autoconf/"
  GNU_OR_DIE=0
}


if test "$GNU_OR_DIE" -eq 0; then
  exit 1
fi


if [ $# != 0 ]
  then
     case $1 in
        -p | --purge)
          shift

          # make -k clean

          # cleanup from previous run and exit

          echo "cleaning generated files from the file system..."

          rm -f *~
          rm -rf .deps .libs

          rm -f libtool.m4.in
          rm -f config.guess
          rm -f config.sub
          rm -f install-sh
          rm -f ltconfig
          rm -f ltmain.sh
          rm -f missing
          rm -f mkinstalldirs
          rm -f INSTALL
          rm -f COPYING

          rm -f acinclude.m4
          rm -f aclocal.m4
          rm -f config.h.in
          rm -f stamp-h.in
          rm -f Makefile.in

          rm -f configure
          rm -f config.h
          rm -f ntop-config
          rm -f stamp.h
          rm -f libtool
          rm -f Makefile
          rm -f stamp-h.in
          rm -f stamp-h

          rm -f config.cache
          rm -f config.status
          rm -f config.log

          rm -f Makefile
          rm -f Makefile.in

          rm -f version.c

          rm -f plugins/Makefile
          rm -f plugins/Makefile.in

          rm -f intop/Makefile
          rm -f intop/Makefile.in

          exit 1
        ;;

#
# all the other options are passed to the configure script
#
#        -*)
#          echo "$progname: unrecognized option \`$arg'" 1>&2
#          echo "$help" 1>&2
#          exit 1
#        ;;
#
#        *)
#          echo "$progname: too many arguments" 1>&2
#          echo "$help" 1>&2
#          exit 1
#        ;;
esac
fi

cat MANIFESTO

echo
echo "Generating configuration files for ntop, please wait...."

# remove this file to avoid history
rm -f config.status
rm -f config.cache
rm -f config.log

#
# 0. prepare the package to use libtool
#

if [ -f /usr/bin/glibtoolize ]; then
glibtoolize --copy --force
else
libtoolize --copy --force
fi

if [ ! -f libtool.m4.in ]; then
  if [ -f /usr/share/aclocal/libtool.m4 ]; then
    cp /usr/share/aclocal/libtool.m4 libtool.m4.in
  else
    cp /usr/local/share/aclocal/libtool.m4 libtool.m4.in
  fi
  echo "0. libtool.m4.in ... done"
fi


#
# 1. create local definitions for automake
#
cat acinclude.m4.in libtool.m4.in > acinclude.m4
echo "1. acinclude.m4 .... done"


#
# 2.
# run 'aclocal' to create aclocal.m4 from configure.in (optionally acinclude.m4)
#
aclocal $ACLOCAL_FLAGS
echo "2. aclocal.m4 ...... done"

#
# 3.
# run 'autoheader' to create config.h.in from configure.in (optionally acconfig.h)
#
autoheader
echo "3. config.h.in ..... done"

echo "timestamp" > stamp-h.in

#
# 4.
# run 'automake' to create Makefile.in from configure.in and Makefile.am
# (optionally aclocal.m4)
# the generated Makefile.in is compliant to GNU Makefile standard
#
automake --add-missing --gnu
echo "4. Makefile.in ..... done"

#
# 5.
# run 'autoconf' to create configure from configure.in
#
autoconf
echo "5. configure ....... done"
echo ""

if test ".$disable_configure" = ".no"; then
#
# 6.
# run './configure' for real fun!
#
  if [ -x config.status -a -z "$*" ]; then
    ./config.status --recheck
  else
    echo "I am going to run configure with no arguments."
    echo "If you wish to pass any to it,"
    echo "please specify them on the command line."
    echo ""
    echo ""
    ./configure "$@" || exit 1
    echo ""

#
# 7. Have fun
#
    echo "Now, just type 'make' or 'gmake' (on *BSD systems) to compile $PACKAGE"
    echo ""
    echo "Have fun now!"
    echo ""

#
# cleanup to handle programs garbage
#
    rm -f /tmp/acin* /tmp/acout*
    rm -f autoha*
    rm -f confdefs.h
  fi
fi


# Local Variables:
# mode:shell-script
# sh-indentation:2
# End:
