#!/bin/sh

# ntop ./configure census
#   Burton - 2003/04/14
censusfile="\$\$census\$\$"

# This script collects info about the environment and sends it to me...

if test -f $censusfile; then
    rm -f $censusfile
fi

configguess=`./config.guess`
configguessstrip=`./config.guess | awk '{ split(\$0, f, "-"); print f[1] "-" f[3] (f[4] != "" ? "-" f[4] : "") }'`

version=`grep version version.c | head -n1 | awk '{ gsub(/[;"]/, "", $5); print $5 }'`

if test -f config.h; then
  threadconfig=`grep '#define *CFG_MULTITHREADED' config.h | awk '{ print $1 }'`
  if test ".${threadconfig}" = "./*"; then
      threading="ST"
  elif test ".${threadconfig}" = ".#undef"; then
      threading="ST?"
  else
      threading="MT"
  fi
else
  threading="unknown"
fi

os=`./utils/linuxrelease --quiet`

gcc=`gcc --version | head -n1`
gccstrip=`gcc --version  | head -n1 | awk '{ gsub(/ [\(\[][^\(\)\[\]]*[\]\)]/, ""); gsub(/^ *gcc */, ""); print \$0}'`

touch $censusfile
echo "ntop ./configure census report" >>$censusfile
echo "==============================" >>$censusfile
echo ""                               >>$censusfile

echo "${configguessstrip} | ${version} | ${threading} | ${os} | ${gccstrip} " >>$censusfile
echo ""                               >>$censusfile
echo ""                               >>$censusfile

echo "uname"                          >>$censusfile
for i in o r p i m v; do
    echo "    ${i} = " `uname -${i} 2>/dev/null`  >>$censusfile
done
echo ""                               >>$censusfile

echo "config.guess  : ${configguess}" >>$censusfile
echo ""                               >>$censusfile
echo -n "gcc --version : ${gcc}"      >>$censusfile
echo ""                               >>$censusfile
echo -n "make --version     : "       >>$censusfile
make --version | head -n1 2> /dev/null >>$censusfile
echo -n "gmake --version    : "       >>$censusfile
gmake --version 2> /dev/null | head -n1 >>$censusfile
echo ""                               >>$censusfile
echo -n "autoconf --version : "       >>$censusfile
autoconf --version 2> /dev/null | head -n1 >>$censusfile
echo ""                               >>$censusfile
echo -n "automake --version : "       >>$censusfile
automake --version 2> /dev/null | head -n1 >>$censusfile
echo ""                               >>$censusfile
echo -n "libtool --version  : "       >>$censusfile
libtool --version 2> /dev/null | head -n1  >>$censusfile
echo ""                               >>$censusfile

if test -f version.c; then
    echo ""                           >>$censusfile
    echo "version.c"                  >>$censusfile
    echo "---------"                  >>$censusfile
    cat version.c                     >>$censusfile
fi

echo ""
echo ""

if test ".$1" = ".fail"; then
    echo " The census information is in $censusfile."
    echo ""
    echo " Please update it with information about the problem(s) you are having"
    echo " (especially cut and paste any error messages plus 10-15 lines before them"
    echo " and email it to census@ntopsupport.com"
    echo ""
    echo " Thank you for providing the information!"
    echo ""

else
    echo " Sending this:"
    echo ""
    cat $censusfile
    echo ""
    echo " As the ntop ./configure census report."
    echo " The census information is in $censusfile."
    echo ""
    echo " Abort in the next 10 seconds if you don't want it sent..."
    echo ""
    echo ""

    sleep 10

    cat $censusfile | mail -s "ntop_census_report-$1-`uname -s`" census@ntopsupport.com

    echo " ntop ./configure census was sent!  Thank you for providing the information!"
    echo ""

fi
