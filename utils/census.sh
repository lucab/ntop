#!/bin/sh

# ntop ./configure census
#   Burton - 2002/10/21
censusfile="\$\$census\$\$"

# This script collects info about the environment and sends it to me...

if test -f $censusfile; then
    rm -f $censusfile
fi

touch $censusfile
echo "ntop ./configure census report" >>$censusfile
echo "==============================" >>$censusfile
echo ""                               >>$censusfile
echo "uname -a (blinded): "           >>$censusfile
echo ""                               >>$censusfile
uname -a | sed 's/\.[[:alnum:]]*\.[[:alnum:]]*[[:space:]]/\.suppressed /g' >> $censusfile
echo ""                               >>$censusfile
echo -n "autoconf --version : "       >>$censusfile
autoconf --version | head -n1         >>$censusfile
echo ""                               >>$censusfile
echo -n "automake --version : "       >>$censusfile
automake --version | head -n1         >>$censusfile
echo ""                               >>$censusfile
echo -n "libtool --version  : "       >>$censusfile
libtool --version | head -n1          >>$censusfile
echo ""                               >>$censusfile
echo -n "make --version     : "       >>$censusfile
make --version | head -n1             >>$censusfile
echo -n "gmake --version    : "       >>$censusfile
gmake --version | head -n1            >>$censusfile
echo ""                               >>$censusfile

if test -f version.c; then
    echo ""                           >>$censusfile
    echo "version.c"                  >>$censusfile
    echo "---------"                  >>$censusfile
    cat version.c                     >>$censusfile
fi

echo ""
echo ""

if ".$1" = ".fail"; then
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
    echo ""
    echo " Abort in the next 10 seconds if you don't want it sent..."
    echo ""
    echo ""

    sleep 10

    if test ".$1" = "."; then
        tail=
    else
        tail="-$1-"`uname -s`
    fi
    cat $censusfile | mail -s ntop_census_report-$tail census@ntopsupport.com

    echo " ntop ./configure census was sent!  Thank you for providing the information!"
    echo ""

fi
