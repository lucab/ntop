#!/bin/sh

# Check for artifacts (files) from old rrd model, warn if found

if ! test -d ${1}/ntop/rrd; then
    exit 0
fi

rc=`ls -l ${1}/ntop/rrd/interfaces/*/hosts/ |
  grep ^d |
  awk '{ print $NF}' |
  grep '[0-9]\.[0-9]' |
  wc -l`

if test ${rc} != 0; then
  echo ""
  echo "************************************************************"
  echo "************************************************************"
  echo "************************************************************"
  echo "************************************************************"
  echo "************************************************************"
  echo ""
  echo "WARNING:"
  echo ""
  echo "You may have existing RRD databases using the so-called"
  echo "'small' model, that is single level directories, such as"
  echo "...ntop/rrd/interfaces/eth0/192.168.42.1/..."
  echo ""
  echo "ntop 3.0 implements ONLY the 'large' model, (which was an"
  echo "option on the rrdPlugin parameter page in 2.2), where each"
  echo "octet is a separate directory level, e.g."
  echo "...ntop/rrd/interfaces/eth0/192/168/42/1/..."
  echo ""
  echo ""
  echo "***  If you do not fix your directories before running   ***"
  echo "***     ntop 3.0, you WILL lose your historical data     ***"
  echo ""
  echo ""
  echo "************************************************************"
  echo "************************************************************"
  echo "************************************************************"
  echo "************************************************************"
  echo "************************************************************"
  echo ""
fi
