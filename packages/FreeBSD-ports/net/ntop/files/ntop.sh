#!/bin/sh

#----------------------------------------------------------------------
# The following variables may be changed
#   Most stuff should be changed in ntop.conf
#

# Network interface(s) to be monitored;
# may be blank, or comma-separated list
interfaces=''

# Specify any additional arguments here - see ntop(8)
additional_args=''

#
# End of user-configurable variables
#----------------------------------------------------------------------

args='-d -L'

[ ! -z $interfaces ] && args="$args -i $interfaces"
[ ! -z "$additional_args" ] && args="$args $additional_args"

case "$1" in
start)
  [ -x %%PREFIX%%/bin/ntop ] && %%PREFIX%%/bin/ntop @%%PREFIX%%/etc/ntop/ntop.conf $args >/dev/null 2>&1 \
    && echo -n ' ntop'
  ;;
stop)
  killall ntop >/dev/null 2>&1 && echo -n ' ntop'
  ;;
*)
  echo "Usage: `basename $0` {start|stop}" >&2
  exit 64
  ;;
esac

exit 0

