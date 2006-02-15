#!/bin/sh

#
# Author Christer Holgersson <ada@riksnet.se>
#

for AS in 1221 4637; do
  tmp=/tmp/AS-list-$AS
  wget -O $tmp -N http://bgp.potaroo.net/as$AS/bgp-table-asorigin.txt
  cat $tmp | \
    grep -v Withdrawn | \
    cut -d+ -f-1 | \
    awk 'NF > 1 { print $NF":"$1 }' | \
    sed 's/[{}]//g' | sed 's/^[^:]+,//' \
  > $tmp.txt
  gzip $tmp.txt
done 
