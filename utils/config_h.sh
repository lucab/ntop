#!/bin/sh

# 
#  -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
#                           http://www.ntop.org
# 
#  Copyright (C) 2003-2004 Burton Strauss <Burton@ntopSupport.com>
# 
#  -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
# 
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
# 
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
# 
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
# 

echo "Creating new-config, new-globals-defines new-globals-report for webInterface.c"

if test -r new-config; then
    rm -f new-config
fi

if test -r new-globals-defines; then
    rm -f new-globals-defines
fi

if test -r new-globals-report; then
    rm -f new-globals-report
fi

if test -r stoplist; then
    rm -f stoplist
fi

if test -r configlist; then
    rm -f configlist
fi

awk -f utils/config_h1.awk config.h.in | \
  sort | \
  uniq > configlist

cat configlist | \
awk -f utils/config_h2.awk config.h.in >new-config

mv configlist stoplist

awk -f utils/config_h1.awk globals-defines.h | \
  sort | \
  uniq | \
  awk -f utils/config_h2.awk globals-defines.h >new-globals-defines

awk -f utils/config_h1.awk globals-report.h | \
  sort | \
  uniq | \
  awk -f utils/config_h2.awk globals-report.h >new-globals-report

if test -r stoplist; then
    rm -f stoplist
fi

echo "Done!  Drop in new-config, new-globals-defines and new-globals-report"

