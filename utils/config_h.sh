#!/bin/sh
echo "Creating new-config and new-globals-defines for webInterface.c"
if test -r new-config; then
    rm -f new-config
fi

if test -r new-globals-define; then
    rm -f new-globals-define
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
  awk -f utils/config_h2.awk globals-defines.h >new-globals-define

if test -r stoplist; then
    rm -f stoplist
fi

echo "Done!  Drop new-config in and edit new-globals-define"

