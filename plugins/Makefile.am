#
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
# auto makefile for the ntop plugins.
# (this file is processed with 'automake' to produce Makefile.in)
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
#
# Luca Deri     <deri@ntop.org>
# Rocco Carbone <rocco@ntop.org>
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

SUBDIRS = . # pep

PLUGIN_DIST_COMMON = Makefile.am Makefile.in
CLEANFILES  =
EXTRA_DIST  =

SUFFIXES    = .so

# 
# Where to install the plugin 
# 
plugindir = $(libdir)/ntop/plugins

INCLUDES = -I.. @INCS@ -I../myrrd

#
# The meat for ntop
#
noinst_PROGRAMS = \
                  icmpPlugin.so \
                  lastSeenPlugin.so \
                  netflowPlugin.so \
                  pdaPlugin.so \
                  rrdPlugin.so \
                  snmpPlugin.so \
                  sflowPlugin.so \
                  xmldumpPlugin.so

lib_LTLIBRARIES = \
                  libicmpPlugin.la \
                  liblastSeenPlugin.la \
                  libnetflowPlugin.la \
                  libpdaPlugin.la \
                  librrdPlugin.la \
                  libsnmpPlugin.la \
                  libsflowPlugin.la \
                  libxmldumpPlugin.la

libicmpPlugin_la_SOURCES = icmpPlugin.c
libicmpPlugin_la_LDFLAGS = -shared -release @PACKAGE_VERSION@ @DYN_FLAGS@
libicmpPlugin_la_CFLAGS = $(AM_CFLAGS)

liblastSeenPlugin_la_SOURCES = lastSeenPlugin.c
liblastSeenPlugin_la_LDFLAGS = -shared -release @PACKAGE_VERSION@ @DYN_FLAGS@
liblastSeenPlugin_la_CFLAGS = $(AM_CFLAGS)

libnetflowPlugin_la_SOURCES = netflowPlugin.c
libnetflowPlugin_la_LDFLAGS = -shared -release @PACKAGE_VERSION@ @DYN_FLAGS@
libnetflowPlugin_la_CFLAGS = $(AM_CFLAGS)

libpdaPlugin_la_SOURCES = pdaPlugin.c
libpdaPlugin_la_LDFLAGS = -shared -release @PACKAGE_VERSION@ @DYN_FLAGS@
libpdaPlugin_la_CFLAGS = $(AM_CFLAGS)

librrdPlugin_la_SOURCES = rrdPlugin.c
librrdPlugin_la_LDFLAGS = -shared -release @PACKAGE_VERSION@ @DYN_FLAGS@
librrdPlugin_la_LIBADD = -L../myrrd/ -lmyrrd
librrdPlugin_la_CFLAGS = $(AM_CFLAGS)

libsnmpPlugin_la_SOURCES = snmpPlugin.c
libsnmpPlugin_la_LDFLAGS = -shared -release @PACKAGE_VERSION@ @DYN_FLAGS@
libsnmpPlugin_la_LIBADD = @SNMP_LIBS@
libsnmpPlugin_la_CFLAGS = $(AM_CFLAGS)

libsflowPlugin_la_SOURCES = sflowPlugin.c
libsflowPlugin_la_LDFLAGS = -shared -release @PACKAGE_VERSION@ @DYN_FLAGS@
libsflowPlugin_la_CFLAGS = $(AM_CFLAGS)

libxmldumpPlugin_la_SOURCES = xmldumpPlugin.c
libxmldumpPlugin_la_LDFLAGS = -shared -release @PACKAGE_VERSION@ @DYN_FLAGS@
libxmldumpPlugin_la_CFLAGS = $(AM_CFLAGS)

#
# Dependencies to allow ntop loading plugins on-place
# by default ntop looks for plugins in the plugins/ subdirectory
#


.libs/libicmpPlugin.so@SO_VERSION_PATCH@:
	@if test -f libicmpPlugin_la-icmpPlugin.o; then \
	$(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libicmpPlugin.so@SO_VERSION_PATCH@ libicmpPlugin_la-icmpPlugin.o; \
	else \
	$(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libicmpPlugin.so@SO_VERSION_PATCH@ icmpPlugin.o; \
	fi

icmpPlugin.so$(EXEEXT): .libs/libicmpPlugin.so@SO_VERSION_PATCH@
	@$(LN_S) .libs/libicmpPlugin.so icmpPlugin.so

.libs/liblastSeenPlugin.so@SO_VERSION_PATCH@:
	@if test -f liblastSeenPlugin_la-lastSeenPlugin.o; then \
	$(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/liblastSeenPlugin.so@SO_VERSION_PATCH@ liblastSeenPlugin_la-lastSeenPlugin.o; \
	else \
	$(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/liblastSeenPlugin.so@SO_VERSION_PATCH@ lastSeenPlugin.o; \
	fi

lastSeenPlugin.so$(EXEEXT): .libs/liblastSeenPlugin.so@SO_VERSION_PATCH@
	@$(LN_S) .libs/liblastSeenPlugin.so lastSeenPlugin.so

.libs/libnetflowPlugin.so@SO_VERSION_PATCH@:
	@if test -f libnetflowPlugin_la-netflowPlugin.o; then \
	$(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libnetflowPlugin.so@SO_VERSION_PATCH@ libnetflowPlugin_la-netflowPlugin.o; \
	else \
	$(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libnetflowPlugin.so@SO_VERSION_PATCH@ netflowPlugin.o; \
	fi

netflowPlugin.so$(EXEEXT): .libs/libnetflowPlugin.so@SO_VERSION_PATCH@
	@$(LN_S) .libs/libnetflowPlugin.so netflowPlugin.so

.libs/libpdaPlugin.so@SO_VERSION_PATCH@:
	@if test -f libpdaPlugin_la-pdaPlugin.o; then \
	$(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libpdaPlugin.so@SO_VERSION_PATCH@ libpdaPlugin_la-pdaPlugin.o; \
	else \
	$(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libpdaPlugin.so@SO_VERSION_PATCH@ pdaPlugin.o; \
	fi

pdaPlugin.so$(EXEEXT): .libs/libpdaPlugin.so@SO_VERSION_PATCH@
	@$(LN_S) .libs/libpdaPlugin.so pdaPlugin.so

.libs/librrdPlugin.so@SO_VERSION_PATCH@:
	@if test -f librrdPlugin_la-rrdPlugin.o; then \
	$(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/librrdPlugin.so@SO_VERSION_PATCH@ librrdPlugin_la-rrdPlugin.o; \
	else \
	$(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/librrdPlugin.so@SO_VERSION_PATCH@ rrdPlugin.o; \
	fi

rrdPlugin.so$(EXEEXT): .libs/librrdPlugin.so@SO_VERSION_PATCH@
	@$(LN_S) .libs/librrdPlugin.so rrdPlugin.so

.libs/libsnmpPlugin.so@SO_VERSION_PATCH@:
	@if test -f libsnmpPlugin_la-snmpPlugin.o; then \
	$(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libsnmpPlugin.so@SO_VERSION_PATCH@ libsnmpPlugin_la-snmpPlugin.o; \
	else \
	$(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libsnmpPlugin.so@SO_VERSION_PATCH@ snmpPlugin.o; \
	fi

snmpPlugin.so$(EXEEXT): .libs/libsnmpPlugin.so@SO_VERSION_PATCH@
	@$(LN_S) .libs/libsnmpPlugin.so snmpPlugin.so

.libs/libsflowPlugin.so@SO_VERSION_PATCH@:
	@if test -f libsflowPlugin_la-sflowPlugin.o; then \
	$(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libsflowPlugin.so@SO_VERSION_PATCH@ libsflowPlugin_la-sflowPlugin.o; \
	else \
	$(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libsflowPlugin.so@SO_VERSION_PATCH@ sflowPlugin.o; \
	fi

sflowPlugin.so$(EXEEXT): .libs/libsflowPlugin.so@SO_VERSION_PATCH@
	@$(LN_S) .libs/libsflowPlugin.so sflowPlugin.so

.libs/libxmldumpPlugin.so@SO_VERSION_PATCH@:
	@if test -f libxmldumpPlugin_la-xmldumpPlugin.o; then \
	$(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libxmldumpPlugin.so@SO_VERSION_PATCH@ libxmldumpPlugin_la-xmldumpPlugin.o; \
	else \
	$(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libxmldumpPlugin.so@SO_VERSION_PATCH@ xmldumpPlugin.o; \
	fi

xmldumpPlugin.so$(EXEEXT): .libs/libxmldumpPlugin.so@SO_VERSION_PATCH@
	@$(LN_S) .libs/libxmldumpPlugin.so xmldumpPlugin.so

install-data-local:
	@$(top_srcdir)/mkinstalldirs $(DESTDIR)$(plugindir);
	@for file in $(noinst_PROGRAMS); do \
             cp -p $$file $(DESTDIR)$(plugindir)/$$file; \
         done
# remove installed libraries
	@for file in $(lib_LTLIBRARIES); do \
             rm -f $(DESTDIR)$(libdir)/$$file; \
         done

#
# Special stuff for xml auto-generation of code from the "doc":
#
xmldumpPlugin.$(OBJEXT): xml_g_cmdopt.inc

xmldumpPlugin.c: xml_*.inc globals-structtypes.xml

xml_*.inc: globals-structtypes.xml
	@echo "Processing globals-structtypes.xml to make xml_*.inc..."
	@@AWK@ -f ../utils/xmldump.awk globals-structtypes.xml

.NOTPARALLEL:
