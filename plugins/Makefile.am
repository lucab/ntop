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

INCLUDES = -I.. @INCS@ ${RRD_INC}

#
# The meat for ntop
#
noinst_PROGRAMS = \
                  icmpPlugin.so \
                  netflowPlugin.so \
                  cpacketPlugin.so \
                  rrdPlugin.so \
                  sflowPlugin.so

lib_LTLIBRARIES = \
                  libicmpPlugin.la \
                  libnetflowPlugin.la \
                  libcpacketPlugin.la \
                  librrdPlugin.la \
                  libsflowPlugin.la

libicmpPlugin_la_SOURCES = icmpPlugin.c
libicmpPlugin_la_LDFLAGS = -shared -release @PACKAGE_VERSION@ @DYN_FLAGS@
libicmpPlugin_la_CFLAGS = $(AM_CFLAGS)

libnetflowPlugin_la_SOURCES = netflowPlugin.c
libnetflowPlugin_la_LDFLAGS = -shared -release @PACKAGE_VERSION@ @DYN_FLAGS@
libnetflowPlugin_la_CFLAGS = $(AM_CFLAGS)

libcpacketPlugin_la_SOURCES = cpacketPlugin.c
libcpacketPlugin_la_LDFLAGS = -shared -release @PACKAGE_VERSION@ @DYN_FLAGS@
libcpacketPlugin_la_CFLAGS = $(AM_CFLAGS)

librrdPlugin_la_SOURCES = rrdPlugin.c
librrdPlugin_la_LDFLAGS = -shared -release @PACKAGE_VERSION@ @DYN_FLAGS@
librrdPlugin_la_LIBADD = ${RRD_LIB}
librrdPlugin_la_CFLAGS = $(AM_CFLAGS)

libsflowPlugin_la_SOURCES = sflowPlugin.c
libsflowPlugin_la_LDFLAGS = -shared -release @PACKAGE_VERSION@ @DYN_FLAGS@
libsflowPlugin_la_CFLAGS = $(AM_CFLAGS)

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

###############

.libs/libnetflowPlugin.so@SO_VERSION_PATCH@:
	@if test -f libnetflowPlugin_la-netflowPlugin.o; then \
	$(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libnetflowPlugin.so@SO_VERSION_PATCH@ libnetflowPlugin_la-netflowPlugin.o; \
	else \
	$(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libnetflowPlugin.so@SO_VERSION_PATCH@ netflowPlugin.o; \
	fi

netflowPlugin.so$(EXEEXT): .libs/libnetflowPlugin.so@SO_VERSION_PATCH@
	@$(LN_S) .libs/libnetflowPlugin.so netflowPlugin.so

###############

.libs/libcpacketPlugin.so@SO_VERSION_PATCH@:
	@if test -f libcpacketPlugin_la-cpacketPlugin.o; then \
	$(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libcpacketPlugin.so@SO_VERSION_PATCH@ libcpacketPlugin_la-cpacketPlugin.o; \
	else \
	$(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libcpacketPlugin.so@SO_VERSION_PATCH@ cpacketPlugin.o; \
	fi

cpacketPlugin.so$(EXEEXT): .libs/libcpacketPlugin.so@SO_VERSION_PATCH@
	@$(LN_S) .libs/libcpacketPlugin.so cpacketPlugin.so

###############

.libs/librrdPlugin.so@SO_VERSION_PATCH@:
	@if test -f librrdPlugin_la-rrdPlugin.o; then \
	$(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/librrdPlugin.so@SO_VERSION_PATCH@ librrdPlugin_la-rrdPlugin.o; \
	else \
	$(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/librrdPlugin.so@SO_VERSION_PATCH@ rrdPlugin.o; \
	fi

rrdPlugin.so$(EXEEXT): .libs/librrdPlugin.so@SO_VERSION_PATCH@
	@$(LN_S) .libs/librrdPlugin.so rrdPlugin.so

###############

.libs/libsflowPlugin.so@SO_VERSION_PATCH@:
	@if test -f libsflowPlugin_la-sflowPlugin.o; then \
	$(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libsflowPlugin.so@SO_VERSION_PATCH@ libsflowPlugin_la-sflowPlugin.o; \
	else \
	$(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libsflowPlugin.so@SO_VERSION_PATCH@ sflowPlugin.o; \
	fi

sflowPlugin.so$(EXEEXT): .libs/libsflowPlugin.so@SO_VERSION_PATCH@
	@$(LN_S) .libs/libsflowPlugin.so sflowPlugin.so

###############

.libs/libxmldumpPlugin.so@SO_VERSION_PATCH@:
	@if test -f libxmldumpPlugin_la-xmldumpPlugin.o; then \
	$(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libxmldumpPlugin.so@SO_VERSION_PATCH@ libxmldumpPlugin_la-xmldumpPlugin.o; \
	else \
	$(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libxmldumpPlugin.so@SO_VERSION_PATCH@ xmldumpPlugin.o; \
	fi

xmldumpPlugin.so$(EXEEXT): .libs/libxmldumpPlugin.so@SO_VERSION_PATCH@
	@$(LN_S) .libs/libxmldumpPlugin.so xmldumpPlugin.so

###############

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
xmldumpPlugin.$(OBJEXT): xml_g_intf.inc

xmldumpPlugin.c: xml_*.inc globals-structtypes.xml

xml_*.inc: globals-structtypes.xml
	@echo "Processing globals-structtypes.xml to make xml_*.inc..."
	@@AWK@ -f ../utils/xmldump.awk globals-structtypes.xml

.NOTPARALLEL:
