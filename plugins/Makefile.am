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

SUBDIRS = . pep

PLUGIN_DIST_COMMON = Makefile.am Makefile.in
CLEANFILES  =
EXTRA_DIST  =

SUFFIXES    = .so

# 
# Where to install the plugin 
# 
plugindir = $(libdir)/ntop/plugins

INCLUDES = -I.. @INCS@

#
# The meat for ntop
#
noinst_PROGRAMS = icmpPlugin.so lastSeenPlugin.so \
                  netflowPlugin.so nfsPlugin.so  \
                  pdaPlugin.so  \
		  sflowPlugin.so rrdPlugin.so
#		  rmonPlugin.so

lib_LTLIBRARIES = libicmpPlugin.la liblastSeenPlugin.la \
                  libnetflowPlugin.la  libnfsPlugin.la  \
                  libpdaPlugin.la  \
		  libsflowPlugin.la librrdPlugin.la
#		  librmonPlugin.la

libicmpPlugin_la_SOURCES = icmpPlugin.c
libicmpPlugin_la_LDFLAGS = -shared -release @PACKAGE_VERSION@ @DYN_FLAGS@

librrdPlugin_la_SOURCES = rrdPlugin.c
librrdPlugin_la_LDFLAGS = -shared -release @PACKAGE_VERSION@ @DYN_FLAGS@ $(RRDLIB)

libpdaPlugin_la_SOURCES = pdaPlugin.c
libpdaPlugin_la_LDFLAGS = -shared -release @PACKAGE_VERSION@ @DYN_FLAGS@

libsflowPlugin_la_SOURCES = sflowPlugin.c
libsflowPlugin_la_LDFLAGS = -shared -release @PACKAGE_VERSION@ @DYN_FLAGS@

liblastSeenPlugin_la_SOURCES = lastSeenPlugin.c
liblastSeenPlugin_la_LDFLAGS = -shared -release @PACKAGE_VERSION@ @DYN_FLAGS@

libnetflowPlugin_la_SOURCES = netflowPlugin.c
libnetflowPlugin_la_LDFLAGS = -shared -release @PACKAGE_VERSION@ @DYN_FLAGS@

libnfsPlugin_la_SOURCES = nfsPlugin.c
libnfsPlugin_la_LDFLAGS = -shared -release @PACKAGE_VERSION@ @DYN_FLAGS@

#librmonPlugin_la_SOURCES = rmonPlugin.c rmon.h
#librmonPlugin_la_LDFLAGS = @SNMPLIBS@ -shared -release @PACKAGE_VERSION@ @DYN_FLAGS@


#
# Dependencies to allow ntop loading plugins on-place
# by default ntop looks for plugins in the plugins/ subdirectory
#


.libs/libicmpPlugin.so@SO_VERSION_PATCH@:
	$(CC) -bundle -flat_namespace -undefined suppress -o .libs/libicmpPlugin.so@SO_VERSION_PATCH@ icmpPlugin.o

icmpPlugin.so$(EXEEXT): .libs/libicmpPlugin.so@SO_VERSION_PATCH@
	@$(LN_S) .libs/libicmpPlugin.so icmpPlugin.so

.libs/librrdPlugin.so@SO_VERSION_PATCH@:
	$(CC) -bundle -flat_namespace -undefined suppress -o .libs/librrdPlugin.so@SO_VERSION_PATCH@ rrdPlugin.o

rrdPlugin.so$(EXEEXT): .libs/librrdPlugin.so@SO_VERSION_PATCH@
	@$(LN_S) .libs/librrdPlugin.so rrdPlugin.so

.libs/libpdaPlugin.so@SO_VERSION_PATCH@:
	$(CC) -bundle -flat_namespace -undefined suppress -o .libs/libpdaPlugin.so@SO_VERSION_PATCH@ pdaPlugin.o

pdaPlugin.so$(EXEEXT): .libs/libpdaPlugin.so@SO_VERSION_PATCH@
	@$(LN_S) .libs/libpdaPlugin.so pdaPlugin.so

.libs/libsflowPlugin.so@SO_VERSION_PATCH@:
	$(CC) -bundle -flat_namespace -undefined suppress -o .libs/libsflowPlugin.so@SO_VERSION_PATCH@ sflowPlugin.o

sflowPlugin.so$(EXEEXT): .libs/libsflowPlugin.so@SO_VERSION_PATCH@
	@$(LN_S) .libs/libsflowPlugin.so sflowPlugin.so

.libs/liblastSeenPlugin.so@SO_VERSION_PATCH@:
	$(CC) -bundle -flat_namespace -undefined suppress -o .libs/liblastSeenPlugin.so@SO_VERSION_PATCH@ lastSeenPlugin.o

lastSeenPlugin.so$(EXEEXT): .libs/liblastSeenPlugin.so@SO_VERSION_PATCH@
	@$(LN_S) .libs/liblastSeenPlugin.so lastSeenPlugin.so

.libs/libnfsPlugin.so@SO_VERSION_PATCH@:
	$(CC) -bundle -flat_namespace -undefined suppress -o .libs/libnfsPlugin.so@SO_VERSION_PATCH@ nfsPlugin.o

netflowPlugin.so$(EXEEXT): .libs/libnetflowPlugin.so@SO_VERSION_PATCH@
	@$(LN_S) .libs/libnetflowPlugin.so netflowPlugin.so

.libs/libnetflowPlugin.so@SO_VERSION_PATCH@:
	$(CC) -bundle -flat_namespace -undefined suppress -o .libs/libnetflowPlugin.so@SO_VERSION_PATCH@ netflowPlugin.o

nfsPlugin.so$(EXEEXT): .libs/libnfsPlugin.so@SO_VERSION_PATCH@
	@$(LN_S) .libs/libnfsPlugin.so nfsPlugin.so

#.libs/librmonPlugin.so@SO_VERSION_PATCH@:
#	$(CC) -bundle -flat_namespace -undefined suppress -o .libs/librmonPlugin.so@SO_VERSION_PATCH@ rmonPlugin.o

#rmonPlugin.so$(EXEEXT): .libs/librmonPlugin.so@SO_VERSION_PATCH@
#	@$(LN_S) .libs/librmonPlugin.so rmonPlugin.so

install-data-local:
	@$(top_srcdir)/mkinstalldirs $(DESTDIR)$(plugindir);
	@for file in $(noinst_PROGRAMS); do \
             cp -p $$file $(DESTDIR)$(plugindir)/$$file; \
         done
# remove installed libraries
	@for file in $(lib_LTLIBRARIES); do \
             rm -f $(DESTDIR)$(libdir)/$$file; \
         done

.NOTPARALLEL:
