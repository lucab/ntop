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

SUBDIRS = . #pep

DIST_COMMON = Makefile.am Makefile.in
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
                  nfsPlugin.so  sflowPlugin.so
#		  rmonPlugin.so wapPlugin.so

lib_LTLIBRARIES = libicmpPlugin.la liblastSeenPlugin.la \
                  libnfsPlugin.la  libsflowPlugin.la
#		  librmonPlugin.la libwapPlugin.la

libicmpPlugin_la_SOURCES = icmpPlugin.c
libicmpPlugin_la_LDFLAGS = -shared -version-info @NTOP_VERSION_INFO@ @DYN_FLAGS@

libsflowPlugin_la_SOURCES = sflowPlugin.c
libsflowPlugin_la_LDFLAGS = -shared -version-info @NTOP_VERSION_INFO@ @DYN_FLAGS@

liblastSeenPlugin_la_SOURCES = lastSeenPlugin.c
liblastSeenPlugin_la_LDFLAGS = -shared -version-info @NTOP_VERSION_INFO@ @DYN_FLAGS@

libnfsPlugin_la_SOURCES = nfsPlugin.c
libnfsPlugin_la_LDFLAGS = -shared -version-info @NTOP_VERSION_INFO@ @DYN_FLAGS@

#librmonPlugin_la_SOURCES = rmonPlugin.c rmon.h
#librmonPlugin_la_LDFLAGS = @SNMPLIBS@ -shared -version-info @NTOP_VERSION_INFO@ @DYN_FLAGS@

#libwapPlugin_la_SOURCES = wapPlugin.c
#libwapPlugin_la_LDFLAGS = -shared -version-info @NTOP_VERSION_INFO@ @DYN_FLAGS@


#
# Dependencies to allow ntop loading plugins on-place
# by default ntop looks for plugins in the plugins/ subdirectory
#


.libs/libicmpPlugin.so@SO_VERSION_PATCH@:
	cc -bundle -flat_namespace -undefined suppress -o .libs/libicmpPlugin.so@SO_VERSION_PATCH@ icmpPlugin.o

icmpPlugin.so: .libs/libicmpPlugin.so@SO_VERSION_PATCH@
	@ln -s .libs/libicmpPlugin.so icmpPlugin.so

.libs/libsflowPlugin.so@SO_VERSION_PATCH@:
	cc -bundle -flat_namespace -undefined suppress -o .libs/libsflowPlugin.so@SO_VERSION_PATCH@ sflowPlugin.o

sflowPlugin.so: .libs/libsflowPlugin.so@SO_VERSION_PATCH@
	@ln -s .libs/libfslowPlugin.so sflowPlugin.so

.libs/liblastSeenPlugin.so@SO_VERSION_PATCH@:
	cc -bundle -flat_namespace -undefined suppress -o .libs/liblastSeenPlugin.so@SO_VERSION_PATCH@ lastSeenPlugin.o

lastSeenPlugin.so: .libs/liblastSeenPlugin.so@SO_VERSION_PATCH@
	@ln -s .libs/liblastSeenPlugin.so lastSeenPlugin.so

.libs/libnfsPlugin.so@SO_VERSION_PATCH@:
	cc -bundle -flat_namespace -undefined suppress -o .libs/libnfsPlugin.so@SO_VERSION_PATCH@ nfsPlugin.o

nfsPlugin.so: .libs/libnfsPlugin.so@SO_VERSION_PATCH@
	@ln -s .libs/libnfsPlugin.so nfsPlugin.so

#.libs/librmonPlugin.so@SO_VERSION_PATCH@:
#	cc -bundle -flat_namespace -undefined suppress -o .libs/librmonPlugin.so@SO_VERSION_PATCH@ rmonPlugin.o

#rmonPlugin.so: .libs/librmonPlugin.so@SO_VERSION_PATCH@
#	@ln -s .libs/librmonPlugin.so rmonPlugin.so

#.libs/libwapPlugin.so@SO_VERSION_PATCH@:
#	cc -bundle -flat_namespace -undefined suppress -o .libs/libwapPlugin.so@SO_VERSION_PATCH@ wapPlugin.o

#wapPlugin.so: .libs/libwapPlugin.so@SO_VERSION_PATCH@
#	@ln -s .libs/libwapPlugin.so wapPlugin.so

install-data-local:
	@$(top_srcdir)/mkinstalldirs $(DESTDIR)$(plugindir);
	@for file in $(noinst_PROGRAMS); do \
             cp -p $$file $(DESTDIR)$(plugindir)/$$file; \
         done
# remove installed libraries
	@for file in $(lib_LTLIBRARIES); do \
             rm -f $(DESTDIR)$(libdir)/$$file; \
         done
