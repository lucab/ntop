#
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
# auto makefile for the ntop's plugins.
## (this file is processed with 'automake' to produce Makefile.in)
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
noinst_PROGRAMS = arpPlugin.so icmpPlugin.so lastSeenPlugin.so \
                  nfsPlugin.so remoteInterface.so \
		  rmonPlugin.so wapPlugin.so

lib_LTLIBRARIES = libarpPlugin.la libicmpPlugin.la liblastSeenPlugin.la \
                  libnfsPlugin.la libremoteInterface.la \
		  librmonPlugin.la libwapPlugin.la

libarpPlugin_la_SOURCES = arpPlugin.c
libarpPlugin_la_LDFLAGS = -shared -version-info @NTOP_VERSION_INFO@

libicmpPlugin_la_SOURCES = icmpPlugin.c
libicmpPlugin_la_LDFLAGS = -shared -version-info @NTOP_VERSION_INFO@

liblastSeenPlugin_la_SOURCES = lastSeenPlugin.c
liblastSeenPlugin_la_LDFLAGS = -shared -version-info @NTOP_VERSION_INFO@

libnfsPlugin_la_SOURCES = nfsPlugin.c
libnfsPlugin_la_LDFLAGS = -shared -version-info @NTOP_VERSION_INFO@

librmonPlugin_la_SOURCES = rmonPlugin.c rmon.h
librmonPlugin_la_LDFLAGS = -shared -version-info @NTOP_VERSION_INFO@

libremoteInterface_la_SOURCES = remoteInterface.c remoteInterface.h
libremoteInterface_la_LDFLAGS = -shared -version-info @NTOP_VERSION_INFO@

libwapPlugin_la_SOURCES = wapPlugin.c
libwapPlugin_la_LDFLAGS = -shared -version-info @NTOP_VERSION_INFO@


#
# Dependencies to allow ntop loading plugins on-place
# by default ntop looks for plugins in the plugins/ subdirectory
#

arpPlugin.so: .libs/libarpPlugin.so
	@ln -s .libs/libarpPlugin.so arpPlugin.so

icmpPlugin.so: .libs/libicmpPlugin.so
	@ln -s .libs/libicmpPlugin.so icmpPlugin.so

lastSeenPlugin.so: .libs/liblastSeenPlugin.so
	@ln -s .libs/liblastSeenPlugin.so lastSeenPlugin.so

nfsPlugin.so: .libs/libnfsPlugin.so
	@ln -s .libs/libnfsPlugin.so nfsPlugin.so

remoteInterface.so: .libs/libremoteInterface.so
	@ln -s .libs/libremoteInterface.so remoteInterface.so

rmonPlugin.so: .libs/librmonPlugin.so
	@ln -s .libs/librmonPlugin.so rmonPlugin.so

wapPlugin.so: .libs/libwapPlugin.so
	@ln -s .libs/libwapPlugin.so wapPlugin.so

install-data-local:
	@$(top_srcdir)/mkinstalldirs $(plugindir);
	@for file in $(noinst_PROGRAMS); do \
             cp -p $$file $(plugindir)/$$file; \
         done
# remove installed libraries
	@for file in $(lib_LTLIBRARIES); do \
             rm -f $(DESTDIR)$(libdir)/$$file; \
         done
