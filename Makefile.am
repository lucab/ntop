#
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
#
# Copyright (c) 1998-2002 Luca Deri <deri@ntop.org>
# Updated 1Q 2000 Rocco Carbone <rocco@ntop.org>
#
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
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


#
# The name of the game with its own major, minor and release version.
#
PKGNAME  = @PACKAGE_NAME@
VERSION  = @PACKAGE_VERSION@
PROGRAM  = $(PKGNAME)-$(VERSION)

DEFS      = @DEFS@
INCS      = @INCS@

INCLUDES  = -I. $(INCS)
LIBS      = @LIBS@
AS        = @AS@
AWK       = @AWK@
CC        = @CC@
CCLD      = @CCLD@
AM_CFLAGS = @CFLAGS@
AM_LDFLAGS= @LDFLAGS@

DISTCLEANFILES = *.db #* *~ *.log
CLEANFILES     = $(DISTCLEANFILES)

# A list of all the files in the current directory which can be regenerated
MAINTAINERCLEANFILES = COPYING Makefile.in aclocal.m4 config.guess \
                       config.h.in config.sub configure install-sh \
                       ltconfig ltmain.sh missing mkinstalldirs \
                       stamp-h.in


SUBDIRS = . @PLUGINS@ @INTOP@

DIST_COMMON =
DIST_COMMON += AUTHORS CONTENTS COPYING ChangeLog \
              MANIFESTO NEWS PORTING  \
              SUPPORT_NTOP.txt THANKS \
              ntop.8 ntop.txt ntop.html \
              ntop-cert.pem

NTOPHTML = html html/*.js html/*.html  html/*.gif html/*.jpg html/*.ico html/*.png html/*.css html/statsicons \
           html/statsicons/flags html/statsicons/os \
           html/statsicons/flags/*.gif html/statsicons/os/*.gif

EXTRA_DIST = Makefile.am Makefile.in \
             acconfig.h acinclude.m4 acinclude.m4.ntop \
             autogen.sh config.guess config.h.in config.sub \
             configure configure.in \
             install-sh libtool ltconfig ltmain.sh \
             missing mkinstalldirs \
             vt.sed

WEBFILES       = `cat www/FILES`
PLUGINSFILES   = `cat plugins/FILES`
INTOPFILES     = `cat intop/FILES`
DATABASEFILES  = `cat database/FILES`
DOCSFILES      = `cat docs/FILES`

THINGS_TO_DISTRIBUTE = $(DISTFILES) $(NTOPHTML) $(PLUGINSFILES) \
		       $(INTOPFILES) $(DATABASEFILES) $(DOCSFILES) $(WEBFILES)

#
# This Makefile is responsible for creating:
# 1. libntop.la, the ntop core library
# 2. libntopreport.la, the ntop library with all the code for html report
# 3. ntop, the binary dynamically linked
#

#
# The Games
#
bin_PROGRAMS   = ntop
EXTRA_PROGRAMS = ntops
bin_SCRIPTS    = 

ntop_SOURCES       = main.c admin.c
ntop_DEPENDENCIES  = libntopreport.la libntop.la
ntop_LDADD         = libntopreport.la libntop.la
ntop_LDFLAGS       = $(AM_LDFLAGS)

ntops_SOURCES      = $(ntop_SOURCES)
ntops_DEPENDENCIES = $(ntop_DEPENDENCIES)
ntops_LDADD        = $(ntop_LDADD)
ntops_LDFLAGS      = $(ntop_LDFLAGS) -static

noinst_HEADERS     = globals-core.h globals-report.h ntop.h regex.h

# all the Archives
lib_LTLIBRARIES    = libntop.la libntopreport.la

# core Archive, or the 'engine'
libntop_la_SOURCES = address.c       dataFormat.c  \
                     globals-core.c  hash.c        initialize.c       \
                     leaks.c         netflow.c  \
                     ntop.c 	     pbuf.c        protocols.c        \
		     plugin.c        qsort.c       regex.c	      \
                     sessions.c         \
                     ssl.c           term.c        traffic.c          \
                     util.c          vendor.c      version.c          \
                     vendortable.h   ntop_darwin.c

libntop_la_DEPENDENCIES = config.h
libntop_la_LIBADD       = 
libntop_la_LDFLAGS      = $(AM_LDFLAGS) -release $(VERSION) -export-dynamic @DYN_FLAGS@

# Archive for http representation, or the 'viewer'
libntopreport_la_SOURCES = emitter.c \
                           globals-report.c \
                           graph.c \
                           http.c  \
                           report.c \
                           reportUtils.c \
                           webInterface.c


libntopreport_la_DEPENDENCIES = config.h
libntopreport_la_LIBADD       = 
libntopreport_la_LDFLAGS      = $(AM_LDFLAGS) -release $(VERSION) -export-dynamic @DYN_FLAGS@

man_MANS = ntop.8

.PHONY: snapshot


acinclude.m4: acinclude.m4.ntop libtool.m4.in
	@cat acinclude.m4.ntop libtool.m4.in >acinclude.m4

#
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
# rules to handle nroff documentation
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
#
ntop.txt: ntop.8
	@echo ""
	@echo "-----------------------------------------------"
	@echo "Converting $< to ASCII format  .... Please wait"
	@echo ""
	@groff -mandoc -Tascii $< | sed 's/_//g' | sed 's/[ -~]//g' > ntop.txt
	@echo "$@ done !"
	@echo "-----------------------------------------------"
	@echo ""


# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# rules to translate ASCII files to HTML
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

ntop.html: ntop.8
	@echo ""
	@echo "-----------------------------------------------"
	@echo "Converting $< to HTML format  .... Please wait"
	@echo ""
	@man2html < ntop.8 > html/ntop.html
	@cp -f html/ntop.html ntop.html
	@echo "$@ done !"
	@echo "-----------------------------------------------"
	@echo ""

ntop-cert.pem:
	openssl req -new -x509 -sha1 -extensions v3_ca -nodes -days 365 -out cert.pem
	cat privkey.pem cert.pem > ntop-cert.pem
	/bin/rm -f privkey.pem cert.pem

install-data-local:
	@cp -p ntop-cert.pem $(DESTDIR)/etc/ntop-cert.pem
	@$(top_srcdir)/mkinstalldirs $(DESTDIR)/$(libdir)/plugins;
	@$(top_srcdir)/mkinstalldirs $(DESTDIR)/$(datadir)/ntop;
	@$(top_srcdir)/mkinstalldirs $(DESTDIR)/$(datadir)/ntop/html;
	@for file in $(NTOPHTML); do \
          if test -d $$file; then \
             $(top_srcdir)/mkinstalldirs $(DESTDIR)/$(datadir)/ntop/$$file; \
           else \
             cp -p $$file $(DESTDIR)/$(datadir)/ntop/$$file; \
          fi; \
        done


# built the vendor table
vt: vendortable.h
	@fgrep -e "(hex)" Internet/oui.txt | cut -c1-8,9,19- | sed -f vt.sed > vendortable.h

# built the IPX SAP table
sapt: saptable.h
	@cat Internet/novell-sap-numbers | cut -c1-3 | sed -f sapt.sed > saptable.h


# download the vendor information table
dnvt:
	@(cd Internet; wget -c http://standards.ieee.org/regauth/oui/oui.txt)

# download the Novell SAP Protocol information table
dnsapt:
	@(cd Internet; wget -c http://www.isi.edu/in-notes/iana/assignments/novell-sap-numbers)

# run ./configure with --showoses
showoses:
	@echo "Processing request... please wait..."
	@./configure --no-create --silent --enable-showoses

# ntop census
census-fail:
        # creates and report for edit and manual send
	@echo "Processing ntop census... please wait..."
	@./utils/census.sh "fail"

census-ok:
        # creates and sends report to census@ntopsupport.com
	@echo "Processing ntop census... please wait..."
	@./utils/census.sh "OK"

