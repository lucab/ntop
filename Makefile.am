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

AUTOMAKE_OPTIONS = 1.6   # Require Automake 1.6 or better.

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

#
# Fake out the missing tests for the auto* tools
#
ACLOCAL = /bin/sh ./missing --run echo
AUTOCONF = /bin/sh ./missing --run echo
AUTOMAKE = /bin/sh ./missing --run echo
AUTOHEADER = /bin/sh ./missing --run echo

# A list of all the files in the current directory which can be regenerated
MAINTAINERCLEANFILES = COPYING Makefile.in aclocal.m4 config.guess \
                       config.h.in config.sub configure install-sh \
                       ltconfig ltmain.sh missing mkinstalldirs \
                       stamp-h.in


SUBDIRS = myrrd . @PLUGINS@

ETTER_PASSIVE_FILE = etter.passive.os.fp
ETTER_PASSIVE = $(ETTER_PASSIVE_FILE).gz
ETTER_PASSIVE_DOWNLOAD_FROM = "http://cvs.sourceforge.net/viewcvs.py/ettercap/ettercap"
ETTER_PASSIVE_DOWNLOAD_PARMS = "rev=HEAD"


DIST_COMMON =
DIST_COMMON += AUTHORS CONTENTS COPYING ChangeLog \
              MANIFESTO NEWS PORTING  \
              SUPPORT_NTOP.txt THANKS \
              ntop.8 ntop.txt ntop.html \
              html/faq.html \
              ntop-cert.pem \
              p2c.opt.table.gz \
              $(ETTER_PASSIVE) \
              oui.txt.gz \
              specialMAC.txt.gz

NTOPDATA = ntop-cert.pem \
           p2c.opt.table.gz \
           $(ETTER_PASSIVE) \
           oui.txt.gz \
           specialMAC.txt.gz

NTOPHTML = html html/*.js html/*.html  html/*.gif html/*.jpg html/*.ico html/*.png \
           html/*.css html/*.dtd \
           html/statsicons \
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
DATABASEFILES  = `cat database/FILES`
DOCSFILES      = `cat docs/FILES`

THINGS_TO_DISTRIBUTE = $(DISTFILES) $(NTOPHTML) $(PLUGINSFILES) \
		       $(DATABASEFILES) $(DOCSFILES) $(WEBFILES)

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
EXTRA_PROGRAMS = ntops sntop
bin_SCRIPTS    = 

ntop_SOURCES       = main.c admin.c
ntop_DEPENDENCIES  = libntopreport.la libntop.la
ntop_LDADD         = libntopreport.la libntop.la
ntop_LDFLAGS       = $(AM_LDFLAGS)
ntop_CFLAGS        = 

ntops_SOURCES      = $(ntop_SOURCES)
ntops_DEPENDENCIES = $(ntop_DEPENDENCIES)
ntops_LDADD        = $(ntop_LDADD)
ntops_LDFLAGS      = $(ntop_LDFLAGS) -static

#
# Static ntop: everything is linked in
#
sntop_SOURCES      = $(ntop_SOURCES) plugins/icmpPlugin.c plugins/lastSeenPlugin.c \
		     plugins/netflowPlugin.c plugins/nfsPlugin.c plugins/pdaPlugin.c  \
		     plugins/sflowPlugin.c plugins/rrdPlugin.c

sntop_DEPENDENCIES = $(ntop_DEPENDENCIES)
sntop_LDADD        = $(ntop_LDADD)
sntop_LDFLAGS      = $(ntop_LDFLAGS) -static

noinst_HEADERS     =  getopt.h globals-core.h globals-report.h ntop.h

# all the Archives
lib_LTLIBRARIES    = libntop.la libntopreport.la

# core Archive, or the 'engine'
libntop_la_SOURCES = address.c    argv.c        dataFormat.c   fcUtils.c \
                     getopt.c     getopt1.c     globals-core.c \
                     hash.c       iface.c       initialize.c  leaks.c        \
                     netflow.c    ntop.c        pbuf.c         \
                     plugin.c     protocols.c   \
                     sessions.c   term.c        util.c         \
                     traffic.c    vendor.c      version.c      \
                     ntop_darwin.c

libntop_la_DEPENDENCIES = myrrd/libmyrrd.a config.h
libntop_la_LIBADD       = 
libntop_la_LDFLAGS      = $(AM_LDFLAGS) -release $(VERSION) -export-dynamic @DYN_FLAGS@

# Archive for http representation, or the 'viewer'
libntopreport_la_SOURCES = emitter.c       globals-report.c  graph.c \
                           http.c          netflow.c         \
                           report.c        reportUtils.c     ssl.c   \
                           webInterface.c  xmldump.c


libntopreport_la_DEPENDENCIES = myrrd/libmyrrd.a config.h
libntopreport_la_LIBADD       = 
libntopreport_la_LDFLAGS      = $(AM_LDFLAGS) -release $(VERSION) -export-dynamic @DYN_FLAGS@

man_MANS = ntop.8

myrrd/libmyrrd.a:
	cd myrrd; make

#
# Special stuff for xml auto-generation of code from the "doc":
#
xmldump.$(OBJEXT): xml_g_cmdopt.inc

xmldump.c: xml_*.inc globals-structtypes.h

xml_*.inc: globals-structtypes.h
	@echo "Processing globals-structtypes.h to make xml_*.inc..."
	@@AWK@ -f utils/xmldump.awk globals-structtypes.h

.PHONY: snapshot


acinclude.m4: acinclude.m4.ntop libtool.m4.in
	@cat acinclude.m4.ntop libtool.m4.in >acinclude.m4

#
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
# rules to handle nroff documentation
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
#
ntop.8:
	@echo ""

ntop.txt: ntop.8
	@echo ""
	@echo "-----------------------------------------------"
	@echo "Converting $< to ASCII format  .... Please wait"
	@echo ""
	@echo "   Oh, yeah..."
	@echo "       If we hang here, then you are probably "
	@echo "       running make not GNU make (gmake)"
	@echo ""
	@groff -mandoc -Tascii $< | LANG=C sed 's/_^H//g' | LANG=C sed 's/^H[ -~]//g' > ntop.txt
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
	@groff -mandoc -Thtml $< | LANG=C sed 's/_^H//g' | LANG=C sed 's/^H[ -~]//g' > html/ntop.html
	@cp -f html/ntop.html ntop.html
	@echo "$@ done !"
	@echo "-----------------------------------------------"
	@echo ""

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# rules to translate FAQ file to HTML
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

faq.html: docs/FAQ
	@echo ""
	@echo "-----------------------------------------------"
	@echo "Converting $< to HTML format  .... Please wait"
	@echo ""
	@@AWK@ -f utils/faqtohtml.awk $< | LANG=C sed 's/_^H//g' | LANG=C sed 's/^H[ -~]//g' > html/faq.html
	@cp -f html/faq.html faq.html
	@echo "$@ done !"
	@echo "-----------------------------------------------"
	@echo ""

ntop-cert.pem:
	openssl req -new -x509 -sha1 -extensions v3_ca -nodes -days 365 -out cert.pem
	cat privkey.pem cert.pem > ntop-cert.pem
	/bin/rm -f privkey.pem cert.pem

install: install-recursive
	@if test -f $(DESTDIR)/$(datadir)/ntop/warnuser; then \
	  echo ""; \
	  echo ""; \
	  echo "************************************************************"; \
	  echo "************************************************************"; \
	  echo ""; \
	  echo "  WARNING: This install created a directory for the ntop"; \
	  echo "           files and databases:"; \
	  echo ""; \
	  echo "             $(DESTDIR)/$(datadir)/ntop"; \
	  echo ""; \
	  echo "           This directory MUST be owned by the user"; \
	  echo "           which you are going to use to run ntop."; \
	  echo ""; \
	  echo "           The command you must issue is something like:"; \
	  echo ""; \
	  echo "           chown -R ntop.ntop $(DESTDIR)/$(datadir)/ntop"; \
	  echo "     or    chown -R ntop:users $(DESTDIR)/$(datadir)/ntop"; \
	  echo ""; \
	  echo "           man chown to check the syntax for YOUR system"; \
	  echo ""; \
	  echo "************************************************************"; \
	  echo "************************************************************"; \
	  echo ""; \
	  echo ""; \
	  rm -f $(DESTDIR)/$(datadir)/ntop/warnuser; \
	fi
	@if ! test -f $(DESTDIR)/$(CFG_CONFIGFILE_DIR)/AS-list.txt.gz; then \
	  echo ""; \
	  echo ""; \
	  echo "NOTE: ntop can show traffic by AS (Autonomous System) Number"; \
	  echo ""; \
	  echo "      Because this feature consumes a number of MB of memory,"; \
	  echo "      the datafile is not installed by default."; \
	  echo ""; \
	  echo "      Which - if there is no file - from this or a previous"; \
	  echo "      install, effectively disables the ASN feature."; \
	  echo ""; \
	  echo "      To install the AS data, type:"; \
	  echo ""; \
	  echo "# make install-data-as"; \
	  echo ""; \
	  echo ""; \
	fi

install-data-as:
	@$(top_srcdir)/mkinstalldirs $(DESTDIR)/$(CFG_CONFIGFILE_DIR);
	@for file in AS-list.txt.gz; do \
          if test -d $$file; then \
             $(top_srcdir)/mkinstalldirs $(DESTDIR)/$(CFG_CONFIGFILE_DIR)/$$file; \
           else \
             cp -p $$file $(DESTDIR)/$(CFG_CONFIGFILE_DIR)/$$file; \
          fi; \
        done

install-data-local: ntop.txt ntop.html faq.html
	@$(top_srcdir)/mkinstalldirs $(DESTDIR)/$(libdir)/plugins;
	@if ! test -d $(DESTDIR)/$(datadir)/ntop; then \
	  $(top_srcdir)/mkinstalldirs $(DESTDIR)/$(datadir)/ntop; \
	  touch $(DESTDIR)/$(datadir)/ntop/warnuser; \
	else \
	  rm -f $(DESTDIR)/$(datadir)/ntop/warnuser; \
	fi
	@$(top_srcdir)/mkinstalldirs $(DESTDIR)/$(datadir)/ntop/html;
	@for file in $(NTOPHTML); do \
          if test -d $$file; then \
             $(top_srcdir)/mkinstalldirs $(DESTDIR)/$(datadir)/ntop/$$file; \
           else \
             cp -p $$file $(DESTDIR)/$(datadir)/ntop/$$file; \
          fi; \
        done
	@$(top_srcdir)/mkinstalldirs $(DESTDIR)/$(CFG_CONFIGFILE_DIR);
	@for file in $(NTOPDATA); do \
          if test -d $$file; then \
             $(top_srcdir)/mkinstalldirs $(DESTDIR)/$(CFG_CONFIGFILE_DIR)/$$file; \
           else \
             cp -p $$file $(DESTDIR)/$(CFG_CONFIGFILE_DIR)/$$file; \
          fi; \
        done


# build the IPX SAP table
sapt: saptable.h
	@cat Internet/novell-sap-numbers | cut -c1-3 | sed -f sapt.sed > saptable.h


# download the vendor information table
dnvt:
	@echo ""
	@echo ""
	@echo -n "Preparing "
	@if test -f oui.txt; then \
	  rm -rf oui.txt; \
	fi
	@if test -f oui.txt.gz.old; then \
	  rm -rf oui.txt.gz.old; \
	fi;
	@mv oui.txt.gz oui.txt.gz.old
	@echo "(old oui.txt.gz file is now oui.txt.gz.old)"
	@echo ""
	@wget -c http://standards.ieee.org/regauth/oui/oui.txt
	@gzip oui.txt
	@echo ""
	@echo ""
	@echo -n "Old file lines were: "
	@gunzip -c oui.txt.gz.old | wc -l
	@echo -n "New file lines are:  "
	@gunzip -c oui.txt.gz | wc -l
	@echo ""
	@echo ""
	@echo "New file is:"
	@ls -l oui.txt.gz

# download the Novell SAP Protocol information table
dnsapt:
	@(cd Internet; wget -c http://www.iana.org/assignments/novell-sap-numbers)

# download the passive ethernet fingerprint database
dnetter:
	@echo ""
	@echo ""
	@echo "Preparing "
	@echo ""

	@if test -f $(ETTER_PASSIVE).old; then \
	  echo "...Deleting prior file, $(ETTER_PASSIVE).old..."; \
	  rm -rf $(ETTER_PASSIVE).old; \
	fi;
	@if test -f $(ETTER_PASSIVE); then \
	  echo "...Moving current $(ETTER_PASSIVE) to $(ETTER_PASSIVE).old"; \
	  mv $(ETTER_PASSIVE) $(ETTER_PASSIVE).old; \
	fi;
	@for file in $(ETTER_PASSIVE) $(ETTER_PASSIVE).gz \
		$(ETTER_PASSIVE_FILE) $(ETTER_PASSIVE_FILE).gz; do \
          if test -f $$file; then \
	     echo "...Deleting prior file, $$file..."; \
             rm -rf $$file; \
          fi; \
        done
	@echo ""
	@echo "...Downloading new file..."
	@wget -O $(ETTER_PASSIVE_FILE) \
		$(ETTER_PASSIVE_DOWNLOAD_FROM)/$(ETTER_PASSIVE_FILE)?$(ETTER_PASSIVE_DOWNLOAD_PARMS)
	@echo ""
	@echo "gziping downloaded file..."
	@gzip $(ETTER_PASSIVE_FILE)
	@echo ""
	@echo ""
	@if test -f $(ETTER_PASSIVE).old; then \
	  echo -n "Old file lines were: "; \
	  gunzip -c $(ETTER_PASSIVE).old | wc -l; \
	fi;
	@echo -n "New file lines are:  "
	@gunzip -c $(ETTER_PASSIVE) | wc -l
	@echo ""
	@echo ""
	@echo "New file is:"
	@ls -l $(ETTER_PASSIVE)

# download the data for and make the p2c.opt.table
p2ctable:
	@utils/p2c

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

