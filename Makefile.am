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


SUBDIRS = myrrd . @PLUGINS@ @NTCSH@

ETTER_PASSIVE = etter.passive.os.fp.gz

DIST_COMMON =
DIST_COMMON += AUTHORS CONTENTS COPYING ChangeLog \
              MANIFESTO NEWS PORTING  \
              SUPPORT_NTOP.txt THANKS \
              ntop.8 ntop.txt ntop.html \
              faq.html \
              ntop-cert.pem \
              p2c.opt.table.gz \
              $(ETTER_PASSIVE) \
              oui.txt.gz \
              specialMAC.txt.gz

NTOPDATA = ntop-cert.pem \
           p2c.opt.table \
           $(ETTER_PASSIVE) \
           oui.txt \
           specialMAC.txt

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
libntop_la_SOURCES = address.c    argv.c        dataFormat.c   \
                     getopt.c     getopt1.c     globals-core.c \
                     hash.c       initialize.c  leaks.c        \
                     netflow.c    ntop.c        pbuf.c         \
                     plugin.c     protocols.c   qsort.c        \
                     sessions.c   term.c        util.c         \
                     traffic.c    vendor.c      version.c      \
                     ntop_darwin.c

libntop_la_DEPENDENCIES = config.h
libntop_la_LIBADD       = 
libntop_la_LDFLAGS      = $(AM_LDFLAGS) -release $(VERSION) -export-dynamic @DYN_FLAGS@

# Archive for http representation, or the 'viewer'
libntopreport_la_SOURCES = emitter.c       globals-report.c  graph.c \
                           http.c          netflow.c         \
                           report.c        reportUtils.c     ssl.c   \
                           webInterface.c  xmldump.c


libntopreport_la_DEPENDENCIES = config.h
libntopreport_la_LIBADD       = 
libntopreport_la_LDFLAGS      = $(AM_LDFLAGS) -release $(VERSION) -export-dynamic @DYN_FLAGS@

man_MANS = ntop.8

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
	@groff -mandoc -Thtml $< | sed 's/_//g' | sed 's/[ -~]//g' > html/ntop.html
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
	@@AWK@ -f utils/faqtohtml.awk $< | sed 's/_//g' | sed 's/[ -~]//g' > html/faq.html
	@cp -f html/faq.html faq.html
	@echo "$@ done !"
	@echo "-----------------------------------------------"
	@echo ""

ntop-cert.pem:
	openssl req -new -x509 -sha1 -extensions v3_ca -nodes -days 365 -out cert.pem
	cat privkey.pem cert.pem > ntop-cert.pem
	/bin/rm -f privkey.pem cert.pem

install-data-local:
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
	@wget -c http://standards.ieee.org/regauth/oui/oui.txt

# download the Novell SAP Protocol information table
dnsapt:
	@(cd Internet; wget -c http://www.iana.org/assignments/novell-sap-numbers)

# download the passive ethernet fingerprint database
dnetter:
	if test -f $(ETTER_PASSIVE).old; then \
	  rm -rf $(ETTER_PASSIVE).old; \
	fi;
	mv $(ETTER_PASSIVE) $(ETTER_PASSIVE).old
	wget -O $(ETTER_PASSIVE) http://cvs.sourceforge.net/cgi-bin/viewcvs.cgi/~checkout~/ettercap/ettercap/etter.passive.os.fp?rev=HEAD\&content-type=text/plain

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

