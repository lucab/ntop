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

AUTOMAKE_OPTIONS = 1.6   # Require Automake 1.6 or better.

#
# The name of the game with its own major, minor and release version.
#
PKGNAME  = @PACKAGE_NAME@
VERSION  = @PACKAGE_VERSION@
PROGRAM  = $(PKGNAME)-$(VERSION)

DEFS      = @DEFS@
INCS      = @INCS@

INCLUDES  = -I. $(INCS) ${RRD_INC} -I @NDPI_INC@
LIBS      =
BASE_LIBS = @LIBS@ @CORELIBS@  ${RRD_LIB} @NDPI_LIB@
AS        = @AS@
AWK       = @AWK@
CC        = @CC@
CCLD      = @CCLD@

#AM_CFLAGS =
#AM_LDFLAGS=
ACLOCAL_AMFLAGS=-I m4

DISTCLEANFILES = trivialcompilemessage *.db #* *~ *.log
CLEANFILES     = $(DISTCLEANFILES) stamp-h1
INSTALLCLEANFILES = addressQueue.db dnsCache.db

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
                       ltmain.sh missing mkinstalldirs \
                       stamp-h.in


SUBDIRS = . @PLUGINS@

ETTER_PASSIVE_FILE = etter.finger.os
ETTER_PASSIVE = $(ETTER_PASSIVE_FILE).gz
ETTER_PASSIVE_DOWNLOAD_FROM = "http://ettercap.cvs.sourceforge.net/ettercap/ettercap_ng/share"
ETTER_PASSIVE_DOWNLOAD_PARMS = "rev=HEAD"

NTOPDATA = ntop-cert.pem \
           $(ETTER_PASSIVE) \
           oui.txt.gz \
           specialMAC.txt.gz \
	   GeoIPASNum.dat \
	   GeoLiteCity.dat

NTOPHTML = html html/*.js html/*.html  html/*.gif html/*.jpg html/*.ico html/*.png \
           html/*.css html/*.dtd \
	   html/jqplot \
	   html/jqplot/*s \
	   html/jqplot/plugins/*.js \
	   html/img_inquisitor \
	   html/img_inquisitor/*gif \
	   html/jscalendar \
	   html/jscalendar/*js \
	   html/jscalendar/lang \
	   html/jscalendar/lang/*js \
           html/statsicons \
           html/statsicons/flags html/statsicons/os \
           html/statsicons/flags/*.gif html/statsicons/os/*.gif

WEBFILES       = `cat www/FILES`
PLUGINSFILES   = `cat plugins/FILES`
DOCSFILES      = `cat docs/FILES`

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
ntop_LDADD         = libntopreport.la libntop.la $(BASE_LIBS)
ntop_LDFLAGS       = $(AM_LDFLAGS)
ntop_CFLAGS        =
EXTRA_HEADERS      =
noinst_HEADERS     = @GETOPT_H@ globals-core.h globals-report.h ntop.h

# all the Archives
lib_LTLIBRARIES    = libntop.la libntopreport.la

# core Archive, or the 'engine'
libntop_la_SOURCES = address.c    argv.c        dataFormat.c   \
                     event.c globals-core.c \
                     hash.c       ip.c		iface.c       initialize.c  leaks.c \
                     ntop.c       pbuf.c \
                     plugin.c     prefs.c       protocols.c   \
                     sessions.c   term.c        util.c        utildl.c \
                     traffic.c    vendor.c      version.c      \
                     ntop_darwin.c \
		     prng.c countmin.c

libntop_la_DEPENDENCIES =  config.h
libntop_la_LIBADD       = $(BASE_LIBS)
libntop_la_LDFLAGS      = $(AM_LDFLAGS) -release $(VERSION) -export-dynamic @DYN_FLAGS@

# Archive for http representation, or the 'viewer'
libntopreport_la_SOURCES = emitter.c       globals-report.c  graph.c \
                           httpd.c            \
                           report.c        reportUtils.c     ssl_utils.c   \
                           webInterface.c  map.c	     \
		           python.c


libntopreport_la_DEPENDENCIES = libntop.la
libntopreport_la_LIBADD       = libntop.la $(BASE_LIBS)
libntopreport_la_LDFLAGS      = $(AM_LDFLAGS) -release $(VERSION) -export-dynamic @DYN_FLAGS@

man_MANS = ntop.8

.PHONY: snapshot


acinclude.m4: acinclude.m4.ntop libtool.m4.in
	@cat acinclude.m4.ntop libtool.m4.in >acinclude.m4

CLEANLIST = `ls -l $(DESTDIR)$(libdir)/*ntop*.so $(DESTDIR)$(libdir)/*Plugin*.so | \
          grep -v $(VERSION) | \
          grep -v '\->' | \
          $(AWK) '{ print $$NF }'`

CLEANLISTD = `find $(DESTDIR)$(datadir) -name '.svn'`
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
	@groff -mandoc -Tascii $< | LANG=C sed 's/_^H//g' | LANG=C sed 's/^H[ -\~]//g' > ntop.txt
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
	@echo "   Oh, yeah..."
	@echo "       If we hang here, then you are probably "
	@echo "       running make not GNU make (gmake)"
	@echo ""
	@groff -mandoc -Thtml $< | LANG=C sed 's/_^H//g' | LANG=C sed 's/^H[ -\~]//g' | @AWK@ -f utils/insertssi.awk > html/ntop.html
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
	@echo "   Oh, yeah..."
	@echo "       If we hang here, then you are probably "
	@echo "       running make not GNU make (gmake)"
	@echo ""
	@@AWK@ -f utils/faqtohtml.awk $< | LANG=C sed 's/_^H//g' | LANG=C sed 's/^H[ -\~]//g' > html/faq.html
	@cp -f html/faq.html faq.html
	@echo "$@ done !"
	@echo "-----------------------------------------------"
	@echo ""

ntop-cert.pem:
	openssl req -new -x509 -sha1 -extensions v3_ca -nodes -days 365 -out cert.pem
	cat privkey.pem cert.pem > ntop-cert.pem
	/bin/rm -f privkey.pem cert.pem

listlibclean:
	@echo ""
	@echo "This is a list of old shared library files that will be deleted"
	@echo "if you run 'make libclean'"
	@echo ""
	@for file in $(CLEANLIST); do \
          if test -f $$file; then \
             echo "   $$file"; \
          fi; \
        done
	@for dir in $(CLEANLISTD); do \
          if test -d $$dir; then \
             echo "   $$dir"; \
          fi; \
        done
	@echo ""

libclean:
	@echo ""
	@echo "Cleanup of old shared library files..."
	@echo ""
	@echo "  This is a list of files that will be deleted..."
	@echo ""
	@for file in $(CLEANLIST); do \
          if test -f $$file; then \
             echo "   $$file"; \
          fi; \
        done
	@echo ""
	@echo ""
	@echo "Press cntl-c to stop or enter to continue and delete these files..."
	@read select
	@echo ""
	@for file in $(CLEANLIST); do \
          if test -f $$file; then \
             echo "   ...Deleting $$file"; \
             rm -f $$file; \
          fi; \
        done

install: install-recursive

	@mkdir -p $(DESTDIR)/$(CFG_DBFILE_DIR)

	@echo ""
	@echo "------------------------------------------------------------"
	@echo ""
	@echo "  Cleanup of old database files..."
	@echo ""
	@for file in $(INSTALLCLEANFILES); do \
	  if test -f $(DESTDIR)$(datadir)/ntop/$$file; then \
	     echo "        ...Deleting $(DESTDIR)$(datadir)/ntop/$$file"; \
	     rm -rf $(DESTDIR)$(datadir)/ntop/$$file; \
	  fi; \
	done

	@if test ".$(CLEANLIST)" != "."; then \
	  echo ""; \
	  echo ""; \
	  echo "************************************************************"; \
	  echo ""; \
	  echo "  There appear to be old shared library files on your system."; \
	  echo "  You may wish to delete these if you are no longer using the"; \
	  echo "  older versions."; \
	  echo ""; \
	  echo "  To see the list of files, run"; \
	  echo ""; \
	  echo "# make listlibclean"; \
	  echo ""; \
	  echo "  To delete them (you will have a chance to abort before the"; \
	  echo "  actual delete):"; \
	  echo ""; \
	  echo "# make libclean"; \
	  echo ""; \
	fi

	@if test -f $(DESTDIR)$(datadir)/ntop/warnuser; then \
	  echo ""; \
	  echo ""; \
	  echo "************************************************************"; \
	  echo "************************************************************"; \
	  echo ""; \
	  echo "  WARNING: This install created a directory for the ntop"; \
	  echo "           files and databases:"; \
	  echo ""; \
	  echo "             $(DESTDIR)$(datadir)/ntop"; \
	  echo ""; \
	  echo "           This directory MUST be owned by the user"; \
	  echo "           which you are going to use to run ntop."; \
	  echo ""; \
	  echo "           The command you must issue is something like:"; \
	  echo ""; \
	  echo "           chown -R ntop.ntop $(DESTDIR)$(datadir)/ntop"; \
	  echo "     or    chown -R ntop:users $(DESTDIR)$(datadir)/ntop"; \
	  echo ""; \
	  echo "           man chown to check the syntax for YOUR system"; \
	  echo ""; \
	  echo "************************************************************"; \
	  echo "************************************************************"; \
	  echo ""; \
	  echo ""; \
	  rm -f $(DESTDIR)$(datadir)/ntop/warnuser; \
	fi

	echo "Shall you be using SELinux please run:"
	echo "make install-selinux-policy"

install-selinux-policy:
	chcon -t textrel_shlib_t $(DESTDIR)$(libdir)/*ntop*.so

install-data-local: ntop.txt ntop.html faq.html
	@$(top_srcdir)/mkinstalldirs $(DESTDIR)/$(libdir)/plugins;
	@if ! test -d $(DESTDIR)$(datadir)/ntop; then \
	  $(top_srcdir)/mkinstalldirs $(DESTDIR)$(datadir)/ntop; \
	  touch $(DESTDIR)$(datadir)/ntop/warnuser; \
	else \
	  rm -f $(DESTDIR)$(datadir)/ntop/warnuser; \
	fi
	@$(top_srcdir)/mkinstalldirs $(DESTDIR)$(datadir)/ntop/html;
	@for file in $(NTOPHTML); do \
          if test -d $$file; then \
             $(top_srcdir)/mkinstalldirs $(DESTDIR)$(datadir)/ntop/$$file; \
           else \
             cp -p $$file $(DESTDIR)$(datadir)/ntop/$$file; \
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
	@$(top_srcdir)/mkinstalldirs $(DESTDIR)$(datadir)/ntop/python
	tar --exclude='.svn' -c -f - python/* | (cd $(DESTDIR)$(datadir)/ntop/python ; tar xfp -)

# build the IPX SAP table
#sapt: saptable.h
#	@cat Internet/novell-sap-numbers | cut -c1-3 | sed -f sapt.sed > saptable.h


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
#dnsapt:
#	@(cd Internet; wget -c http://www.iana.org/assignments/novell-sap-numbers)

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

# ntop census
census-fail:
	@echo "This option is no longer available... thanks for trying"

census-ok:
	@echo "This option is no longer available... thanks for trying"

# Create ntop's package for Debian GNU/Linux using Official scripts
# Please keep silent the building process.
QUIET  = 1> /dev/null 2>&1
deb-official:
	@echo "Making Debian package using scripts in packages/debian.official/. Please be patient..."
	@fakeroot make -f packages/debian.official/rules binary $(QUIET)
	@rm -f packages/debian.official/files packages/debian.official/ntop.substvars
	@version=`head -1 packages/debian.official/changelog | cut -d " " -f 2 | sed -e 's|(||' | sed -e 's|)||'` && mv ../ntop_$$version_*.deb packages/debian.official/
	@rm -rf packages/debian.official/ntop
	@echo "Your Debian package is under packages/debian.official/"
