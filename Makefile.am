#
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
# auto makefile for the top-level ntop program
## (this file is processed with 'automake' to produce Makefile.in)
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
PKGNAME  = ntop
VERSION  = @VERSION@
PROGRAM  = $(PKGNAME)-$(VERSION)
OSNAME   = @target_os@

DEFS      = @DEFS@
INCS      = @INCS@

INCLUDES  = -I. $(INCS)
LIBS      = @LIBS@ @MORELIBS@
CCLD      = @CCLD@

CORELIBS  = @CORELIBS@
MORELIBS  = @MORELIBS@


DISTCLEANFILES = *.db ntops ntopd ntop-config #* *~ *.log
CLEANFILES     = $(DISTCLEANFILES)

# A list of all the files in the current directory which can be regenerated
MAINTAINERCLEANFILES = COPYING Makefile.in aclocal.m4 config.guess \
                       config.h.in config.sub configure install-sh \
                       ltconfig ltmain.sh missing mkinstalldirs \
                       ntop-config stamp-h.in


SUBDIRS = . @PLUGINS@ @INTOP@

DIST_COMMON += AUTHORS CONTENTS COPYING ChangeLog \
               MANIFESTO NEWS PORTING  \
               SUPPORT_NTOP.txt THANKS \
               ntop.8 ntop.txt ntop.html \
               ntop-cert.pem

NTOPHTML = html html/*.js html/*.html  html/*.gif html/*.jpg html/*.ico html/*.png html/*.css html/statsicons \
           html/statsicons/flags html/statsicons/os \
           html/statsicons/flags/*.gif html/statsicons/os/*.gif

EXTRA_DIST = Makefile.am Makefile.in \
             acconfig.h acinclude.m4 acinclude.m4.in \
             autogen.sh config.guess config.h.in config.sub \
             configure configure.in \
             install-sh libtool ltconfig ltmain.sh \
             missing mkinstalldirs ntop-config.in \
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
# 4. ntops, the binary statically linked
# 5. ntopd, the ntop daemon, simply a link to the ntop binary
#

#
# The Games
#
bin_PROGRAMS   = ntop
EXTRA_PROGRAMS = ntops ntopd
bin_SCRIPTS    = ntop-config

ntop_SOURCES   = main.c admin.c
ntops_SOURCES  = $(ntop_SOURCES)
ntopd_SOURCES  = $(ntop_SOURCES)

ntop_DEPENDENCIES = libntopreport.la libntop.la
ntop_LDADD        = libntopreport.la libntop.la
ntop_LDFLAGS      =

ntops_DEPENDENCIES = libntopreport.la libntop.la
ntops_LDADD        = libntopreport.la libntop.la
ntops_LDFLAGS      = -static

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
libntop_la_LIBADD       = $(CORELIBS)
libntop_la_LDFLAGS      = -version-info @NTOP_VERSION_INFO@ -release @NTOP_RELEASE@ -export-dynamic @DYN_FLAGS@

# Archive for http representation, or the 'viewer'
libntopreport_la_SOURCES = emitter.c \
                           globals-report.c \
                           graph.c \
                           http.c  \
                           report.c \
                           reportUtils.c \
                           webInterface.c


libntopreport_la_DEPENDENCIES = config.h
libntopreport_la_LIBADD       = $(MORELIBS)
libntopreport_la_LDFLAGS      = -version-info @NTOP_VERSION_INFO@ -release @NTOP_RELEASE@ -export-dynamic @DYN_FLAGS@

man_MANS = ntop.8

.PHONY: snapshot

#ntopd: ntop
#	@ln -sf ntop ntopd
#	@-(cd .libs && ln -sf ntop ntopd)

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
# Distribution
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
snapshot: version.c
	@echo "generating configuration files ............. please wait"
	@automake --add-missing --gnu --include-deps >/dev/null 2>&1
	@autoconf  >/dev/null 2>&1
	@./configure >/dev/null 2>&1
	@-if [ -d distribution ]; then true; else mkdir distribution; fi
	@-if [ -d distribution/$(PROGRAM) ]; then true; else mkdir distribution/$(PROGRAM); fi
	@echo "copying files ............. please wait"
	@for file in $(THINGS_TO_DISTRIBUTE); do \
          if test -d $$file; then \
              mkdir distribution/$(PROGRAM)/$$file; \
          else cp -p $$file distribution/$(PROGRAM)/$$file; \
          fi; \
        done
	@echo "== making tar file distribution/$(PROGRAM).tar.gz ... please wait"
	@(date=`date`; \
          day=`echo $$date | cut -f3 -d" "`; \
          month=`echo $$date | cut -f2 -d" "`; \
          year=`echo $$date | cut -f6 -d" "`; \
         cd distribution; tar cvfz $(PROGRAM)-$$month-$$day-$$year.tar.gz $(PROGRAM))
	@rm -rf distribution/$(PROGRAM)
	@automake --add-missing --gnu >/dev/null 2>&1
	@autoconf  >/dev/null 2>&1
	@./configure >/dev/null 2>&1
	@echo "== distribution => done"


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

# built the mac table
# mact: mactable.h
#	@fgrep -e "(hex)" oui.txt | cut -c1-8,9,19- | sed -f mact.sed > mactable.h

# built the IPX SAP table
sapt: saptable.h
	@cat Internet/novell-sap-numbers | cut -c1-3 | sed -f sapt.sed > saptable.h


# download the vendor information table
dnvt:
	@(cd Internet; wget -c http://standards.ieee.org/regauth/oui/oui.txt)

# download the mac information table
#dnmact:
#	@(cd Internet; wget -c http://www.cavebear.com/CaveBear/Ethernet/vendor.html)

# download the Novell SAP Protocol information table
dnsapt:
	@(cd Internet; wget -c http://www.isi.edu/in-notes/iana/assignments/novell-sap-numbers)

#
# Below you can find some rules for
# building packages automatically. Most
# of them are outdated and need to be updated.
# 

#
# rpm for Suse 7 (tested on 7.3)
# Based on work of Ralf.Amandi <ralf.amandi@accordata.net>
#
make-suse:
	./configure --prefix=/usr --mandir=/usr/share/man --localstatedir=/var/lib
	make
	make install
	$(mkinstalldirs) /usr/share/man/man8/ /usr/share/man/man1/ /usr/share/doc/packages/ntop
	cp ntop.8 /usr/share/man/man8/
	cp intop/intop.1 /usr/share/man/man1/
	gzip -f /usr/share/man/man8/ntop.8
	gzip -f /usr/share/man/man1/intop.1
	cp -r docs/* /usr/share/doc/packages/ntop
	install -m 755  packages/suse/ntopd /etc/init.d/ntopd
	ln -sf ../../etc/init.d/ntopd /usr/sbin/rcntopd
	install -m 644  packages/suse/rc.config.ntopd /var/adm/fillup-templates/rc.config.ntopd
	mkdir -p /var/lib/ntop
	rpm -bb packages/suse/ntop.spec


#make-deb: ntop ntop.html
#	echo "Only root can do this. Wait please...."
#	cp ntop packages/debian/sbin
#	cp -r ntop.html html/* packages/debian$(etcdir)/html
#	chown root.sys packages/debian/sbin/ntop
#	chmod gou+x packages/debian/sbin/ntop
#	chmod u+s packages/debian/sbin/ntop
#	cp ntop.8 packages/debian/usr/man/man8
#	gzip packages/debian/usr/man/man8/ntop.8
#	dpkg-deb -b packages/debian packages/ntop-$(VERSION)-$(OSNAME).deb
#	rm packages/debian/sbin/ntop
#	rm packages/debian/usr/man/man8/ntop.8.gz
#
#make-generic: ntop ntop.html
#	cp ntop packages/generic/sbin
#	cp -r ntop.html html/* packages/generic$(etcdir)/html
#	chown root.sys packages/generic/sbin/ntop
#	chmod gou+x packages/generic/sbin/ntop
#	chmod u+s packages/generic/sbin/ntop
#	gzip packages/generic/usr/man/man8/ntop.8
#	cd packages/generic; tar cvf - . > ../ntop-$(VERSION)-$(OSNAME).tar
#	compress packages/ntop-$(VERSION)-$(OSNAME).tar
#	rm packages/generic/sbin/ntop
#	rm packages/generic/usr/man/man8/ntop.8.gz
#	rm packages/generic$(etcdir)/html/*
#
#make-slack: ntop ntop.html
#	echo "Only root can do this. Wait please...."
#	cp ntop packages/slackware/sbin
#	cp -r ntop.html html/* packages/slackware$(etcdir)/html
#	chown root.sys packages/slackware/sbin/ntop
#	chmod gou+x packages/slackware/sbin/ntop
#	chmod u+s packages/slackware/sbin/ntop
#	gzip packages/slackware/usr/man/man8/ntop.8
#	cd packages/slackware; tar cvfz - . > ../ntop-$(VERSION)-slackware.tgz
#	mv packages/ntop-$(VERSION)-slackware.tgz packages/slackware
#	rm packages/slackware/sbin/ntop
#	rm packages/slackware/usr/man/man8/ntop.8.gz
#	rm packages/slackware$(etcdir)/html/*
#	echo "The package file is under packages/slackware: have fun!"
#
#
#make-bsd: ntop ntop.html
#	echo "Only root can do this. Wait please...."
#	cp ntop packages/freebsd/sbin
#	cp -r ntop.html html/* packages/freebsd$(etcdir)/html
#	chown root.sys packages/freebsd/sbin/ntop
#	chmod gou+x packages/freebsd/sbin/ntop
#	chmod u+s packages/freebsd/sbin/ntop
#	gzip packages/freebsd/usr/man/man8/ntop.8
#	cd packages/freebsd; tar cvfz - . > ../ntop-$(VERSION)-freebsd.tgz
#	mv packages/ntop-$(VERSION)-freebsd.tgz packages/freebsd
#	rm packages/freebsd/sbin/ntop
#	rm packages/freebsd/usr/man/man8/ntop.8.gz
#	rm packages/freebsd$(etcdir)/html/*
#	echo "The package file is under packages/freebsd: have fun!"
#
#
#make-solaris: ntop ntop.html
#	echo "Only root can do this. Wait please...."
#	/bin/rm -rf /opt/ntop
#	/bin/rm -rf /var/spool/ntop
#	$(mkinstalldirs) -p /opt/ntop/bin
#	$(mkinstalldirs) -p /opt/ntop/man/man8
#	$(mkinstalldirs) -p /opt/ntop$(etcdir)/html
#	cp ntop /opt/ntop/bin
#	cp -r ntop.html html/* /opt/ntop$(etcdir)/html
#	chown -R bin /opt/ntop
#	chgrp -R bin /opt/ntop
#	chmod gou+x /opt/ntop/bin/ntop
#	chmod u+s /opt/ntop/bin/ntop
#	cp ntop.8 /opt/ntop/man/man8
#	cd /opt/ntop; find . -print | pkgproto > prototype
#	echo "i pkginfo=/opt/ntop/pkginfo" >> prototype
#	cat /opt/ntop/prototype >> prototype
#	mv prototype /opt/ntop/prototype
#	cp packages/solaris/ntop/pkginfo /opt/ntop
#	cd /opt/ntop; pkgmk -o -r `pwd`
#	cd /var/spool/pkg; pkgtrans -o -s `pwd` /tmp/ntop-$(VERSION)-solaris.$(MACHTYPE)
#	cd /tmp; gzip ntop-$(VERSION)-solaris.$(MACHTYPE)
#	/bin/rm -rf /opt/ntop
#	/bin/rm -rf /var/spool/ntop
#	echo "The package file is in /tmp/ntop-$(VERSION)-solaris.$(MACHTYPE).gz: have fun!"
