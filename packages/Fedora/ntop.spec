%bcond_without  fedora

# Once this package has passed review, a formal uid should be assigned.
# http://fedoraproject.org/wiki/PackageUserRegistry
%define         registry_uid   %nil
%define         registry_name  ntop

%define         cvsversion     20070608cvs

Name:           ntop
Version:        3.3
Release:        0.13.%{cvsversion}%{?dist}
Summary:        A network traffic probe similar to the UNIX top command

Group:          Applications/Internet
License:        GPL
URL:            http://www.ntop.org
#Source0:        http://downloads.sourceforge.net/ntop/ntop-3.3.tgz
# This source comes from the ntop cvs.  It is a pre-release of the 3.3 source.
# It was taken on 2007-Jun-08.  You can recreate this tarball with the
# following commands:
#   CVSROOT=:pserver:anonymous@cvs.ntop.org:/export/home/ntop
#   cvs login               (enter 'ntop' as password)
#   cvs checkout -D "2007-06-08 00:00:00 UTC" ntop
#   tar -cvzf ntop-20070608cvs.tar.gz ntop
Source0:        ntop-%{cvsversion}.tar.gz
Source1:        ntop.init

Patch0:         ntop-conf.patch
Patch1:         ntop-am.patch
Patch2:         ntop-running-user.patch
Patch3:         ntop-dbfile-default-dir.patch
Patch4:         ntop-remove-rc.patch
Patch10:        ntop-shrext.patch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  autoconf, automake, pkgconfig, libtool, groff, libpcap-devel
BuildRequires:  gdbm-devel, gd-devel, rrdtool-devel, openssl-devel
BuildRequires:  net-snmp-devel, lm_sensors-devel, fedora-usermgmt-devel
BuildRequires:  pcre-devel, mysql-devel

%if 0%{?fedora} >= 7
BuildRequires:  tcp_wrappers-devel
%else
BuildRequires:  tcp_wrappers
%endif

Requires:       initscripts
Requires(post): /sbin/chkconfig       
Requires(preun):/sbin/chkconfig       
%{?FE_USERADD_REQ}


%description
ntop is a network traffic probe that shows the network usage, similar to what
the popular top Unix command does. ntop is based on libpcap and it has been
written in a portable way in order to virtually run on every Unix platform and
on Win32 as well.

ntop users can use a a web browser (e.g. netscape) to navigate through ntop
(that acts as a web server) traffic information and get a dump of the network
status. In the latter case, ntop can be seen as a simple RMON-like agent with
an embedded web interface. The use of:

    * a web interface
    * limited configuration and administration via the web interface
    * reduced CPU and memory usage (they vary according to network size and
      traffic) 

make ntop easy to use and suitable for monitoring various kind of networks.

ntop should be manually started the first time so that the administrator
password can be selected.


%prep
%setup -q -n ntop

# While we are using CVS, kill all the CVS files and directories
find . -type d -name CVS | xargs rm -rf

# executable bits are set on some config files and docs that go into
# %%{_sysconfdir}/ntop and %%{_datadir}, and some debug source files.  Remove
# the execute bits - in the build directory
find . \( -name \*\.gz -o -name \*\.c -o -name \*\.h -o -name \*\.pdf \
     -o -name \*\.dtd -o -name \*\.html -o -name \*\.js \) -print     \
     | xargs chmod a-x

%patch0 -p1 -b .conf
%patch1 -p1 -b .am
%patch2 -p1 -b .user
%patch3 -p1 -b .dbfile-default-dir
%patch4 -p1 -b .remove-rc
%patch10 -R -p1 -b .shrext


%build
autoreconf -i -f

#export CFLAGS="%{optflags} -DDEBUG"
%{configure} --enable-optimize                         \
             --with-tcpwrap                            \
             --enable-largerrdpop                      \
             --enable-sslv3                            \
             --enable-i18n                             \
             --enable-snmp                             \
             --enable-mysql                            \
             --disable-static

%{__make} %{?_smp_mflags} faq.html ntop.txt ntop.html all


%install
%{__rm} -rf $RPM_BUILD_ROOT
%{__make} install install-data-local install-data-as DESTDIR=$RPM_BUILD_ROOT

# Now add init, etc
%{__install} -d $RPM_BUILD_ROOT/%{_initrddir}
%{__install} -p -m 0755 %SOURCE1 $RPM_BUILD_ROOT/%{_initrddir}/ntop
%{__install} -p -m 0644 packages/RedHat/ntop.conf.sample $RPM_BUILD_ROOT/%{_sysconfdir}/ntop.conf

# remove libtool archives and -devel type stuff (but leave dlopened modules)
#find $RPM_BUILD_ROOT -name \*\.la -print -o -name \*\.a -print | xargs rm -f
find $RPM_BUILD_ROOT -name \*\.la -print | xargs rm -f
# these are not dlopened modules, but -devel cruft
rm -f $RPM_BUILD_ROOT/%{_libdir}/lib{myrrd,ntop,ntopreport,*Plugin*}.so

# strip off version number from plugin .so files
for file in $RPM_BUILD_ROOT/%{_libdir}/%{name}/plugins/*so; do
  if test -L $file; then
    base=`basename $file .so`
    mv $RPM_BUILD_ROOT/%{_libdir}/%{name}/plugins/$base-%{version}.so $file
  fi
done

# Create files to be %ghost'ed - %ghost'ed files must exist in the buildroot
%{__install} -d $RPM_BUILD_ROOT/%{_localstatedir}/lib/ntop/rrd/{flows,graphics}
%{__install} -d $RPM_BUILD_ROOT/%{_localstatedir}/lib/ntop/rrd/interfaces
touch $RPM_BUILD_ROOT/%{_localstatedir}/lib/ntop/{addressQueue,dnsCache,fingerprint,LsWatch,macPrefix,ntop_pw,prefsCache}.db

%clean
%{__rm} -rf $RPM_BUILD_ROOT

%pre
if [ $1 = 1 ]; then
  %{__fe_groupadd} %{registry_uid} -r ntop &> /dev/null || :
  %{__fe_useradd}  %{registry_uid} -r -s /sbin/nologin  \
                   -d %{_localstatedir}/lib/ntop -M -c 'ntop' \
                   -g %{registry_name} %{registry_name} &> /dev/null || :
fi

%post
if [ $1 = 1 ]; then
  /sbin/chkconfig --add %{name} &> /dev/null || :
fi

%preun
if [ $1 = 0 ]; then
  /sbin/service %{name} stop    &> /dev/null || :
  /sbin/chkconfig --del %{name} &> /dev/null || :
fi

%postun
if [ "$1" -ge "1" ]; then
  /sbin/service %{name} condrestart &> /dev/null || :
else
  %{__fe_userdel}  %{registry_name} &> /dev/null || :
  %{__fe_groupdel} %{registry_name} &> /dev/null || :
fi

%files
%defattr(-,root,root,-)
%doc AUTHORS ChangeLog COPYING MANIFESTO
%doc docs/BUG_REPORT docs/database/README docs/database/README.mySQL docs/FAQ
%doc docs/FAQarchive docs/FAQ docs/HACKING docs/KNOWN_BUGS docs/TODO
%doc docs/1STRUN.txt NEWS README SUPPORT_NTOP.txt THANKS
%config(noreplace) %{_sysconfdir}/ntop.conf
%config(noreplace) %{_sysconfdir}/ntop
%{_initrddir}/ntop
%{_sbindir}/*
%{_libdir}/lib*%{version}*.so
%{_libdir}/ntop
%{_mandir}/man8/*
%{_datadir}/ntop
%dir %{_localstatedir}/lib/ntop
%defattr(0640,root,root,-)
%ghost %{_localstatedir}/lib/ntop/addressQueue.db
%ghost %{_localstatedir}/lib/ntop/dnsCache.db
%ghost %{_localstatedir}/lib/ntop/fingerprint.db
%ghost %{_localstatedir}/lib/ntop/LsWatch.db
%ghost %{_localstatedir}/lib/ntop/macPrefix.db
%ghost %{_localstatedir}/lib/ntop/ntop_pw.db
%ghost %{_localstatedir}/lib/ntop/prefsCache.db
# This will catch all the directories in rrd.  If %ghost'ed files are added
# under rrd, this will have to be changed to %dir and more directives for
# directories under rrd will have to be added.
%defattr(0770,root,ntop,-)
%{_localstatedir}/lib/ntop/rrd

%changelog
* Wed Jun 08 2007 Bernard Johnson <bjohnson@symetrix.com> - 3.3-0.13.20070608cvs
- update to 20070608cvs
- update patch to remove rc version
- remove remove-gd-version-guess.patch (not needed anymore)
- remove xmldump plugin dependencies since it has been disabled (broken) in
  default ntop installation

* Fri Apr 06 2007 Bernard Johnson <bjohnson@symetrix.com> - 3.3-0.12.20070407cvs
- update to 20070407cvs
- compile with -DDEBUG for now to check for problems
- rework ntop-am.patch with recent changes
- patch to remove gdVersionGuessValue from plugin
- repatch with shrext patch

* Mon Mar 19 2007 Bernard Johnson <bjohnson@symetrix.com> - 3.3-0.11.20070319cvs
- update to 20070319cvs
- remove patches that have been added upstream

* Fri Mar 16 2007 Bernard Johnson <bjohnson@symetrix.com> - 3.3-0.10.20070314cvs
- fix rpmlint warning for initfile
- include 2 of Patrice's patches to cleanup builds
- remove repotag

* Fri Mar 16 2007 Bernard Johnson <bjohnson@symetrix.com> - 3.3-0.9.20070314cvs
- update to 20070314cvs
- add additional mysql patch from Patrice
- remove all of unused logrotate pieces
- use /sbin/service to start/stop services
- update scriptlets to be easier to read
- Better description to initfile summary
- add LSB bits to initfile

* Mon Mar 07 2007 Bernard Johnson <bjohnson@symetrix.com> - 3.3-0.8.20070307cvs
- update to 20070307cvs
- move database files to %%{_localstatedir}/lib/ntop
- fix javascript files not being installed
- remove x bit from additional javascript files

* Sat Mar 03 2007 Bernard Johnson <bjohnson@symetrix.com> - 3.3-0.6.20060207cvs
- add --enable-mysql to compile mysql support

* Sat Mar 03 2007 Bernard Johnson <bjohnson@symetrix.com> - 3.3-0.5.20060207cvs
- prefix patches with ntop-
- explanation on how to retrieve cvs source
- fix removal of %%{_libdir}/.so plugin files no matter the version
- reduce dependency on mysql-server to just mysql

* Fri Mar 02 2007 Bernard Johnson <bjohnson@symetrix.com> - 3.3-0.4.20060227cvs
- add pcre-devel to BR so payloads can be matched
- remove unused Source4 line
- enabled mysql storage of net flow data

* Tue Feb 27 2007 Bernard Johnson <bjohnson@symetrix.com> - 3.3-0.3.20060227cvs
- update to ntop cvs 20060227
- kill all the CVS files/directories
- remove glib2-devel BR because gdome2-devel requires it
- tcp_wrappers vs. tcp_wrappers-devel no dependent on os release
- add initscripts to requires since init file uses daemon function
- patch .so files to just version 3.3 not 3.3rc0; otherwise rpmlint complains
- fix typo in init file

* Wed Feb 18 2007 Bernard Johnson <bjohnson@symetrix.com> - 3.3-0.2.20060218cvs
- update to ntop cvs 20060208

* Wed Feb 07 2007 Bernard Johnson <bjohnson@symetrix.com> - 3.3-0.1.20060207cvs
- update to ntop cvs 20060207
- remove gdbm, pidfile, and FEDORAextra patches
- ntopdump.dtd has fixed eol markers now
- update nolibs patch so there is no complaint about xmldump libraries/headers

* Tue Feb 06 2007 Bernard Johnson <bjohnson@symetrix.com> - 3.2-8.1.20060206cvs
- update to cvs 20060206
- update ntop-am.patch for cvs version
- get rid of plugins patch and just remove cruft in spec file

* Thu Dec 14 2006 Bernard Johnson <bjohnson@symetrix.com> - 3.2-7
- add missing net-snmp-devel, and lm_sensors-devel BR

* Thu Dec 14 2006 Bernard Johnson <bjohnson@symetrix.com> - 3.2-6
- configure --disable-static
- configure --enable-snmp
- patch to fix permissions of created gdbm databases
- no more ntop-passwd
- fix OK printing in init file, redirect stdout of ntop command to null
- fix permissions on LsWatch.db database creation
- only listen on 127.0.0.1:3000 by default

* Mon Dec 11 2006 Bernard Johnson <bjohnson@symetrix.com> - 3.2-5
- use ntop.conf.sample with some modifications
- change default syslog facilty to daemon in init file
- add repo tag for those who want to use it
- install as-data by default, at least for now
- fix package detection of gdome library
- remove extraneous ldconfig call

* Mon Dec 11 2006 Bernard Johnson <bjohnson@symetrix.com> - 3.2-4
- fix detection of glib-2.0 and gdome2
- remove Requires: entries to let rpm figure them out
- remove BR libxml2, zlib-devel as they are pulled by other packages
- added scriplet requires for /sbin/chkconfig
- add logrotate to requires
- add BR dependency on pkgconfig since patch to fix missing files depends on it

* Mon Dec 11 2006 Bernard Johnson <bjohnson@symetrix.com> - 3.2-3
- fix: do not package debug files in arch package
- fix: remove x bit from /usr/src debug files
- fix: direct source download link
- fix: don't package devel libraries in /usr/lib
- integrate previous package ntop.sysv to ntop.init
- remove sysconfig file
- clean up usage of fedora-usermgt
- remove ldconfig calls
- create a ntop-passwd wrapper to set the passwd
- fix: directory permission in directory, init, and passwd wrapper

* Sat Dec 09 2006 Bernard Johnson <bjohnson@symetrix.com> - 3.2-2
- revert to 3.2 sources
- integrate changes from previous package

* Fri Dec 08 2006 Bernard Johnson <bjohnson@symetrix.com> - 3.2-1.20061208cvs
- initial package
