#
# spec file for package ntop (Version 2)
# 
# (c) Pablo Ruiz Garcia 2002 (pruiz@ip6seguridad.com)
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
# 
#

%define ntopversion %{!?version:2.0} %{?version:%version}
%define ntoprelease 1

Name:         ntop
Copyright:    GPL
Group:        Networking/Utilities
Autoreqprov:  on
Version:      %{ntopversion}
Release:      %( ([ "%version" != "current" ]&& echo "%ntoprelease") || echo "%(date +%d%m%Y)" )
Summary:      Web-based Network Traffic Monitor
Source:		ntop-%{version}%([ "%version" != "current" ]&& echo "-src").tgz
Source1:       ntopd
URL:          http://www.ntop.org
Buildroot:	%{_tmppath}/%{name}-root
%define prefix /usr

%description
ntop is a web-based traffic monitor that shows the network usage.
It can be used in both interactive or web mode using the
embedded web server.

Authors:
--------
    Luca Deri <deri@ntop.org>
    Pablo Ruiz <pruiz@ip6seguridad.com>

%prep
if [ -n "$RPM_BUILD_ROOT" ] ; then
   [ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
fi
%setup -c ntop-%{version}
if [ -n "ntop-%{version}" ] ; then
	[ "ntop-%{version}" == "ntop-current" ] && cd ntop-current
fi
cd gdchart0.94c/
rm -rf gd-1.8.3
rm -rf zlib-1.1.3
sed -e 's/\(all:.*\)\$.GD_LIB.\/libgd.a\(.*\)/\1 \2/g' Makefile.in > Make.tmp
mv Make.tmp Makefile.in
CFLAGS="${RPM_OPT_FLAGS}" ./configure
make
cd ..
cd ntop
mkdir ../gdchart0.94c/zlib-1.1.3/
touch ../gdchart0.94c/zlib-1.1.3/libz.a
mkdir ../gdchart0.94c/gd-1.8.3/
touch ../gdchart0.94c/gd-1.8.3/libgd.a
touch ../gdchart0.94c/gd-1.8.3/gd.h
CFLAGS="${RPM_OPT_FLAGS}" ./configure --prefix=%{prefix} --mandir=%{_mandir} --sysconfdir=/etc/ntop --localstatedir=/var/lib
rm -rf ../gdchart0.94c/zlib-1.1.3/
rm -rf ../gdchart0.94c/gd-1.8.3/
make

%install
if [ -n "$RPM_BUILD_ROOT" ] ; then
   [ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
fi
mkdir -p "$RPM_BUILD_ROOT/usr/share/man/man1/intop"
cd ntop
mkdir -p "$RPM_BUILD_ROOT/etc/rc.d/init.d"
mkdir -p "$RPM_BUILD_ROOT/etc/init.d"
make install DESTDIR="${RPM_BUILD_ROOT}"
mv $RPM_BUILD_ROOT/usr/share/man/man1/intop/* "$RPM_BUILD_ROOT/usr/share/man/man1/"
chmod +x ${RPM_BUILD_ROOT}%{prefix}/lib/*.so.*.*
install -m 755 %{S:1}           ${RPM_BUILD_ROOT}/etc/init.d/ntopd
mkdir -p ${RPM_BUILD_ROOT}/var/lib/ntop
mv $RPM_BUILD_ROOT/etc/init.d/* "$RPM_BUILD_ROOT/etc/rc.d/init.d/"

%post
/sbin/chkconfig --add ntopd

%postun
if [ "$1" = 0 ]
then
	/sbin/service ntopd stop > /dev/null 2>&1 || :
	/sbin/chkconfig --del ntopd
fi
/sbin/service ntopd condrestart > /dev/null 2>&1 || :

%files
#%doc docs
%config /etc/rc.d/init.d/ntopd
/usr/bin/intop
/usr/bin/ntop
/usr/bin/ntop-config
/usr/lib/libicmpPlugin.*
/usr/lib/liblastSeenPlugin.*
/usr/lib/libnfsPlugin.*
/usr/lib/libntop-2.0.*
/usr/lib/libntop.*
/usr/lib/libntopreport-2.0.*
/usr/lib/libntopreport.*
%dir /usr/share/ntop
/usr/share/ntop/html
%dir /usr/lib/ntop
/usr/lib/ntop/plugins
%doc %{_mandir}/man1/intop.1.gz
%doc %{_mandir}/man8/ntop.8.gz
%dir /var/lib/ntop

%changelog -n ntop
* Tue Jan 22 2002 - pruiz@ip6seguridad.com
- Modified to work with Redhat
- Modified to work with current and 2.0
* Sun Dec 23 2001 - deri@ntop.org
- Updated to version 2.0
* Wed Jul 18 2001 - uli@suse.de
- fixed OS ident via nmap
* Thu Jul 05 2001 - bg@suse.de
- fix Bug #9056
- add ucdsnmp and ssl
- activate gdchart
* Mon Jun 11 2001 - bg@suse.de
- moved AC_INIT to the beginning of configure.in
* Wed May 09 2001 - mfabian@suse.de
- bzip2 sources
* Fri Feb 23 2001 - ro@suse.de
- added readline/readline-devel to neededforbuild (split from bash)
* Fri Dec 01 2000 - ro@suse.de
- moved startscript to etc
* Fri Nov 24 2000 - bg@suse.de
- cleaned up specfile with ro
* Thu Nov 23 2000 - bg@suse.de
- removed runlevel links in ntop.spec
- fixed init script for 7.1
* Fri Nov 10 2000 - bg@suse.de
- new verion 1.3.2
  this fixes Bug #4121
* Fri Oct 13 2000 - kukuk@suse.de
- fix compiling with glibc 2.2
* Mon Aug 28 2000 - ro@suse.de
- cvs-update of 2000/08/28 (all patches included)
* Tue Aug 15 2000 - ro@suse.de
- update to cvs version of 2000/08/15
* Tue Aug 15 2000 - ro@suse.de
- removed deprecated referring to .ntop
* Wed Jul 05 2000 - ro@suse.de
- fixed another segfault
* Fri Jun 30 2000 - ro@suse.de
- added fix for segfault from cvs
* Tue Jun 27 2000 - ro@suse.de
- update to 1.3.1
* Sat Mar 04 2000 - uli@suse.de
- moved man page to %%{_mandir}
* Thu Jan 13 2000 - freitag@suse.de
- dropped own libpcap and use one in needforbuild
- update to version 1.1
- using configure instead of own Makefile
- new tags in specfile like version
* Mon Sep 13 1999 - bs@suse.de
- ran old prepare_spec on spec file to switch to new prepare_spec.
* Sat Jun 12 1999 - ray@suse.de
- fix in init-script
* Tue Dec 01 1998 - ray@suse.de
- new package

