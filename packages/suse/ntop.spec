#
# spec file for package ntop (Version 2)
# 
# Copyright  (c)  2001  SuSE GmbH  Nuernberg, Germany.
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
# 
# please send bugfixes or comments to feedback@suse.de.
#

# neededforbuild  gpp libgpp libpcap libpng lsof openssl openssl-devel readline readline-devel ucdsnmp
# usedforbuild    aaa_base aaa_dir autoconf automake base bash bindutil binutils bison bzip compress cpio cpp cracklib cyrus-sasl db devs diffutils e2fsprogs file fileutils findutils flex gawk gcc gdbm gdbm-devel gettext glibc glibc-devel gpm gpp gppshare grep groff gzip kbd less libgpp libpcap libpng libtool libz lsof m4 make man mktemp modutils ncurses ncurses-devel net-tools netcfg openssl openssl-devel pam pam-devel patch perl ps rcs readline readline-devel rpm sendmail sh-utils shadow strace syslogd sysvinit texinfo textutils timezone ucdsnmp unzip util-linux vim

Name:         ntop
Copyright:    GPL
Group:        Networking/Utilities
Autoreqprov:  on
Version:      2.0
Release:      0
Summary:      Web-based Network Traffic Monitor
Source:       ntopd
Source1:      rc.config.ntopd
URL:          http://www.ntop.org

%description
ntop is a web-based traffic monitor that shows the network usage.
It can be used in both interactive or web mode using the
embedded web server.

Authors:
--------
    Luca Deri <deri@ntop.org>

SuSE series: n

%post
echo "Updating etc/rc.config..."
if [ -x bin/fillup ] ; then
    bin/fillup -q -d = etc/rc.config var/adm/fillup-templates/rc.config.ntopd
else
    echo "ERROR: fillup not found. This should not happen. Please compare"
    echo "etc/rc.config and var/adm/fillup-templates/rc.config.ntopd and"
    echo "update by hand."
fi
##### send mail to root #####
mkdir -p var/adm/notify/messages
cat << EOT > var/adm/notify/messages/ntopd-notify
ntop is a tool that shows the network usage
-------------------------------------------
Supposing to start  ntop  at  the port  3000,
the  URL  to  access  is http://hostname:3000/
Administrators can protect with password selected URLs.
All the administration is performed with ntop.
The default administrator user is 'admin' with password 'admin'.
Make sure you change these default settings for your own security.
Please note that an HTTP server is NOT needed  in
order to use the program in interactive mode.
EOT
# This will make the links for init.
sbin/insserv etc/init.d/ntopd

%postun
sbin/insserv etc/init.d/

%files
#%doc docs
%config /etc/init.d/ntopd
/usr/bin/intop
/usr/bin/ntop
/usr/bin/ntop-cert.pem
/usr/bin/ntop-config
/usr/lib/libicmpPlugin.*
/usr/lib/liblastSeenPlugin.*
/usr/lib/libnfsPlugin.*
/usr/lib/libntop-2.0.*
/usr/lib/libntop.*
/usr/lib/libntopreport-2.0.*
/usr/lib/libntopreport.*
/usr/sbin/rcntopd
%dir /usr/share/ntop
/usr/share/ntop/html
%dir /usr/lib/ntop
/usr/lib/ntop/plugins
%doc %{_mandir}/man1/intop.1.gz
%doc %{_mandir}/man8/ntop.8.gz
/var/adm/fillup-templates/rc.config.ntopd
%dir /var/lib/ntop

%changelog -n ntop
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
