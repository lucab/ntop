%define ntoproot	/usr

Summary: ntop shows the network usage
Name: ntop
Version: 3.0rc1
Release: 0
Source: ntop-3.0rc1.tgz
Source1: ntop.init
Source2: ntop.logrotate
Source3: ntop.conf.sample
Source4: 1STRUN.txt
Source5: FAQ
Patch1: version.patch
#Patch2: makefile_am.patch
Copyright: GPL
Group: Applications/System
BuildPrereq: glibc, glibc-devel, gcc, cpp, gawk, autoconf, automake, binutils, openssl, openssl-devel, gdbm, gdbm-devel, libpcap, zlib-devel, glib-devel
Requires: glibc, openssl, gdbm, libpcap, chkconfig

Buildroot: %{_tmppath}/%{name}-root
Prereq: /sbin/chkconfig, /sbin/ldconfig

%description
ntop is a network and traffic analyzer that provides a wealth of information on
various networking hosts and protocols. ntop is primarily accessed via a built-in 
web interface. Optionally, data may be stored into a database for analysis or 
extracted from the web server in formats suitable for manipulation in perl or php.

See 1STRUN.txt for the 1st time startup procedure!  See FAQ for answers to questions.

ntop 3.0rc1 is a TEST release, from the ntop cvs tree at cvs.ntop.org.
Our intention is to release this or something much like it as ntop 3.0
in a short period of time.

There are no major changes 3.0pre2... minor stuff:

  * A few minor tweaks of things found by Valgrind
  * Luca's changes on how ntop reports dropped packets
  * Minor mods to the m4 macros so that the newest auto* tools don't choke
  * force_runtime added to version.c from configureextra
  * optional remote fingerprint page restored
  * make listlibclean and libclean options
  * Capture length problem, and Solaris 9's hate for ehdr.ether_dhost were fixed
  * Locale info added to info.html and textinfo.html

docs/FAQ has been extensively re-written!

For those upgrading from 2.2, note:

   gdchart is gone - replaced by a small, focused, internal graphics creator,
   graph.c.  We still use the gd library.

   This version is compiled with a frozen, captive version of rrdtool, called
   myrrd. It is compiled and linked automatically.

   The so-called 'large population model' for rrd data files is now standard.
   There is a script at SourceForge in the user contributed area to help
   convert - but backup your data FIRST.

   The netflow Plugin no longer acts as a probe (that is sending netflow
   packets to another device).

This version is compiled WITH SSLv3.

This version is compiled WITHOUT --enable-xmldump (dump.xml handler)

This version is compiled WITH --enable-i18n.

SSLWATCHDOG is not compiled but may be selected at run time.

Note that the command line version, intop, is gone.

This version is compiled on a Pentium III, under RedHat 9.0.

YOU MUST SETUP A PASSWORD BEFORE RUNNING NTOP - see 1STRUN.txt in /usr/share/doc/ntop-<release>

Please send problem reports (using the automatically generated form if at all possible)
(Click on the 'bug' icon on the About tab) to the ntop mailing list.

%prep
%setup -q -c ${NAME}${VERSION}

%build
unset RPM_OPT_FLAGS
%undefine optflags 
# Adjust the .tgz format to what we expect for build...
mv ntop-3.0rc1 ntop
# Patches
patch -p0 < ../../SOURCES/version.patch
#patch -p0 < ../../SOURCES/makefile_am.patch
cd ntop
# Now, configure and build ntop
# %automake
# %autoconf
%configure --enable-optimize  --bindir=%{_bindir} --datadir=%{ntoproot}/share \
     --enable-sslv3 \
     --enable-i18n
make faq.html
make ntop.txt
make ntop.html
make

%install
cd ntop
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d \
         $RPM_BUILD_ROOT/%{_bindir} \
         $RPM_BUILD_ROOT/etc/logrotate.d \
         $RPM_BUILD_ROOT/%{_datadir}/%{name}

make install DESTDIR=$RPM_BUILD_ROOT
make install-data-local DESTDIR=$RPM_BUILD_ROOT

if test -f $RPM_BUILD_ROOT/usr/bin/i386-redhat-linux-ntop; then
    mv -f $RPM_BUILD_ROOT/usr/bin/i386-redhat-linux-ntop \
          $RPM_BUILD_ROOT/usr/bin/ntop
fi
if test -f $RPM_BUILD_ROOT/usr/share/man/man8/i386-redhat-linux-ntop.8; then
    mv -f $RPM_BUILD_ROOT/usr/share/man/man8/i386-redhat-linux-ntop.8 \
          $RPM_BUILD_ROOT/usr/share/man/man8/ntop.8
fi

install -c -m0755 %{SOURCE1} $RPM_BUILD_ROOT/etc/rc.d/init.d/ntop
install -c -m0644 %{SOURCE2} $RPM_BUILD_ROOT/etc/logrotate.d/ntop
install -c -m0700 %{SOURCE3} $RPM_BUILD_ROOT/etc/ntop.conf.sample

%pre
g=`cat /etc/group | grep ^ntop:`
if test ".${g}" = "."; then
    /usr/sbin/groupadd -r ntop 2>/dev/null || :
fi
u=`cat /etc/passwd | grep ^ntop:`
if test ".${u}" = "."; then
    /usr/sbin/useradd -s /bin/false -c "ntop server user" -g ntop \
                      -d %{ntoproot}/share/ntop -M -r ntop 2>/dev/null || :
fi

%post
echo "***********************************************************************"
mkdir /usr/share/ntop/rrd
chown ntop:ntop /usr/share/ntop
echo "***********************************************************************"
if test -f /etc/init.d/ntop; then
    /sbin/chkconfig --add  ntop
    /sbin/ldconfig
    echo "***********************************************************************"
    if ! test -f /usr/share/ntop/ntop_pw.db; then
        if ! test -f /etc/ntop.conf; then
            echo "*    You must configure /etc/ntop.conf - see /etc/ntop.conf.sample    *"
            echo "*                                                                     *"
            echo "*    (as root run) $ cp /etc/ntop.conf.sample /etc/ntop.conf          *"
            echo "*                  $ vi /etc/ntop.conf                                *"
            echo "*                                                                     *"
            echo "***********************************************************************"
        fi
        echo "* YOU MUST SETUP A PASSWORD BEFORE RUNNING NTOP                       *"
        echo "*                                                                     *"
        echo "*       (as root run) $ /usr/bin/ntop @/etc/ntop.conf -A              *"
        echo "*                                                                     *"
        echo "*       see 1STRUN.txt in /usr/share/doc/ntop-<release>               *"
        echo "***********************************************************************"
    elif ! test -f /etc/ntop.conf; then
        echo "*    You must configure /etc/ntop.conf - see /etc/ntop.conf.sample    *"
        echo "*                                                                     *"
        echo "*    (as root run) $ cp /etc/ntop.conf.sample /etc/ntop.conf          *"
        echo "*                  $ vi /etc/ntop.conf                                *"
        echo "*                                                                     *"
    else
        echo "*                                                                     *"
        echo "*    Starting ntop using a pre-existing setup - check the results!    *"
        echo "*                                                                     *"
        /sbin/service ntop condrestart > /dev/null 2>&1
    fi
fi
echo "***********************************************************************"
echo " "
echo "Questions?  See the FAQ in /usr/share/doc/ntop-<release>"
echo " "

%preun
if [ "$1" = "0" ]; then
	/sbin/service ntop stop > /dev/null 2>&1
	/sbin/chkconfig --del ntop
fi

%postun
if [ "$1" -ge "1" ]; then
	/sbin/service ntop condrestart > /dev/null 2>&1
fi
/sbin/ldconfig

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc ntop/AUTHORS
%doc ntop/CONTENTS
%doc ntop/MANIFESTO
%doc ntop/COPYING
%doc ntop/ChangeLog
%doc ntop/docs/BUILD-NTOP.txt
%doc ntop/docs/FAQ
%doc ntop/docs/HACKING
%doc ntop/docs/KNOWN_BUGS
%doc ntop/docs/TODO
%doc ntop/docs/1STRUN.txt
%doc ntop/NEWS
%doc ntop/PORTING
%doc ntop/README
%doc ntop/SUPPORT_NTOP.txt
%doc ntop/THANKS
%config %{_sysconfdir}/rc.d/init.d/ntop
%config %{_sysconfdir}/logrotate.d/ntop
%config %{_sysconfdir}/ntop.conf.sample
%{_bindir}/ntop
%{_datadir}/%{name}
/etc/ntop

%{_mandir}/man8/ntop.8.gz

%{_libdir}/ntop
%{_libdir}/plugins
%{_libdir}/libntop*
%{_libdir}/lib*Plugin*

%changelog
* Thu Mar 18 2004 Burton M. Strauss III <burton@ntopsupport.com>
- v3.0rc1 - TEST release for 3.0

* Mon Mar 03 2004 Burton M. Strauss III <burton@ntopsupport.com>
- v3.0pre2 - TEST release for 3.0

* Mon Feb 16 2004 Burton M. Strauss III <burton@ntopsupport.com>
- v3.0pre1 - TEST release for 3.0

* Wed Sep 03 2003 Burton M. Strauss III <burton@ntopsupport.com>
- v2.2.94 - TEST release for 2.3

* Fri Aug 22 2003 Burton M. Strauss III <burton@ntopsupport.com>
- v2.2.93 - TEST release for 2.3

* Mon Jul  4 2003 Burton M. Strauss III <burton@ntopsupport.com>
- v2.2c   - Released - bug fixes incl backport from 2.2.2/2.2.3

* Mon Apr 14 2003 Burton M. Strauss III <burton@ntopsupport.com>
- v2.2    - Released!

* Thu Apr 10 2003 Burton M. Strauss III <burton@ntopsupport.com>
- v2.1.92 - Of major note is the rewrite of the ./configure system
            should be more accurate, more informative and not
            require the auto* tools for non-developers.

* Wed Apr 02 2003 Burton M. Strauss III <burton@ntopsupport.com>
- v2.1.91

* Mon Mar 17 2003 Burton M. Strauss III <burton@ntopsupport.com>
- v2.1.90

* Fri Mar 14 2003 Burton M. Strauss III <burton@ntopsupport.com>
- v2.1.58 -1 add the data and .pem files to the install

* Sat Feb 08 2003 Burton M. Strauss III <burton@ntopsupport.com>
- v2.1.57 - Minor fixup in ntop.init where I had the old name for ntop.conf
          - Enabled i18n
- v2.1.56 

* Tue Jan 28 2003 Burton M. Strauss III <burton@ntopsupport.com>
- v2.1.55 

* Sat Dec 14 2002 Burton M. Strauss III <burton@ntopsupport.com>
- -1 - Fix init and logrotate scripts, also create rrd directory and chown it
- v2.1.53 - Fix deadlock occuring in 2.1.52
          - other minor stuff

* Wed Dec 05 2002 Burton M. Strauss III <burton@ntopsupport.com>
- v2.1.52 - ./configure scripts
          - rrd
          - Force gdchart to i386
          - 1strun stuff
          - @/etc/ntop.conf

* Sun Nov 24 2002 Burton M. Strauss III <burton@ntopsupport.com>
- v2.1.51-1 (new tigger/ur-tigger)

* Fri Nov 1 2002 Burton M. Strauss III <burton@ntopsupport.com>
- v2.1.51

* Tue Sep 20 2002 Burton M. Strauss III <burton@ntopsupport.com>
- v2.1.3

* Tue Jul 30 2002 Burton M. Strauss III <burton@ntopsupport.com>
- v2.1.2a (not released) - added chkconfig to requires list
-                        - rearranged patches
-                        - Added creation of ntop user

* Thu Jul 25 2002 Burton M. Strauss III <burton@ntopsupport.com>
- v2.1.2

* Thu Jul 11 2002 Burton M. Strauss III <burton@ntopsupport.com>
- v2.1

* Thu Jul 03 2002 Burton M. Strauss III <burton@ntopsupport.com>
- Updated to RC3

* Thu Jun 20 2002 Burton M. Strauss III <burton@ntopsupport.com>
- Updated to RC2A - unofficial post RC2 build.

* Tue Jun 04 2002 Burton M. Strauss III <burton@ntopsupport.com>
- Updated to RC2

* Fri May 17 2002 Burton M. Strauss III <burton@ntopsupport.com>
- Updated to RC1

* Mon May 13 2002 Burton M. Strauss III <burton@ntopsupport.com>
- Updated for 2.0.99 - beta - from 13May2002 snapshot

* Fri Nov 23 2001 Hal Burgiss <hal@foobox.net>
- Updated for 2.0 beta.

* Thu Oct 11 2001 Hal Burgiss <hal@foobox.net>
- Updated for 2.0 pre-release snapshots. Many changes.

