# Copyright 1999-2003 Gentoo Technologies, Inc.
# Distributed under the terms of the GNU General Public License v2
# $Header$

IUSE="ssl tcpd"

S=${WORKDIR}/ntop-3.0pre2
DESCRIPTION="ntop is a unix tool that shows network usage like top"
SRC_URI="mirror://sourceforge/ntop/ntop-3.0pre2.tgz"
HOMEPAGE="http://www.ntop.org/ntop.html"

SLOT="0"
LICENSE="GPL-2"
KEYWORDS="x86 ~ppc ~sparc hppa"

DEPEND=">=sys-libs/gdbm-1.8.0
	>=net-libs/libpcap-0.6.2
	tcpd? ( >=sys-apps/tcp-wrappers-7.6-r4 )
	ssl? ( >=dev-libs/openssl-0.9.6 )
	media-libs/libgd
	media-libs/libpng"
DEPEND=">=sys-libs/gdbm-1.8.0
	>=net-libs/libpcap-0.6.2
	media-libs/libgd
	media-libs/libpng"

src_compile() {
	cd ${S}

        mv configure.in configure.zzz
        cat configure.zzz | \
          sed -e 's/NTOP_VERSION_EXTRA=""/NTOP_VERSION_EXTRA="Gentoo ebuild"/' > configure.in

	local myconf

	use tcpd	|| myconf="${myconf} --with-tcpwrap"
	use ssl		|| myconf="${myconf} --without-ssl"

	# ntop 3.0 ships with its own version of rrd, myrrd.
	# ntop must be built with the static version it ships with
	econf ${myconf} || die "configure problem"
	make || die "compile problem"
}

src_install () {
	make DESTDIR=${D} install || die "install problem"

	doman ntop.8

        dodoc AUTHORS ChangeLog CONTENTS COPYING INSTALL MANIFESTO
        dodoc NEWS PORTING README SUPPORT_NTOP.txt THANKS
	dodoc docs/*

	dohtml ntop.html faq.html

	exeinto /etc/init.d ; newexe ${FILESDIR}/ntop-init ntop
	insinto /etc/conf.d ; newins ${FILESDIR}/ntop-confd ntop

        dodir /var/lib/ntop
        fowners nobody:nobody /var/lib/ntop
	keepdir /var/lib/ntop

}

