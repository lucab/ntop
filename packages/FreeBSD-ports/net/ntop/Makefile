# New ports collection makefile for:   ntop
# Date created:        April 2003
# Whom:                Burton Strauss <burton@ntopsupport.com>
#
# $FreeBSD: ports/net/ntop/Makefile,v 1.26 2003/02/20 18:51:01 knu Exp $
#

PORTNAME=	ntop
PORTVERSION=	3.0pre2
PORTREVISION=	0
CATEGORIES=	net
MASTER_SITES= 	${MASTER_SITE_SOURCEFORGE}
MASTER_SITE_SUBDIR=	sourceforge/ntop/
COMMENT=        network monitor

DISTNAME=	${PORTNAME}-${PORTVERSION:S|.r|-rc|}
EXTRACT_SUFX=	.tgz

MAINTAINER=	ports@FreeBSD.org

# Besides the required dependencies listed here, this port can optionally
# make use of sysutils/lsof if installed.
LIB_DEPENDS=	gdbm:${PORTSDIR}/databases/gdbm
BUILD_DEPENDS=	

# ntop will store its runtime database files in ${DBDIR}/ntop/
DBDIR?=		/var/db

# The default startup script in ${LOCALBASE}/etc/rc.d will invoke
# with a flag to force it to log to ${LOGDIR}
LOGDIR?=	/var/log

WRKSRC=		${WRKDIR}/${PORTNAME}-${PORTVERSION}
USE_GMAKE=	yes
USE_LIBTOOL=	yes
INSTALLS_SHLIB=	yes
PLIST_SUB+=	DBDIR=${DBDIR}
PKGMESSAGE=	${WRKDIR}/pkg-message
CONFIGURE_ARGS=	--localstatedir=${DBDIR} \
		--with-gdbm-root=${LOCALBASE} \
		--with-ossl-include=/usr/include/openssl  \
		--with-zlib-include=/usr/include/net  \
		--with-rrd-root=${LOCALBASE} \
		--with-gdchart-root=${LOCALBASE} \
		--with-rrd-root=${LOCALBASE} \
		--with-gd-root=${LOCALBASE} \
		--with-png-include=${LOCALBASE}/include/libpng  \
		--with-png-lib=${LOCALBASE} \
		--enable-i18n \
		--with-localedir=/usr/share/locale

.if !defined(WITHOUT_TCPWRAP)
CONFIGURE_ARGS+=	--enable-tcpwrap
.endif

.include <bsd.port.pre.mk>

MAN8=		ntop.8

# Remove included dependencies as a precaution against polluting the
# configuration.  Not strictly necessary.
pre-configure:
	@ ${RM} -rf ${WRKDIR}/${PORTNAME}-${PORTVERSION}/gdchart*

post-configure:
	@ ${SED} -e 's#%%LOCALBASE%%#${LOCALBASE}#g' \
	  pkg-message > ${PKGMESSAGE}

post-install:
	@ if ! pw groupshow ntop 2>&1 > /dev/null; then pw groupadd ntop; fi
	@ if ! pw usershow ntop 2>&1 > /dev/null; then pw useradd ntop -g ntop -s /sbin/nologin; fi
	@ ${MKDIR} ${DBDIR}/${PORTNAME}
	@ ${MKDIR} ${DBDIR}/${PORTNAME}/rrd
	@ chown -R ntop:ntop ${DBDIR}/${PORTNAME}
	@ mv ${PREFIX}/man/man8/i386-portbld-freebsd*-ntop.8 ${PREFIX}/man/man8/ntop.8
	@ mv ${PREFIX}/bin/i386-portbld-freebsd*-ntop ${PREFIX}/bin/ntop
	@ ${MKDIR} ${PREFIX}/etc/rc.d
	@ ${SED} -e "s#%%PREFIX%%#${PREFIX}#g" \
	  -e "s#%%LOGDIR%%#${LOGDIR}#g" ${FILESDIR}/ntop.sh > \
	  ${WRKDIR}/ntop.sh
	@ ${INSTALL_DATA} ${WRKDIR}/ntop.sh ${PREFIX}/etc/rc.d
	@ ${SED} -e "s#%%DBDIR%%#${DBDIR}#g" \
	  ${FILESDIR}/ntop.conf.sample > \
	  ${WRKDIR}/ntop.conf.sample
	@ ${INSTALL_DATA} ${WRKDIR}/ntop.conf.sample ${PREFIX}/etc/ntop
.if !defined(BATCH)
	@ ${CAT} ${PKGMESSAGE}
.endif

.include <bsd.port.post.mk>
