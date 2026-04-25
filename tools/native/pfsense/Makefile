# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# pfSense pkg-build Makefile for TrustForge.
#
# pfSense packages are FreeBSD `pkg(8)` packages with a small XML
# overlay (see files/usr/local/pkg/trustforge.xml) that registers the
# package with pfSense's web UI. This Makefile produces a `.pkg` file
# suitable for upload to a pfSense Plus appliance and for inclusion in
# the upstream `pfSense-pkg-trustforge` port.
#
# Toolchain:   FreeBSD ports framework (bmake)
# Target host: pfSense Plus 23.x or later (FreeBSD 14-CURRENT base)

PORTNAME=	pfSense-pkg-trustforge
PORTVERSION=	0.1.0
CATEGORIES=	security
MASTER_SITES=	https://github.com/trustforge/trustforge/releases/download/v${PORTVERSION}/
DISTFILES=	tf-daemon-amd64-pfsense.tar.gz

MAINTAINER=	maintainers@trustforge.dev
COMMENT=	TrustForge identity, capability, and proof daemon for pfSense

LICENSE=	APACHE20 MIT
LICENSE_COMB=	dual

RUN_DEPENDS=	bash:shells/bash

NO_BUILD=	yes
NO_ARCH=	yes
USES=		shebangfix

SHEBANG_FILES=	files/usr/local/etc/rc.d/trustforge.sh

SUB_FILES=	pkg-descr pkg-plist
SUB_LIST=	PORTNAME=${PORTNAME} PORTVERSION=${PORTVERSION}

# pfSense expects the XML package descriptor to land in
# /usr/local/pkg/, the rc script in /usr/local/etc/rc.d/, and the web
# UI PHP page in /usr/local/www/. The pkg-plist enumerates the exact
# install paths.
do-install:
	@${MKDIR} ${STAGEDIR}/usr/local/bin
	${INSTALL_PROGRAM} ${WRKSRC}/tf-daemon ${STAGEDIR}/usr/local/bin/tf-daemon

	@${MKDIR} ${STAGEDIR}/usr/local/etc/rc.d
	${INSTALL_SCRIPT} ${FILESDIR}/usr/local/etc/rc.d/trustforge.sh \
		${STAGEDIR}/usr/local/etc/rc.d/trustforge.sh

	@${MKDIR} ${STAGEDIR}/usr/local/etc/trustforge
	${INSTALL_DATA} ${FILESDIR}/usr/local/etc/trustforge/config.yaml.sample \
		${STAGEDIR}/usr/local/etc/trustforge/config.yaml.sample

	@${MKDIR} ${STAGEDIR}/usr/local/pkg
	${INSTALL_DATA} ${FILESDIR}/usr/local/pkg/trustforge.xml \
		${STAGEDIR}/usr/local/pkg/trustforge.xml

	@${MKDIR} ${STAGEDIR}/usr/local/www
	${INSTALL_DATA} ${FILESDIR}/usr/local/www/trustforge.php \
		${STAGEDIR}/usr/local/www/trustforge.php

.include <bsd.port.mk>
