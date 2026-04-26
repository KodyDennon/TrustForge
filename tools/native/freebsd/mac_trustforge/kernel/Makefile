# SPDX-License-Identifier: BSD-2-Clause
#
# bsd.kmod.mk style Makefile for mac_trustforge.ko
#
# Build (must be on a real FreeBSD host):
#   make
#   make install
#   make clean
#   sudo kldload ./mac_trustforge.ko
#   sudo kldunload mac_trustforge
#
# Requires: FreeBSD >= 13.0 source tree (or world headers) at SRCDIR.
# The MAC framework (CONFIG: options MAC) must be present in the running
# kernel's GENERIC config (it is by default on FreeBSD >= 13).

KMOD=	mac_trustforge
SRCS=	mac_trustforge.c

# Pull in vnode_if.h and sockets layer; bsd.kmod.mk handles SYSDIR.
SRCS+=	vnode_if.h opt_global.h

CFLAGS+=	-DMAC_TRUSTFORGE_VERSION=\"0.1.0\"

# Where to install the .ko on `make install`.
KMODDIR?=	/boot/modules

.include <bsd.kmod.mk>
