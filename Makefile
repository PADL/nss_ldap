# Copyright (C) 1997 Luke Howard.
# This file is part of the nss_ldap Library.

# The nss_ldap library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Library General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.

# The nss_ldap Library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Library General Public License for more details.

# You should have received a copy of the GNU Library General Public
# License along with the nss_ldap Library; see the file COPYING.LIB.  If not,
# write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 02111-1307, USA.

#
# $Id$
#

MODULE=nss_ldap
HDRS=	\
	ldap-alias.h \
	ldap-ethers.h \
	ldap-grp.h \
	ldap-hosts.h \
	ldap-netgrp.h \
	ldap-network.h \
	ldap-nss.h \
	ldap-proto.h \
	ldap-pwd.h \
	ldap-rpc.h \
	ldap-service.h \
	ldap-spwd.h \
	util.h \
	globals.h \
	ltf.h \
	irs-nss.h \
	ldap-parse.h \
	snprintf.h

SRCS=	ldap-nss.c \
	ldap-pwd.c \
	ldap-grp.c \
	ldap-rpc.c \
	ldap-hosts.c \
	ldap-network.c \
	ldap-proto.c \
	ldap-spwd.c \
	ldap-alias.c \
	ldap-service.c \
	ldap-ethers.c \
	ldap-bp.c \
	util.c \
	globals.c \
	ltf.c \
	snprintf.c

OBJS=${SRCS:.c=.o}
LIB=${MODULE}.so.1
# uncomment NSFLAGS if you are using the Netscape SDK
#NSFLAGS=-I/usr/local/ldapsdk/include -DNETSCAPE_SDK
# uncomment GNUFLAGS if you are building a GNU glibc-2.x module
#GNUFLAGS=-DGNU_NSS
# uncomment BSDFLAGS if you are building this as part of the BIND IRS
#BSDFLAGS=-DIRS_NSS
SUNFLAGS=-DSUN_NSS -D_REENTRANT -DSUNOS_54
INCDIRS=-I/usr/local/include
LIBDIRS=-L/usr/ucblib -L/usr/local/lib
LIBS=-lldap_pic -llber_pic 
GCCFLAGS=-g -Wall -fPIC #-O
SUNCFLAGS=-g -pic
#DEBUGFLAGS=-DDEBUG

#CC=cc
#COMPILERFLAGS=${SUNCFLAGS}
CC=gcc
COMPILERFLAGS=${GCCFLAGS}

CFLAGS=-DLDAP_REFERRALS ${DEBUGFLAGS} ${NSFLAGS} ${SUNFLAGS} ${BSDFLAGS} ${GNUFLAGS} ${COMPILERFLAGS} ${INCDIRS}

all: ${MODULE} install

${MODULE}: ${OBJS}
	cc ${LIBDIRS} -G -z text -o /tmp/${LIB} ${OBJS} ${LIBS}

install:
	cp /tmp/${LIB} /usr/lib/

clean:
	rm -f ${OBJS} ${LIB}

test:
	gcc -g -o testpw3 testpw3.c
	gcc -g -o testpw testpw.c
	gcc -g -o testpw2 testpw.c -lthread
	gcc -g -o testgr testgr.c

#STAMP=`date "+%y%m%d-%H%M"`
STAMP=0.11

dist:
	gnutar czvf ../nss_ldap-${STAMP}.tar.gz .

libldap_dist:
	gnutar czvf libldap-nss-${STAMP}.tar.gz libldap/

