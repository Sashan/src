#	$OpenBSD$

PROG=	lockstat
SRCS=	lockstat.c
MAN=	lockstat.8

CFLAGS+= -I${.CURDIR}
CFLAGS+= -Wall -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith \
         -Wno-uninitialized

.include <bsd.prog.mk>
