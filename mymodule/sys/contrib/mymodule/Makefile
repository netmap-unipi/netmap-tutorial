.PATH: .
KMOD=	mymodule
SRCS=	mymodule.c
TARGET!=	uname -m
IDENT!=		uname -i
CFLAGS+= -I$(KSRC)
CFLAGS+= -I../../../sys/
CFLAGS+= -I$(KSRC)/sys/$(TARGET)/compile/$(IDENT)

.include <bsd.kmod.mk>
