CONFIG_MYMODULE:=m
mymodule_lin-objs := mymodule.o
obj-$(CONFIG_MYMODULE) = mymodule_lin.o

M:=$(CURDIR)
SRC ?= $(KSRC)
EXTRA_CFLAGS := -I$(NSRC)/ -I$(NSRC)/LINUX -I$(NSRC)/sys -I$(M)/../sys -DCONFIG_NETMAP

all:	build
build:
	make -C $(SRC) M=$(CURDIR) \
		CONFIG_NETMAP=m CONFIG_NETMAP_VALE=y CONFIG_MYMODULE=m \
		EXTRA_CFLAGS='$(EXTRA_CFLAGS)' KBUILD_EXTRA_SYMBOLS=$(NSRC)/Module.symvers
	ls -l `find . -name \*.ko`
clean:
	(rm -rf *.o *.ko modules.order mymodule_lin.mod.c Module.symvers)

$(obj)/mymodule.o:	$(M)/../sys/contrib/mymodule/mymodule.c
	$(call cmd,cc_o_c)
	$(call cmd,modversions)
