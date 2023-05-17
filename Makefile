MODULE_VERSION := 1.0
MODULE_NAME := ipt_RAWCOOKIE
MODULE_LIB := libxt_RAWCOOKIE
KERNEL_VERSION ?=$(shell uname -r)
KERNEL_SRC := /lib/modules/$(KERNEL_VERSION)/build
MODPATH := /lib/modules/$(KERNEL_VERSION)

obj-m+=ipt_RAWCOOKIE.o

all: $(MODULE_LIB).so
	make -C $(KERNEL_SRC) M=$(PWD) modules

$(MODULE_LIB).so: $(MODULE_LIB).o
	$(CC) -shared -fPIC -o $@ $<

$(MODULE_LIB).o: $(MODULE_LIB).c
	$(CC) $(CFLAGS) -Wall -pipe -DPIC -fPIC -g -O2 -o $@ -c $<

clean:
	make -C $(MODPATH)/build/ M=$(PWD) clean
	rm -f $(MODULE_LIB).so

install:

	install -D -t $(DESTDIR)/$(MODPATH)/kernel/net/netfilter $(MODULE_NAME).ko
	install -D -t $(DESTDIR)/usr/lib64/xtables $(MODULE_LIB).so


tar:
	tar cvzf xt_RAWCOOKIE-$(MODULE_VERSION).tar.gz --transform 's,^,xt_RAWCOOKIE-$(MODULE_VERSION)/,' *.c *.h Makefile
