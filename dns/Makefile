ifneq ($(KERNELRELEASE),)
obj-m += dns.o
obj-m += xt_dns.o
obj-m += xt_DNSCACHE.o
else
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
CFLAGS += -I${PWD}/include

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) EXTRA_CFLAGS="${CFLAGS}" modules
	$(CC) ${CFLAGS} -Wall -fPIC -shared -o libxt_dns.so libxt_dns.c
clean:
	rm -rf *.o *.ko *.mod.c Module.symvers modules.order *.so .*.cmd \
		.tmp_versions
endif
