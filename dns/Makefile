ifneq ($(KERNELRELEASE),)
obj-m += xt_dns.o
else
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
CC += -I$(PWD) -g

default:
	$(MAKE) CC="${CC}" -C $(KERNELDIR) M=$(PWD) modules
	$(CC) -Wall -fPIC -shared -o libxt_dns.so libxt_dns.c
clean:
	rm -rf *.o *.ko *.mod.c Module.symvers modules.order *.so .*.cmd \
		.tmp_versions
endif
