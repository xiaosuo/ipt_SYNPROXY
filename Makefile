ifneq ($(KERNELRELEASE),)
obj-m += ipt_SYNPROXY.o
else
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
	$(CC) -Wall -fPIC -shared -o libipt_SYNPROXY.so libipt_SYNPROXY.c
clean:
	rm -rf *.o *.ko *.mod.c Module.symvers modules.order *.so .*.cmd \
		.tmp_versions
endif
