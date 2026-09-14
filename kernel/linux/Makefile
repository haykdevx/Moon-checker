# Build the moonmon kernel module against the running kernel's headers.
#   make          # builds moonmon.ko
#   sudo insmod moonmon.ko
#   sudo rmmod moonmon
obj-m += moonmon.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
