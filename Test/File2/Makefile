obj-m := kernel.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

kernel:	
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

module: 
	gcc -o user user.c

clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean