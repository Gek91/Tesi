obj-m := SLK.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all: kernel

kernel:	
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean: cleank

cleank:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean
