obj-m := SLK.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all: user kernel

kernel:	
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

user:
	gcc -o user -pthread user.c

clean: cleanu cleank

cleank:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean

cleanu:
	rm users log