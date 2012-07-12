obj-m := l2filter.o
l2filter-objs := filter.o dump.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

modules_install:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules_install

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f .*.cmd *.mod.c
