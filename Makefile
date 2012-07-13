obj-m := l2filter.o
l2filter-objs := l2filter_main.o dump.o filter.o user_comm.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

modules_install:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules_install

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
	rm -f .*.cmd *.mod.c *.o
