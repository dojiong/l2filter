obj-m := l2filter.o

clean:
	rm -rf *.ko *.mod.c *.order *.symvers *.o .*.cmd .tmp_versions