obj-m += dynamic_baselib.o

dynamic_baselib-objs := baselib_main.o process_exit_hook.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) clean