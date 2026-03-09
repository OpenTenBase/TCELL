obj-m += measure.o

measure-y := dynamic_measure.o vma_hash_calculator.o ../encryption/sm3.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) KBUILD_EXTRA_SYMBOLS=$(CURDIR)/../dynamic_baselib/Module.symvers modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) clean
	rm -f ../encryption/*.o ../encryption/.*.cmd
