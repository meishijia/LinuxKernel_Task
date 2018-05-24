KVERS = $(shell uname -r)
  
CURDIR = $(shell pwd)
#KERN_DIR = /usr/src/$(shell uname -r)
KERN_DIR = /lib/modules/$(KVERS)/build
  
# Kernel modules  
obj-m += mymodule.o  
  
# Specify flags for the module compilation.  
#EXTRA_CFLAGS=-g -O0  
  
build: kernel_modules user_test  
  
kernel_modules:  
	make -C $(KERN_DIR) M=$(CURDIR) modules  
user_test:  
	gcc -o module_test testmodule.c  
  
clean:  
	make -C $(KERN_DIR) M=$(CURDIR) clean
