TARGET := janitor
KDIR := /lib/modules/$(shell uname -r)/build


$(TARGET)-objs += main.o rkdetect.o utility.o
obj-m += $(TARGET).o


all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean
