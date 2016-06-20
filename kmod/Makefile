KDIR?=/usr/src/linux-headers-$(shell uname -r)
ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

obj-m += ipt_SYNSANITY.o xt_syncookies.o xt_condition.o

all:
	$(BUILD_VARS) make -C $(KDIR) M=$(ROOT_DIR) modules

clean:
	$(BUILD_VARS) make -C $(KDIR) M=$(ROOT_DIR) clean
