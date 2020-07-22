ifneq ($(KERNELRELEASE),)
# kbuild part of makefile
include Kbuild

else
# normal makefile
KERNEL_VERSION ?= `uname -r`
KERNEL_SRC ?= /lib/modules/$(KERNEL_VERSION)/build
INSTALL_HDR_PATH ?= /usr/src/ivc

default:
	$(MAKE) -C $(KERNEL_SRC) M=$$PWD

clean:
	$(MAKE) -C $(KERNEL_SRC) M=$$PWD clean

modules_install:
	$(MAKE) -C $(KERNEL_SRC) M=$$PWD modules_install

headers_install:
	install -d $(INSTALL_HDR_PATH)/include
	install -m 0644 ../include/core/libivc_debug.h $(INSTALL_HDR_PATH)/include/libivc_debug.h
	install -m 0644 ../include/core/libivc.h $(INSTALL_HDR_PATH)/include/libivc.h
	install -m 0644 ../include/core/libivc_private.h $(INSTALL_HDR_PATH)/include/libivc_private.h
	install -m 0644 ../include/core/libivc_types.h $(INSTALL_HDR_PATH)/include/libivc_types.h

endif
