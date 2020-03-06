ifndef KDIR
$(error KDIR is not set)
endif

obj-m := ivc.o
ivc-y := ks/platform/linux/platform.o
ivc-y += ks/platform/linux/compatibility.o
ivc-y += data-structures/ringbuffer.o
ivc-y += core/libivc_debug.o
ivc-y += core/libivc.o
ivc-y += ks/core/ks_ivc_core.o

ccflags-y := -I$(IVC_BASE_DIR)/include
ccflags-y += -I$(IVC_BASE_DIR)/include/core
ccflags-y += -I$(IVC_BASE_DIR)/include/ks
ccflags-y += -I$(IVC_BASE_DIR)/include/ks/platform/linux
ccflags-y += -I$(IVC_BASE_DIR)/include/us
ccflags-y += -I$(IVC_BASE_DIR)/include/us/platform
ccflags-y += -I$(IVC_BASE_DIR)/include/us/platform/linux
ccflags-y += -I$(IVC_BASE_DIR)/src/data-structures
ccflags-y += -DKERNEL -Wall -D__KERNEL__ -DMODULE -g -fno-omit-frame-pointer -ftree-ter

ifeq (Release, ${IVC_PRODUCTION})
   ccflags-y += -O3 -DNDEBUG
endif

all: 
	$(MAKE) -C $(KDIR) M=$(IVC_BASE_DIR)/src

modules_install:
	$(MAKE) -C $(KDIR) M=$(IVC_BASE_DIR)/src
