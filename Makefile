# Copyright (C) 2015 Assured Information Security, inc.
# Authors:
#   -Dave Staelens    <staelensd@ainfosec.com>
# 	-Kyle J. Temkin   <temkink@ainfosec.com>
# 	-Brendan Kerrigan <kerriganb@ainfosec.com>
#
# <PLACE LICENSE INFORMATION HERE>
#

#In most cases, this file will be run from the IVC base directory, so assume that 
#path unless we've been passed another one.
export IVC_BASE_DIR ?= $(shell pwd)

#If no kernel directory was provided, try to use the kernel source for the kernel
#running on the build machine. This eases the common debugging case.
export KDIR         ?= /lib/modules/`uname -r`/build

#Allow the user to override the destination prefix; this allows package
#magenement systems to install to e.g. /usr.
export PREFIX       ?=/usr/local

#If no production flag is set, default to release mode
export IVC_PRODUCTION ?=Release

#If no output directory for the rpm is specified provide it to the current one
export RPM_OUTDIR ?= $(shell pwd)

#
# Main build targets
#
all: kernel user tests

kernel:
	$(MAKE) -C src/

user:
	cd src/us; cmake -DCMAKE_BUILD_TYPE=$(IVC_PRODUCTION) -DCMAKE_INSTALL_PREFIX=$(PREFIX) .
	$(MAKE) -C src/us/

tests:
	cd src/test/us; cmake .
	$(MAKE) -C src/test/us/

deb:
	dpkg-buildpackage -b -uc

deb-dkms:
	dpkg-buildpackage -A -uc

rpm-libivc:
	fpm -s dir -t rpm -n libivc -v 1.0 -p "$(RPM_OUTDIR)" -a all --vendor AIS -m AIS@ainfosec.com src/us/lib/=/lib64

rpm:
	fpm -s dir -t rpm -n ivc -v 1.0 -p "$(RPM_OUTDIR)" -d "dkms" -a all --prefix /usr/src/ivc-1.0/ --after-install rpmdkms/dkmspostinstall --before-remove rpmdkms/dkmspreuninstall --after-remove rpmdkms/dkmspostuninstall --vendor AIS -m AIS@ainfosec.com include/ src/ dkms.conf Makefile

#
# Installation targets
#
install: install_kernel install_user install_tests

install_kernel: kernel
	$(MAKE) -C src/ modules_install

install_user: user
	$(MAKE) -C src/us install

install_tests: tests
	$(MAKE) -C src/test/us install

#
# Cleanup
#
clean:
	find $(IVC_BASE_DIR) -name '*\.o\.cmd' | xargs rm -f
	find $(IVC_BASE_DIR) -name '*\.o' | xargs rm -f 
	find $(IVC_BASE_DIR) -name '*\.ko' | xargs rm -f
	find $(IVC_BASE_DIR) -name '[mM]odule*' | xargs rm -f
	find $(IVC_BASE_DIR) -name '*\.mod\.c' | xargs rm -f
	find $(IVC_BASE_DIR) -name '*\.ko\.cmd' | xargs rm -f
	find $(IVC_BASE_DIR) -name '\.tmp_versions' | xargs rm -rf
	find $(IVC_BASE_DIR) -name '*\.so' | xargs rm -rf
	find $(IVC_BASE_DIR) -name '*\.rpm' | xargs rm -f
	rm -rf $(IVC_BASE_DIR)/src/ringbuffer/src/ringbuffer/.tmp_versions/
