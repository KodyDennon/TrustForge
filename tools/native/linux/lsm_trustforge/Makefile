# TrustForge LSM kernel module Makefile
#
# Build:
#   make            # builds trustforge_lsm.ko against the running kernel
#   make KDIR=/path/to/kernel/source
#   make clean
#   make dkms       # install via DKMS
#
# Requires: kernel >= 5.15 with CONFIG_SECURITY=y and CONFIG_SECURITY_NETWORK=y.

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

obj-m += trustforge_lsm.o

# Bridge userspace daemon (out-of-tree build).
BRIDGE_SRC := userspace/tf-lsm-bridge.c
BRIDGE_BIN := userspace/tf-lsm-bridge
CC         ?= cc
CFLAGS     ?= -O2 -Wall -Wextra -Wno-unused-parameter

DKMS_NAME    := trustforge-lsm
DKMS_VERSION := 0.1.0

.PHONY: all module bridge clean install dkms uninstall test

all: module bridge

module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

bridge: $(BRIDGE_BIN)

$(BRIDGE_BIN): $(BRIDGE_SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f $(BRIDGE_BIN)

install: all
	install -d $(DESTDIR)/lib/modules/$(shell uname -r)/extra/
	install -m 0644 trustforge_lsm.ko $(DESTDIR)/lib/modules/$(shell uname -r)/extra/
	install -d $(DESTDIR)/usr/sbin/
	install -m 0755 $(BRIDGE_BIN) $(DESTDIR)/usr/sbin/
	depmod -a

dkms:
	cp -r . /usr/src/$(DKMS_NAME)-$(DKMS_VERSION)/
	dkms add     -m $(DKMS_NAME) -v $(DKMS_VERSION)
	dkms build   -m $(DKMS_NAME) -v $(DKMS_VERSION)
	dkms install -m $(DKMS_NAME) -v $(DKMS_VERSION)

uninstall:
	-dkms remove -m $(DKMS_NAME) -v $(DKMS_VERSION) --all || true
	rm -rf /usr/src/$(DKMS_NAME)-$(DKMS_VERSION)
	rm -f $(DESTDIR)/lib/modules/$(shell uname -r)/extra/trustforge_lsm.ko
	rm -f $(DESTDIR)/usr/sbin/tf-lsm-bridge
	depmod -a || true

test:
	bash tests/test-load-unload.sh
