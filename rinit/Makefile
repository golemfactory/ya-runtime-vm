SHELL := /bin/bash
CC := musl-gcc
CXX := /bin/false
NEW_ROOT := newroot
MKFS_NAME := mkfs.ext2

BUSYBOX := extern-libs/busybox
LIBSECCOMP_SUBMODULE ?= extern-libs/libseccomp
UNPACKED_KERNEL := extern-libs/unpacked_kernel
UNPACKED_HEADERS := extern-libs/unpacked_headers
SRC_DIR ?= extern-libs/src

# -MMD to create dependency files (*.d) on first compilation
CFLAGS := -MMD -std=c11 -O2 -Wall -Wextra -Werror -Wmaybe-uninitialized -fPIE -pie \
          -I$(UNPACKED_HEADERS)/usr/include -I$(LIBSECCOMP_SUBMODULE)/include '-DNEW_ROOT="$(NEW_ROOT)"'

ifneq ($(DEBUG), "")
CFLAGS += -DNDEBUG
endif

KERNEL_VER ?= 5.10.29-0-virt
KERNEL_URL ?= https://ya-runtime.s3-eu-west-1.amazonaws.com/vm/kernel/linux-virt-5.10.29-r0.apk
KERNEL_SHA256 ?= f3f7ca3421c5232e260b2a8a741bbf72c21881006afcf790aa3bc938e2262719

HEADERS_URL ?= https://ya-runtime.s3-eu-west-1.amazonaws.com/vm/kernel/linux-headers-5.7.8-r0.apk
HEADERS_SHA256 ?= 0b0f0c30be30ff367f5d1eaee227e919efc4b7f442bc03b3190c6e0d1a165362

# Add headers to object dependencies for conditional recompilation on header change
SOURCES = $(wildcard $(SRC_DIR)/*.c)
DEPS = $(SOURCES:%.c=%.d)
-include $(DEPS)

# Below are the steps performed by this Makefile:
# - download the kernel && kernel headers apk packages
# - verify checksums of the downloaded packages
# - extract the contents of the downloaded packages
# - copy vmlinuz-virt from the extracted kernel package
# - create a build directory for initramfs
# - copy required kernel modules from the extracted kernel package to initramfs build directory
# - bundle initramfs.cpio.gz
# - compile init (https://en.wikipedia.org/wiki/Init) from sources

.DEFAULT_GOAL = all
.PHONY: all clean distclean

all: vmlinuz-virt initramfs.cpio.gz

clean:
	$(RM) init $(SRC_DIR)/*.o $(SRC_DIR)/*.d *.o extern-libs/libseccomp.a
	$(RM) vmlinuz-virt initramfs.cpio.gz
	$(MAKE) -s -C $(LIBSECCOMP_SUBMODULE) clean

distclean: clean
	$(RM) -rf $(UNPACKED_KERNEL) $(UNPACKED_HEADERS)
	git submodule foreach git reset --hard


init: extern-libs/libseccomp.a
	@echo init
	cargo build --color always --target=x86_64-unknown-linux-musl -p rinit --release --bin rinit
	cp ../target/x86_64-unknown-linux-musl/release/rinit $@
	@# default musl libs on some distros have debug symbols, lets strip them (and everything else)
# strip $@

$(UNPACKED_HEADERS):
	wget -q -O "headers" $(HEADERS_URL)
	echo $(HEADERS_SHA256) "headers" | sha256sum -c || (echo "Headers apk checksum verification failed!" && exit 1)
	$(RM) -rf $(UNPACKED_HEADERS)
	mkdir $(UNPACKED_HEADERS)
	tar --warning=no-unknown-keyword -C $(UNPACKED_HEADERS) -vxzf headers >/dev/null
	$(RM) headers

$(UNPACKED_KERNEL):
	wget -q -O "kernel" $(KERNEL_URL)
	echo $(KERNEL_SHA256) "kernel" | sha256sum -c || (echo "Kernel apk checksum verification failed!" && exit 1)
	$(RM) -rf $(UNPACKED_KERNEL)
	mkdir $(UNPACKED_KERNEL)
	tar --warning=no-unknown-keyword -C $(UNPACKED_KERNEL) -vxzf kernel >/dev/null
	$(RM) kernel

vmlinuz-virt: $(UNPACKED_KERNEL)
	cp $(UNPACKED_KERNEL)/boot/vmlinuz-virt .

initramfs.cpio.gz: init $(UNPACKED_KERNEL)
	$(RM) -rf initramfs
	echo "Building initramfs.cpio.gz"
	mkdir initramfs
	cp $< initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/drivers/virtio/virtio.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/drivers/virtio/virtio_ring.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/drivers/virtio/virtio_pci.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/drivers/char/hw_random/rng-core.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/drivers/char/hw_random/virtio-rng.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/drivers/char/virtio_console.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/drivers/block/virtio_blk.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/drivers/net/tun.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/drivers/net/net_failover.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/drivers/net/virtio_net.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/fs/9p/9p.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/fs/mbcache.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/fs/ext2/ext2.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/fs/squashfs/squashfs.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/fs/overlayfs/overlay.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/fs/fscache/fscache.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/net/9p/9pnet.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/net/9p/9pnet_virtio.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/net/core/failover.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/net/ipv6/ipv6.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/net/packet/af_packet.ko initramfs
	cp $(BUSYBOX)/$(MKFS_NAME) initramfs
	mkdir initramfs/$(NEW_ROOT)
	set -euo pipefail; cd initramfs && find . | cpio --quiet -o -H newc -R 0:0 | gzip -9 > ../$@
	$(RM) -rf initramfs

$(LIBSECCOMP_SUBMODULE)/src/.libs/libseccomp.a $(LIBSECCOMP_SUBMODULE)/include/seccomp.h: $(UNPACKED_HEADERS)
	set -euo pipefail; \
	cd $(LIBSECCOMP_SUBMODULE); \
	export CC=$(CC) CXX=$(CXX) CFLAGS=-I"$$PWD/../../$(UNPACKED_HEADERS)/usr/include";\
	./autogen.sh; \
	./configure --disable-python;\
	$(MAKE) all

$(SRC_DIR)/seccomp.o: $(LIBSECCOMP_SUBMODULE)/include/seccomp.h

extern-libs/libseccomp.a: $(LIBSECCOMP_SUBMODULE)/src/.libs/libseccomp.a $(SRC_DIR)/seccomp.o
	cp -f $(LIBSECCOMP_SUBMODULE)/src/.libs/libseccomp.a $@
	$(AR) $(ARFLAGS) $@ $(SRC_DIR)/seccomp.o

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<
