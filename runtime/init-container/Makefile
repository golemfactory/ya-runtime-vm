CC := musl-gcc
CXX := /bin/false
# -MMD to create dependency files (*.d) on first compilation
CFLAGS := -MMD -std=c11 -O2 -Wall -Wextra -Werror -fPIE -pie -Iinclude/ -Wmaybe-uninitialized

ifneq ($(DEBUG), "")
CFLAGS += -DNDEBUG
endif

ifneq ($(findstring $(MAKEFLAGS),s),s)
ifndef V
	QUIET_CC = @echo '    '   CC $@;
endif
endif

KERNEL_VER ?= 5.10.29-0-virt
KERNEL_URL ?= https://ya-runtime.s3-eu-west-1.amazonaws.com/vm/kernel/linux-virt-5.10.29-r0.apk
KERNEL_SHA256 ?= f3f7ca3421c5232e260b2a8a741bbf72c21881006afcf790aa3bc938e2262719

HEADERS_URL ?= https://ya-runtime.s3-eu-west-1.amazonaws.com/vm/kernel/linux-headers-5.7.8-r0.apk
HEADERS_SHA256 ?= 0b0f0c30be30ff367f5d1eaee227e919efc4b7f442bc03b3190c6e0d1a165362

UNPACKED_KERNEL := unpacked_kernel
UNPACKED_HEADERS := unpacked_headers
LIBURING_SUBMODULE ?= liburing
SRC_DIR ?= src
TEST_DIR ?= tests

OBJECTS = $(addprefix $(SRC_DIR)/,init.o communication.o process_bookkeeping.o cyclic_buffer.o)
OBJECTS_EXT = $(addprefix $(SRC_DIR)/,network.o forward.o)

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
# - build liburing
# - compile init (https://en.wikipedia.org/wiki/Init) from sources

.DEFAULT_GOAL = all
.PHONY: all
all: vmlinuz-virt initramfs.cpio.gz

$(SRC_DIR)/network.o: $(SRC_DIR)/network.c
	$(QUIET_CC)$(CC) $(CFLAGS) \
	    -I"$(CURDIR)/$(UNPACKED_HEADERS)/usr/include" \
	    -o $@ -c $<

$(SRC_DIR)/forward.o: $(SRC_DIR)/forward.c uring
	$(QUIET_CC)$(CC) -MMD -O2 -Wall -Wextra -Werror -fPIE -pie \
	    -I"$(CURDIR)/$(UNPACKED_HEADERS)/usr/include/" \
        -I"$(CURDIR)/$(LIBURING_SUBMODULE)/src/include/" \
        -Iinclude/ \
        -lstdthreads \
	    -o $@ -c $<

%.o: %.c
	$(QUIET_CC)$(CC) $(CFLAGS) -o $@ -c $<

init: $(UNPACKED_HEADERS) uring $(OBJECTS) $(OBJECTS_EXT)
	@echo init
	$(QUIET_CC)$(CC) $(CFLAGS) -static -o $@ $(wordlist 3, $(words $^), $^) "$(CURDIR)/$(LIBURING_SUBMODULE)/src/liburing.a"
	@# default musl libs on some distros have debug symbols, lets strip them (and everything else)
	strip $@

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

uring: $(UNPACKED_HEADERS)
	(cd $(LIBURING_SUBMODULE) && CC=$(CC) CXX=$(CXX) ./configure > /dev/null)
	$(MAKE) -e CC=$(CC) -e CFLAGS=-I"$(CURDIR)/$(UNPACKED_HEADERS)/usr/include" -C "$(LIBURING_SUBMODULE)/src" all

vmlinuz-virt: $(UNPACKED_KERNEL)
	cp $(UNPACKED_KERNEL)/boot/vmlinuz-virt .

initramfs.cpio.gz: init $(UNPACKED_KERNEL)
	$(RM) -rf initramfs
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
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/fs/squashfs/squashfs.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/fs/overlayfs/overlay.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/fs/fscache/fscache.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/net/9p/9pnet.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/net/9p/9pnet_virtio.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/net/core/failover.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/net/ipv6/ipv6.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/net/packet/af_packet.ko initramfs
	cd initramfs && find . | cpio --quiet -o -H newc -R 0:0 | gzip -9 > ../$@
	$(RM) -rf initramfs

TESTS_NAMES := cyclic_buffer
TESTS := $(addprefix $(TEST_DIR)/,$(TESTS_NAMES))

$(TESTS): %: %.o $(addprefix $(SRC_DIR)/,cyclic_buffer.o)
	$(CC) $(CFLAGS) -static -o $@ $^

.PHONY: test
test: $(TESTS)
	for t in $(TESTS) ; do \
		$$t ; \
	done

.PHONY: clean
clean:
	$(RM) init $(SRC_DIR)/*.o $(SRC_DIR)/*.d $(TEST_DIR)/*.o *.o $(TESTS)
	$(RM) vmlinuz-virt initramfs.cpio.gz
	$(MAKE) -s -C $(LIBURING_SUBMODULE) clean

.PHONY: distclean
distclean:
	$(RM) -rf $(UNPACKED_KERNEL) $(UNPACKED_HEADERS)
	$(MAKE) -s -C $(LIBURING_SUBMODULE) clean
	git submodule foreach git reset --hard
