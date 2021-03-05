CC := musl-gcc
CXX := /bin/false
CFLAGS := -std=c11 -O2 -Wall -Wextra -Werror -fPIE -pie -Iinclude/

ifneq ($(DEBUG), "")
CFLAGS += -DNDEBUG
endif

ifneq ($(findstring $(MAKEFLAGS),s),s)
ifndef V
	QUIET_CC = @echo '    '   CC $@;
endif
endif

KERNEL_VER ?= 5.10.16-0-virt
KERNEL_URL ?= https://nl.alpinelinux.org/alpine/v3.13/main/x86_64/linux-virt-5.10.16-r0.apk
KERNEL_SHA256 ?= d3de4dc7b8c71582cb2e2f78fd742b60e7c718ea59754a42762d45abe601a7cd

HEADERS_URL ?= https://nl.alpinelinux.org/alpine/v3.13/main/x86_64/linux-headers-5.7.8-r0.apk
HEADERS_SHA256 ?= 0b0f0c30be30ff367f5d1eaee227e919efc4b7f442bc03b3190c6e0d1a165362

UNPACKED_KERNEL := unpacked_kernel
UNPACKED_HEADERS := unpacked_headers
SRC_DIR ?= src
TEST_DIR ?= tests
LIBURING_DIR ?= external/liburing

OBJECTS = $(addprefix $(SRC_DIR)/,init.o communication.o process_bookkeeping.o cyclic_buffer.o)
OBJECTS_EXT = $(addprefix $(SRC_DIR)/,network.o forward.o)

.DEFAULT_GOAL = all
.PHONY: all
all: vmlinuz-virt initramfs.cpio.gz

$(SRC_DIR)/network.o: $(SRC_DIR)/network.c
	$(QUIET_CC)$(CC) $(CFLAGS) \
	    -I"$(CURDIR)/$(UNPACKED_HEADERS)/usr/include" \
	    -o $@ -c $^

$(SRC_DIR)/forward.o: $(SRC_DIR)/forward.c
	$(QUIET_CC)$(CC) -O2 -Wall -Wextra -Werror -fPIE -pie \
	    -I"$(CURDIR)/$(UNPACKED_HEADERS)/usr/include/" \
        -I"$(LIBURING_DIR)/src/include/" \
        -Iinclude/ \
        -lstdthreads \
	    -o $@ -c $^

%.o: %.c
	$(QUIET_CC)$(CC) $(CFLAGS) -o $@ -c $^

init: $(UNPACKED_HEADERS) liburing $(OBJECTS) $(OBJECTS_EXT)
	$(QUIET_CC)$(CC) $(CFLAGS) -static -o $@ $(wordlist 3, $(words $^), $^) "$(CURDIR)/$(LIBURING_DIR)/src/liburing.a"
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

liburing: $(UNPACKED_HEADERS)
	@echo build liburing
	(cd $(LIBURING_DIR) && CC=$(CC) CXX=$(CXX) ./configure > /dev/null)
	$(MAKE) -e CC=$(CC) -e CFLAGS=-I"$(CURDIR)/unpacked_headers/usr/include" -C "$(LIBURING_DIR)/src" all

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
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/fs/9p/9p.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/fs/squashfs/squashfs.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/fs/overlayfs/overlay.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/fs/fscache/fscache.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/net/9p/9pnet.ko initramfs
	cp $(UNPACKED_KERNEL)/lib/modules/$(KERNEL_VER)/kernel/net/9p/9pnet_virtio.ko initramfs
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
	$(RM) init $(SRC_DIR)/*.o $(TEST_DIR)/*.o *.o $(TESTS)
	$(RM) vmlinuz-virt initramfs.cpio.gz
	$(MAKE) -s -C external/liburing/src clean
	$(MAKE) -s -C external/liburing clean

.PHONY: distclean
distclean:
	$(RM) -rf $(UNPACKED_KERNEL) $(UNPACKED_HEADERS)
	$(MAKE) -s -C external/liburing/src clean
	$(MAKE) -s -C external/liburing clean
	git submodule foreach git reset --hard
