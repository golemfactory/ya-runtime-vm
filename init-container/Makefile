CC := musl-gcc

CFLAGS := -std=c11 -O2 -Wall -Werror -fPIE -pie -Iinclude/

ifneq ($(DEBUG), "")
CFLAGS += -DNDEBUG
endif

SRC_DIR ?= src

KERNEL_URL ?= "https://nl.alpinelinux.org/alpine/v3.11/main/x86_64/linux-virt-5.4.34-r0.apk"
KERNEL_SHA256 ?= "a6b32dc0ba8a52604b2adc9f9ae5035dc1d7936d81324911b9ee089eca81b2e3"

UNPACKED_DIR := unpacked_kernel

.DEFAULT_GOAL = all
.PHONY: all
all: vmlinuz-virt initramfs.cpio.gz

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $^

init: $(addprefix $(SRC_DIR)/,init.o communication.o process_bookkeeping.o)
	$(CC) $(CFLAGS) -static -o $@ $^
	@# default musl libs on some distros have debug symbols, lets strip them (and everythig else)
	strip $@

$(UNPACKED_DIR):
	wget -q -O "unverified" $(KERNEL_URL)
	echo $(KERNEL_SHA256) "unverified" | sha256sum -c || (echo "Kernel apk checksum verification failed!" && exit 1)
	$(RM) -rf $(UNPACKED_DIR)
	mkdir $(UNPACKED_DIR)
	tar --warning=no-unknown-keyword -C $(UNPACKED_DIR) -vxzf unverified >/dev/null
	$(RM) unverified

vmlinuz-virt: $(UNPACKED_DIR)
	cp $(UNPACKED_DIR)/boot/vmlinuz-virt .

initramfs.cpio.gz: init $(UNPACKED_DIR)
	$(RM) -rf initramfs
	mkdir initramfs
	cp $< initramfs
	cp $(UNPACKED_DIR)/lib/modules/5.4.34-0-virt/kernel/drivers/virtio/virtio.ko initramfs
	cp $(UNPACKED_DIR)/lib/modules/5.4.34-0-virt/kernel/drivers/virtio/virtio_ring.ko initramfs
	cp $(UNPACKED_DIR)/lib/modules/5.4.34-0-virt/kernel/drivers/virtio/virtio_pci.ko initramfs
	cp $(UNPACKED_DIR)/lib/modules/5.4.34-0-virt/kernel/drivers/char/virtio_console.ko initramfs
	cp $(UNPACKED_DIR)/lib/modules/5.4.34-0-virt/kernel/drivers/block/virtio_blk.ko initramfs
	cp $(UNPACKED_DIR)/lib/modules/5.4.34-0-virt/kernel/fs/squashfs/squashfs.ko initramfs
	cp $(UNPACKED_DIR)/lib/modules/5.4.34-0-virt/kernel/fs/overlayfs/overlay.ko initramfs
	cp $(UNPACKED_DIR)/lib/modules/5.4.34-0-virt/kernel/fs/fscache/fscache.ko initramfs
	cp $(UNPACKED_DIR)/lib/modules/5.4.34-0-virt/kernel/net/9p/9pnet.ko initramfs
	cp $(UNPACKED_DIR)/lib/modules/5.4.34-0-virt/kernel/net/9p/9pnet_virtio.ko initramfs
	cp $(UNPACKED_DIR)/lib/modules/5.4.34-0-virt/kernel/fs/9p/9p.ko initramfs
	cd initramfs && find . | cpio --quiet -o -H newc -R 0:0 | gzip -9 > ../$@
	$(RM) -rf initramfs

.PHONY: clean
clean:
	$(RM) init $(SRC_DIR)/*.o
	$(RM) vmlinuz-virt initramfs.cpio.gz

.PHONY: distclean
distclean:
	$(RM) -rf $(UNPACKED_DIR)
