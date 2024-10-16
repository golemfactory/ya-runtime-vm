#!/bin/bash
./vmrt \
  -nographic \
  -no-reboot \
  -m 512M \
  -kernel vmlinuz-virt \
  -initrd initramfs.cpio.gz \
  -enable-kvm \
  -cpu host \
  -smp 1 \
  -device virtio-serial \
  -device virtio-rng-pci \
  -chardev socket,path=/tmp/b2dc373c3caa4842bf229eb22a9912a2.sock,server=on,wait=off,id=manager_cdev \
  -device virtserialport,chardev=manager_cdev,name=manager_port \
  -drive file=/home/aljen/.local/lib/yagna/plugins/ya-runtime-vm/runtime/self-test.gvmi,cache=unsafe,readonly=on,format=raw,id=rootfs,if=none \
  -device virtio-blk-pci,drive=rootfs,serial=rootfs \
  -vga none \
  -append "console=ttyS0 panic=1 vol-0-path=/ vol-0-size=1073741824 vol-1-path=/golem/storage2 vol-1-errors=continue vol-2-path=/golem/storage vol-2-errors=remount-ro" \
  -net none \
  -chardev socket,path=/tmp/b2dc373c3caa4842bf229eb22a9912a2_vpn.sock,server,wait=off,id=vpn_cdev \
  -device virtserialport,chardev=vpn_cdev,name=vpn_port \
  -chardev socket,path=/tmp/b2dc373c3caa4842bf229eb22a9912a2_inet.sock,server,wait=off,id=inet_cdev \
  -device virtserialport,chardev=inet_cdev,name=inet_port \
  -virtfs local,id=mnt0,path=mnt0,security_model=none,mount_tag=mnt0

  # -drive file=/tmp/ya-runtime-vm-self-test-deb24ca8-75c9-485c-bd3b-de89db2830a6/vol-facf2cc8-99e2-4a48-b91c-edceb5327f07.img,format=qcow2,media=disk,id=vol-1,if=none \
  # -device virtio-blk-pci,drive=vol-1,serial=vol-1 \
  # -drive file=/tmp/ya-runtime-vm-self-test-deb24ca8-75c9-485c-bd3b-de89db2830a6/vol-717a8184-6f15-4ec9-a5de-081c6d4f5ce4.img,format=qcow2,media=disk,id=vol-2,if=none \
  # -device virtio-blk-pci,drive=vol-2,serial=vol-2 \
