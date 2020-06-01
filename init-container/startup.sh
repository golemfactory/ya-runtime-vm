#! /bin/sh

depmod

modprobe virtio_balloon
modprobe virtio_input
modprobe virtio_ring
modprobe virtio_blk
modprobe virtio_pci
modprobe squashfs
modprobe 9pnet_virtio
modprobe virtio-net
modprobe virtio-console
modprobe hv-vmbus

mkdir /var/run

/sbin/rngd

mkdir /mnt /mnt/work /mnt/app-ro /mnt/app-rw 
mount /dev/vda /mnt/app-ro

mount -t tmpfs tmpfs /mnt/work
mkdir /mnt/work/u /mnt/work/w

mount -t overlay overlay -o lowerdir=/mnt/app-ro,upperdir=/mnt/work/u,workdir=/mnt/work/w /mnt/app-rw
mount -o bind /dev /mnt/app-rw/dev
mount -o bind /proc /mnt/app-rw/proc
test -d /mnt/app-rw/tmp && mount -t tmpfs none /mnt/app-rw/tmp

for arg in $(cat /proc/cmdline)
do
	case $arg
	in
		volmnt*)
			CMD_ARG="${arg#volmnt=}"
			SRC=$(echo $CMD_ARG| awk -F : '{ print $1 }')
			DST=$(echo $CMD_ARG| awk -F : '{ print $2 }')
			OUT_DST="/mnt/app-rw/${DST}"
			test -d "$OUT_DST" || mkdir -p "$OUT_DST"
			mount -t 9p -o trans=virtio "$SRC" "$OUT_DST"
			;;
	esac
done


