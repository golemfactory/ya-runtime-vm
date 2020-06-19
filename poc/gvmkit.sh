#! /bin/bash

usage() {
	local ME=$(basename $0)
	echo ""
	echo -e "\tGolem VMKIT"
	echo ""
	echo "Usage:"
	echo ""
	echo "$ME build <docker-image> [output-name]"
	echo ""
	echo "$ME run {-v <fs-path>:<image-path> } [-m <memory> ] <vmkit-image> [ <cmd> <args>... ]"
	echo ""
}

err() {
	echo $@ >&2
	exit 1
}

do_build() {
	set -x
	local IMAGE CONTAINER
	IMAGE="$1"
	CONTAINER=$(docker create "${IMAGE}") || err "unable to load image: $IMAGE"
	IMAGE_HASH=$(docker inspect $CONTAINER| jq .[0].Image -r | cut -c 8-20)
	local OUT_DIR="out-$IMAGE_HASH"
	mkdir "$OUT_DIR"
	fakeroot "$0" repack "$CONTAINER" "$OUT_DIR"
	rm -fr "$OUT_DIR"
	docker rm "$CONTAINER"
}

do_repack() {
	local cmd
	local OUT="$2"
	docker export "$1" | tar xf - -C "$OUT"
	docker inspect "$1" | jq '.[0].Config.Env[]' -r > $OUT/.env
	ep=$(docker inspect "$1" | jq '.[0].Config.Entrypoint[]' -e -r) && echo $ep > $OUT/.entrypoint
	cmd=$(docker inspect "$1" | jq '.[0].Config.Cmd[]' -e -r) && echo $cmd > $OUT/.cmd
  vols=$(docker inspect "$1" | jq '.[0].Config.Volumes | keys[]' -e -r) && echo $vols > $OUT/.vols
  docker inspect "$1" | jq '.[0].Config' > "${OUT}.json"
	mksquashfs "$OUT" "$OUT.golem-app" -comp lzo
  (
  cat "${OUT}.json"
  printf "%08d" $(stat -c%s "${OUT}.json")
  ) >> "$OUT.golem-app" 

}

SCRIPT_DIR=$(readlink -f ${0%/*})

do_run() {
	echo script_dir=$SCRIPT_DIR
	local CUR=$(pwd)
	local memory="200m"
        local arg=""
	local append=""
	local tag=0

	while getopts "dm:v:" o; do
		case "${o}" in
        	m)
            		memory=${OPTARG}
            		;;
		d)
			echo debug
			append="$append NO_LOADER=1 NO_POWEROFF=1"
			;;
        	v)
			IFS=':' read -ra VOLDEF <<< "$OPTARG"
			SRC=$(cd ${VOLDEF[0]} 2>/dev/null && pwd) || err "invalid path :${VOLDEF[0]}"
			DST="${VOLDEF[1]}"
			MODE=${VOLDEF[2]:-rw}
			tag=$[tag+1]
            		arg="$arg -virtfs local,path=$SRC,id=vol${tag},mount_tag=vol${tag},security_model=none"
			arg="$arg -device virtio-9p-pci,fsdev=vol${tag},mount_tag=vol${tag}"
			append="$append volmnt=vol${tag}:$DST"
            		;;
        	*)
            		usage
            		;;
    		esac
	done
	shift $((OPTIND-1))
	echo memory=$memory
	echo arg=$arg

	local VMIMG="$(cd $(dirname "$1") && pwd)/$(basename "$1")"
	test -f "$VMIMG" || err "missing application image: $VMIMG"

	echo vmkit=$VMIMG

	cd $SCRIPT_DIR/runtime
	shift
	for a in $@
	do
		append="$append apparg=\"$a\""
	done
	echo $@
	./vmrt -m "$memory" -nographic -vga none -kernel vmlinuz-virt -initrd initramfs-virt -net none -accel kvm -cpu "host" -smp $(nproc) \
		-device virtio-serial,id=ser0 -device virtserialport,chardev=foo,name=org.fedoraproject.port.0 -chardev socket,path=/tmp/foo,server,nowait,id=foo \
		-append "console=ttyS0 panic=1 $append" \
		-drive file="$VMIMG",cache=none,readonly=on,format=raw,if=virtio -no-reboot	\
		$arg
}

case $1 
in
	build)
		do_build $2
		;;
	repack)
		shift
		do_repack $@
		;;
	run)
		shift
		do_run $@
		;;
	*)
		usage
		exit 1
esac


