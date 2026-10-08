FROM ubuntu:24.04

ARG QEMU_VERSION=11.1.2
ARG QEMU_COMMIT=4fc49f46dc95d4a27de2509e7fceb2931e91faeb

RUN apt update \
    && \
    \
    DEBIAN_FRONTEND=noninteractive \
    apt install --assume-yes \
        build-essential \
        ca-certificates \
        git \
        make \
        python3 \
        python3-pip \
        python3-venv \
        wget \
        pkg-config \
        libglib2.0-dev \
        libpixman-1-dev \
        libmount-dev \
        libffi-dev \
        libselinux1-dev \
        libcap-ng-dev \
        libattr1-dev \
        ninja-build \
    && \
    \
    rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/qemu/qemu.git --depth 1 -b "v${QEMU_VERSION}" \
    && test "$(git -C /qemu rev-parse HEAD)" = "${QEMU_COMMIT}"

RUN echo CONFIG_VIRTIO=y >> /qemu/configs/devices/i386-softmmu/default.mak
RUN echo CONFIG_VIRTIO_SERIAL=y >> /qemu/configs/devices/i386-softmmu/default.mak
RUN echo CONFIG_VIRTIO_PCI=y >> /qemu/configs/devices/i386-softmmu/default.mak
RUN echo CONFIG_VIRTIO_NET=y >> /qemu/configs/devices/i386-softmmu/default.mak
RUN echo CONFIG_VIRTIO_RNG=y >> /qemu/configs/devices/i386-softmmu/default.mak
RUN echo CONFIG_VIRTIO_MMIO=y >> /qemu/configs/devices/i386-softmmu/default.mak
RUN echo CONFIG_VIRTIO_SCSI=y >> /qemu/configs/devices/i386-softmmu/default.mak
RUN echo CONFIG_VIRTIO_BLK=y >> /qemu/configs/devices/i386-softmmu/default.mak
RUN echo CONFIG_VIRTIO_9P=y >> /qemu/configs/devices/i386-softmmu/default.mak
RUN echo CONFIG_PARALLEL=y >> /qemu/configs/devices/i386-softmmu/default.mak
RUN echo CONFIG_FSDEV_9P=y >> /qemu/configs/devices/i386-softmmu/default.mak
RUN echo CONFIG_VFIO=y >> /qemu/configs/devices/i386-softmmu/default.mak
RUN echo CONFIG_VFIO_PCI=y >> /qemu/configs/devices/i386-softmmu/default.mak
RUN echo CONFIG_EDID=y >> /qemu/configs/devices/i386-softmmu/default.mak
RUN echo CONFIG_VGA=y >> /qemu/configs/devices/i386-softmmu/default.mak
RUN echo CONFIG_VGA_PCI=y >> /qemu/configs/devices/i386-softmmu/default.mak
RUN echo CONFIG_PCIE_PORT=y >> /qemu/configs/devices/i386-softmmu/default.mak
RUN echo CONFIG_I440FX=y >> /qemu/configs/devices/i386-softmmu/default.mak
RUN echo CONFIG_Q35=y >> /qemu/configs/devices/i386-softmmu/default.mak

# --without-default-devices
RUN mkdir build && \
  cd build && \
  /qemu/configure \
    --target-list=x86_64-softmmu \
    --static \
    --audio-drv-list="" \
    --disable-slirp \
    --disable-tcg-interpreter \
    --disable-containers \
    --disable-gtk \
    --disable-capstone \
    --disable-replication \
    --disable-parallels \
    --disable-vvfat \
    --disable-qed \
    --disable-vdi \
    --disable-qcow1 \
    --disable-dmg \
    --disable-cloop \
    --disable-bochs \
    --disable-bzip2 \
    --disable-guest-agent \
    --disable-numa \
    --disable-tcg \
    --disable-nitro \
    --disable-mshv \
    --disable-vnc \
    --disable-gio \
    --disable-docs \
    --disable-werror \
    --disable-tools \
    --disable-rust \
    --enable-lto \
    --extra-cflags=-Os \
    --enable-vhost-kernel \
    --enable-virtfs \
    --without-default-devices

RUN cd build && make -j4

RUN mkdir /out \
    && cp /build/qemu-system-x86_64 /out/vmrt \
    && strip /out/vmrt \
    && for firmware in bios-256k.bin vgabios-stdvga.bin kvmvapic.bin linuxboot_dma.bin efi-virtio.rom; do \
         cp "/qemu/pc-bios/${firmware}" /out/; \
       done \
    && /out/vmrt --version \
    && ! readelf -l /out/vmrt | grep -q INTERP
