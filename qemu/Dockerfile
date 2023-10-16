FROM ubuntu:22.04

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

RUN git clone https://github.com/qemu/qemu.git -b v8.1.1 --recurse-submodules

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
    --disable-avx2 \
    --disable-avx512f \
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
    --disable-vnc \
    --disable-live-block-migration \
    --disable-gio \
    --enable-vhost-kernel \
    --enable-virtfs \
    --without-default-devices

RUN cd build && make V=1 CFLAGS+="-Os -flto" -j4

RUN cp /build/x86_64-softmmu/qemu-system-x86_64 vmrt 
