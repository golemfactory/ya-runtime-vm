FROM ubuntu:18.04

RUN apt update \
    && \
    \
    DEBIAN_FRONTEND=noninteractive \
    apt install --assume-yes  \
        build-essential ca-certificates git make \
        python3 wget pkg-config libglib2.0-dev libpixman-1-dev \
        libmount-dev libffi-dev libselinux1-dev libcap-ng-dev libattr1-dev \
    && \
    \
    rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/qemu/qemu.git -b v5.1.0 --recurse-submodules

# --without-default-devices
RUN mkdir build && \
  cd build && \
  /qemu/configure --target-list=x86_64-softmmu --static --audio-drv-list="" \
  --disable-slirp --disable-tcg-interpreter --disable-containers --disable-gtk \
  --disable-capstone --disable-avx2 --disable-avx512f --disable-replication \
  --disable-parallels --disable-sheepdog --disable-vvfat --disable-qed --disable-vdi \
  --disable-qcow1 --disable-dmg --disable-cloop --disable-bochs --disable-bzip2 \
  --disable-guest-agent --disable-numa --disable-tcg --disable-vnc \
   --disable-live-block-migration --enable-virtfs --enable-vhost-vsock \
  --without-default-devices
RUN echo CONFIG_PARALLEL=y >> build/config-host.mak
RUN echo CONFIG_VIRTIO=y >> build/config-host.mak
RUN echo CONFIG_VIRTIO_SERIAL=y >> build/config-host.mak
RUN echo CONFIG_VIRTIO_PCI=y >> build/config-host.mak
RUN echo CONFIG_VIRTIO_RNG=y >> build/config-host.mak
RUN echo CONFIG_VIRTIO_MMIO=y >> build/config-host.mak
RUN echo CONFIG_VIRTIO_SCSI=y >> build/config-host.mak
RUN echo CONFIG_VIRTIO_BLK=y >> build/config-host.mak
RUN echo CONFIG_VIRTIO_9P=y >> build/config-host.mak
RUN echo CONFIG_FSDEV_9P=y >> build/config-host.mak

RUN cd build && make x86_64-softmmu/all V=1 CFLAGS+="-Os -flto" -j4 LIBS+="-flto -lblkid -luuid -lpixman-1 -lutil"
#RUN cd build && make x86_64-softmmu/all V=1 LIBS+="-flto -lblkid -luuid -lpixman-1 -lutil" CONFIG_PARALLEL=y CONFIG_VIRTIO_SERIAL=y

#RUN cd build/x86_64-softmmu && -lmount -lblkid -luuid

RUN cp /build/x86_64-softmmu/qemu-system-x86_64 vmrt 

