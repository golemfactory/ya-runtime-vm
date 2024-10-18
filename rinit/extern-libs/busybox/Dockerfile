FROM alpine:3.14
RUN  apk update \
    && apk add git build-base linux-headers \
    && git clone https://github.com/mirror/busybox
COPY config busybox/.config
RUN cd busybox \
    && git checkout 2d4a3d9e6c1493a9520b907e07a41aca90cdfd94 \
    && make oldconfig \
    && CFLAGS="-Os" LDFLAGS="--static" ./make_single_applets.sh