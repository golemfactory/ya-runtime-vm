OUTPUT_DIR ?= ../runtime/poc/runtime
IMAGE ?= ya-runtime-vm-qemu:11.1.2

all: vmrt

vmrt: Dockerfile copy_img
	docker build --platform linux/amd64 -t "$(IMAGE)" .
	mkdir -p "$(OUTPUT_DIR)"
	bash copy_img "$(IMAGE)" /out/. "$(OUTPUT_DIR)"

.PHONY: all vmrt
