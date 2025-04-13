all: vmrt

VIRTIOFS ?= false
NUMA ?= $(if $(filter true,$(VIRTIOFS)),true,false)

vmrt: Dockerfile
	docker build \
		--build-arg VIRTIOFS=$(VIRTIOFS) \
		--build-arg NUMA=$(NUMA) \
		-t build-qemu .
	$(SHELL) copy_img build-qemu vmrt .
	$(SHELL) copy_img build-qemu /qemu/pc-bios/vgabios-stdvga.bin .

.PHONY: all
