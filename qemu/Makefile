all: vmrt

vmrt: Dockerfile
	docker build -t build-qemu .
	$(SHELL) copy_img build-qemu vmrt .
	$(SHELL) copy_img build-qemu /qemu/pc-bios/vgabios-stdvga.bin .

.PHONY: all
