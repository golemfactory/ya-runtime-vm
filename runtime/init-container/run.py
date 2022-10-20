"""Helper script for running VM manually under Windows"""
import os
command = ""
command += "qemu-system-x86_64.exe "
command += "-m 1G "
command += "-nographic -vga none "
command += "-kernel vmlinuz-virt "
command += "-initrd initramfs.cpio.gz "
command += "-net none -smp 2 "
command += '-append "console=ttyS0 panic=1" '
command += "-device virtio-serial "
command += "-chardev socket,id=manager_cdev,host=127.0.0.1,port=9003,server,nowait "
command += "-chardev socket,id=net_cdev,host=127.0.0.1,port=9004,server,nowait "
command += "-chardev socket,id=p9_cdev,host=127.0.0.1,port=9005,server,nowait "
command += "-device virtserialport,chardev=manager_cdev,name=manager_port "
command += "-device virtserialport,chardev=net_cdev,name=net_port "
command += "-device virtserialport,chardev=p9_cdev,name=p9_port "
command += "-drive file=ubuntu.gvmi,cache=unsafe,readonly=on,format=raw,if=virtio "
command += "-drive file=empty_10GB.qcow2,format=qcow2,if=virtio "
command += "-no-reboot "
command += "-accel whpx "
command += "-nodefaults "
command += "--serial stdio "

print(command)
os.system(command)


