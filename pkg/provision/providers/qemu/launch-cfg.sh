# OG
-monitor unix:/Users/orz/.talos/clusters/talos-default/talos-default-controlplane-1.monitor,server,nowait \
-chardev socket,path=/Users/orz/.talos/clusters/talos-default/talos-default-controlplane-1.sock,server=on,wait=off,id=qga0 \
-device virtserialport,chardev=qga0,name=org.qemu.guest_agent.0 \
-kernel /Users/orz/work/talos/_out/vmlinuz-arm64 \
-initrd /Users/orz/work/talos/_out/initramfs-arm64.xz \
  -append "init_on_alloc=1 slab_nomerge pti=on consoleblank=0 nvme_core.io_timeout=4294967295 printk.devkmsg=on ima_template=ima-ng ima_appraise=fix ima_hash=sha512 console=ttyAMA0,115200n8 reboot=k panic=1 talos.shutdown=halt talos.platform=metal talos.config=http://10.5.0.1:52097/config.yaml"



# Jazz
  -monitor pty \
  -serial pty \
  -chardev pty,id=char0 \

sudo qemu-system-aarch64 \
-m 2048 \
-smp cpus=2 \
-cpu max \
  -netdev vmnet-shared,id=net0 \
-device virtio-net-device,netdev=net0,mac=54:54:00:55:54:51 \
-device virtio-rng-pci \
-device virtio-balloon,deflate-on-oom=on \
-device virtio-serial \
-no-reboot \
-boot order=cn,reboot-timeout=5000 \
-smbios type=1,uuid=d61fdeba-29b6-42c3-baf0-5d5d31f907cf \
-device i6300esb,id=watchdog0 \
  -watchdog-action poweroff \
-drive format=raw,if=virtio,file=/Users/orz/.talos/clusters/talos-default/talos-default-controlplane-1-0.disk,cache=none, \
  -machine virt,gic-version=max,accel=hvf \
  -drive file=/Users/orz/.talos/clusters/talos-default/talos-default-controlplane-1-flash0.img,format=raw,if=pflash \
  -drive file=/Users/orz/.talos/clusters/talos-default/talos-default-controlplane-1-flash1.img,format=raw,if=pflash \
  -serial stdio \
-cdrom metal-arm64.iso 

sudo qemu-system-aarch64 \
-m 2048 \
-smp cpus=2 \
-device virtio-rng-pci \
-device virtio-balloon,deflate-on-oom=on \
-device virtio-serial \
-no-reboot \
-boot order=cn,reboot-timeout=5000 \
-cdrom talos/metal-arm64.iso \
-smbios type=1,uuid=d61fdeba-29b6-42c3-baf0-5d5d31f907cf \
-device i6300esb,id=watchdog0 \
-watchdog-action pause \
-machine virt,gic-version=max,accel=hvf \
-drive if=pflash,format=raw,file=/opt/homebrew/share/qemu/edk2-aarch64-code.fd \
    -drive file=/Users/orz/.talos/clusters/talos-default/talos-default-controlplane-1-flash1.img,format=raw,if=pflash \
-cpu max \
-drive format=raw,if=virtio,file=/Users/orz/.talos/clusters/talos-default/talos-default-controlplane-1-0.disk,cache=none, \
-drive file=alpine.qcow2,media=disk,if=virtio \
-netdev vmnet-shared,id=net0 \
-serial stdio \
-device virtio-net-device,netdev=net0,mac=54:54:00:55:54:51
