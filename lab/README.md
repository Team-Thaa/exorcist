# Test lab (owner: Nitin)

Pi 5 gateway + QEMU VMs. Lab only: our own harmless scripts, never real malware, never touch anything outside the lab subnets.

- `pi-setup/`: bridge `br-lan` 192.168.50.0/24, Zeek install, decoy IP .99
- `vms/`: OpenWrt x86-64 router VM, fake camera VM
- `fake-bot/`: harmless bot script (variants: full, scan only, beacon only, slow scan)
- `fake-c2/`: fake C2 server at 10.66.0.10:8080 on a dummy interface on the Pi
- `captures/`: pcaps and Zeek logs (git-ignored)
