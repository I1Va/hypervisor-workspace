I have host PC (PC) and debug testbench (DTB)

DTB connected to PC with
1) mini com port dev/tty/usb0. Debug info port
2) arduino comport dev/tty/usb1. remote reset control via arduino
3) you need to run http server for boot serve.sh script in efi-superrepo

PC will be located ssh to window
ssh to windows DTB `ssh -p 22 Арсений@192.168.3.67`, пароль: `user` 
It will be aavailable once it boots.
If ssh does not come, it probably means that hypervisor failed to boot. In such cases use remote reset.

Sometimes bsod appears and TBD powers down. In this case you need to use "tools/reset_pc.py" 

To bring TBD to a running state just run "./tools/reset_pc.py". It checks the
motherboard power LED first: if the PC is off it presses the power button, if it
is on it pulses the reset header. Do not check, which commands arduino can
receive, just run the script.



remote DTB Reset: tools/reset_pc.py

read thr readme in the hypervisor/efi-superrepo
DO NOT lAUNCH SIMULATOR


Our goal is to develop INVISIBLE for DTB OS (windows) hypervisor for cheats creation.
Hypervisor pass criteria - invisibility by
https://github.com/NotRequiem/VMAware/releases
VMAware placed in /user/Арсений/Desktop
Vmaware might freese DTB because of hypervisor bugs. It is normal situation, do reset in this case. 



you dont need to clone, just run serve.sh and reset pc
To boot, you need to serve.sh and reset. Reset script works fine, dont invent anything yourself.



my pc ip: 192.168.3.13/24


notice, that extensive loging SLOWS booting a lot.
