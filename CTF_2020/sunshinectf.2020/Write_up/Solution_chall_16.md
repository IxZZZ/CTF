# **speedrun-16**
## Task
nc chal.2020.sunshinectf.org 30016
File: chall_16
Tag: binary exploitation 

## Solution

### Checksec
```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
* No defect found 
* System 64 bit

### Decompile with ghidra
```c
void main(void)
{
  size_t sVar1;
  size_t sVar2;
  long in_FS_OFFSET;
  int local_60;
  char local_58 [56];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  fgets(local_58,0x31,stdin);
  sVar1 = strlen(local_58);
  sVar2 = strlen(key);
  if (sVar1 == sVar2) {
    local_60 = 0;
    while( true ) {
      sVar1 = strlen(key);
      if (sVar1 <= (ulong)(long)local_60) break;
      if (local_58[local_60] != key[local_60]) {
                    /* WARNING: Subroutine does not return */
        exit(0);
      }
      local_60 = local_60 + 1;
    }
    system("/bin/sh");
  }
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
This is similiar with RE challange than pwn. Just read the program.

The program compare `local_58` with `key`. So just send payload with key to the server to get the flag.
### Exploit
```python
from pwn import *

binary = context.binary = ELF('./chall_16')
p = remote('chal.2020.sunshinectf.org',30016)
p.sendline(binary.string(binary.sym.key))
p.interactive()
```
### Output
```bash
[*] '/home/kali/speedrun_sunshineCTF2020/chall_16'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to chal.2020.sunshinectf.org on port 30016: Done
[*] Switching to interactive mode
$ ls
chall_16
flag.txt
$ cat flag.txt
sun{beast-and-the-harlot-73058b6d2812c771}
```
