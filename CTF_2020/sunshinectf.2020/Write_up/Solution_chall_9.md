# **speedrun-09**
## Task
nc chal.2020.sunshinectf.org 30009
File: chall_09
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
  int local_5c;
  byte local_58 [56];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  fgets((char *)local_58,0x31,stdin);
  sVar1 = strlen((char *)local_58);
  sVar2 = strlen(key);
  if (sVar1 == sVar2) {
    local_5c = 0;
    while( true ) {
      sVar1 = strlen(key);
      if (sVar1 <= (ulong)(long)local_5c) break;
      if ((local_58[local_5c] ^ 0x30) != key[local_5c]) {
                    /* WARNING: Subroutine does not return */
        exit(0);
      }
      local_5c = local_5c + 1;
    }
    system("/bin/sh");
  }
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

void win(void)
{
  system("/bin/sh");
  return;
}
```
Just read the source code, it's easy challenge

Program try to `xor` the input with `0x30` then compare with `key` value

Let's reverse it !!!

### Exploit
```python
from pwn import *
binary = context.binary = ELF('./chall_09')

payload = xor(binary.string(binary.sym.key),0x30)
p = remote('chal.2020.sunshinectf.org',30009)
p.sendline(payload)
p.interactive();
```
### Output
```bash
[*] '/home/kali/speedrun_sunshineCTF2020/chall_09'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to chal.2020.sunshinectf.org on port 30009: Done
[*] Switching to interactive mode
$ ls
chall_09
flag.txt
$ cat flag.txt
sun{coming-home-4202dcd54b230a00}
```