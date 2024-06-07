#!usr/bin/env python
import os

fout = os.popen("strings guess-passwd | grep sW33")
passwd = fout.read()
print("candl{" + passwd.rstrip() + "}")


