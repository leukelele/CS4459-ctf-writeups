#include <stdio.h>
#include <unistd.h>
int main(void) {
  setregid(70004, 70004);
  execve("/bin/sh",0,0);
  return 0;
}
