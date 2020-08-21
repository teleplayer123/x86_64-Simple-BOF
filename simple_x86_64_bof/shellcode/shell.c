#include <stdio.h>

//program to test shellcode

void main(int argc, char **argv) {
    int (*ret)() = (int(*)())argv[1];
    ret();
}