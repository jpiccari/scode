scode
=====

A simple shellcode development tool.

Compiling
=========

`cc -o scode scode.c` should do it. It may also be worth noting that some systems
may default to compiling position independent code which is then used to randomize
memory locations via ALSR. This scenario may not be ideal. Most compilers have a
flag to turn off such features (-mdynamic-no-pic, -fno-pie, -no_pie, etc.).
