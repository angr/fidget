fidget
======

Fidget is a project to analyze an ELF, parse out its functions, and mess with 
the stack frame allocation and layout of each function such that any attack 
that makes assumptions about the stack layout will fail, which should protect 
against any exploit leveraging a buffer overflow or format string 
vulnerability, which is most of them.

It is not done.
