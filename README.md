fidget
======

Fidget is a project to analyze an ELF, parse out its functions, and mess with 
the stack frame allocation and layout of each function such that any attack 
that makes assumptions about the stack layout will fail, which should protect 
against any exploit leveraging a buffer overflow or format string 
vulnerability, which is most of them.

So how do you use it? Well, the folder named fidget is a python module, so 
stick that in your pythonpath. Then, you can run fidget the program with:

`python -m fidget <arguments>`

Run it with no arguments for usage information.
