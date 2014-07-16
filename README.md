fidget
======

Fidget is a project to analyze an ELF, parse out its functions, and mess with 
the stack frame allocation and layout of each function such that any attack 
that makes assumptions about the stack layout will fail, which should protect 
against any exploit leveraging a buffer overflow or format string 
vulnerability, which is most of them.

It works for all the x86, amd64, and ARM binaries I've thrown at it, though 
some of the ones with more complex buffer manipulations require the --safe flag 
to properly function. It is also kind of slow at the moment, because 
interfacing with IDA has an assload of latency for some reason.

You'll want to have `idal` and `idal64` in your PATH.