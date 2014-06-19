This should be the program's processing checklist:

[x] Load file via idalink, pyelftools - verify it's an ELF (for now)
[x] Find the .text section - use pyelftools
[x] Find all the functions in .text - use idalink
[ ] Figure out what kind of stack frame is used in each function
[ ] Find all references to stack memory (ebp-stuff, esp+stuff on calling conventions w/ args in registers)
[ ] Figure out which references are actually offsets into variables - i.e. find variables
[ ] Resize stack frame - add CONST_OFFSET + num_vars * CONST_SPACING bytes of size
[ ] Relocate variables - move each up by CONST_OFFSET + num_vars_below * CONST_SPACING


The idaPy docs suuuuuck (protip: read the source), so here's my notes on it:

idautils.XrefsFrom(memaddr)
    Returns a generator listing the relationships accessed by this instruction
    Includes the relationship that the instruction pointer will be moved to its neighbor from it

idautils.XrefsTo(memaddr)
    Returns a generator listing the relationships that access this instruction
    Includes the relationship that the instruction pointer will be moved to it from its neighbor

idautils._xref
    A class describing a relationship. Important properties:
    - `frm`: the memaddr that's doing the accessing
    - `to`: the memaddr that's getting accessed
    - `iscode`: a bool-int that is true if the relationship is anything that changes eip?

idautils.Chunks(memaddr)
    Returns a generator listing presumably the single tuple (or no tuple) that holds the start and end addresses of
    the function that the address resides in.

idautils.Functions()
    Returns a generator listing the memaddresses of all the functions IDA knows about.


