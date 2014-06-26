This should be the program's processing checklist:

- [x] Load file via idalink, pyelftools - verify it's an ELF (for now)
- [x] Find the .text section - use pyelftools
- [x] Find all the functions in .text - use idalink
- [X] Figure out what kind of stack frame is used in each function
- [X] Find all references to stack memory (ebp-stuff, esp+stuff on calling conventions w/ args in registers)
- [X] Figure out which references are actually offsets into variables - i.e. find variables
- [ ] Find limitations on how far things can be moved
- [ ] Resize stack frame - add CONST_OFFSET + num_vars * CONST_SPACING bytes of size
- [ ] Relocate variables - move each up by CONST_OFFSET + num_vars_below * CONST_SPACING

There needs to be a good way to create a nice bridge between the values 
reported by IDA and the actual bits, so here's my checklist for how to do that:

- [X] Everything happens in this BinaryData class, in executable.py
- [ ] If we're ARM, fuck everything (special case)
- [ ] Otherwise, start at the longest word size and iterate down to the smaller ones when you run out of room
- [ ] Iterate through the bits (only word-aligned?) and check if the value you're searching for is present
- [ ] If it is, sanity check by changing it (via ida's binary patching stuffs), reading off the instruction string from ida again, and making sure that the only change in the string is exactly what you meant to change

The idaPy docs suuuuuck (protip: read the source), so here's my notes on it:

- `idautils.XrefsFrom(memaddr)`
    Returns a generator listing the relationships accessed by this instruction
    Includes the relationship that the instruction pointer will be moved to its neighbor from it

- `idautils.XrefsTo(memaddr)`
    Returns a generator listing the relationships that access this instruction
    Includes the relationship that the instruction pointer will be moved to it from its neighbor

- `idaapi._xref`
    A class describing a relationship. Important properties:
    - `frm`: the memaddr that's doing the accessing
    - `to`: the memaddr that's getting accessed
    - `iscode`: a bool-int that is true if the relationship is anything that changes eip?

- `idautils.Chunks(memaddr)`
    Returns a generator listing presumably the single tuple (or no tuple) that holds the start and end addresses of
    the function that the address resides in.

- `idautils.Functions()`
    Returns a generator listing the memaddresses of all the functions IDA knows about.

- `idc.GetDisasm(memaddr)`
    Returns the text that is the disassembly of the opcode at the given address. Ex: `mov   rbp, rsp`

- `idc.GetMnem(memaddr)`
    Returns the name of the opcode used at the given address. Ex: `"mov"`

- `idc.GetOpnd(memaddr, n)`
    Returns the nth operand of the opcode at the given address as a string, or an empty string if there are fewer 
    than n operands. Ex: `"[esp+0Ch]"`

- `idc.GetOpType(memaddr, n)`
    Returns a number representing the type of the operand.
    Constants defined in idaapi.py, ~line 50,000

- `idc.GetOperandValue(memaddr, n)`
    Returns the numerical value of the nth operand

- `idc.Name(memaddr)`
    Returns a string naming the address, or empty string.

- `idc.here()`
    Returns the memaddress at which the cursor is currently situated.

- `idc.Jump(memaddr)`
    Moves the user's cursor to the specified address

- `idc.NextHead(memaddr)`
    Returns the memaddr of the first data or instruction starting after the given address

- `idc.GetSpd(memaddr)`
    Returns the difference between esp and ebp at this point in the function

- `idaapi.get_fileregion_offset(memaddr)`
    Returns the physaddr corresponding to the memaddr

- `idaapi.get_fileregion_ea(physaddr)`
    Returns the memaddr corresponding to the physaddr

- `idautils.DecodeInstruction(memaddr)`
    Returns an object of type `idaapi.insn_t` describing the instruction at the given address

- `idaapi.insn_t`
    A class describing an instruction. Important properties:
    - `ea`: The memaddress of the instruction
    - `Operands`: a list of the instruction's operands, as `idaapi.op_t` types
    - `Op1`, `Op2` ... `Op6`: Shortcuts to the instruction's operands
    - `itype`: An integer identifier for the opcode mnemomic. Not sure what table this indexes...
    - `size`: The number of bytes used by the instruction
    - `get_canon_mnem()`: returns the instruction's mnemomic

- `idaapi.op_t`
    A class describing an instruction's operand. Important properties:
    - `type`: The type from idc.GetOpType
    - `reg`: The ID number of the register involved in the operand
    - `dtyp`: 
    - `has_reg()`: Returns if the opcode has a register in it
    - `is_reg()`: Returns if the opcode is nothing but a register, probably
    - `value`: The numerical value of an operand-- does not work for dereference offsets
    - `n`: Which number operand this is, i.e. 0 for the first, 1 for the second...

- `idc.OpHex(memaddr, n)`
    Convert the nth operand of the instruction at memaddr to be displayed in hexadecimal


IDA's identification numbers, until I find a better way:

x86/amd64: (r** == e** = **)
- 0: ax || nothing-- be careful!
- 1: cx
- 2: dx
- 3: bx
- 4: sp
- 5: bp
- 6: si
- 7: di
- 8: r8
- 9: r9
- 10: r10
- 11: r11
- 12: r12
- 16: al
- 17: cl
- 31: ss (???)
- 23: bh

ARM: (:D)
- 0-12: R0-R12
- 13: SP
- 14: LR


Different kinds of stack frame headers I've found:

- `55 89 E5 83 EC ??` x86 8-bit stack frame
- `55 89 E5 81 EC ?? ?? ?? ??` x86 32-bit stack frame
- `55 89 E5 83 E4 F0 83 EC ??` x86 8-bit aligned stack frame

- `55 48 89 E5 48 83 EC ??` amd64 8-bit stack frame
- `55 48 89 E5 53 48 83 EC ??` amd64 8-bit stack frame, saves rbx
- `55 48 89 E5 41 54 53 48 83 EC ??` amd64 8-bit stack frame, saves rbx, r12
- `55 48 89 E5 41 55 41 54 53 48 83 EC ??` amd64 8-bit stack frame, saves rbx, r12, r13
- `55 48 89 E5 53 48 81 EC ?? ?? ?? ??` amd64 32-bit stack frame, saves rbx
- `55 48 89 E5` amd64 topless stack frame


SP-based stack frames - Do not attempt to change unless you're dead sure you've found the other end of the function and you can change the restore too
- `55 53 48 83 EC ??` amd64 sp-based 8-bit stack frame, saves rbp, rbx
- `48 83 EC ??` amd64 sp-based 8-bit stack frame


Long and short of it: look for a `mov ebp, esp` to tell if its bp-based, and `sub esp, ???` for how large the stack frame is
