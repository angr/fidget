# functions that provide the interface for messing with
# binaries and stuff, via whatever tools.

from elftools.elf.elffile import ELFFile
import idalink

# Executable
# not actually a class! fakes being a class because it
# basically just looks at the filetype, determines what kind
# of binary it is (ELF, PE, w/e) and switches control to an
# appropriate class, all of which inherit from _Executable,
# the actual class

#hopefully the only processors we should ever have to target
procesors = ['x86', 'amd64', 'arm', 'ppc', 'mips']

word_size = {0: 1, 1: 2, 2: 4, 7: 8}

def resign_int(n, dtyp):
    if (dtyp == 0): # 8 bit
        top = 0xFF
    elif (dtyp == 1): # 16 bit
        top = 0xFFFF
    elif (dtyp == 2): # 32 bit
        top = 0xFFFFFFFF
    elif (dtyp == 7): # 64 bit
        top = 0xFFFFFFFFFFFFFFFF
    else:
        return None
    if (n > top):
        return None
    if (n < top/2): # woo int division
        return n
    return -((n ^ top) + 1)

def unsign_int(n, dtyp):
    if (dtyp == 0): # 8 bit
        top = 0xFF
    elif (dtyp == 1): # 16 bit
        top = 0xFFFF
    elif (dtyp == 2): # 32 bit
        top = 0xFFFFFFFF
    elif (dtyp == 7): # 64 bit
        top = 0xFFFFFFFFFFFFFFFF
    else:
        return None
    if (n > top/2):
        return None
    elif (n < -top/2):
        return None
    if (n >= 0):
        return n
    return -((n ^ top) + 1)

def Executable(filename):
    return ElfExecutable(filename) # ...

class _Executable():
    def iterate_instructions(self, funcaddr):
        fstart, fend = next(self.ida.idautils.Chunks(funcaddr))
        while True:
            yield self.ida.idautils.DecodeInstruction(fstart)
            fstart = self.ida.idc.NextHead(fstart)
            if fstart >= fend:
                break

    def guess_dtype(self, sval):
        for dtype in [0, 1, 2, 7]:
            if unsign_int(sval, dtype) is not None:
                return dtype
        return None # ..?

    def identify_instr(self, ins): #only works on x86 right now, maybe amd64
        if self.verbose:
            print '%8x:       %s' % (ins.ea, self.ida.idc.GetDisasm(ins.ea))
        op = self.ida.idc.GetMnem(ins.ea)
        op1 = self.ida.idc.GetOpnd(ins.ea, 0)
        op2 = self.ida.idc.GetOpnd(ins.ea, 1)
        if (op == 'mov' and op1 == 'ebp' and op2 == 'esp') or \
           (op == 'mov' and op1 == 'rbp' and op2 == 'rsp'):
            return ('STACK_TYPE_BP', 0)
        if op == 'sub' and (op1 == 'esp' or op1 == 'rsp'):
            return ('STACK_FRAME_ALLOC', ins.Op2.value)
        if op == 'add' and (op1 == 'esp' or op1 == 'rsp'):
            return ('STACK_FRAME_DEALLOC', ins.Op2.value)
        for opn in ins.Operands:
            if opn.type == 0: break
            if opn.type == 3 and opn.has_reg(self.ida.idautils.procregs.sp):
                return ('STACK_SP_ACCESS', 0)
            if opn.type != 4: continue
            if opn.has_reg(self.ida.idautils.procregs.sp):
               return ('STACK_SP_ACCESS', resign_int(opn.addr, self.native_dtyp))
            elif opn.has_reg(self.ida.idautils.procregs.bp):
               return ('STACK_BP_ACCESS', resign_int(opn.addr, self.native_dtyp))
        return ('', 0)
        



class ElfExecutable(_Executable):
    def __init__(self, filename):
        self.verbose = False
        self.filename = filename
        self.elfreader = ELFFile(open(filename))
        self.native_dtyp = 7 if self.is_64_bit() else 2
        self.ida = idalink.IDALink(filename, "idal64" if self.is_64_bit() else "idal")
        self.get_section_by_name = self.elfreader.get_section_by_name

    def is_64_bit(self):
        return self.elfreader.header.e_ident.EI_CLASS == 'ELFCLASS64'


