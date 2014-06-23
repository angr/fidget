# functions that provide the interface for messing with
# binaries and stuff, via whatever tools.

from elftools.elf.elffile import ELFFile
from elftools.elf.descriptions import describe_e_machine
import idalink

# Executable
# not actually a class! fakes being a class because it
# basically just looks at the filetype, determines what kind
# of binary it is (ELF, PE, w/e) and switches control to an
# appropriate class, all of which inherit from _Executable,
# the actual class

#hopefully the only processors we should ever have to target
processors = ['x86', 'amd64', 'arm', 'ppc', 'mips']

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
        if self.verbose > 2:
            print '%8x:       %s' % (ins.ea, self.ida.idc.GetDisasm(ins.ea))
        s = [self.ida.idc.GetMnem(ins.ea)] + map(lambda x: self.ida.idc.GetOpnd(ins.ea, x), range(6))
        if self.identify_bp_assignment(s):
            return ('STACK_TYPE_BP', 0)
        if self.identify_sp_assignment(s):
            return ('STACK_FRAME_ALLOC', ins.Op2.value)
        if s[0] == 'add' and (s[1] == 'esp' or s[1] == 'rsp'):
            return ('STACK_FRAME_DEALLOC', ins.Op2.value)
        for opn in ins.Operands:
            if opn.type == 0: break
            if opn.type == 3 and opn.has_reg(self.ida.idautils.procregs.sp):
                if not self.sanity_check(ins.ea, opn):
                    continue
                return ('STACK_SP_ACCESS', 0)
            if opn.type != 4: continue
            if opn.has_reg(self.ida.idautils.procregs.sp):
                #sanity check first
                if not self.sanity_check(ins.ea, opn):
                    continue
                return ('STACK_SP_ACCESS', resign_int(opn.addr, self.native_dtyp))
            elif opn.has_reg(self.ida.idautils.procregs.bp):
                if not self.sanity_check(ins.ea, opn):
                    continue
                return ('STACK_BP_ACCESS', resign_int(opn.addr, self.native_dtyp))
        return ('', 0)

    def identify_bp_assignment(self, s):
        return s[:3] == ['mov', 'ebp', 'esp'] or \
                s[:3] == ['mov', 'rbp', 'rsp'] or \
                s[:4] == ['ADD', 'R11', 'SP', '#0']

    def identify_sp_assignment(self, s):
        return s[:2] == ['sub', 'esp'] or \
                s[:2] == ['sub', 'rsp'] or \
                s[:3] == ['SUB', 'SP', 'SP']

    def construct_operand(self, op):
        if op.type == 3:
            return '[%s]' % self.construct_register(op.reg, op.dtyp)
        if op.type == 4:
            addr = resign_int(op.addr, self.native_dtyp)
            return '[%s%+d]' % (self.construct_register(op.reg, self.native_dtyp), addr)
        
    def construct_register(self, reg, dtyp):
        prefix = 'r' if dtyp == 7 else 'e' if dtyp == 2 else ''
        return prefix + ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', '8', '9', '10', '11', '12'][reg]

    def sanity_check(self, ea, op):
        self.ida.idc.OpDecimal(ea, op.n)
        mine = self.construct_operand(op)
        idas = self.ida.idc.GetOpnd(ea, op.n)
        if mine not in idas:
            if self.verbose > 1:
                print '\t*** IDA is lying (%s): %s not in %s' % \
                    (ea, mine, idas)
            return False
        return True



class ElfExecutable(_Executable):
    def __init__(self, filename):
        self.verbose = 0
        self.filename = filename
        self.elfreader = ELFFile(open(filename))
        self.native_dtyp = 7 if self.is_64_bit() else 2
        elfproc = self.elfreader.header.e_machine
        if elfproc == 'EM_386':
            self.processor = 0
        elif elfproc == 'EM_X86_64':
            self.processor = 1
        elif elfproc == 'EM_ARM':
            self.processor = 2
        else:
            raise ValueError('Unsupported processor type: %s' % elfproc)
        self.ida = idalink.IDALink(filename, "idal64" if self.is_64_bit() else "idal")
        self.get_section_by_name = self.elfreader.get_section_by_name

    def is_64_bit(self):
        return self.elfreader.header.e_ident.EI_CLASS == 'ELFCLASS64'

    def is_convention_stack_args(self):
        return self.processor == 0


