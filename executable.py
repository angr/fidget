# functions that provide the interface for messing with
# binaries and stuff, via whatever tools.

from elftools.elf.elffile import ELFFile
from elftools.elf.descriptions import describe_e_machine
from elftools.common import exceptions
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
        return int(n)
    return int(-((n ^ top) + 1))

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
        return int(n)
    return int(-((n ^ top) + 1))


def Executable(filename):
    return ElfExecutable(filename) # ...

class _Executable():
    def iterate_instructions(self, funcaddr):
        fstart, fend = next(self.ida.idautils.Chunks(funcaddr))
        while True:
            a = self.ida.idautils.DecodeInstruction(fstart)
            if a is not None:   # ... ARM is weird
                yield a
            fstart = self.ida.idc.NextHead(fstart)
            if fstart >= fend:
                break

    def guess_dtype(self, sval):
        for dtype in [0, 1, 2, 7]:
            if unsign_int(sval, dtype) is not None:
                return dtype
        return None # ..?

    def identify_instr(self, ins):
        s = [self.ida.idc.GetMnem(ins.ea)] + map(lambda x: self.ida.idc.GetOpnd(ins.ea, x), range(6))
        if self.identify_bp_assignment(s):
            return ('STACK_TYPE_BP', ins.Op3.value) # somewhat dangerous hack for ARM
        if self.identify_sp_assignment(s):
            return ('STACK_FRAME_ALLOC', ins.Op2.value if self.processor < 2 else ins.Op3.value)
        if self.identify_sp_deassignment(s):
            return ('STACK_FRAME_DEALLOC', ins.Op2.value if self.processor < 2 else ins.Op3.value)
        if self.identify_bp_pointer(s):
            reladdr = ins.Op3.value * (-1 if s[0].lower() == 'sub' else 1)
            n_ea = ins.ea
            if self.verbose > 1:
                print '\t* Found complex pointer'
            while True:
                n_ea = self.ida.idc.NextHead(n_ea)
                n_mnem = self.ida.idc.GetMnem(n_ea).lower()
                if n_mnem not in ('add', 'sub'): break
                if self.ida.idc.GetOpnd(n_ea, 1) != s[1]: break
                if self.ida.idc.GetOpType(n_ea, 2) != 5: break # must be immediate value
                if self.verbose > 1:
                    print '\t* Expanding complex pointer'
                s[1] = self.ida.idc.GetOpnd(n_ea, 0)
                reladdr += self.ida.idc.GetOperandValue(n_ea, 2) * (-1 if n_mnem == 'sub' else 1)
            return ('STACK_BP_ACCESS', reladdr, 1)
        for opn in ins.Operands:
            if opn.type == 0: break
            if opn.type == 3 and opn.has_reg(self.ida.idautils.procregs.sp):
                if not self.sanity_check(ins.ea, opn):
                    continue
                return ('STACK_SP_ACCESS', 0, opn.n)
            if opn.type != 4: continue
            if opn.has_reg(self.get_sp()):
                #sanity check first
                if not self.sanity_check(ins.ea, opn):
                    continue
                return ('STACK_SP_ACCESS', resign_int(opn.addr, self.native_dtyp), opn.n)
            elif opn.has_reg(self.get_bp()):
                if not self.sanity_check(ins.ea, opn):
                    continue
                return ('STACK_BP_ACCESS', resign_int(opn.addr, self.native_dtyp), opn.n)
        return ('', 0)

    def identify_bp_assignment(self, s):
        return s[:3] == ['mov', 'ebp', 'esp'] or \
                s[:3] == ['mov', 'rbp', 'rsp'] or \
                s[:3] == ['ADD', 'R11', 'SP']

    def identify_sp_assignment(self, s):
        return s[:2] == ['sub', 'esp'] or \
                s[:2] == ['sub', 'rsp'] or \
                s[:3] == ['SUB', 'SP', 'SP']

    def identify_sp_deassignment(self, s):
        return s[:2] == ['add', 'esp'] or \
                s[:2] == ['add', 'rsp'] or \
                s[:3] == ['ADD', 'SP', 'SP']

    def identify_bp_pointer(self, s):
        return (s[0] in ('SUB', 'ADD') and s[2] == 'R11' and s[1] != 'SP')

    def construct_operand_x86(self, op):
        if op.type == 3:
            return '[%s]' % self.construct_register(op.reg, op.dtyp)
        if op.type == 4:
            addr = resign_int(op.addr, self.native_dtyp)
            return '[%s%+d]' % (self.construct_register(op.reg, self.native_dtyp), addr)

    def construct_operand_arm(self, op):
        if op.type == 4:
            addr = resign_int(op.addr, self.native_dtyp)
            if addr == 0: return '[%s]' % self.construct_register(op.reg, self.native_dtyp)
            return '[%s,#%d]' % (self.construct_register(op.reg, self.native_dtyp), addr)
        
    def construct_register(self, reg, dtyp):
        if self.processor == 0 or self.processor == 1:
            prefix = 'r' if dtyp == 7 else 'e' if dtyp == 2 else ''
            suffix = ''
        else:
            prefix = ''
            suffix = ''
        x86regs = ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', '8', '9', '10', '11', '12']
        armregs = ['R0', 'R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R8', 'R9', 'R10', 'R11', 'R12', 'SP', 'LR']
        return prefix + [x86regs, x86regs, armregs][self.processor][reg] + suffix

    def get_sp(self, constant=False):
        if not constant:
            if self.processor == 0 or self.processor == 1 or self.processor == 2:
                return self.ida.idautils.procregs.sp
        else:
            if self.processor == 0 or self.processor == 1:
                return 4
            elif self.processor == 2:
                return 13

    def get_bp(self, constant=False):
        if not constant:
            if self.processor == 0 or self.processor == 1:
                return self.ida.idautils.procregs.bp
            elif self.processor == 2:
                return self.ida.idautils.procregs.r11
        else:
            if self.processor == 0 or self.processor == 1:
                return 5
            elif self.processor == 2:
                return 11

    def sanity_check(self, ea, op):
        self.ida.idc.OpDecimal(ea, op.n)
        mine = self.construct_operand(op)
        idas = self.ida.idc.GetOpnd(ea, op.n)
        if mine not in idas:
            if self.verbose > 1:
                 print '\t*** IDA is lying (%x): %s not in %s' % \
                    (ea, mine, idas)
            return False
        return True

    # Access flags - returns an int
    # bit 0 (lsb) will be set if the operand reads from the address
    # bit 1 will be set if the operand writes to the address
    # bit 2 will be set if the operand loads a pointer to the address
    # bit 3 will be set if the address is read from before it is written to -- must be implemented by the caller

    def get_access_flags(self, ins, opn):
        op = ins.Operands[opn]
        mnem = self.ida.idc.GetMnem(ins.ea)
        if self.processor < 2:
            if mnem in ('call', 'push', 'cmp', 'test'): # read-only
                return 1
            if mnem in ('pop'): # write-only
                return 2
            if mnem in ('lea') and opn == 1: # both - passing a pointer so who knows?
                return 4
            if opn == 0: # if it's the first operand, it's usually being written to
                return 2
            return 1 # otherwise just reading
        elif self.processor == 2:
            if 'LDR' in mnem:
                return 1
            elif 'STR' in mnem:
                return 2
            elif mnem in ('ADD', 'SUB'):
                return 4
            return 1



class ElfExecutable(_Executable):
    def __init__(self, filename):
        self.verbose = 0
        self.filename = filename
        try:
            self.elfreader = ELFFile(open(filename))
            self.error = False
        except exceptions.ELFError:
            self.error = True
            return
        self.native_dtyp = 7 if self.is_64_bit() else 2
        elfproc = self.elfreader.header.e_machine
        if elfproc == 'EM_386':
            self.processor = 0
            self.construct_operand = self.construct_operand_x86
        elif elfproc == 'EM_X86_64':
            self.processor = 1
            self.construct_operand = self.construct_operand_x86
        elif elfproc == 'EM_ARM':
            self.processor = 2
            self.construct_operand = self.construct_operand_arm
        else:
            raise ValueError('Unsupported processor type: %s' % elfproc)
        self.ida = idalink.IDALink(filename, "idal64" if self.is_64_bit() else "idal")
        self.get_section_by_name = self.elfreader.get_section_by_name

    def is_64_bit(self):
        return self.elfreader.header.e_ident.EI_CLASS == 'ELFCLASS64'

    def is_convention_stack_args(self):
        return self.processor == 0


