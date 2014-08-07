# Home of the BlockState and SmartExpression classes
# Basically stuff for tracking data flow through a basic block and generating tags for it

import claripy
import vexutils
from binary_data import BinaryData, BinaryDataConglomerate

class AccessType:       # enum, basically :P
    READ = 1
    WRITE = 2
    POINTER = 4
    UNINITREAD = 8

class BlockState:
    def __init__(self, binrepr, addr):
        self.binrepr = binrepr
        self.addr = addr
        self.irsb = binrepr.angr.block(addr)
        self.regs = {}
        self.temps = {}
        self.stack_cache = {}
        self.tags = []
        stackexp = ConstExpression()
        stackexp.stack_addr = True
        self.regs[self.binrepr.angr.arch.sp_offset] = stackexp

    def __str__(self):
        return 'BlockState(binrepr, 0x%x)' % self.addr

    def __repr__(self):
        return str(self)

    def copy(self, newaddr):
        out = BlockState(self.binrepr, newaddr)
        s = self.binrepr.angr.arch.sp_offset
        out.regs[s] = self.regs[s]
        b = self.binrepr.angr.arch.bp_offset
        if self.binrepr.processor == 3:
            b = 140 # On PPC, make sure to copy over r31
        elif self.binrepr.processor == 5:
            b = 264 # Same for PPC64
        if b in self.regs and self.regs[b].stack_addr:
            out.regs[b] = self.regs[b]
        return out

    def get_reg(self, regnum):
        if not regnum in self.regs:
            return ConstExpression()
        return self.regs[regnum]

    def get_tmp(self, tmpnum):
        return self.temps[tmpnum]

    def get_mem(self, addr, size):
        if addr.stack_addr:
            if addr.cleanval in self.stack_cache:
                return self.stack_cache[addr.cleanval]
            return ConstExpression()
        if addr.cleanval in self.binrepr.angr.main_binary.ida.mem:
            strval = ''.join(self.binrepr.angr.main_binary.ida.mem[addr.cleanval + i] for i in xrange(size))
            return ConstExpression(self.binrepr.unpack_format(strval, size))
        #physaddr = self.binrepr.relocate_to_physaddr(addr.cleanval)
        #if physaddr is None:
        #    return ConstExpression()
        #self.binrepr.filestream.seek(physaddr)
        #return ConstExpression(self.binrepr.unpack_format(self.binrepr.filestream.read(size), size))
        return ConstExpression()

    def set_ip(self, addr):
        self.regs[self.binrepr.angr.arch.ip_offset] = ConstExpression(addr)

    def access(self, addr_expression, access_type):
        if not addr_expression.stack_addr:
            return
        self.tags.append(('STACK_ACCESS', addr_expression.make_bindata(access_type)))

    def assign(self, vextatement, expression, line):
        if vextatement.tag == 'Ist_WrTmp':
            size = vexutils.extract_int(self.irsb.tyenv.typeOf(vextatement.tmp))
            expression.dirtyval = vexutils.ZExtTo(size, expression.dirtyval)
            self.temps[vextatement.tmp] = expression
        elif vextatement.tag == 'Ist_Put':
            self.regs[vextatement.offset] = expression
            if vextatement.offset == self.binrepr.angr.arch.sp_offset:
                if expression.cleanval == 0:
                    self.tags.append(('STACK_DEALLOC', expression.make_bindata(0)))
                else:
                    self.tags.append(('STACK_ALLOC', expression.make_bindata(0)))
        elif vextatement.tag == 'Ist_Store':
            addr_expr = SmartExpression(self, vextatement.addr, expression.mark, [line, 'addr'])
            self.access(addr_expr, AccessType.WRITE)
            if addr_expr.stack_addr:
                self.stack_cache[addr_expr.cleanval] = expression
            if expression.stack_addr:
                self.access(expression, AccessType.POINTER)

    def end(self):
        for offset, value in self.regs.iteritems():
            if offset in (self.binrepr.angr.arch.sp_offset, self.binrepr.angr.arch.bp_offset, self.binrepr.angr.arch.ip_offset):
                continue
            self.access(value, AccessType.POINTER)

class SmartExpression:
    def __init__(self, blockstate, vexpression, mark, path):
        self.blockstate = blockstate
        self.vexpression = vexpression
        self.mark = mark
        self.path = path
        self.cleanval = 0
        self.dirtyval = 0
        self.deps = []
        self.stack_addr = False
        self.rootval = False
        self.bincache = [None]
        if vexpression.tag == 'Iex_Get':
            self.copy_to_self(blockstate.get_reg(vexpression.offset))
        elif vexpression.tag == 'Iex_RdTmp':
            self.copy_to_self(self.blockstate.get_tmp(vexpression.tmp))
        elif vexpression.tag == 'Iex_Load':
            addr_expression = SmartExpression(blockstate, vexpression.addr, mark, path + ['addr'])
            self.blockstate.access(addr_expression, AccessType.READ)
            size = vexutils.extract_int(vexpression.type) / 8
            self.copy_to_self(self.blockstate.get_mem(addr_expression, size))
        elif vexpression.tag == 'Iex_Const' or dir(vexpression)[0] == 'F32': # TODO: Make this not a hack
            if vexpression.tag == 'Iex_Const':
                vexpression = vexpression.con
            size = vexutils.extract_int(vexpression.tag)
            self.cleanval = self.blockstate.binrepr.resign_int(vexpression.value, size)
            self.dirtyval = self.blockstate.binrepr.claripy.BitVec('%x_%d' % (mark.addr, path[0]), size)
            self.rootval = True
        elif vexpression.tag == 'Iex_ITE':
            false_expr = SmartExpression(blockstate, vexpression.iffalse, mark, path + ['iffalse'])
            truth_expr = SmartExpression(blockstate, vexpression.iftrue, mark, path + ['iftrue'])

            if truth_expr.stack_addr:
                self.copy_to_self(truth_expr)
            else:
                self.copy_to_self(false_expr)
            SmartExpression(blockstate, vexpression.cond, mark, path + ['cond'])
        elif vexpression.tag in ('Iex_Unop','Iex_Binop','Iex_Triop','Iex_Qop'):
            for i, expr in enumerate(vexpression.args()):
                self.deps.append(SmartExpression(blockstate, expr, mark, path + ['arg%d' % (i+1)]))
            opsize = vexutils.extract_int(vexpression.op)
            if vexpression.op.endswith('to1'):
                if self.deps[0].cleanval != 0:
                    self.cleanval = 1
                self.dirtyval = 0 # TODO: ????
            elif vexpression.op.startswith('Iop_Not'):
                self.cleanval = self.deps[0].cleanval ^ ((1 << opsize) - 1)
                self.dirtyval = ~self.deps[0].dirtyval
            elif vexpression.op.startswith('Iop_Sub'):
                self.cleanval = self.deps[0].cleanval - self.deps[1].cleanval
                self.dirtyval = self.deps[0].dirtyval - self.deps[1].dirtyval
                self.stack_addr = self.deps[0].stack_addr and not self.deps[1].stack_addr
            elif vexpression.op.startswith('Iop_Add'):
                self.cleanval = self.deps[0].cleanval + self.deps[1].cleanval
                self.dirtyval = self.deps[0].dirtyval + self.deps[1].dirtyval
                self.stack_addr = self.deps[0].stack_addr or self.deps[1].stack_addr
            elif vexpression.op.startswith('Iop_Mul'):
                self.cleanval = self.deps[0].cleanval * self.deps[1].cleanval
                self.dirtyval = self.deps[0].dirtyval * self.deps[1].dirtyval
            elif vexpression.op.startswith('Iop_Div'):
                self.cleanval = self.deps[0].cleanval * self.deps[1].cleanval
                self.dirtyval = self.deps[0].dirtyval * self.deps[1].dirtyval
            elif vexpression.op in ('Iop_And64', 'Iop_And32', 'Iop_And8'):
                self.shield_constants(self.deps)
                self.cleanval = self.deps[0].cleanval & self.deps[1].cleanval
                self.dirtyval = self.deps[0].dirtyval & self.deps[1].dirtyval
                self.stack_addr = self.deps[0].stack_addr or self.deps[1].stack_addr
            elif vexpression.op in ('Iop_Or64', 'Iop_Or32', 'Iop_Or8'):
                self.cleanval = self.deps[0].cleanval | self.deps[1].cleanval
                self.dirtyval = self.deps[0].dirtyval | self.deps[1].dirtyval
                self.stack_addr = self.deps[0].stack_addr or self.deps[1].stack_addr
            elif vexpression.op in ('Iop_Xor64', 'Iop_Xor32', 'Iop_Xor8'):
                self.cleanval = self.deps[0].cleanval ^ self.deps[1].cleanval
                self.dirtyval = self.deps[0].dirtyval ^ self.deps[1].dirtyval
                self.stack_addr = self.deps[0].stack_addr or self.deps[1].stack_addr
            elif vexpression.op in ('Iop_Shl64', 'Iop_Shl32'):
                self.cleanval = self.deps[0].cleanval << self.deps[1].cleanval
                self.dirtyval = self.deps[0].dirtyval << vexutils.ZExtTo(opsize, self.deps[1].dirtyval)
            elif vexpression.op in ('Iop_Sar64', 'Iop_Sar32'):
                self.cleanval = self.deps[0].cleanval << self.deps[1].cleanval
                self.dirtyval = self.deps[0].dirtyval << vexutils.ZExtTo(opsize, self.deps[1].dirtyval)
            elif vexpression.op in ('Iop_Shr64', 'Iop_Shr32'):
                self.cleanval = self.deps[0].cleanval << self.deps[1].cleanval
                if type(self.deps[0].dirtyval) in (int, long) or type(self.deps[1].dirtyval) in (int, long):
                    self.dirtyval = self.deps[0].dirtyval << self.deps[1].dirtyval
                else:
                    self.dirtyval = self.blockstate.binrepr.claripy.LShR(self.deps[0].dirtyval, vexutils.ZExtTo(opsize, self.deps[1].dirtyval))
            elif vexpression.op in ('Iop_1Uto64', 'Iop_1Uto32', 'Iop_1Uto16', 'Iop_1Uto8'):
                pass # Why does this even
            elif vexpression.op in ('Iop_64to8', 'Iop_32to8', 'Iop_16to8'):
                self.cleanval = self.deps[0].cleanval
                self.dirtyval = vexutils.ZExtTo(8, self.deps[0].dirtyval)
            elif vexpression.op in ('Iop_32to16',):
                self.cleanval = self.deps[0].cleanval
                self.dirtyval = vexutils.ZExtTo(16, self.deps[0].dirtyval)
            elif vexpression.op in ('Iop_64to32', 'Iop_8Uto32'):
                self.cleanval = self.deps[0].cleanval
                self.dirtyval = vexutils.ZExtTo(32, self.deps[0].dirtyval)
            elif vexpression.op in ('Iop_32Uto64', 'Iop_16Uto32', 'Iop_8Uto64'):
                self.cleanval = self.deps[0].cleanval
                self.dirtyval = vexutils.ZExtTo(64, self.deps[0].dirtyval)
            elif vexpression.op in ('Iop_16Sto32', 'Iop_8Sto32'):
                self.cleanval = self.deps[0].cleanval
                self.dirtyval = vexutils.SExtTo(32, self.deps[0].dirtyval)
            elif vexpression.op in ('Iop_32Sto64',):
                self.cleanval = self.deps[0].cleanval
                self.dirtyval = vexutils.SExtTo(64, self.deps[0].dirtyval)
            elif vexpression.op in ('Iop_64HIto32',):
                self.cleanval = self.deps[0].cleanval >> 32
                self.dirtyval = self.deps[0].dirtyval >> 32 if type(self.deps[0].dirtyval) in (int, long) else self.deps[0].dirtyval[63:32]
            elif vexpression.op == 'Iop_32HLto64':
                self.cleanval = (self.deps[0].cleanval << 32) | self.deps[1].cleanval
                a1 = vexutils.ZExtTo(64, self.deps[0].dirtyval)
                a2 = vexutils.ZExtTo(64, self.deps[1].dirtyval)
                self.dirtyval = (a1 << 32) | a2
            elif 'Cmp' in vexpression.op:
                self.cleanval = 0
                self.dirtyval = 0
                self.deps = []
            elif vexpression.op.startswith('Iop_Clz'):
                self.cleanval = 0
                tmp_clean = self.deps[0].cleanval
                for _ in xrange(opsize):
                    tmp_clean <<= 1
                    if tmp_clean >= (1 << opsize):
                        break
                    self.cleanval += 1
                self.dirtyval = 0 # Nope, fuck this
            elif vexpression.op.startswith('Iop_Ctz'):
                self.cleanval = 0
                tmp_clean = self.deps[0].cleanval
                for _ in xrange(opsize):
                    if tmp_clean % 2 == 1:
                        break
                    tmp_clean >>= 1
                    self.cleanval += 1
                self.dirtyval = 0 # Again with the Fucking of This

            else:
                raise Exception('Unknown operator (%x): "%s"' % (mark.addr, vexpression.op))
        elif vexpression.tag == 'Iex_CCall':
            pass
        else:
            import pdb; pdb.set_trace()
            raise Exception('Unknown expression tag (%x): "%s"' % (mark.addr, vexpression.tag))


    def copy_to_self(self, other):
        self.cleanval = other.cleanval
        self.dirtyval = other.dirtyval
        self.deps = other.deps
        self.bincache = other.bincache
        self.stack_addr = other.stack_addr
        self.rootval = other.rootval
        self.path = other.path

    def shield_constants(self, expr_list, exception_list=[]):
        for i, expr in enumerate(expr_list):
            if i in exception_list: continue
            if expr.rootval:
                expr_list[i] = ConstExpression(expr.cleanval)

    def make_bindata(self, flags=None):
        if self.bincache[0] is not None and flags is None:
            return self.bincache[0]
        elif self.bincache[0] is None:
            if self.rootval:
                self.bincache[0] = [BinaryData(self.mark, self.path + ['con', 'value'], \
                        self.cleanval, self.dirtyval, self.blockstate.binrepr)]
                return self.bincache[0]
            
            self.bincache[0] = sum(map(lambda x: x.make_bindata(), self.deps), [])

        if flags is None:
            return self.bincache[0]
        else:
            acc = BinaryDataConglomerate(self.cleanval, self.dirtyval, flags)
            acc.dependencies = self.bincache[0]
            acc.memaddr = self.mark.addr
            return acc

    def __str__(self):
        return 'Expression at 0x%x stmt %d' % (self.mark.addr, self.path[0])

class ConstExpression:
    def __init__(self, val=0):
        self.cleanval = val
        self.dirtyval = val
        self.deps = []
        self.stack_addr = False
        self.bincache = [None]
        self.rootval = False
        self.mark = None
        self.path = []

    def make_bindata(self):
        return []
