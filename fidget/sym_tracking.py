# Home of find_stack_tags and the BlockState and SmartExpression classes
# Basically stuff for tracking data flow through a basic block and generating tags for it

from angr import AngrMemoryError

from .binary_data import BinaryData, BinaryDataConglomerate
from .errors import FidgetError, FidgetUnsupportedError
from . import vexutils

import logging
l = logging.getLogger('fidget.sym_tracking')

def find_stack_tags(binrepr, symrepr, funcaddr):
    queue = [BlockState(binrepr, symrepr, funcaddr)]
    cache = set()
    while len(queue) > 0:
        blockstate = queue.pop(0)
        if blockstate.addr in cache:
            continue
        mark = None
        pathindex = 0
        block = binrepr.angr.block(blockstate.addr)
        for stmt in block.statements:
            if stmt.tag == 'Ist_IMark':
                mark = stmt
                cache.add(mark.addr)
                pathindex = -1
                #sys.stdout.flush()
                #stmt.pp()
                #print
                continue

            pathindex += 1
            #import sys;
            #sys.stdout.write('%.3d  ' % pathindex)
            #stmt.pp()
            #print
            if stmt.tag in ('Ist_NoOp', 'Ist_AbiHint'):
                pass

            elif stmt.tag == 'Ist_Exit':
                if stmt.jumpkind == 'Ijk_Boring':
                    dest = SmartExpression(blockstate, stmt.dst, mark, [pathindex, 'dst'])
                    try:
                        queue.append(blockstate.copy(dest.cleanval))
                    except AngrMemoryError:
                        pass
                else:
                    l.warning('(%s) Not sure what to do with jumpkind %s', hex(mark.addr), stmt.jumpkind)

            elif stmt.tag in ('Ist_WrTmp', 'Ist_Store', 'Ist_Put'):
                this_expression = SmartExpression(blockstate, stmt.data, mark, [pathindex, 'data'])
                blockstate.assign(stmt, this_expression, pathindex)

            elif stmt.tag == 'Ist_LoadG':
                # Conditional loads. Lots of bullshit.
                this_expression = SmartExpression(blockstate, stmt.addr, mark, [pathindex, 'addr'])
                blockstate.access(this_expression, 1)
                tmp_size = vexutils.extract_int(block.tyenv.typeOf(stmt.dst))
                this_expression.dirtyval = vexutils.ZExtTo(tmp_size, this_expression.dirtyval)
                blockstate.temps[stmt.dst] = this_expression
                SmartExpression(blockstate, stmt.guard, mark, [pathindex, 'guard'])
                SmartExpression(blockstate, stmt.alt, mark, [pathindex, 'alt'])

            elif stmt.tag == 'Ist_StoreG':
                # Conditional store
                addr_expr = SmartExpression(blockstate, stmt.addr, mark, [pathindex, 'addr'])
                value_expr = SmartExpression(blockstate, stmt.data, mark, [pathindex, 'data'])
                blockstate.access(addr_expr, 2)
                if addr_expr.stack_addr:
                    blockstate.stack_cache[addr_expr.cleanval] = value_expr
                if value_expr.stack_addr:
                    blockstate.access(value_expr, 4)

                SmartExpression(blockstate, stmt.guard, mark, [pathindex, 'guard'])


            else:
                raise FidgetUnsupportedError("Unknown vex instruction???", stmt)

        # The last argument is wrong but I dont't think it matters
        if block.jumpkind == 'Ijk_Boring':
            dest = SmartExpression(blockstate, block.next, mark, [pathindex, 'next'])
            if dest.cleanval not in binrepr.angr.sim_procedures:
                try:
                    queue.append(blockstate.copy(dest.cleanval))
                except AngrMemoryError:
                    pass
        elif block.jumpkind in ('Ijk_Ret', 'Ijk_NoDecode'):
            pass
        elif block.jumpkind == 'Ijk_Call':
            if binrepr.call_pushes_ret():
                # Pop the return address off the stack and keep going
                stack = blockstate.get_reg(binrepr.angr.arch.sp_offset)
                popped = stack.deps[0] if stack.deps[0].stack_addr else stack.deps[1]
                blockstate.regs[binrepr.angr.arch.sp_offset] = popped
                # Discard the last two tags -- they'll be an alloc and an access for the call (the push and the retaddr)
                blockstate.tags = blockstate.tags[:-2]

            for simirsb, jumpkind in binrepr.cfg.get_successors_and_jumpkind(binrepr.cfg.get_any_irsb(blockstate.addr), False):
                if jumpkind != 'Ijk_FakeRet':
                    continue
                try:
                    queue.append(blockstate.copy(simirsb.addr))
                except AngrMemoryError:
                    pass
        else:
            raise FidgetError("({:#x}) Can't proceed from unknown jumpkind {!r}".format(mark.addr, block.jumpkind))

        blockstate.end()
        for tag in blockstate.tags:
            yield tag


class AccessType:       # enum, basically :P
    def __init__(self):
        pass

    READ = 1
    WRITE = 2
    POINTER = 4
    UNINITREAD = 8

class BlockState:
    def __init__(self, binrepr, symrepr, addr):
        self.binrepr = binrepr
        self.symrepr = symrepr
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
        out = BlockState(self.binrepr, self.symrepr, newaddr)
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
        if addr.cleanval in self.binrepr.angr.ld.memory:
            strval = ''.join(self.binrepr.angr.ld.memory[addr.cleanval + i] for i in xrange(size))
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
            size = vexutils.extract_int(self.irsb.tyenv.types[vextatement.tmp])
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
        self.binrepr = self.blockstate.binrepr
        self.symrepr = self.blockstate.symrepr
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
        elif vexpression.tag == 'Iex_Const' or vexpression.tag.startswith('Ico_'):
            if vexpression.tag == 'Iex_Const':
                vexpression = vexpression.con
            size = vexutils.extract_int(vexpression.tag)
            self.cleanval = self.binrepr.resign_int(vexpression.value, size)
            self.dirtyval = self.symrepr._claripy.BitVec('%x_%d' % (mark.addr, path[0]), size)
            self.rootval = True
        elif vexpression.tag.startswith('Ico'):
            if vexpression.tag == 'Iex_Const':
                vexpression = vexpression.con
            size = vexutils.extract_int(vexpression.tag)
            self.cleanval = self.binrepr.resign_int(vexpression.value, size)
            self.dirtyval = self.symrepr._claripy.BitVec('%x_%d' % (mark.addr, path[0]), size)
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
            try:
                for i, expr in enumerate(vexpression.args):
                    self.deps.append(SmartExpression(blockstate, expr, mark, path + ['args', i]))
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
                    self.shield_constants(self.deps)
                    self.cleanval = self.deps[0].cleanval * self.deps[1].cleanval
                    self.dirtyval = self.deps[0].dirtyval * self.deps[1].dirtyval
                elif vexpression.op.startswith('Iop_Div') and ('Mod' not in vexpression.op):
                    self.cleanval = self.deps[0].cleanval / self.deps[1].cleanval
                    self.dirtyval = self.deps[0].dirtyval / self.deps[1].dirtyval
                elif vexpression.op.startswith('Iop_And'):
                    self.shield_constants(self.deps)
                    self.cleanval = self.deps[0].cleanval & self.deps[1].cleanval
                    self.dirtyval = self.deps[0].dirtyval & self.deps[1].dirtyval
                    self.stack_addr = self.deps[0].stack_addr or self.deps[1].stack_addr
                elif vexpression.op.startswith('Iop_Or'):
                    self.cleanval = self.deps[0].cleanval | self.deps[1].cleanval
                    self.dirtyval = self.deps[0].dirtyval | self.deps[1].dirtyval
                    self.stack_addr = self.deps[0].stack_addr or self.deps[1].stack_addr
                elif vexpression.op.startswith('Iop_Xor'):
                    self.cleanval = self.deps[0].cleanval ^ self.deps[1].cleanval
                    self.dirtyval = self.deps[0].dirtyval ^ self.deps[1].dirtyval
                    self.stack_addr = self.deps[0].stack_addr or self.deps[1].stack_addr
                elif vexpression.op.startswith('Iop_Shl'):
                    self.cleanval = self.deps[0].cleanval << self.deps[1].cleanval
                    self.dirtyval = self.deps[0].dirtyval << vexutils.ZExtTo(opsize, self.deps[1].dirtyval)
                elif vexpression.op.startswith('Iop_Sar'):
                    self.cleanval = self.deps[0].cleanval << self.deps[1].cleanval
                    self.dirtyval = self.deps[0].dirtyval << vexutils.ZExtTo(opsize, self.deps[1].dirtyval)
                elif vexpression.op.startswith('Iop_Shr'):
                    self.cleanval = self.deps[0].cleanval << self.deps[1].cleanval
                    if type(self.deps[0].dirtyval) in (int, long) or type(self.deps[1].dirtyval) in (int, long):
                        self.dirtyval = self.deps[0].dirtyval << self.deps[1].dirtyval
                    else:
                        self.dirtyval = self.symrepr._claripy.LShR(self.deps[0].dirtyval, vexutils.ZExtTo(opsize, self.deps[1].dirtyval))
                elif vexpression.op == 'Iop_DivModU64to32':
                    cvd = (self.deps[0].cleanval / self.deps[1].cleanval) & (2**32-1)
                    cvm = (self.deps[0].cleanval % self.deps[1].cleanval) & (2**32-1)
                    self.cleanval = (cvm << 32) | cvd
                    dvd = (self.deps[0].dirtyval / vexutils.ZExtTo(64, self.deps[1].dirtyval))[31:0]
                    dvm = (self.deps[0].dirtyval % vexutils.ZExtTo(64, self.deps[1].dirtyval))[31:0]
                    self.dirtyval = self.symrepr._claripy.Concat(dvm, dvd)
                elif vexpression.op == 'Iop_DivModS64to32':
                    cvd = (self.deps[0].cleanval / self.deps[1].cleanval) & (2**32-1)
                    cvm = (self.deps[0].cleanval % self.deps[1].cleanval) & (2**32-1)
                    self.cleanval = (cvm << 32) | cvd
                    dvd = (self.deps[0].dirtyval / vexutils.SExtTo(64, self.deps[1].dirtyval))[31:0]
                    dvm = (self.deps[0].dirtyval % vexutils.SExtTo(64, self.deps[1].dirtyval))[31:0]
                    self.dirtyval = self.symrepr._claripy.Concat(dvm, dvd)
                elif vexpression.op == 'Iop_DivModU128to64':
                    cvd = (self.deps[0].cleanval / self.deps[1].cleanval) & (2**64-1)
                    cvm = (self.deps[0].cleanval % self.deps[1].cleanval) & (2**64-1)
                    self.cleanval = (cvm << 64) | cvd
                    dvd = (self.deps[0].dirtyval / vexutils.ZExtTo(128, self.deps[1].dirtyval))[63:0]
                    dvm = (self.deps[0].dirtyval % vexutils.ZExtTo(128, self.deps[1].dirtyval))[63:0]
                    self.dirtyval = self.symrepr._claripy.Concat(dvm, dvd)
                elif vexpression.op == 'Iop_DivModS128to64':
                    cvd = (self.deps[0].cleanval / self.deps[1].cleanval) & (2**64-1)
                    cvm = (self.deps[0].cleanval % self.deps[1].cleanval) & (2**64-1)
                    self.cleanval = (cvm << 64) | cvd
                    dvd = (self.deps[0].dirtyval / vexutils.SExtTo(128, self.deps[1].dirtyval))[63:0]
                    dvm = (self.deps[0].dirtyval % vexutils.SExtTo(128, self.deps[1].dirtyval))[63:0]
                    self.dirtyval = self.symrepr._claripy.Concat(dvm, dvd)
                elif vexpression.op == 'Iop_DivModS64to64':
                    cvd = self.deps[0].cleanval / self.deps[1].cleanval
                    cvm = self.deps[0].cleanval % self.deps[1].cleanval
                    self.cleanval = (cvm << 64) | cvd
                    dvd = self.deps[0].dirtyval / self.deps[1].dirtyval
                    dvm = self.deps[0].dirtyval % self.deps[1].dirtyval
                    self.dirtyval = self.symrepr._claripy.Concat(dvm, dvd)
                elif vexpression.op in ('Iop_1Uto64', 'Iop_1Uto32', 'Iop_1Uto16', 'Iop_1Uto8'):
                    pass # Why does this even
                elif vexpression.op in ('Iop_128to8', 'Iop_64to8', 'Iop_32to8', 'Iop_16to8'):
                    self.cleanval = self.deps[0].cleanval
                    self.dirtyval = vexutils.ZExtTo(8, self.deps[0].dirtyval)
                elif vexpression.op in ('Iop_8Sto16',):
                    self.cleanval = self.deps[0].cleanval
                    self.dirtyval = vexutils.SExtTo(16, self.deps[0].dirtyval)
                elif vexpression.op in ('Iop_128to16', 'Iop_64to16', 'Iop_32to16', 'Iop_8Uto16'):
                    self.cleanval = self.deps[0].cleanval
                    self.dirtyval = vexutils.ZExtTo(16, self.deps[0].dirtyval)
                elif vexpression.op in ('Iop_16Sto32', 'Iop_8Sto32'):
                    self.cleanval = self.deps[0].cleanval
                    self.dirtyval = vexutils.SExtTo(32, self.deps[0].dirtyval)
                elif vexpression.op in ('Iop_128to32', 'Iop_64to32', 'Iop_16Uto32', 'Iop_8Uto32'):
                    self.cleanval = self.deps[0].cleanval
                    self.dirtyval = vexutils.ZExtTo(32, self.deps[0].dirtyval)
                elif vexpression.op in ('Iop_32Sto64', 'Iop_16Sto64', 'Iop_8Sto64'):
                    self.cleanval = self.deps[0].cleanval
                    self.dirtyval = vexutils.SExtTo(64, self.deps[0].dirtyval)
                elif vexpression.op in ('Iop_128to64', 'Iop_32Uto64', 'Iop_16Uto64', 'Iop_8Uto64'):
                    self.cleanval = self.deps[0].cleanval
                    self.dirtyval = vexutils.ZExtTo(64, self.deps[0].dirtyval)
                elif vexpression.op in ('Iop_64Sto128', 'Iop_32Sto128', 'Iop_16Sto128', 'Iop_8Sto128'):
                    self.cleanval = self.deps[0].cleanval
                    self.dirtyval = vexutils.SExtTo(128, self.deps[0].dirtyval)
                elif vexpression.op in ('Iop_64Uto128', 'Iop_32Uto128', 'Iop_16Uto128', 'Iop_8Uto128'):
                    self.cleanval = self.deps[0].cleanval
                    self.dirtyval = vexutils.ZExtTo(128, self.deps[0].dirtyval)
                elif vexpression.op in ('Iop_16HIto8',):
                    self.cleanval = self.deps[0].cleanval >> 8
                    self.dirtyval = self.deps[0].dirtyval >> 8 if type(self.deps[0].dirtyval) in (int, long) else self.deps[0].dirtyval[15:8]
                elif vexpression.op in ('Iop_32HIto16',):
                    self.cleanval = self.deps[0].cleanval >> 16
                    self.dirtyval = self.deps[0].dirtyval >> 16 if type(self.deps[0].dirtyval) in (int, long) else self.deps[0].dirtyval[31:16]
                elif vexpression.op in ('Iop_64HIto32',):
                    self.cleanval = self.deps[0].cleanval >> 32
                    self.dirtyval = self.deps[0].dirtyval >> 32 if type(self.deps[0].dirtyval) in (int, long) else self.deps[0].dirtyval[63:32]
                elif vexpression.op in ('Iop_128HIto64',):
                    self.cleanval = self.deps[0].cleanval >> 64
                    self.dirtyval = self.deps[0].dirtyval >> 64 if type(self.deps[0].dirtyval) in (int, long) else self.deps[0].dirtyval[127:64]
                elif vexpression.op == 'Iop_32HLto64':
                    self.cleanval = (self.deps[0].cleanval << 32) | self.deps[1].cleanval
                    a1 = vexutils.ZExtTo(64, self.deps[0].dirtyval)
                    a2 = vexutils.ZExtTo(64, self.deps[1].dirtyval)
                    self.dirtyval = (a1 << 32) | a2
                elif vexpression.op == 'Iop_64HLto128':
                    self.cleanval = (self.deps[0].cleanval << 64) | self.deps[1].cleanval
                    a1 = vexutils.ZExtTo(128, self.deps[0].dirtyval)
                    a2 = vexutils.ZExtTo(128, self.deps[1].dirtyval)
                    self.dirtyval = self.symrepr._claripy.Concat(a1, a2)
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
                    raise FidgetUnsupportedError('Unknown operator ({:#x}): {!r}'.format(mark.addr, vexpression.op))
            except ZeroDivisionError:
                self.cleanval = 0
                self.dirtyval = 0
                self.deps = []
        elif vexpression.tag == 'Iex_CCall':
            pass
        else:
            raise FidgetUnsupportedError('Unknown expression tag ({:#x}): {!r}'.format(mark.addr, vexpression.tag))


    def copy_to_self(self, other):
        self.cleanval = other.cleanval
        self.dirtyval = other.dirtyval
        self.deps = other.deps
        self.bincache = other.bincache
        self.stack_addr = other.stack_addr
        self.rootval = other.rootval
        self.path = other.path

    @staticmethod
    def shield_constants(expr_list, exception_list=None):
        exception_list = exception_list if exception_list is not None else []
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
                        self.cleanval, self.dirtyval, self.binrepr, self.symrepr)]
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

    @staticmethod
    def make_bindata():
        return []
