# Home of find_stack_tags and the BlockState and SmartExpression classes
# Basically stuff for tracking data flow through a basic block and generating tags for it

from angr import AngrMemoryError

from .binary_data import BinaryData, BinaryDataConglomerate
from .errors import FidgetError, FidgetUnsupportedError
from . import vexutils
from simuvex import operations, SimOperationError

import logging
l = logging.getLogger('fidget.sym_tracking')

def find_stack_tags(binrepr, symrepr, funcaddr):
    queue = [BlockState(binrepr, symrepr, funcaddr)]
    cache = set()
    while len(queue) > 0:
        blockstate = queue.pop(0)
        if blockstate.addr in cache:
            continue
        l.debug("Analyzing block 0x%x", blockstate.addr)
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
                SmartExpression(blockstate, stmt.dst, mark, [pathindex, 'dst'])
                # Let the cfg take care of control flow!

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

            elif stmt.tag == 'Ist_PutI':    # haha no
                SmartExpression(blockstate, stmt.data, mark, [pathindex, 'data'])
            elif stmt.tag == 'Ist_Dirty':   # hahAHAHAH NO
                pass
            else:
                raise FidgetUnsupportedError("Unknown vex instruction???", stmt)

        if block.jumpkind in ('Ijk_Call', 'Ijk_Boring'):
            if block.jumpkind == 'Ijk_Call' and binrepr.angr.arch.call_pushes_ret:
                # Pop the return address off the stack and keep going
                stack = blockstate.get_reg(binrepr.angr.arch.sp_offset, binrepr.angr.arch.bytes)
                popped = stack.deps[0] if stack.deps[0].stack_addr else stack.deps[1]
                blockstate.regs[binrepr.angr.arch.sp_offset] = popped
                # Discard the last two tags -- they'll be an alloc and an access for the call (the push and the retaddr)
                blockstate.tags = blockstate.tags[:-2]

            for context in binrepr.cfg.get_all_nodes(blockstate.addr):
                for node, jumpkind in binrepr.cfg.get_successors_and_jumpkind( \
                                        context, \
                                        excluding_fakeret=False):
                    if jumpkind == 'Ijk_Call':
                        continue
                    try:
                        queue.append(blockstate.copy(node.addr))
                    except AngrMemoryError:
                        pass

        elif block.jumpkind in ('Ijk_Ret', 'Ijk_NoDecode'):
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
        stackexp = ConstExpression(symrepr._claripy.BitVecVal(0, binrepr.angr.arch.bits))
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

    def get_reg(self, regnum, size):
        if not regnum in self.regs:
            return ConstExpression(self.symrepr._claripy.BitVecVal(0, size*8))
        return self.regs[regnum].truncate(size*8)

    def get_tmp(self, tmpnum):
        return self.temps[tmpnum]

    def get_mem(self, addr, size):
        if addr.stack_addr:
            if addr.cleanval in self.stack_cache:
                return self.stack_cache[addr.cleanval]
            return ConstExpression(self.symrepr._claripy.BitVecVal(0, size*8))
        if addr.cleanval in self.binrepr.angr.ld.memory:
            strval = ''.join(self.binrepr.angr.ld.memory[addr.cleanval + i] for i in xrange(size))
            return ConstExpression(self.symrepr._claripy.BitVecVal(self.binrepr.unpack_format(strval, size), size*8))
        #physaddr = self.binrepr.relocate_to_physaddr(addr.cleanval)
        #if physaddr is None:
        #    return ConstExpression()
        #self.binrepr.filestream.seek(physaddr)
        #return ConstExpression(self.binrepr.unpack_format(self.binrepr.filestream.read(size), size))
        return ConstExpression(self.symrepr._claripy.BitVecVal(0, size*8))

    def set_ip(self, addr):
        self.regs[self.binrepr.angr.arch.ip_offset] = ConstExpression(self.symrepr._claripy.BitVecVal(addr, self.binrepr.angr.arch.bits))

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
            if not vextatement.offset in self.regs:
                self.regs[vextatement.offset] = ConstExpression(self.symrepr._claripy.BitVecVal(0, self.binrepr.angr.arch.bits))
            self.regs[vextatement.offset] = expression.overwrite(self.regs[vextatement.offset])
            if vextatement.offset == self.binrepr.angr.arch.sp_offset:
                if expression.cleanval.model.value == 0:
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
        self.deps = []
        self.stack_addr = False
        self.rootval = False
        self.bincache = [None]
        self.size = vexpression.result_size if not vexpression.tag.startswith('Ico_') else vexpression.size
        self.cleanval = self.symrepr._claripy.BitVecVal(0, self.size)
        self.dirtyval = self.symrepr._claripy.BitVecVal(0, self.size)
        if vexpression.tag == 'Iex_Get':
            self.copy_to_self(blockstate.get_reg(vexpression.offset, self.size/8))
        elif vexpression.tag == 'Iex_RdTmp':
            self.copy_to_self(self.blockstate.get_tmp(vexpression.tmp))
        elif vexpression.tag == 'Iex_Load':
            addr_expression = SmartExpression(blockstate, vexpression.addr, mark, path + ['addr'])
            self.blockstate.access(addr_expression, AccessType.READ)
            self.copy_to_self(self.blockstate.get_mem(addr_expression, self.size/8))
        elif vexpression.tag == 'Iex_Const' or vexpression.tag.startswith('Ico_'):
            if vexpression.tag == 'Iex_Const':
                vexpression = vexpression.con
            self.cleanval = self.symrepr._claripy.BitVecVal(vexpression.value, self.size)
            self.dirtyval = self.symrepr._claripy.BitVec('%x_%d' % (mark.addr, path[0]), self.size)
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
                if vexpression.op.startswith('Iop_Mul') or vexpression.op.startswith('Iop_And'):
                    self.shield_constants(self.deps)
                self.cleanval = operations[vexpression.op].calculate(self.symrepr._claripy, *(x.cleanval for x in self.deps))
                self.dirtyval = operations[vexpression.op].calculate(self.symrepr._claripy, *(x.dirtyval for x in self.deps))
                if vexpression.op.startswith('Iop_Add') or vexpression.op.startswith('Iop_And') or \
                   vexpression.op.startswith('Iop_Or') or vexpression.op.startswith('Iop_Xor'):
                    self.stack_addr = self.deps[0].stack_addr or self.deps[1].stack_addr
                elif vexpression.op.startswith('Iop_Sub'):
                    self.stack_addr = self.deps[0].stack_addr and not self.deps[1].stack_addr
            except SimOperationError:
                l.exception("SimOperationError while running op '%s', returning null", vexpression.op)
            except KeyError:
                l.error("Unsupported operation '%s', returning null", vexpression.op)
        elif vexpression.tag == 'Iex_CCall':
            pass
        elif vexpression.tag == 'Iex_GetI':
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

    def null(self, size):
        return self.symrepr._claripy.BitVec(0, size)

    def make_bindata(self, flags=None):
        if self.bincache[0] is not None and flags is None:
            return self.bincache[0]
        elif self.bincache[0] is None:
            if self.rootval:
                self.bincache[0] = [BinaryData(self.mark, self.path + ['con', 'value'], \
                        self.cleanval.model.signed, self.dirtyval, self.binrepr, self.symrepr)]
                return self.bincache[0]

            self.bincache[0] = sum(map(lambda x: x.make_bindata(), self.deps), [])

        if flags is None:
            return self.bincache[0]
        else:
            acc = BinaryDataConglomerate(self.cleanval.model.signed, self.dirtyval, flags)
            acc.dependencies = self.bincache[0]
            acc.memaddr = self.mark.addr
            return acc

    def overwrite(self, other):
        if self.size > other.size:
            l.warning("Overwriting a SmartExpression with a larger SmartExpression. Are you SURE you know what you're doing?")
            return self
        if self.size == other.size:
            return self
        smaller = self
        larger = other
        out = CustomExpression()
        out.deps = [smaller, larger]
        out.size = larger.size
        out.blockstate = smaller.blockstate
        out.mark = smaller.mark # ??? what will be done with this
        out.path = smaller.path
        out.binrepr = out.blockstate.binrepr
        out.symrepr = out.blockstate.symrepr
        out.stack_addr = larger.stack_addr # sketchy...
        out.rootval = False
        out.bincache = [None]
        out.cleanval = out.symrepr._claripy.Concat(larger.cleanval[larger.size-1:smaller.size], smaller.cleanval)
        out.dirtyval = out.symrepr._claripy.Concat(larger.dirtyval[larger.size-1:smaller.size], smaller.dirtyval)
        return out

    def truncate(self, size):
        if size > self.size:
            l.error("Attempting to truncate SmartExpression of size %d to size %d", self.size, size)
            return self
        if size == self.size:
            return self
        out = CustomExpression()
        out.deps = [self]
        out.size = size
        out.blockstate = self.blockstate
        out.mark = self.mark # ??? what will be done with this
        out.path = self.path
        out.binrepr = out.blockstate.binrepr
        out.symrepr = out.blockstate.symrepr
        out.stack_addr = False
        out.rootval = False
        out.bincache = [None]
        out.cleanval = self.cleanval[size-1:0]
        out.dirtyval = self.dirtyval[size-1:0]
        return out

    def __str__(self):
        return 'Expression at 0x%x stmt %d' % (self.mark.addr, self.path[0])

class CustomExpression(SmartExpression):
    def __init__(self): # pylint: disable=super-init-not-called
        pass

class ConstExpression(object):
    def __init__(self, val):
        self.size = val.size()
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

    def truncate(self, size):
        if size > self.size:
            l.error("Attempting to truncate SmartExpression of size %d to size %d", self.size, size)
            return self
        if size == self.size:
            return self
        return ConstExpression(self.cleanval[size-1:0])
