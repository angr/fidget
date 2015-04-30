# Home of find_stack_tags and the BlockState and SmartExpression classes
# Basically stuff for tracking data flow through a basic block and generating tags for it

from angr import AngrMemoryError
import pyvex

from .binary_data import BinaryData, BinaryDataConglomerate
from .errors import FidgetError, FidgetUnsupportedError
from . import vexutils
from simuvex import operations, SimOperationError

import logging
l = logging.getLogger('fidget.sym_tracking')

def find_stack_tags(binrepr, symrepr, funcaddr):
    queue = [BlockState(binrepr, symrepr, funcaddr)]
    headcache = set()
    cache = set()
    while len(queue) > 0:
        blockstate = queue.pop(0)
        if blockstate.addr in headcache:
            continue
        l.debug("Analyzing block 0x%x", blockstate.addr)
        try:
            block = binrepr.angr.block(blockstate.addr)
        except AngrMemoryError:
            continue
        imarks = [ s for s in block.statements if isinstance(s, pyvex.IRStmt.IMark) ]
        headcache.add(imarks[0].addr)
        # FIXME: This part might break for thumb
        for mark in imarks:
            cache.add(mark.addr)
            insnblock = binrepr.angr.block(mark.addr, max_size=mark.len, num_inst=-1)
            temps = TempStore(insnblock.tyenv)
            blockstate.load_tempstore(temps)
            stmtgen = enumerate(insnblock.statements)
            for _, stmt in stmtgen:
                if isinstance(stmt, pyvex.IRStmt.IMark): break

            for stmt_idx, stmt in stmtgen:
                if stmt.tag in ('Ist_NoOp', 'Ist_AbiHint'):
                    pass

                elif stmt.tag == 'Ist_Exit':
                    SmartExpression(blockstate, stmt.dst, mark, [stmt_idx, 'dst'])
                    # Let the cfg take care of control flow!

                elif stmt.tag in ('Ist_WrTmp', 'Ist_Store', 'Ist_Put'):
                    this_expression = SmartExpression(blockstate, stmt.data, mark, [stmt_idx, 'data'])
                    blockstate.assign(stmt, this_expression, stmt_idx)

                elif stmt.tag == 'Ist_LoadG':
                    # Conditional loads. Lots of bullshit.
                    this_expression = SmartExpression(blockstate, stmt.addr, mark, [stmt_idx, 'addr'])
                    blockstate.access(this_expression, 1)
                    tmp_size = temps.size_of(stmt.dst)
                    temps.write(stmt.dst, vexutils.ZExtTo(tmp_size, this_expression.dirtyval))
                    blockstate.temps[stmt.dst] = this_expression
                    SmartExpression(blockstate, stmt.guard, mark, [stmt_idx, 'guard'])
                    SmartExpression(blockstate, stmt.alt, mark, [stmt_idx, 'alt'])

                elif stmt.tag == 'Ist_StoreG':
                    # Conditional store
                    addr_expr = SmartExpression(blockstate, stmt.addr, mark, [stmt_idx, 'addr'])
                    value_expr = SmartExpression(blockstate, stmt.data, mark, [stmt_idx, 'data'])
                    blockstate.access(addr_expr, 2)
                    if addr_expr.stack_addr:
                        blockstate.stack_cache[addr_expr.cleanval] = value_expr
                    if value_expr.stack_addr:
                        blockstate.access(value_expr, 4)
                    SmartExpression(blockstate, stmt.guard, mark, [stmt_idx, 'guard'])

                elif stmt.tag == 'Ist_PutI':    # haha no
                    SmartExpression(blockstate, stmt.data, mark, [stmt_idx, 'data'])
                elif stmt.tag == 'Ist_Dirty':   # hahAHAHAH NO
                    pass
                else:
                    raise FidgetUnsupportedError("Unknown vex instruction???", stmt)

        if block.jumpkind in ('Ijk_Call', 'Ijk_Boring', 'Ijk_Sys_int128', 'Ijk_SigTRAP'):
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
                    if jumpkind not in ('Ijk_Boring', 'Ijk_FakeRet'):
                        continue
                    elif node.addr in headcache:
                        continue
                    elif node.simprocedure_name is not None:
                        continue
                    elif node.addr in cache:
                        for succ, jumpkind in binrepr.cfg.get_successors_and_jumpkind(node, excluding_fakeret=False):
                            if jumpkind in ('Ijk_Boring', 'Ijk_FakeRet') and succ.addr not in cache and succ.simprocedure_name is None:
                                queue.append(blockstate.copy(succ.addr))
                    else:
                        queue.append(blockstate.copy(node.addr))

        elif block.jumpkind in ('Ijk_Ret', 'Ijk_NoDecode'):
            pass
        else:
            raise FidgetError("({:#x}) Can't proceed from unknown jumpkind {!r}".format(imarks[0].addr, block.jumpkind))

        blockstate.end()
        for tag in blockstate.tags:
            yield tag

class TempStore(object):
    def __init__(self, tyenv):
        self.tyenv = tyenv
        self.storage = {}

    def read(self, tmp):
        if tmp not in self.storage:
            raise ValueError('Temp not assigned to yet')
        else:
            return self.storage[tmp]

    def size_of(self, tmp):
        if tmp >= len(self.tyenv.types):
            raise ValueError('Temp not valid in curent env')
        return vexutils.extract_int(self.tyenv.types[tmp])

    def write(self, tmp, value):
        size = self.size_of(tmp)
        value.cleanval = vexutils.ZExtTo(size, value.cleanval)
        value.dirtyval = vexutils.ZExtTo(size, value.dirtyval)
        self.storage[tmp] = value

class AccessType:       # pylint: disable=no-init
    READ = 1
    WRITE = 2
    POINTER = 4
    UNINITREAD = 8

class BlockState:
    def __init__(self, binrepr, symrepr, addr):
        self.binrepr = binrepr
        self.symrepr = symrepr
        self.addr = addr
        self.regs = {}
        self.stack_cache = {}
        self.tags = []
        self.tempstore = None
        stackexp = ConstExpression(symrepr._claripy.BitVecVal(0, binrepr.angr.arch.bits))
        stackexp.stack_addr = True
        self.regs[self.binrepr.angr.arch.sp_offset] = stackexp

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

    def load_tempstore(self, tempstore):
        self.tempstore = tempstore

    def get_reg(self, regnum, size):
        if not regnum in self.regs:
            return ConstExpression(self.symrepr._claripy.BitVecVal(0, size*8))
        return self.regs[regnum].truncate(size*8)

    def get_tmp(self, tmpnum):
        return self.tempstore.read(tmpnum)

    def get_mem(self, addr, size):
        if addr.stack_addr:
            if addr.cleanval in self.stack_cache:
                return self.stack_cache[addr.cleanval]
            return ConstExpression(self.symrepr._claripy.BitVecVal(0, size*8))
        cleanestval = addr.cleanval.model.value
        if cleanestval in self.binrepr.angr.ld.memory:
            strval = ''.join(self.binrepr.angr.ld.memory[cleanestval + i] for i in xrange(size))
            return ConstExpression(self.symrepr._claripy.BitVecVal(self.binrepr.unpack_format(strval, size), size*8))
        return ConstExpression(self.symrepr._claripy.BitVecVal(0, size*8))

    def access(self, addr_expression, access_type):
        if not addr_expression.stack_addr:
            return
        self.tags.append(('STACK_ACCESS', addr_expression.make_bindata(access_type)))

    def assign(self, vextatement, expression, stmt_idx):
        if vextatement.tag == 'Ist_WrTmp':
            self.tempstore.write(vextatement.tmp, expression)
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
            addr_expr = SmartExpression(self, vextatement.addr, expression.mark, [stmt_idx, 'addr'])
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
