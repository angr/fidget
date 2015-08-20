# Home of find_stack_tags and the BlockState and SmartExpression classes
# Basically stuff for tracking data flow through a basic block and generating tags for it

from angr import AngrMemoryError
import pyvex
import claripy

from .binary_data import BinaryData, BinaryDataConglomerate
from .errors import FidgetError, FidgetUnsupportedError, ValueNotFoundError
from . import vexutils
from simuvex import operations, SimOperationError

import logging
l = logging.getLogger('fidget.sym_tracking')

OK_CONTINUE_JUMPS = ('Ijk_FakeRet', 'Ijk_Boring', 'Ijk_FakeRet', 'Ijk_Sys_int128', 'Ijk_SigTRAP', 'Ijk_Sys_syscall')

ROUNDING_IROPS = ('Iop_AddF64', 'Iop_SubF64', 'Iop_MulF64', 'Iop_DivF64',
                  'Iop_AddF32', 'Iop_SubF32', 'Iop_MulF32', 'Iop_DivF32',
                  'Iop_AddF128', 'Iop_SubF128', 'Iop_MulF128', 'Iop_DivF128',
                  'Iop_AddF64r32', 'Iop_SubF64r32', 'Iop_MulF64r32', 'Iop_DivF64r32',
                  'Iop_F64toI32S', 'Iop_SqrtF64', 'Iop_SqrtF32', 'Iop_SqrtF128',
                  'Iop_F64toI16S', 'Iop_F64toI32S', 'Iop_F64toI64S', 'Iop_F64toI64U',
                  'Iop_F64toI32U', 'Iop_I32StoF64', 'Iop_I64StoF64', 'Iop_I64UtoF64',
                  'Iop_I64UtoF32', 'Iop_I32UtoF32', 'Iop_I32UtoF64', 'Iop_F32toI32S',
                  'Iop_F32toI64S', 'Iop_F32toI32U', 'Iop_F32toI64U', 'Iop_I32StoF32',
                  'Iop_I64StoF32', 'Iop_F64toF32'
                  'Iop_F128toI32S', 'Iop_F128toI64S', 'Iop_F128toI32U', 'Iop_F128toI64U',
                  'Iop_F128toF64', 'Iop_F128toF32'
                  'Iop_AtanF64', 'Iop_Yl2xF64', 'Iop_Yl2xp1F64',
                  'Iop_PRemF64', 'Iop_PRemC3210F64', 'Iop_PRem1F64', 'Iop_PRem1C3210F64',
                  'Iop_ScaleF64', 'Iop_SinF64', 'Iop_CosF64', 'Iop_TanF64',
                  'Iop_2xm1F64', 'Iop_RoundF64toInt', 'Iop_RoundF32toInt',
                  'Iop_MAddF32', 'Iop_MSubF32', 'Iop_MAddF64', 'Iop_MSubF64',
                  'Iop_MAddF64r32', 'Iop_MSubF64r32',
                  'Iop_RoundF64toF32', 'Iop_RecpExpF64', 'Iop_RecpExpF64', 'Iop_RecpExpF32',
                  'Iop_F64toF16', 'Iop_F32toF16',
                  'Iop_AddD64', 'Iop_SubD64', 'Iop_MulD64', 'Iop_DivD64',
                  'Iop_AddD128', 'Iop_SubD128', 'Iop_MulD128', 'Iop_DivD128',
                  'Iop_D64toD32', 'Iop_D128toD64', 'Iop_I64StoD64', 'Iop_I64UtoD64',
                  'Iop_D64toI32S', 'Iop_D64toI32U', 'Iop_D64toI64S', 'Iop_D64toI64U',
                  'Iop_D128toI32S', 'Iop_D128toI32U', 'Iop_D128toI64S', 'Iop_D128toI64U',
                  'Iop_F32toD32', 'Iop_F32toD64', 'Iop_F32toD128', 'Iop_F64toD32',
                  'Iop_F64toD64', 'Iop_F64toD128', 'Iop_F128toD32', 'Iop_F128toD64',
                  'Iop_F128toD128', 'Iop_D32toF32', 'Iop_D32toF64', 'Iop_D32toF128',
                  'Iop_D64toF32', 'Iop_D64toF64', 'Iop_D64toF128', 'Iop_D128toF32',
                  'Iop_D128toF64', 'Iop_D128toF128', 'Iop_RoundD64toInt',
                  'Iop_RoundD128toInt', 'Iop_QuantizeD64' 'Iop_QuantizeD128',
                  'Iop_SignificanceRoundD64', 'Iop_SignificanceRoundD128',
                  'Iop_Add32Fx4', 'Iop_Sub32Fx4', 'Iop_Mul32Fx4', 'Iop_Div32Fx4',
                  'Iop_Add64Fx2', 'Iop_Sub64Fx2', 'Iop_Mul64Fx2', 'Iop_Div64Fx2',
                  'Iop_Add64Fx4', 'Iop_Sub64Fx4', 'Iop_Mul64Fx4', 'Iop_Div64Fx4',
                  'Iop_Add32Fx8', 'Iop_Sub32Fx8', 'Iop_Mul32Fx8', 'Iop_Div32Fx8'
                 )

def find_stack_tags(project, cfg, funcaddr):
    queue = [BlockState(project, funcaddr)]
    headcache = set()
    cache = set()
    while len(queue) > 0:
        blockstate = queue.pop(0)
        if blockstate.addr in headcache:
            continue
        l.debug("Analyzing block 0x%x", blockstate.addr)

        try:
            block = blockstate.lift(opt_level=1, max_size=400)
        except AngrMemoryError:
            continue

        mark_addrs = [
                        s.addr + s.delta
                        for s in block.statements
                        if isinstance(s, pyvex.IRStmt.IMark)
                     ]
        if block.jumpkind == 'Ijk_NoDecode':
            l.error("Block at %#x ends in NoDecode", blockstate.addr)
            mark_addrs.pop()
        headcache.add(blockstate.addr)

        for addr in mark_addrs:
            if addr != funcaddr and addr in cfg.function_manager.functions:
                l.warning("\tThis function jumps into another function (%#x). Abort.", addr)
                yield ("ABORT_HIT_OTHER_FUNCTION_HEAD", addr)
                return
            cache.add(addr)

            insnblock = blockstate.lift(addr, num_inst=1, max_size=400, opt_level=1)
            temps = TempStore(insnblock.tyenv)
            blockstate.load_tempstore(temps)
            stmtgen = enumerate(insnblock.statements)
            for _, stmt in stmtgen:
                if isinstance(stmt, pyvex.IRStmt.IMark): break

            for stmt_idx, stmt in stmtgen:
                path = ['statements', stmt_idx]
                if stmt.tag in ('Ist_NoOp', 'Ist_AbiHint', 'Ist_MBE'):
                    pass

                elif stmt.tag == 'Ist_Exit':
                    SmartExpression(blockstate, stmt.dst, addr, path + ['dst'])
                    # Let the cfg take care of control flow!

                elif stmt.tag in ('Ist_WrTmp', 'Ist_Store', 'Ist_Put'):
                    this_expression = SmartExpression(blockstate, stmt.data, addr, path + ['data'])
                    blockstate.assign(stmt, this_expression, stmt_idx)

                elif stmt.tag == 'Ist_LoadG':
                    # Conditional loads. Lots of bullshit.
                    addr_expression = SmartExpression(blockstate, stmt.addr, addr, path + ['addr'])
                    blockstate.access(addr_expression, AccessType.READ)

                    # load the actual data
                    data_expression = blockstate.get_mem(addr_expression, stmt.cvt_types[0])
                    # it then needs a type conversion applied to it
                    cvt_data_expression = CustomExpression()
                    cvt_data_expression.copy_to_self(data_expression)
                    cvt_data_expression.type = stmt.cvt_types[1]
                    conv_diff = vexutils.extract_int(stmt.cvt_types[1]) - vexutils.extract_int(stmt.cvt_types[0])
                    if conv_diff != 0:
                        if 'S' in stmt.cvt:
                            cvt_data_expression.cleanval = cvt_data_expression.cleanval.sign_extend(conv_diff)
                            cvt_data_expression.dirtyval = cvt_data_expression.dirtyval.sign_extend(conv_diff)
                        else:
                            cvt_data_expression.cleanval = cvt_data_expression.cleanval.zero_extend(conv_diff)
                            cvt_data_expression.dirtyval = cvt_data_expression.dirtyval.zero_extend(conv_diff)

                    temps.write(stmt.dst, cvt_data_expression)
                    SmartExpression(blockstate, stmt.guard, addr, path + ['guard'])
                    SmartExpression(blockstate, stmt.alt, addr, path + ['alt'])

                elif stmt.tag == 'Ist_StoreG':
                    # Conditional store
                    addr_expr = SmartExpression(blockstate, stmt.addr, addr, path + ['addr'])
                    value_expr = SmartExpression(blockstate, stmt.data, addr, path + ['data'])
                    blockstate.access(addr_expr, AccessType.WRITE)
                    if addr_expr.stack_addr:
                        blockstate.stack_cache[addr_expr.cleanval] = value_expr
                    if value_expr.stack_addr:
                        blockstate.access(value_expr, AccessType.POINTER)

                    SmartExpression(blockstate, stmt.guard, addr, path + ['guard'])

                elif stmt.tag == 'Ist_PutI':    # haha no
                    SmartExpression(blockstate, stmt.data, addr, path + ['data'])
                elif stmt.tag == 'Ist_CAS':     # HA ha no
                    if stmt.oldLo != 4294967295:
                        blockstate.tempstore.default(stmt.oldLo)
                    if stmt.oldHi != 4294967295:
                        blockstate.tempstore.default(stmt.oldHi)
                elif stmt.tag == 'Ist_Dirty':   # hahAHAHAH NO
                    if stmt.tmp != 4294967295:
                        blockstate.tempstore.default(stmt.tmp)
                else:
                    raise FidgetUnsupportedError("Unknown vex instruction???", stmt)

        if block.jumpkind == 'Ijk_Call' or block.jumpkind in OK_CONTINUE_JUMPS:
            if block.jumpkind == 'Ijk_Call' and project.arch.call_pushes_ret:
                # Pop the return address off the stack and keep going
                stack = blockstate.get_reg(project.arch.sp_offset, project.arch.bits)
                popped = stack.deps[0] if stack.deps[0].stack_addr else stack.deps[1]
                blockstate.regs[project.arch.sp_offset] = popped
                # Discard the last two tags -- they'll be an alloc and an access for the call
                # (the push and the retaddr)
                blockstate.tags = blockstate.tags[:-2]

            for context in cfg.get_all_nodes(blockstate.addr):
                for node, jumpkind in cfg.get_successors_and_jumpkind( \
                                        context, \
                                        excluding_fakeret=False):
                    if jumpkind not in OK_CONTINUE_JUMPS:
                        continue
                    elif node.addr in headcache:
                        continue
                    elif node.simprocedure_name is not None:
                        continue
                    elif node.addr in cache:
                        for succ, jumpkind in cfg.get_successors_and_jumpkind(node, excluding_fakeret=False):
                            if jumpkind in OK_CONTINUE_JUMPS and succ.addr not in cache and succ.simprocedure_name is None:
                                queue.append(blockstate.copy(succ.addr))
                    else:
                        queue.append(blockstate.copy(node.addr))

        elif block.jumpkind in ('Ijk_Ret', 'Ijk_NoDecode'):
            pass
        else:
            raise FidgetError("(%#x) Can't proceed from unknown jumpkind %s" % (blockstate.addr, block.jumpkind))

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
        if value.type != self.tyenv.types[tmp]:
            raise ValueError('Invalid type!')
        size = self.size_of(tmp)
        value.cleanval = vexutils.ZExtTo(size, value.cleanval)
        value.dirtyval = vexutils.ZExtTo(size, value.dirtyval)
        self.storage[tmp] = value

    def default(self, tmp):
        val = ConstExpression.default(self.tyenv.types[tmp])
        self.write(tmp, val)

class AccessType:       # pylint: disable=no-init
    READ = 1
    WRITE = 2
    POINTER = 4
    UNINITREAD = 8

class BlockState:
    def __init__(self, project, addr):
        self.addr = addr
        self.project = project
        self.regs = {}
        self.stack_cache = {}
        self.tags = []
        self.tempstore = None
        stackexp = ConstExpression(claripy.BVV(0, project.arch.bits), 'Ity_I%d' % project.arch.bits, True)
        stackexp.stack_addr = True
        stackexp.addr = addr
        self.regs[self.project.arch.sp_offset] = stackexp
        if project.arch.name == 'AMD64':
            self.regs[144] = ConstExpression.default('Ity_I64')
            self.regs[156] = ConstExpression.default('Ity_I64')
        elif project.arch.name == 'X86':
            self.regs[216] = ConstExpression.default('Ity_I32')
            self.regs[884] = ConstExpression.default('Ity_I32')
        elif project.arch.name.startswith('ARM'):
            self.regs[392] = ConstExpression.default('Ity_I32')
            self.regs[392].it_taint = True

    def copy(self, newaddr):
        out = BlockState(self.project, newaddr)

        # copy over all registers that hold pointers to the stack
        for offset, val in self.regs.iteritems():
            if val.stack_addr:
                out.regs[offset] = val
        return out

    def lift(self, addr=None, **options):
        if addr is None: addr = self.addr
        return self.project.factory.block(addr, **options).vex

    def load_tempstore(self, tempstore):
        self.tempstore = tempstore

    def get_reg(self, regnum, ty):
        if isinstance(ty, (int, long)):
            ty = 'Ity_I%d' % ty

        if not regnum in self.regs:
            if 'F' in ty or vexutils.extract_int(ty) > self.project.arch.bits:
                self.regs[regnum] = ConstExpression.default(ty)
            else:
                self.regs[regnum] = ConstExpression.default('Ity_I%d' % self.project.arch.bits)
            return self.regs[regnum].truncate(ty)

        if 'F' in self.regs[regnum].type:
            if self.regs[regnum].type.split('_')[1] != ty.split('_')[1]:
                l.warning("Don't know how to change type %s to %s, discarding", self.regs[regnum].type, ty)
                self.regs[regnum] = ConstExpression.default(ty)
            return self.regs[regnum]
        else:
            return self.regs[regnum].truncate(ty)


    def get_tmp(self, tmpnum):
        return self.tempstore.read(tmpnum)

    def get_mem(self, addr, ty):
        if addr.stack_addr:
            if addr.cleanval in self.stack_cache:
                val = self.stack_cache[addr.cleanval]
                if val.type == ty:
                    return val
            return ConstExpression.default(ty)
        cleanestval = addr.cleanval.model.value
        if cleanestval in self.project.loader.memory and 'F' not in ty:    # TODO: support this
            size_bytes = vexutils.extract_int(ty)/8
            strval = ''.join(self.project.loader.memory[cleanestval + i] for i in xrange(size_bytes))
            if self.project.arch.memory_endness == 'Iend_LE':
                strval = str(reversed(strval))
            intval = int(strval.encode('hex'), 16)
            return ConstExpression(claripy.BVV(intval, size_bytes*8), ty, True)
        return ConstExpression.default(ty)

    def access(self, addr_expression, access_type):
        if not addr_expression.stack_addr:
            return
        self.tags.append(('STACK_ACCESS', addr_expression.make_bindata(access_type)))

    def assign(self, vextatement, expression, stmt_idx):
        if vextatement.tag == 'Ist_WrTmp':
            self.tempstore.write(vextatement.tmp, expression)
        elif vextatement.tag == 'Ist_Put':
            if 'F' in expression.type or expression.size > self.project.arch.bits:
                self.regs[vextatement.offset] = expression
            else:
                if not vextatement.offset in self.regs:
                    self.regs[vextatement.offset] = ConstExpression.default('Ity_I%d' % self.project.arch.bits)
                self.regs[vextatement.offset] = expression.overwrite(self.regs[vextatement.offset])
            if vextatement.offset == self.project.arch.sp_offset:
                if not expression.is_concrete:
                    l.warning("This function appears to use alloca(). Abort.")
                    self.tags.append(('ABORT_ALLOCA', expression.make_bindata(0)))
                elif expression.cleanval.model.value == 0:
                    self.tags.append(('STACK_DEALLOC', expression.make_bindata(0)))
                else:
                    self.tags.append(('STACK_ALLOC', expression.make_bindata(0)))
        elif vextatement.tag == 'Ist_Store':
            addr_expr = SmartExpression(self, vextatement.addr, expression.addr, ['statements', stmt_idx, 'addr'])
            self.access(addr_expr, AccessType.WRITE)
            if addr_expr.stack_addr:
                self.stack_cache[addr_expr.cleanval] = expression
            if expression.stack_addr:
                self.access(expression, AccessType.POINTER)

    def end(self):
        for offset, value in self.regs.iteritems():
            if offset in (self.project.arch.sp_offset, self.project.arch.bp_offset, self.project.arch.ip_offset):
                continue
            self.access(value, AccessType.POINTER)

class SmartExpression:
    def __init__(self, blockstate, vexpression, addr, path):
        self.blockstate = blockstate
        self.vexpression = vexpression
        self.addr = addr
        self.path = path
        self.project = self.blockstate.project
        self.deps = []
        self.stack_addr = False
        self.is_concrete = False
        self.it_taint = False
        self.rootval = False
        self._bindata = [None]
        self.size = vexpression.result_size if not vexpression.tag.startswith('Ico_') else vexpression.size
        self.type = vexpression.result_type if not vexpression.tag.startswith('Ico_') else vexpression.type
        self.cleanval = vexutils.make_default_value(self.type)
        self.dirtyval = vexutils.make_default_value(self.type)
        if vexpression.tag == 'Iex_Get':
            self.copy_to_self(blockstate.get_reg(vexpression.offset, self.type))
        elif vexpression.tag == 'Iex_RdTmp':
            self.copy_to_self(self.blockstate.get_tmp(vexpression.tmp))
        elif vexpression.tag == 'Iex_Load':
            addr_expression = SmartExpression(blockstate, vexpression.addr, addr, path + ['addr'])
            self.blockstate.access(addr_expression, AccessType.READ)
            self.copy_to_self(self.blockstate.get_mem(addr_expression, self.type))
        elif vexpression.tag == 'Iex_Const' or vexpression.tag.startswith('Ico_'):
            if vexpression.tag == 'Iex_Const':
                vexpression = vexpression.con
            if 'F' in self.type:
                if self.size == 32:
                    self.cleanval = claripy.FPV(vexpression.value, claripy.fp.FSORT_FLOAT)
                    self.dirtyval = claripy.FloatingPoint('%x_%d' % (addr, path[1]), claripy.fp.FSORT_FLOAT)
                elif self.size == 64:
                    self.cleanval = claripy.FPV(vexpression.value, claripy.fp.FSORT_DOUBLE)
                    self.dirtyval = claripy.FloatingPoint('%x_%d' % (addr, path[1]), claripy.fp.FSORT_DOUBLE)
                else:
                    raise FidgetUnsupportedError("Why is there a FP const of size %d" % self.size)
            else:
                self.cleanval = claripy.BVV(vexpression.value, self.size)
                self.dirtyval = claripy.BV('%x_%d' % (addr, path[1]), self.size)
            self.rootval = True
            self.is_concrete = True
        elif vexpression.tag == 'Iex_ITE':
            false_expr = SmartExpression(blockstate, vexpression.iffalse, addr, path + ['iffalse'])
            truth_expr = SmartExpression(blockstate, vexpression.iftrue, addr, path + ['iftrue'])
            if truth_expr.stack_addr:
                self.copy_to_self(truth_expr)
            else:
                self.copy_to_self(false_expr)
            cond_expr = SmartExpression(blockstate, vexpression.cond, addr, path + ['cond'])
            if not cond_expr.it_taint:
                self.is_concrete = false_expr.is_concrete and truth_expr.is_concrete
            self.it_taint = false_expr.it_taint or truth_expr.it_taint
        elif vexpression.tag in ('Iex_Unop','Iex_Binop','Iex_Triop','Iex_Qop'):
            try:
                self.is_concrete = True
                for i, expr in enumerate(vexpression.args):
                    arg = SmartExpression(blockstate, expr, addr, path + ['args', i])
                    self.is_concrete = self.is_concrete and arg.is_concrete
                    self.it_taint = self.it_taint or arg.it_taint
                    self.deps.append(arg)
                if vexpression.op.startswith('Iop_Mul') or vexpression.op.startswith('Iop_And'):
                    self.shield_constants(self.deps)
                if vexpression.op in ROUNDING_IROPS:
                    self.shield_constants(self.deps, whitelist=[0])
                self.cleanval = operations[vexpression.op].calculate(*(x.cleanval for x in self.deps))
                self.dirtyval = operations[vexpression.op].calculate(*(x.dirtyval for x in self.deps))
                if vexpression.op.startswith('Iop_Add') or vexpression.op.startswith('Iop_And') or \
                   vexpression.op.startswith('Iop_Or') or vexpression.op.startswith('Iop_Xor'):
                    self.stack_addr = self.deps[0].stack_addr or self.deps[1].stack_addr
                elif vexpression.op.startswith('Iop_Sub'):
                    self.stack_addr = self.deps[0].stack_addr and not self.deps[1].stack_addr
            except SimOperationError:
                if vexpression.op == 'Iop_F64toI32S':
                    raise
                l.exception("SimOperationError while running op '%s', returning null", vexpression.op)
                self.is_concrete = False
            except KeyError:
                l.error("Unsupported operation '%s', returning null", vexpression.op)
                self.is_concrete = False
        elif vexpression.tag == 'Iex_CCall':
            for i, expr in enumerate(vexpression.args):
                arg = SmartExpression(blockstate, expr, addr, path + ['args', i])
                self.it_taint = self.it_taint or arg.it_taint
        elif vexpression.tag == 'Iex_GetI':
            pass
        else:
            raise FidgetUnsupportedError('Unknown expression tag ({:#x}): {!r}'.format(addr, vexpression.tag))

    @property
    def bindata(self):
        return self._bindata[0]

    @bindata.setter
    def bindata(self, value):
        self._bindata[0] = value

    def copy_to_self(self, other):
        self.cleanval = other.cleanval
        self.dirtyval = other.dirtyval
        self.deps = other.deps
        self.addr = other.addr
        self._bindata = other._bindata
        self.stack_addr = other.stack_addr
        self.is_concrete = other.is_concrete
        self.it_taint = other.it_taint
        self.rootval = other.rootval
        self.path = other.path

    @staticmethod
    def shield_constants(expr_list, whitelist=None):
        for i, expr in enumerate(expr_list):
            if whitelist is not None and i not in whitelist: continue
            if expr.rootval:
                expr_list[i] = ConstExpression(expr.cleanval, expr.type, expr.is_concrete)

    def make_bindata(self, flags):
        # this is the top level call. It returns a BinaryDataConglomerate.
        # flags is the access type
        data = BinaryDataConglomerate(self.addr, self.cleanval.model.signed, self.dirtyval, flags)
        for dirtyval, bindata in self.make_bindata_internal():
            data.add(bindata, dirtyval)
        return data

    def make_bindata_internal(self):
        # this makes sure that self.bindata is populated with a list of tuples (a, b)
        # where a is the symbolic value hooked directly to an instruction and b is
        # the BinaryData instance related to that instruction. If the BinaryData cannot
        # be constructed (Value Not Found Error), it will be the integer value that it
        # needs to stay fixed as.
        # it also returns self.bindata
        if self.bindata is not None:
            return self.bindata
        if self.rootval:
            try:
                binary_data = BinaryData(
                        self.project,
                        self.addr,
                        self.cleanval.model.value,
                        path=self.path + ['con', 'value']
                    )
            except ValueNotFoundError as e:
                l.debug(e.message)
                binary_data = self.cleanval.model.value
            self.bindata = [(self.dirtyval, binary_data)]
            return self.bindata
        else:
            self.bindata = []
            for dep in self.deps:
                self.bindata.extend(dep.make_bindata_internal())
            return self.bindata

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
        out.type = larger.type
        out.blockstate = smaller.blockstate
        out.addr = smaller.addr # ??? what will be done with this
        out.path = smaller.path
        out.project = out.blockstate.project
        out.stack_addr = larger.stack_addr # sketchy...
        out.is_concrete = smaller.is_concrete and larger.is_concrete
        out.it_taint = False
        out.rootval = False
        out._bindata = [None]
        out.cleanval = claripy.Concat(larger.cleanval[larger.size-1:smaller.size], smaller.cleanval)
        out.dirtyval = claripy.Concat(larger.dirtyval[larger.size-1:smaller.size], smaller.dirtyval)
        return out

    def truncate(self, ty):
        if ty == self.type:
            return self
        if 'F' in self.type:
            raise ValueError("Cannot coerce floating point values")
        size_bits = vexutils.extract_int(ty)
        if size_bits > self.size:
            l.error("Attempting to truncate SmartExpression of size %d to size %d", self.size, size_bits)
            return self
        out = CustomExpression()
        out.deps = [self]
        out.size = size_bits
        out.type = ty
        out.blockstate = self.blockstate
        out.addr = self.addr # ??? what will be done with this
        out.path = self.path
        out.project = out.blockstate.project
        out.stack_addr = False
        out.is_concrete = self.is_concrete
        out.it_taint = False
        out.rootval = False
        out._bindata = [None]
        out.cleanval = self.cleanval[size_bits-1:0]
        out.dirtyval = self.dirtyval[size_bits-1:0]
        return out

    def __str__(self):
        return 'Expression at 0x%x stmt %d' % (self.addr, self.path[1])

class CustomExpression(SmartExpression):
    def __init__(self): # pylint: disable=super-init-not-called
        pass

class ConstExpression(object):
    def __init__(self, val, ty, is_concrete):
        self.size = val.size()
        self.type = ty
        self.cleanval = val
        self.dirtyval = val
        self.deps = []
        self.stack_addr = False
        self.is_concrete = is_concrete
        self.it_taint = False
        self._bindata = [None]
        self.rootval = False
        self.addr = None
        self.path = []

    @staticmethod
    def make_bindata_internal():
        return []

    def truncate(self, ty):
        if ty == self.type:
            return self
        if 'F' in self.type:
            raise ValueError("Cannot coerce floating point values")
        size_bits = vexutils.extract_int(ty)
        if size_bits > self.size:
            l.error("Attempting to truncate SmartExpression of size %d to size %d", self.size, size_bits)
            return self
        return ConstExpression(self.cleanval[size_bits-1:0], ty, self.is_concrete)

    @staticmethod
    def default(ty):
        return ConstExpression(vexutils.make_default_value(ty), ty, False)
