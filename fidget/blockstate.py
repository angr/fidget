import claripy
from angr.engines.vex.claripy.irop import operations
from angr.errors import SimOperationError
from angr import SimState
from angr import sim_options

from .memory import SpecialFillerRegionedMemory
from .binary_data import PendingBinaryData
from .errors import FidgetUnsupportedError, FidgetAnalysisFailure
from . import vexutils
from .bihead import BiHead

import logging
l = logging.getLogger('fidget.blockstate')

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
ACCESS_READ = 1
ACCESS_WRITE = 2
ACCESS_POINTER = 4
ACCESS_UNINITREAD = 8
ACCESS_MAPPING = {0: '<none>', 1: 'READ', 2: 'WRITE', 4: 'POINTER', 8: 'UNINITREAD'}

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
        if value.length != self.size_of(tmp):
            raise ValueError('Invalid type!')
        self.storage[tmp] = value

    def default(self, tmp):
        val = BiHead.default(self.tyenv.types[tmp])
        self.write(tmp, val)

class BlockState(object):
    def __init__(self, project, addr, state=None, taint_region=None):
        self.project = project
        self.addr = addr
        self.block_addr = addr
        self.taint_region = taint_region
        self.state = state

        self.tempstore = None
        self.tags = []
        self.write_targets = []

        if self.state is None:
            self.state = SimState(arch=project.arch,
                    mode='symbolic',
                    special_memory_filler=lambda name, bits, _state: BiHead(claripy.BVV(0, bits), claripy.BVV(0, bits)),
                    add_options={sim_options.ABSTRACT_MEMORY, sim_options.SPECIAL_MEMORY_FILL},
                    remove_options={sim_options.FAST_MEMORY},
                    plugin_preset="fidget_plugins",
                    regioned_memory_cls=SpecialFillerRegionedMemory,
                )
            self.state.scratch.ins_addr = 0
            if project.arch.name.startswith('ARM'):
                it = self.state.regs.itstate
                it.taints['it'] = True
                self.state.regs.itstate = it

    def copy(self, newaddr):
        return BlockState(self.project, newaddr, state=self.state.copy(), taint_region=self.taint_region)

    def get_reg(self, offset, ty):
        if isinstance(ty, int):
            ty = 'Ity_I%d' % ty
        size = vexutils.extract_int(ty)
        val = self.state.registers.load(offset, size//8)
        if ty.startswith('Ity_F'):
            val = val.raw_to_fp()
        return val

    def put_reg(self, offset, val):
        self.state.registers.store(offset, val)

    def get_tmp(self, tmpnum):
        return self.tempstore.read(tmpnum)

    def put_tmp(self, tmpnum, val):
        self.tempstore.write(tmpnum, val)

    def get_mem(self, addr, ty):
        if isinstance(ty, int):
            ty = 'Ity_I%d' % ty
        size = vexutils.extract_int(ty)
        addr_vs = self.state.solver.VS(bits=self.state.arch.bits, region=addr.taints['pointer'] if addr.taints['pointer'] else 'global', val=addr.as_unsigned)
        val = self.state.memory.load(addr_vs, size//8, endness=self.state.arch.memory_endness)
        if ty.startswith('Ity_F'):
            val = val.raw_to_fp()
        return val

    def put_mem(self, addr, val):
        if not addr.taints['pointer']:
            return      # don't store anything to memory that's not an accounted-for region
        addr_vs = self.state.solver.VS(bits=self.state.arch.bits, region=addr.taints['pointer'], val=addr.as_unsigned)
        self.state.scratch.ins_addr += 1
        self.state.memory.store(addr_vs, val, endness=self.state.arch.memory_endness)
        self.write_targets.append((addr_vs, val.length//8))

    def access(self, addr_expression, access_type):
        if addr_expression.taints['pointer'] != self.taint_region:
            return
        self.tags.append(('ACCESS', PendingBinaryData.make_bindata(addr_expression, self.addr, access_type)))

    def alloc(self, addr_expression):
        self.tags.append(('ALLOC', PendingBinaryData.make_bindata(addr_expression, self.addr, 0)))

    def handle_irsb(self, block):
        self.tempstore = TempStore(block.tyenv)

        for stmt_idx, stmt in enumerate(block.statements):
            path = ['statements', stmt_idx]
            self.handle_statement(stmt, block.tyenv, path)

    def handle_statement(self, stmt, tyenv, path):
        if stmt.tag in ('Ist_NoOp', 'Ist_AbiHint', 'Ist_MBE'):
            pass

        elif stmt.tag == 'Ist_IMark':
            self.addr = stmt.addr + stmt.delta

        elif stmt.tag == 'Ist_Exit':
            self.handle_expression(stmt.dst, tyenv, path + ['dst'])
            # Let the cfg take care of control flow!

        elif stmt.tag == 'Ist_WrTmp':
            expression = self.handle_expression(stmt.data, tyenv, path + ['data'])
            self.put_tmp(stmt.tmp, expression)

        elif stmt.tag == 'Ist_Store':
            expression = self.handle_expression(stmt.data, tyenv, path + ['data'])
            address = self.handle_expression(stmt.addr, tyenv, path + ['addr'])
            self.put_mem(address, expression)
            self.access(address, ACCESS_WRITE)
            self.access(expression, ACCESS_POINTER)

        elif stmt.tag == 'Ist_Put':
            expression = self.handle_expression(stmt.data, tyenv, path + ['data'])
            self.put_reg(stmt.offset, expression)
            if stmt.offset == self.project.arch.sp_offset:
                if not expression.taints['concrete']:
                    l.warning("This function appears to use alloca(). Abort.")
                    raise FidgetAnalysisFailure
                self.alloc(expression)

        elif stmt.tag == 'Ist_LoadG':
            # Conditional loads. Lots of bullshit.
            addr_expression = self.handle_expression(stmt.addr, tyenv, path + ['addr'])
            self.access(addr_expression, ACCESS_READ)

            # load the actual data
            data_expression = self.get_mem(addr_expression, stmt.cvt_types[0])
            # it then needs a type conversion applied to it
            conv_diff = vexutils.extract_int(stmt.cvt_types[1]) - vexutils.extract_int(stmt.cvt_types[0])
            if conv_diff != 0:
                concrete = data_expression.taints['concrete']
                deps = data_expression.taints['deps']
                if 'S' in stmt.cvt:
                    data_expression = data_expression.sign_extend(conv_diff)
                else:
                    data_expression = data_expression.zero_extend(conv_diff)
                data_expression.taints['concrete'] = concrete
                data_expression.taints['deps'] = deps

            self.put_tmp(stmt.dst, data_expression)
            self.handle_expression(stmt.guard, tyenv, path + ['guard'])
            self.handle_expression(stmt.alt, tyenv, path + ['alt'])

        elif stmt.tag == 'Ist_StoreG':
            # Conditional store
            addr_expr = self.handle_expression(stmt.addr, tyenv, path + ['addr'])
            value_expr = self.handle_expression(stmt.data, tyenv, path + ['data'])
            self.handle_expression(stmt.guard, tyenv, path + ['guard'])
            self.put_mem(addr_expr, value_expr)
            self.access(addr_expr, ACCESS_WRITE)
            self.access(value_expr, ACCESS_POINTER)

        elif stmt.tag == 'Ist_PutI':    # haha no
            self.handle_expression(stmt.data, tyenv, path + ['data'])
        elif stmt.tag == 'Ist_CAS':     # HA ha no
            if stmt.oldLo != 4294967295:
                self.tempstore.default(stmt.oldLo)
            if stmt.oldHi != 4294967295:
                self.tempstore.default(stmt.oldHi)
        elif stmt.tag == 'Ist_Dirty':   # hahAHAHAH NO
            if stmt.tmp != 4294967295:
                self.tempstore.default(stmt.tmp)
        else:
            raise FidgetUnsupportedError("Unknown vex instruction???", stmt)

    def handle_expression(self, expr, tyenv, path):
        size = expr.result_size(tyenv) if not expr.tag.startswith('Ico_') else expr.size
        ty = expr.result_type(tyenv) if not expr.tag.startswith('Ico_') else expr.type
        addr = self.addr
        if expr.tag == 'Iex_Get':
            return self.get_reg(expr.offset, ty)
        elif expr.tag == 'Iex_RdTmp':
            return self.get_tmp(expr.tmp)
        elif expr.tag == 'Iex_Load':
            addr_expression = self.handle_expression(expr.addr, tyenv, path + ['addr'])
            self.access(addr_expression, ACCESS_READ)
            return self.get_mem(addr_expression, ty)
        elif expr.tag == 'Iex_Const' or expr.tag.startswith('Ico_'):
            if expr.tag == 'Iex_Const':
                expr = expr.con
            if 'F' in ty:
                if size == 32:
                    values = BiHead(
                            claripy.FPV(expr.value, claripy.fp.FSORT_FLOAT),
                            claripy.FPS('%x_%d' % (addr, path[1]), claripy.fp.FSORT_FLOAT)
                        )
                elif size == 64:
                    values = BiHead(
                            claripy.FPV(expr.value, claripy.fp.FSORT_DOUBLE),
                            claripy.FPS('%x_%d' % (addr, path[1]), claripy.fp.FSORT_DOUBLE)
                        )
                else:
                    raise FidgetUnsupportedError("Why is there a FP const of size %d" % size)
            else:
                values = BiHead(
                        claripy.BVV(expr.value, size),
                        claripy.BVS('%x_%d' % (addr, path[1]), size)
                    )
            values.taints['deps'].append(PendingBinaryData(self.project, self.addr, values, path))
            values.taints['concrete'] = True
            values.taints['concrete_root'] = True
            return values
        elif expr.tag == 'Iex_ITE':
            false_expr = self.handle_expression(expr.iffalse, tyenv, path + ['iffalse'])
            truth_expr = self.handle_expression(expr.iftrue, tyenv, path + ['iftrue'])
            values = truth_expr if truth_expr.taints['pointer'] else false_expr
            cond_expr = self.handle_expression(expr.cond, tyenv, path + ['cond'])
            if not cond_expr.taints['it']:
                values.taints['concrete'] = false_expr.taints['concrete'] and truth_expr.taints['concrete']
            values.taints['it'] = false_expr.taints['it'] or truth_expr.taints['it']
            return values
        elif expr.tag in ('Iex_Unop','Iex_Binop','Iex_Triop','Iex_Qop'):
            args = []
            for i, sub_expr in enumerate(expr.args):
                arg = self.handle_expression(sub_expr, tyenv, path + ['args', i])
                if expr.op.startswith('Iop_Mul') or expr.op.startswith('Iop_And') \
                        or (i == 0 and expr.op in ROUNDING_IROPS):
                    if arg.taints['concrete_root']:
                        arg = BiHead(arg.cleanval, arg.cleanval)
                        arg.taints['concrete'] = True
                args.append(arg)
            try:
                values = BiHead(
                        operations[expr.op].calculate(*(x.cleanval for x in args)),
                        operations[expr.op].calculate(*(x.dirtyval for x in args))
                    )
            except SimOperationError:
                l.exception("SimOperationError while running op '%s', returning null", expr.op)
                return BiHead.default(ty)
            except KeyError:
                l.error("Unsupported operation '%s', returning null", expr.op)
                return BiHead.default(ty)
            else:
                # propogate the taints correctly
                values.taints['concrete'] = True
                for arg in args:
                    values.taints['deps'].extend(arg.taints['deps'])
                    values.taints['concrete'] = values.taints['concrete'] and arg.taints['concrete']
                    values.taints['it'] = values.taints['it'] or arg.taints['it']
                if expr.op.startswith('Iop_Add') or expr.op.startswith('Iop_And') or \
                   expr.op.startswith('Iop_Or') or expr.op.startswith('Iop_Xor'):
                    t1 = args[0].taints['pointer']
                    t2 = args[1].taints['pointer']
                    values.taints['pointer'] = (t1 if t1 else t2) if (bool(t1) ^ bool(t2)) else False
                elif expr.op.startswith('Iop_Sub'):
                    t1 = args[0].taints['pointer']
                    t2 = args[1].taints['pointer']
                    values.taints['pointer'] = t1 if t1 and not t2 else False
                return values
        elif expr.tag == 'Iex_CCall':
            values = BiHead.default(ty)
            for i, expr in enumerate(expr.args):
                arg = self.handle_expression(expr, tyenv, path + ['args', i])
                values.taints['it'] = values.taints['it'] or arg.taints['it']
            return values
        elif expr.tag == 'Iex_GetI':
            return BiHead.default(ty)
        else:
            raise FidgetUnsupportedError('Unknown expression tag ({:#x}): {!r}'.format(addr, expr.tag))

    def end(self, clean=False):
        for name in self.project.arch.default_symbolic_registers:
            offset = self.project.arch.registers[name][0]
            if offset in (self.project.arch.sp_offset, self.project.arch.bp_offset, self.project.arch.ip_offset):
                continue
            if name == 'r7' and self.project.arch.name.startswith('ARM') and self.addr & 1 == 1:
                continue
            # values remaining in registers at end-of-block are pointers! Probably.
            value = getattr(self.state.regs, name)
            if value.taints['already_pointered']:
                continue
            self.access(value, ACCESS_POINTER)
            value.taints['already_pointered'] = True
            if value.taints['concrete'] and not value.taints['pointer']:
                # Don't let nonpointer values persist between block states
                value = BiHead(value.cleanval, value.cleanval)
            self.state.registers.store(offset, value)

        # If a call, scrub the return-value register
        if clean:
            self.state.registers.store(self.state.arch.ret_offset, BiHead(claripy.BVV(0, self.state.arch.bits), claripy.BVV(0, self.state.arch.bits)))

        # Don't let nonpointer vales persist between block state... in memory!
        for addr, size in self.write_targets:
            value = self.state.memory.load(addr, size, endness=self.state.arch.memory_endness)
            if not value.taints['pointer']:
                replacement = BiHead(value.cleanval, value.cleanval)
                self.state.scratch.ins_addr += 1
                self.state.memory.store(addr, replacement, endness=self.state.arch.memory_endness)
