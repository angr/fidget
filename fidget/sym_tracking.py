from angr import AngrMemoryError
import pyvex
import claripy

from .binary_data import BinaryData, BinaryDataConglomerate
from .stack_magic import Struct
from .errors import FidgetError, FidgetUnsupportedError, ValueNotFoundError, FidgetAnalysisFailure
from .bihead import BiHead
from . import vexutils
from simuvex import operations, SimOperationError, SimState, s_options as sim_options

from collections import defaultdict

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

class StructureAnalysis(object):
    def __init__(self,
                 project,
                 cfg=None,
                 functions_list=None,
                 chase_structs=False):
        self.project = project
        self.cfg = cfg
        self.functions_list = functions_list
        self.chase_structs = chase_structs

        self.structures = {}
        self.stack_frames = defaultdict(lambda: None)

        if self.cfg is None:
            self.cfg = project.analyses.CFG(enable_symbolic_back_traversal=True)
        if self.functions_list is None:
            self.functions_list = self.real_functions(self.cfg)

        for func in self.functions_list:
            try:
                struct = self.analyze_stack(func._addr)
            except FidgetAnalysisFailure:
                pass
            else:
                self.add_struct(struct)
                self.stack_frames[func._addr] = struct.name

        if chase_structs:
            raise FidgetUnsupportedError("lmao what")

    def add_struct(self, struct):
        self.structures[struct.name] = struct

    @staticmethod
    def real_functions(cfg):
        project = cfg._project

        # Find the real _start on MIPS so we don't touch it
        do_not_touch = None
        if project.arch.name == 'MIPS32':
            for context in cfg.get_all_nodes(project.entry):
                for succ, jumpkind in cfg.get_successors_and_jumpkind(context):
                    if jumpkind == 'Ijk_Call':
                        do_not_touch = succ.addr
                        l.debug('Found MIPS entry point stub target %#x', do_not_touch)

        for funcaddr, func in cfg.function_manager.functions.iteritems():
            # But don't touch _start. Seriously.
            if funcaddr == project.entry:
                l.debug('Skipping entry point')
                continue

            # On MIPS there's another function that's part of the entry point.
            # Trying to mess with it will cause catastrope.
            if funcaddr == do_not_touch:
                l.debug('Skipping MIPS entry point stub target')
                continue

            # Don't try to patch simprocedures
            if project.is_hooked(funcaddr):
                l.debug("Skipping simprocedure %s", project._sim_procedures[funcaddr][0].__name__)
                continue

            # Don't touch functions not in any segment
            if project.loader.main_bin.find_segment_containing(funcaddr) is None:
                l.debug('Skipping function %s not mapped', func.name)
                continue

            # If the text section exists, only patch functions in it
            if '.text' not in project.loader.main_bin.sections_map:
                sec = project.loader.main_bin.find_section_containing(funcaddr)
                if sec is None or sec.name != '.text':
                    l.debug('Skipping function %s not in .text', func.name)
                    continue

            # Don't patch functions in the PLT
            if funcaddr in project.loader.main_bin.plt.values():
                l.debug('Skipping function %s in PLT', func.name)
                continue

            # If the CFG couldn't parse an indirect jump, avoid
            if func.has_unresolved_jumps:
                l.debug("Skipping function %s with unresolved jumps", func.name)
                continue

            # Check if the function starts at a SimProcedure (edge case)
            if cfg.get_any_node(funcaddr).simprocedure_name is not None:
                l.debug('Skipping function %s starting with a SimProcedure', func.name)

            # This function is APPROVED
            yield func

    def analyze_stack(self, funcaddr):
        struct = Struct(self.project.arch, is_stack_frame=True)
        initial_state = BlockState(self.project, funcaddr, taint_region=struct.name)
        sp = initial_state.state.regs.sp
        sp.taints['pointer'] = struct.name
        sp.taints['concrete'] = True
        initial_state.state.regs.sp = sp

        queue = [initial_state]
        headcache = set()
        cache = set()
        while len(queue) > 0:
            blockstate = queue.pop(0)
            if blockstate.addr in headcache:
                continue

            try:
                block = blockstate.lift(opt_level=1, max_size=400)
            except AngrMemoryError:
                l.error("Couldn't lift block at %#x", blockstate.addr)
                continue

            l.debug("Analyzing block %#x", blockstate.addr)
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
                if addr != funcaddr and addr in self.cfg.function_manager.functions:
                    l.warning("\tThis function jumps into another function (%#x). Abort.", addr)
                    raise FidgetAnalysisFailure
                cache.add(addr)

                insnblock = blockstate.lift(addr, num_inst=1, max_size=400, opt_level=1)
                temps = TempStore(insnblock.tyenv)
                blockstate.load_tempstore(temps)
                blockstate.addr = addr
                stmtgen = enumerate(insnblock.statements)
                for _, stmt in stmtgen:
                    if isinstance(stmt, pyvex.IRStmt.IMark): break

                for stmt_idx, stmt in stmtgen:
                    path = ['statements', stmt_idx]
                    if stmt.tag in ('Ist_NoOp', 'Ist_AbiHint', 'Ist_MBE'):
                        pass

                    elif stmt.tag == 'Ist_Exit':
                        handle_expression(blockstate, stmt.dst, path + ['dst'])
                        # Let the cfg take care of control flow!

                    elif stmt.tag == 'Ist_WrTmp':
                        expression = handle_expression(blockstate, stmt.data, path + ['data'])
                        blockstate.put_tmp(stmt.tmp, expression)

                    elif stmt.tag == 'Ist_Store':
                        expression = handle_expression(blockstate, stmt.data, path + ['data'])
                        address = handle_expression(blockstate, stmt.addr, path + ['addr'])
                        blockstate.put_mem(address, expression)
                        blockstate.access(address, AccessType.WRITE)
                        blockstate.access(expression, AccessType.POINTER)

                    elif stmt.tag == 'Ist_Put':
                        expression = handle_expression(blockstate, stmt.data, path + ['data'])
                        blockstate.put_reg(stmt.offset, expression)
                        if stmt.offset == self.project.arch.sp_offset:
                            if not expression.taints['concrete']:
                                l.warning("This function appears to use alloca(). Abort.")
                                raise FidgetAnalysisFailure
                            blockstate.alloc(expression)

                    elif stmt.tag == 'Ist_LoadG':
                        # Conditional loads. Lots of bullshit.
                        addr_expression = handle_expression(blockstate, stmt.addr, path + ['addr'])
                        blockstate.access(addr_expression, AccessType.READ)

                        # load the actual data
                        data_expression = blockstate.get_mem(addr_expression, stmt.cvt_types[0])
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

                        blockstate.put_tmp(stmt.dst, data_expression)
                        handle_expression(blockstate, stmt.guard, path + ['guard'])
                        handle_expression(blockstate, stmt.alt, path + ['alt'])

                    elif stmt.tag == 'Ist_StoreG':
                        # Conditional store
                        addr_expr = handle_expression(blockstate, stmt.addr, path + ['addr'])
                        value_expr = handle_expression(blockstate, stmt.data, path + ['data'])
                        handle_expression(blockstate, stmt.guard, path + ['guard'])
                        blockstate.put_mem(addr_expr, value_expr)
                        blockstate.access(addr_expr, AccessType.WRITE)
                        blockstate.access(value_expr, AccessType.POINTER)

                    elif stmt.tag == 'Ist_PutI':    # haha no
                        handle_expression(blockstate, stmt.data, path + ['data'])
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

            if block.jumpkind == 'Ijk_Call' and self.project.arch.call_pushes_ret:
                # Pop the return address off the stack and keep going
                stack = blockstate.state.regs.sp
                popped = stack - self.project.arch.stack_change
                # Discard the last two tags -- they'll be an alloc and an access for the call
                # (the push and the retaddr)
                popped.taints = stack.taints
                # Do NOT discard the regs, as they constrain the amount that was added to sizeof(void*)
                blockstate.state.regs.sp = popped
                blockstate.tags = blockstate.tags[:-2]

            blockstate.end(clean=block.jumpkind == 'Ijk_Call')

            if block.jumpkind == 'Ijk_Call' or block.jumpkind in OK_CONTINUE_JUMPS:

                for context in self.cfg.get_all_nodes(blockstate.block_addr):
                    for node, jumpkind in self.cfg.get_successors_and_jumpkind( \
                                            context, \
                                            excluding_fakeret=False):
                        if jumpkind not in OK_CONTINUE_JUMPS:
                            continue
                        elif node.addr in headcache:
                            continue
                        elif node.simprocedure_name is not None:
                            continue
                        elif node.addr in cache:
                            for succ, jumpkind in self.cfg.get_successors_and_jumpkind(node, excluding_fakeret=False):
                                if jumpkind in OK_CONTINUE_JUMPS and succ.addr not in cache and succ.simprocedure_name is None:
                                    queue.append(blockstate.copy(succ.addr))
                        else:
                            queue.append(blockstate.copy(node.addr))

            elif block.jumpkind in ('Ijk_Ret', 'Ijk_NoDecode'):
                pass
            else:
                raise FidgetError("(%#x) Can't proceed from unknown jumpkind %s" % (blockstate.addr, block.jumpkind))

            for tag, bindata in blockstate.tags:
                if tag == 'ALLOC':
                    l.debug("Got tag: %#0.8x  ALLOC %#x", bindata.addr, bindata.value)
                    struct.alloc(bindata)
                elif tag == 'ACCESS':
                    l.debug("Got tag: %#0.8x ACCESS %s %#x", bindata.addr, AccessType.mapping[bindata.access_flags], bindata.value)
                    struct.access(bindata)
                else:
                    raise FidgetUnsupportedError('You forgot to update the tag list, jerkface!')

        return struct

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

class AccessType:       # pylint: disable=no-init
    READ = 1
    WRITE = 2
    POINTER = 4
    UNINITREAD = 8
    mapping = {0: '<none>', 1: 'READ', 2: 'WRITE', 4: 'POINTER', 8: 'UNINITREAD'}

class BlockState:
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
                    special_memory_filler=lambda name, bits: BiHead(claripy.BVV(0, bits), claripy.BVV(0, bits)),
                    add_options={sim_options.ABSTRACT_MEMORY, sim_options.SPECIAL_MEMORY_FILL}
                )
            if project.arch.name.startswith('ARM'):
                it = self.state.regs.itstate
                it.taints['it'] = True
                self.state.regs.itstate = it

    def copy(self, newaddr):
        return BlockState(self.project, newaddr, state=self.state.copy(), taint_region=self.taint_region)

    def lift(self, addr=None, **options):
        if addr is None: addr = self.addr
        return self.project.factory.block(addr, **options).vex

    def load_tempstore(self, tempstore):
        self.tempstore = tempstore

    def get_reg(self, offset, ty):
        if isinstance(ty, (int, long)):
            ty = 'Ity_I%d' % ty
        size = vexutils.extract_int(ty)
        val = self.state.registers.load(offset, size/8)
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
        if isinstance(ty, (int, long)):
            ty = 'Ity_I%d' % ty
        size = vexutils.extract_int(ty)
        addr_vs = self.state.se.VS(bits=self.state.arch.bits, region=addr.taints['pointer'] if addr.taints['pointer'] else 'global', val=addr.as_unsigned)
        val = self.state.memory.load(addr_vs, size/8, endness=self.state.arch.memory_endness)
        if ty.startswith('Ity_F'):
            val = val.raw_to_fp()
        return val

    def put_mem(self, addr, val):
        if not addr.taints['pointer']:
            return      # don't store anything to memory that's not an accounted-for region
        addr_vs = self.state.se.VS(bits=self.state.arch.bits, region=addr.taints['pointer'], val=addr.as_unsigned)
        self.state.memory.store(addr_vs, val, endness=self.state.arch.memory_endness)
        self.write_targets.append((addr_vs, val.length))

    def access(self, addr_expression, access_type):
        if addr_expression.taints['pointer'] != self.taint_region:
            return
        self.tags.append(('ACCESS', make_bindata(addr_expression, self.addr, access_type)))

    def alloc(self, addr_expression):
        self.tags.append(('ALLOC', make_bindata(addr_expression, self.addr, 0)))

    def end(self, clean=False):
        for offset, name in self.project.arch.register_names.iteritems():
            if offset in (self.project.arch.sp_offset, self.project.arch.bp_offset, self.project.arch.ip_offset):
                continue
            if offset == 36 and self.project.arch.name.startswith('ARM') and self.addr & 1 == 1:
                continue
            # values remaining in registers at end-of-block are pointers! Probably.
            value = getattr(self.state.regs, name)
            if value.taints['already_pointered']:
                continue
            self.access(value, AccessType.POINTER)
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
                self.state.memory.store(addr, replacement, endness=self.state.arch.memory_endness)

bd_cache = {}

class PendingBinaryData(object):
    __slots__ = ('project', 'addr', 'value', 'sym_value', 'path', '_hash')
    def __init__(self, project, addr, values, path):
        self.project = project
        self.addr = addr
        self.value = values.as_unsigned
        self.sym_value = values.dirtyval
        self.path = tuple(path)
        self._hash = None

    def __hash__(self):
        if not self._hash: self._hash = hash(('pbd', self.project.filename, self.addr, self.value, self.path))
        return self._hash

    def __eq__(self, other):
        return self.project.filename == other.project.filename and self.addr == other.addr and self.value == other.value and self.path == other.path

    def resolve(self):
        if self in bd_cache:
            return bd_cache[self]
        else:
            try:
                binary_data = BinaryData(
                        self.project,
                        self.addr,
                        self.value,
                        path=list(self.path) + ['con', 'value']
                    )
            except ValueNotFoundError as e:
                l.debug(e.message)
                binary_data = self.value
            out = (self.sym_value, binary_data)
            bd_cache[self] = out
            return out


def handle_expression(blockstate, vexpression, path):
    size = vexpression.result_size if not vexpression.tag.startswith('Ico_') else vexpression.size
    ty = vexpression.result_type if not vexpression.tag.startswith('Ico_') else vexpression.type
    addr = blockstate.addr
    if vexpression.tag == 'Iex_Get':
        return blockstate.get_reg(vexpression.offset, ty)
    elif vexpression.tag == 'Iex_RdTmp':
        return blockstate.get_tmp(vexpression.tmp)
    elif vexpression.tag == 'Iex_Load':
        addr_expression = handle_expression(blockstate, vexpression.addr, path + ['addr'])
        blockstate.access(addr_expression, AccessType.READ)
        return blockstate.get_mem(addr_expression, ty)
    elif vexpression.tag == 'Iex_Const' or vexpression.tag.startswith('Ico_'):
        if vexpression.tag == 'Iex_Const':
            vexpression = vexpression.con
        if 'F' in ty:
            if size == 32:
                values = BiHead(
                        claripy.FPV(vexpression.value, claripy.fp.FSORT_FLOAT),
                        claripy.FloatingPoint('%x_%d' % (addr, path[1]), claripy.fp.FSORT_FLOAT)
                    )
            elif size == 64:
                values = BiHead(
                        claripy.FPV(vexpression.value, claripy.fp.FSORT_DOUBLE),
                        claripy.FloatingPoint('%x_%d' % (addr, path[1]), claripy.fp.FSORT_DOUBLE)
                    )
            else:
                raise FidgetUnsupportedError("Why is there a FP const of size %d" % size)
        else:
            values = BiHead(
                    claripy.BVV(vexpression.value, size),
                    claripy.BV('%x_%d' % (addr, path[1]), size)
                )
        values.taints['deps'].append(PendingBinaryData(blockstate.project, blockstate.addr, values, path))
        values.taints['concrete'] = True
        values.taints['concrete_root'] = True
        return values
    elif vexpression.tag == 'Iex_ITE':
        false_expr = handle_expression(blockstate, vexpression.iffalse, path + ['iffalse'])
        truth_expr = handle_expression(blockstate, vexpression.iftrue, path + ['iftrue'])
        values = truth_expr if truth_expr.taints['pointer'] else false_expr
        cond_expr = handle_expression(blockstate, vexpression.cond, path + ['cond'])
        if not cond_expr.taints['it']:
            values.taints['concrete'] = false_expr.taints['concrete'] and truth_expr.taints['concrete']
        values.taints['it'] = false_expr.taints['it'] or truth_expr.taints['it']
        return values
    elif vexpression.tag in ('Iex_Unop','Iex_Binop','Iex_Triop','Iex_Qop'):
        args = []
        for i, expr in enumerate(vexpression.args):
            arg = handle_expression(blockstate, expr, path + ['args', i])
            if vexpression.op.startswith('Iop_Mul') or vexpression.op.startswith('Iop_And') \
                    or (i == 0 and vexpression.op in ROUNDING_IROPS):
                if arg.taints['concrete_root']:
                    arg = BiHead(arg.cleanval, arg.cleanval)
                    arg.taints['concrete'] = True
            args.append(arg)
        try:
            values = BiHead(
                    operations[vexpression.op].calculate(*(x.cleanval for x in args)),
                    operations[vexpression.op].calculate(*(x.dirtyval for x in args))
                )
        except SimOperationError:
            l.exception("SimOperationError while running op '%s', returning null", vexpression.op)
            return BiHead.default(ty)
        except KeyError:
            l.error("Unsupported operation '%s', returning null", vexpression.op)
            return BiHead.default(ty)
        else:
            # propogate the taints correctly
            values.taints['concrete'] = True
            for arg in args:
                values.taints['deps'].extend(arg.taints['deps'])
                values.taints['concrete'] = values.taints['concrete'] and arg.taints['concrete']
                values.taints['it'] = values.taints['it'] or arg.taints['it']
            if vexpression.op.startswith('Iop_Add') or vexpression.op.startswith('Iop_And') or \
               vexpression.op.startswith('Iop_Or') or vexpression.op.startswith('Iop_Xor'):
                t1 = args[0].taints['pointer']
                t2 = args[1].taints['pointer']
                values.taints['pointer'] = (t1 if t1 else t2) if (bool(t1) ^ bool(t2)) else False
            elif vexpression.op.startswith('Iop_Sub'):
                t1 = args[0].taints['pointer']
                t2 = args[1].taints['pointer']
                values.taints['pointer'] = t1 if t1 and not t2 else False
            return values
    elif vexpression.tag == 'Iex_CCall':
        values = BiHead.default(ty)
        for i, expr in enumerate(vexpression.args):
            arg = handle_expression(blockstate, expr, path + ['args', i])
            values.taints['it'] = values.taints['it'] or arg.taints['it']
        return values
    elif vexpression.tag == 'Iex_GetI':
        return BiHead.default(ty)
    else:
        raise FidgetUnsupportedError('Unknown expression tag ({:#x}): {!r}'.format(addr, vexpression.tag))


def make_bindata(values, addr, flags):
    # flags is the access type
    data = BinaryDataConglomerate(addr, values.as_signed, values.dirtyval, flags)
    for resolver in values.taints['deps']:
        dirtyval, bindata = resolver.resolve()
        data.add(bindata, dirtyval)
    return data
