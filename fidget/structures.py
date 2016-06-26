from angr import AngrMemoryError
import claripy
import pyvex

from .errors import FidgetAnalysisFailure, FidgetUnsupportedError, FidgetError
from .blockstate import BlockState, ACCESS_MAPPING

import bisect
from collections import defaultdict

import logging
l = logging.getLogger('fidget.structures')

OK_CONTINUE_JUMPS = ('Ijk_FakeRet', 'Ijk_Boring', 'Ijk_FakeRet', 'Ijk_Sys_int128', 'Ijk_SigTRAP', 'Ijk_Sys_syscall')

class Access(object):
    def __init__(self, bindata):
        self.bindata = bindata
        self.offset = 0

    @property
    def access_flags(self):
        return self.bindata.access_flags

    @property
    def conc_addr(self):
        return self.bindata.value

    @property
    def sym_addr(self):
        return self.bindata.symval

    def get_patches(self, solver):
        return self.bindata.get_patch_data(solver)

    def sym_link(self, variable, solver):
        self.bindata.apply_constraints(solver)
        solver.add(self.sym_addr - self.offset == variable.sym_addr)

class Variable(object):
    def __init__(self, address, sym_addr):
        self.conc_addr = address
        self.sym_addr = sym_addr

        self.accesses = []
        self.access_flags = 0
        self.special_bottom = self.conc_addr >= 0
        self.special_top = False
        self.size = None
        self.unsafe_constraints = []

    @property
    def special(self):
        return self.special_bottom or self.special_top

    def add_access(self, access):
        self.accesses.append(access)
        access.offset = access.conc_addr - self.conc_addr
        if access.access_flags == 1 and self.access_flags == 0:
            self.access_flags = 9
        else:
            self.access_flags |= access.access_flags

    def merge(self, child):
        for access in child.accesses:
            self.add_access(access)

    def sym_link(self, solver, stack):
        for access in self.accesses:
            access.sym_link(self, solver)

        if self.special_bottom:
            solver.add(self.sym_addr == self.conc_addr)
        if self.special_top:
            solver.add(self.sym_addr == (self.conc_addr - stack.conc_size) + stack.sym_size)
        if self.special:
            return

        #self.unsafe_constraints.append(self.sym_addr < self.conc_addr)

    def get_patches(self, solver):
        return sum((access.get_patches(solver) for access in self.accesses), [])

num_structs = 0

class Struct(object):
    def __init__(self, arch, is_stack_frame=False):
        self.arch = arch
        self.is_stack_frame = is_stack_frame
        self.variables = {} # all the variables, indexed by address
        self.addr_list = [] # all the addresses, kept sorted
        self.conc_size = 0
        self.sym_size = claripy.BVS("stack_size", arch.bits)
        self.unsafe_constraints = []
        self.name = self._make_name()

        self.alloc_op = None
        self.dealloc_ops = []
        self.least_alloc = None

    def _make_name(self):
        global num_structs
        name = ('stack_%0.4d' if self.is_stack_frame else 'struct_%0.4d') % num_structs
        num_structs += 1
        return name

    def __iter__(self):
        for addr in self.addr_list:
            yield self.variables[addr]

    def __reversed__(self):
        for addr in reversed(self.addr_list):
            yield self.variables[addr]

    def access(self, bindata):
        access = Access(bindata)
        #if access.conc_addr < -self.conc_size:
        #    access.special_top = True

        if access.conc_addr not in self.variables:
            name_prefix = 'var' if access.conc_addr < 0 else 'arg'
            sym_addr = claripy.BVS('%s_%x' % (name_prefix, abs(access.conc_addr)), self.arch.bits)
            self.add_variable(Variable(access.conc_addr, sym_addr))
        self.variables[access.conc_addr].add_access(access)

    def alloc(self, bindata):
        if bindata.value == 0:
            if not bindata.symval.symbolic:
                return
            self.dealloc_ops.append(bindata)
            if self.least_alloc is None or bindata.value > self.least_alloc.value:
                self.least_alloc = bindata
        else:
            if self.alloc_op is None or bindata.value < self.alloc_op.value:
                self.alloc_op = bindata
                self.conc_size = -self.alloc_op.value
            if self.least_alloc is None or bindata.value > self.least_alloc.value:
                self.least_alloc = bindata

    def add_variable(self, var):
        self.variables[var.conc_addr] = var
        bisect.insort(self.addr_list, var.conc_addr)

    @property
    def all_accs(self):
        return sum(map(lambda x: x.accesses, self.all_vars), [])

    @property
    def all_vars(self):
        return map(lambda x: self.variables[x], self.addr_list)

    @property
    def num_accs(self):
        return len(self.all_accs)

    @property
    def num_vars(self):
        return len(self.variables)

    def get_patches(self, solver):
        out = sum((var.get_patches(solver) for var in self), [])
        out += self.alloc_op.get_patch_data(solver)
        out += sum((dealloc.get_patch_data(solver) for dealloc in self.dealloc_ops), [])
        return out

    def sym_link(self, solver, safe=False):
        solver.add(self.sym_size >= self.conc_size)
        solver.add(self.sym_size % (self.arch.bytes) == 0)
        self.unsafe_constraints.append(self.sym_size > self.conc_size)

        first = self.variables[self.addr_list[0]]
        solver.add(first.sym_addr >= (first.conc_addr + self.conc_size) - self.sym_size)
        var_list = list(self)
        for var, next_var in zip(var_list, var_list[1:] + [None]):
            var.sym_link(solver, self)
            self.unsafe_constraints.extend(var.unsafe_constraints)
            if var.conc_addr % (self.arch.bytes) == 0:
                solver.add(var.sym_addr % (self.arch.bytes) == 0)

            if var.special:
                # We're one of the args that needs to stay fixed relative somewhere
                pass
            elif next_var is None or next_var.special:
                # If we're the last free-floating variable, set a solid bottom
                solver.add(var.sym_addr <= var.conc_addr)
                if var.size is not None:
                    solver.add(claripy.SLE(var.sym_addr, var.sym_addr + var.size))
                    solver.add(var.sym_addr + var.size <= next_var.sym_addr)
                    self.unsafe_constraints.append(var.sym_addr + var.size < next_var.sym_addr)
            else:
                # Otherwise we're one of the free-floating variables
                solver.add(var.sym_addr <= var.sym_addr + var.size)
                self.unsafe_constraints.append(var.sym_addr + var.size < next_var.sym_addr)
                if safe:
                    solver.add(var.sym_addr + var.size == next_var.sym_addr)
                else:
                    solver.add(var.sym_addr + var.size <= next_var.sym_addr)

    def collapse(self):
        i = 0               # old fashioned loop because we're removing items
        while i < len(self.addr_list) - 1:
            i += 1
            var = self.variables[self.addr_list[i]]
            if var.special:
                continue
            if var.conc_addr % (self.arch.bytes) != 0:
                self.merge_up(i)
                i -= 1
            elif var.access_flags & 8:
                self.merge_up(i)
                i -= 1
            elif var.access_flags & 4:
                pass
            elif var.access_flags != 3:
                self.merge_up(i)
                i -= 1

    def merge_up(self, i):
        child = self.variables.pop(self.addr_list.pop(i))
        parent = self.variables[self.addr_list[i-1]]
        parent.merge(child)
        l.debug('Merged %s into %s', hex(child.conc_addr), hex(parent.conc_addr))

    def mark_sizes(self):
        for i, addr in enumerate(self.addr_list[:-1]):
            var = self.variables[addr]
            next_var = self.variables[self.addr_list[i+1]]
            var.size = next_var.conc_addr - var.conc_addr
        var = self.variables[self.addr_list[-1]]
        var.size = None


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
            self.cfg = project.analyses.CFGAccurate(enable_symbolic_back_traversal=True, keep_state=True)
        if self.functions_list is None:
            self.functions_list = self.real_functions(self.cfg)

        for func in self.functions_list:
            try:
                struct = self.analyze_stack(func.addr)
            except FidgetAnalysisFailure:
                pass
            else:
                self.add_struct(struct)
                self.stack_frames[func.addr] = struct.name

        if chase_structs:
            raise FidgetUnsupportedError("lmao what")

    def add_struct(self, struct):
        self.structures[struct.name] = struct

    @staticmethod
    def real_functions(cfg):
        project = cfg.project
        funcman = project.kb.functions

        # Find the real _start on MIPS so we don't touch it
        do_not_touch = None
        if project.arch.name == 'MIPS32':
            for context in cfg.get_all_nodes(project.entry):
                for succ, jumpkind in cfg.get_successors_and_jumpkind(context):
                    if jumpkind == 'Ijk_Call':
                        do_not_touch = succ.addr
                        l.debug('Found MIPS entry point stub target %#x', do_not_touch)

        for funcaddr, func in funcman.iteritems():
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
                block = self.project.factory.block(blockstate.block_addr, opt_level=1, max_size=400).vex
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
                if addr != funcaddr and addr in self.project.kb.functions:
                    l.warning("\tThis function jumps into another function (%#x). Abort.", addr)
                    raise FidgetAnalysisFailure
                cache.add(addr)
                insnblock = self.project.factory.block(addr, num_inst=1, max_size=400, opt_level=1).vex
                blockstate.handle_irsb(insnblock)

            if block.jumpkind == 'Ijk_Call' and self.project.arch.call_pushes_ret:
                # Pop the return address off the stack and keep going
                stack = blockstate.state.regs.sp
                popped = stack - self.project.arch.stack_change
                popped.taints = stack.taints
                blockstate.state.regs.sp = popped
                # Discard the last two tags -- they'll be an alloc and an access for the call
                # (the push and the retaddr)
                blockstate.tags = blockstate.tags[:-2]
                # Do NOT discard the regs, as they constrain the amount that was added to sizeof(void*)

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
                    l.debug("Got tag: %#0.8x ACCESS %s %#x", bindata.addr, ACCESS_MAPPING[bindata.access_flags], bindata.value)
                    struct.access(bindata)
                else:
                    raise FidgetUnsupportedError('You forgot to update the tag list, jerkface!')

        return struct

