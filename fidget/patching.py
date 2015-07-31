import os, shutil
import claripy

from .stack_magic import Stack
from .executable import Executable
from .sym_tracking import find_stack_tags
from .errors import FidgetError, FidgetUnsupportedError

import logging
l = logging.getLogger('fidget.patching')

class Fidget(object):
    def __init__(self, infile, cache=False, cfg_options=None, debugangr=False):
        self.infile = infile
        self.error = False
        self._stack_patch_data = []
        if cfg_options is None:
            cfg_options = {'enable_symbolic_back_traversal': True}
        self._binrepr = Executable(infile, cache, cfg_options, debugangr)

    def apply_patches(self, outfile=None):
        tempfile = '/tmp/fidget-%d' % os.getpid()
        patchdata = self.dump_patches()
        l.info('Accumulated %d patches, %d bytes of data', len(patchdata), sum(map(lambda x: len(x[1]), patchdata)))

        if outfile is None:
            outfile = self.infile + '.out'
        l.debug('Patching to %s', outfile)

        fin = open(self.infile, 'rb')
        fout = open(tempfile, 'wb')

        buf = 'a'
        while buf:
            buf = fin.read(1024*1024)
            fout.write(buf)

        for offset, data in patchdata:
            fout.seek(offset)
            fout.write(data)
        fin.close()
        fout.close()
        os.chmod(tempfile, 0755)
        shutil.move(tempfile, outfile)
        l.debug('Patching complete!')

    def dump_patches(self):
        # TODO: More kinds of patches please :P
        return self._stack_patch_data

    def patch(self, **options):
        self.patch_stack(**options.pop('stacks', {})) # :(

    def patch_stack(self, whitelist=None, blacklist=None, **kwargs):
        whitelist = whitelist if whitelist is not None else []
        blacklist = blacklist if blacklist is not None else []
        l.debug('Patching function stacks')
        self._stack_patch_data = []

        # Loop through all the functions as found by angr's CFG
        funcs = self._binrepr.funcman.functions

        # Find the real _start on MIPS so we don't touch it
        do_not_touch = None
        if self._binrepr.angr.arch.name == 'MIPS32':
            for context in self._binrepr.cfg.get_all_nodes(self._binrepr.angr.entry):
                for succ, jumpkind in self._binrepr.cfg.get_successors_and_jumpkind(context):
                    if jumpkind == 'Ijk_Call':
                        do_not_touch = succ.addr
                        l.debug('Found MIPS entry point stub target %#x', do_not_touch)

        last_size = 0
        successes = 0
        totals = 0
        for funcaddr, func in funcs.iteritems():
            # But don't touch _start. Seriously.
            if funcaddr == self._binrepr.angr.entry:
                l.debug('Skipping entry point')
                continue

            # On MIPS there's another function that's part of the entry point.
            # Trying to mess with it will cause catastrope.
            if funcaddr == do_not_touch:
                l.debug('Skipping MIPS entry point stub target')
                continue

            # Don't try to patch simprocedures
            if self._binrepr.angr.is_hooked(funcaddr):
                l.debug("Skipping simprocedure %s", self._binrepr.angr._sim_procedures[funcaddr][0].__name__)
                continue

            # Don't touch functions not in any segment
            if self._binrepr.angr.loader.main_bin.find_segment_containing(funcaddr) is None:
                l.debug('Skipping function %s not mapped', func.name)
                continue

            # If the text section exists, only patch functions in it
            if '.text' not in self._binrepr.angr.loader.main_bin.sections_map:
                sec = self._binrepr.angr.loader.main_bin.find_section_containing(funcaddr)
                if sec is None or sec.name != '.text':
                    l.debug('Skipping function %s not in .text', func.name)
                    continue

            # Don't patch functions in the PLT
            if funcaddr in self._binrepr.angr.loader.main_bin.plt.values():
                l.debug('Skipping function %s in PLT', func.name)
                continue

            # If the CFG couldn't parse an indirect jump, avoid
            if func.has_unresolved_jumps:
                l.debug("Skipping function %s with unresolved jumps", func.name)
                continue

            # Check if the function starts at a SimProcedure (edge case)
            if self._binrepr.cfg.get_any_node(funcaddr).simprocedure_name is not None:
                l.debug('Skipping function %s starting with a SimProcedure', func.name)

            # Check if the function is white/blacklisted
            if (len(whitelist) > 0 and func.name not in whitelist) or \
               (len(blacklist) > 0 and func.name in blacklist):
                l.debug('Function %s removed by whitelist/blacklist', func.name)
                continue

            l.info('Patching stack of %s', func.name)
            self.patch_function_stack(funcaddr, has_return=func.has_return, **kwargs)
            if len(self._stack_patch_data) > last_size:
                last_size = len(self._stack_patch_data)
                successes += 1
            totals += 1
        if successes == 0:
            l.error("Could not patch any functions' stacks!")
        else:
            l.info('Patched %d/%d functions', successes, totals)


    def patch_function_stack(self, funcaddr, has_return, safe=False, largemode=False):
        solver = claripy.Solver()
        alloc_op = None   # the instruction that performs a stack allocation
        dealloc_ops = []  # the instructions that perform a stack deallocation
        least_alloc = None # the smallest allocation known
        stack = Stack(self._binrepr, solver, 0)
        for tag, bindata in find_stack_tags(self._binrepr, funcaddr):
            if tag == '':
                continue
            elif tag.startswith('ABORT'):
                return
            l.debug('Got a tag at %#0.8x: %s: %#x', bindata.addr, tag, bindata.value)

            if tag == 'STACK_ALLOC':
                if alloc_op is None or bindata.value < alloc_op.value:
                    alloc_op = bindata
                    stack.conc_size = -alloc_op.value
                if least_alloc is None or bindata.value > least_alloc.value:
                    least_alloc = bindata
            elif tag == 'STACK_DEALLOC':
                if not bindata.symval.symbolic:
                    continue
                dealloc_ops.append(bindata)
                if least_alloc is None or bindata.value > least_alloc.value:
                    least_alloc = bindata
            elif tag == 'STACK_ACCESS':
                stack.access(bindata)
            else:
                raise FidgetUnsupportedError('You forgot to update the tag list, jerkface!')

        if alloc_op is None:
            l.info('\tFunction does not appear to have a stack frame (No alloc)')
            return

        if has_return and least_alloc.value != self._binrepr.angr.arch.bytes if self._binrepr.angr.arch.call_pushes_ret else 0:
            l.info('\tFunction does not ever deallocate stack frame (Least alloc is %d for %s)', -least_alloc.value, self._binrepr.angr.arch.name)
            return

        if has_return and len(dealloc_ops) == 0:
            l.error('\tFunction does not ever deallocate stack frame (No zero alloc)')
            return

        if stack.conc_size <= 0:
            l.error('\tFunction has invalid stack size of %#x', stack.conc_size)
            return

    # Find the lowest sp-access that isn't an argument to the next function
    # By starting at accesses to [esp] and stepping up a word at a time
        if self._binrepr.angr.arch.name == 'X86':
            last_addr = -stack.conc_size
            for var in stack:
                if var.conc_addr != last_addr:
                    break
                last_addr += self._binrepr.angr.arch.bytes
                #var.special_top = True
                #l.debug("Marked TOP addr %d as special", var.conc_addr)

        last_addr = None
        for var in reversed(stack):
            if last_addr is None:
                if var.conc_addr < 0:
                    break       # why would this happen
                last_addr = var.conc_addr
            if var.conc_addr != last_addr:
                break
            last_addr -= self._binrepr.angr.arch.bytes
            var.special_bottom = True
            l.debug("Marked BOTTOM addr %d as special", var.conc_addr)

        if stack.num_vars == 0:
            l.info("\tFunction has %#x-byte stack frame, but doesn't use it for local vars", stack.conc_size)
            return

        l.info('\tFunction has a stack frame of %#x bytes', stack.conc_size)
        l.info('\t%d access%s to %d address%s %s made.',
            stack.num_accs, '' if stack.num_accs == 1 else 'es',
            stack.num_vars, '' if stack.num_vars == 1 else 'es',
            'is' if stack.num_accs == 1 else 'are')

        l.debug('Stack addresses: [%s]', ', '.join(hex(var.conc_addr) for var in stack))

        stack.collapse()
        stack.mark_sizes()

        alloc_op.apply_constraints(solver)
        solver.add(alloc_op.symval == -stack.sym_size)
        for op in dealloc_ops:
            op.apply_constraints(solver)
            solver.add(op.symval == 0)

        if largemode and not safe:
            solver.add(stack.sym_size <= stack.conc_size + (1024 * stack.num_vars + 2048))
            stack.unsafe_constraints.append(stack.sym_size >= stack.conc_size + (1024 * stack.num_vars))
            stack.unsafe_constraints.append(stack.sym_size >= 0x78)
            stack.unsafe_constraints.append(stack.sym_size >= 0xF8)
        elif largemode and safe:
            solver.add(stack.sym_size <= stack.conc_size + 1024*16)
            stack.unsafe_constraints.append(stack.sym_size >= stack.conc_size + 1024*8)
            stack.unsafe_constraints.append(stack.sym_size >= 0x78)
            stack.unsafe_constraints.append(stack.sym_size >= 0xF0)
        elif not largemode and safe:
            solver.add(stack.sym_size <= stack.conc_size + 256)
        elif not largemode and not safe:
            solver.add(stack.sym_size <= stack.conc_size + (16 * stack.num_vars + 32))

        stack.sym_link(safe=safe)

        # OKAY HERE WE GO
        #print '\nConstraints:'
        #vexutils.columnize(str(x) for x in solver.constraints)
        #print

        if not solver.satisfiable():
            l.critical('(%#x) Safe constraints unsatisfiable, fix this NOW', funcaddr)
            raise FidgetError("You're a terrible programmer")

        # z3 is smart enough that this doesn't add any noticable overhead
        for constraint in stack.unsafe_constraints:
            if solver.satisfiable(extra_constraints=[constraint]):
                l.debug("Added unsafe constraint:         %s", constraint)
                solver.add(constraint)
            else:
                l.debug("Failed to add unsafe constraint: %s", constraint)

        new_stack = solver.eval(stack.sym_size, 1)[0].value
        if new_stack == stack.conc_size:
            l.warning('\tUnable to resize stack')
            return

        l.info('\tResized stack from 0x%x to 0x%x', stack.conc_size, new_stack)

        for var in stack:
            fixedval = solver.eval(var.sym_addr, 1)[0].signed
            if var.size is None:
                l.debug('Moved %#x (unsized) to %#x', var.conc_addr, fixedval)
            else:
                l.debug('Moved %#x (size %#x) to %#x', var.conc_addr, var.size, fixedval)

        self._stack_patch_data += alloc_op.get_patch_data(solver)
        for dealloc in dealloc_ops:
            self._stack_patch_data += dealloc.get_patch_data(solver)
        self._stack_patch_data += stack.patches

