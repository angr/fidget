from angr import Project
import claripy

from .structures import StructureAnalysis
from .errors import FidgetError

import os, shutil, pickle
import logging
l = logging.getLogger('fidget.patching')

class Fidget(object):
    def __init__(self, infile, cache=False, cfg_options=None, debugangr=False):
        self.infile = infile
        self.error = False
        self._stack_patch_data = []
        if cfg_options is None:
            cfg_options = {'enable_symbolic_back_traversal': True}
        cachename = infile + '.fcfg'

        l.info("Loading %s", infile)
        try:
            if not cache: raise IOError('fuck off')
            fh = open(cachename, 'rb')
            self.project, self.cfg = pickle.load(fh)
            self.cfg.project = self.project
            fh.close()
        except (IOError, OSError, pickle.UnpicklingError):
            if debugangr:
                import ipdb; ipdb.set_trace()
            self.project = Project(infile, load_options={'auto_load_libs': False})
            self.cfg = self.project.analyses.CFGAccurate(**cfg_options)
            try:
                fh = open(cachename, 'wb')
                pickle.dump((self.project, self.cfg), fh, -1)
                fh.close()
            except (IOError, OSError, pickle.PicklingError):
                l.exception('Error pickling CFG')

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
        last_size = 0
        successes = 0
        totals = 0

        for func in StructureAnalysis.real_functions(self.cfg):
            # Check if the function is white/blacklisted
            if (len(whitelist) > 0 and func.name not in whitelist) or \
               (len(blacklist) > 0 and func.name in blacklist):
                l.debug('Function %s removed by whitelist/blacklist', func.name)
                continue

            l.info('Patching stack of %s', func.name)
            self.patch_function_stack(func, **kwargs)
            if len(self._stack_patch_data) > last_size:
                last_size = len(self._stack_patch_data)
                successes += 1
            totals += 1
        if successes == 0:
            l.error("Could not patch any functions' stacks!")
        else:
            l.info('Patched %d/%d functions', successes, totals)


    def patch_function_stack(self, func, safe=False, largemode=False):
        solver = claripy.Solver()
        analysis_result = StructureAnalysis(self.project, self.cfg, [func], False)
        stack = analysis_result.stack_frames[func.addr]
        if stack is None:
            return
        stack = analysis_result.structures[stack]

        if stack.alloc_op is None:
            l.info('\tFunction does not appear to have a stack frame (No alloc)')
            return False

        if func.has_return and stack.least_alloc.value != self.project.arch.bytes if self.project.arch.call_pushes_ret else 0:
            l.info('\tFunction does not ever deallocate stack frame (Least alloc is %d for %s)', -stack.least_alloc.value, self.project.arch.name)
            return False

        if func.has_return and len(stack.dealloc_ops) == 0:
            l.error('\tFunction does not ever deallocate stack frame (No zero alloc)')
            return False

        if stack.conc_size <= 0:
            l.error('\tFunction has invalid stack size of %#x', stack.conc_size)
            return False

        # Find the lowest sp-access that isn't an argument to the next function
        # By starting at accesses to [esp] and stepping up a word at a time
        if self.project.arch.name == 'X86':
            last_addr = -stack.conc_size
            for var in stack:
                if var.conc_addr != last_addr:
                    break
                last_addr += self.project.arch.bytes
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
            last_addr -= self.project.arch.bytes
            var.special_bottom = True
            l.debug("Marked BOTTOM addr %d as special", var.conc_addr)

        if stack.num_vars == 0:
            l.info("\tFunction has %#x-byte stack frame, but doesn't use it for local vars", stack.conc_size)
            return False

        l.info('\tFunction has a stack frame of %#x bytes', stack.conc_size)
        l.info('\t%d access%s to %d address%s %s made.',
            stack.num_accs, '' if stack.num_accs == 1 else 'es',
            stack.num_vars, '' if stack.num_vars == 1 else 'es',
            'is' if stack.num_accs == 1 else 'are')

        l.debug('Stack addresses: [%s]', ', '.join(hex(var.conc_addr) for var in stack))

        stack.collapse()
        stack.mark_sizes()

        stack.alloc_op.apply_constraints(solver)
        solver.add(stack.alloc_op.symval == -stack.sym_size)
        for op in stack.dealloc_ops:
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

        stack.sym_link(solver, safe=safe)

        # OKAY HERE WE GO
        #print '\nConstraints:'
        #vexutils.columnize(str(x) for x in solver.constraints)
        #print

        if not solver.satisfiable():
            l.critical('(%#x) Safe constraints unsatisfiable, fix this NOW', func.addr)
            raise FidgetError("You're a terrible programmer")

        # z3 is smart enough that this doesn't add any noticable overhead
        for constraint in stack.unsafe_constraints:
            if solver.satisfiable(extra_constraints=[constraint]):
                l.debug("Added unsafe constraint:         %s", constraint)
                solver.add(constraint)
            else:
                l.debug("Failed to add unsafe constraint: %s", constraint)

        new_stack = solver.eval(stack.sym_size, 1)[0]
        if new_stack == stack.conc_size:
            l.warning('\tUnable to resize stack')
            return False

        l.info('\tResized stack from 0x%x to 0x%x', stack.conc_size, new_stack)

        for var in stack:
            fixedval = solver.eval_to_ast(var.sym_addr, 1)[0]._model_concrete.signed
            if var.size is None:
                l.debug('Moved %#x (unsized) to %#x', var.conc_addr, fixedval)
            else:
                l.debug('Moved %#x (size %#x) to %#x', var.conc_addr, var.size, fixedval)

        self._stack_patch_data += stack.get_patches(solver)
        return True

