import sys, os
import claripy
import subprocess

from stack_magic import Access, Variable, VarList
from executable import Executable
from binary_patch import binary_patch
from sym_tracking import find_stack_tags
import vexutils

class Fidget(object):
    def __init__(self, infile, safe=False, verbose=1, whitelist=[], blacklist=[], debug=False, debugangr=False):
        self.infile = infile
        self.safe = safe
        self.verbose = verbose
        self.whitelist = whitelist
        self.blacklist = blacklist
        self.debug = debug
        self.debugangr = debugangr

        self.error = False
        self._stack_patch_data = []

        if self.verbose >= 0:
            print 'Loading %s...' % infile

        self._binrepr = Executable(infile, debugangr)
        if self._binrepr.error:
            print >>sys.stderr, '*** CRITICAL: Loading error'
            self.error = True
            return

        self._binrepr.verbose = verbose
        self._binrepr.safe = safe


    def apply_patches(self, outfile=None):
        patchdata = self.dump_patches()
        if self._binrepr.verbose > 0:
            print 'Accumulated %d patches, %d bytes of data' % (len(patchdata), sum(map(lambda x: len(x[1]), patchdata)))

        if outfile is None:
            outfile = self.infile + '.out'

        # Create the output file as a copy of the input. Pipe will force it synchronous.
        subprocess.Popen(['cp', self.infile, outfile], stdout=subprocess.PIPE)

        fin = open(self.infile)
        fout = open(outfile, 'w')
        for offset, data in patchdata:
            fout.seek(offset)
            fout.write(data)
        fin.close()
        fout.close()

        subprocess.Popen(['chmod', '+x', outfile])

    def dump_patches(self):
        # TODO: More kinds of patches please :P
        return self._stack_patch_data

    def patch(self):
        self.patch_stack() # :(

    def patch_stack(self):
        self._stack_patch_data = []

        # Loop through all the functions as found by angr's CFG
        funcs = self._binrepr.funcman.functions.keys()
        for funcaddr in funcs:
            # But don't touch _start. Seriously.
            if funcaddr == self._binrepr.get_entry_point():
                continue

            # Only patch functions in the text section
            sec = self._binrepr.locate_physaddr(funcaddr)
            if sec is None or sec != 'text':
                continue

            # Check if the function is white/blacklisted
            # TODO: Do a real name lookup instead of a fake one
            funcname = 'sub_%x' % funcaddr
            if (len(self.whitelist) > 0 and funcname not in self.whitelist) or \
               (len(self.blacklist) > 0 and funcname in self.blacklist):
                continue

            if self._binrepr.verbose >= 0:
                print 'Parsing %s...' % funcname
            self.patch_function_stack(funcaddr)


    def patch_function_stack(self, funcaddr):
        clrp = claripy.ClaripyStandalone()
        clrp.unique_names = False
        symrepr = clrp.solver()
        alloc_op = None   # the instruction that performs a stack allocation
        dealloc_ops = []  # the instructions that perform a stack deallocation
        variables = VarList(self._binrepr, symrepr, 0)
        for tag, bindata in find_stack_tags(self._binrepr, symrepr, funcaddr):
            if tag == '': continue
            if self._binrepr.verbose > 1:
                print '\t%8.0x    %s: %s' % (bindata.memaddr, tag, hex(bindata.value))

            if tag == 'STACK_ALLOC':
                if alloc_op is None:
                    alloc_op = bindata
                elif bindata.value < alloc_op.value:
                    alloc_op = bindata
                variables.stack_size = -alloc_op.value

            elif tag == 'STACK_DEALLOC':
                if type(bindata.symval) in (int, long):
                    continue
                dealloc_ops.append(bindata)

            elif tag == 'STACK_ACCESS':
                # This constructor adds itself to the variable tracker
                Access(bindata, variables, bindata.value < -variables.stack_size)

            elif tag == 'STACK_ALLOCA':
                if self._binrepr.verbose > 0: print '\t*** WARNING: Function appears to use alloca, abandoning\n'
                return

            else:
                raise Exception('You forgot to update the tag list, jerkface!')

        if alloc_op is None:
            if self._binrepr.verbose > 0: print '\tFunction does not appear to have a stack frame (No alloc)\n'
            return

        if len(dealloc_ops) == 0:
            if self._binrepr.verbose > 0: print '\t*** WARNING: Function does not ever deallocate stack frame\n'
        
    # Find the lowest sp-access that isn't an argument to the next function
    # By starting at accesses to [esp] and stepping up a word at a time
        if self._binrepr.is_convention_stack_args():
            wordsize = self._binrepr.native_word
            i = variables.stack_size
            while True:
                if i in variables:
                    variables[i].special = True
                    i += wordsize
                else:
                    break

        num_vars = len(variables)
        if num_vars > 0:
            if self._binrepr.verbose > 0:
                num_accs = variables.num_accesses()
                print '\tFunction has a stack frame of %d bytes.' % variables.stack_size
                print '\t%d access%s to %d address%s %s made.''' % \
                    (num_accs, '' if num_accs == 1 else 'es',
                    num_vars, '' if num_vars == 1 else 'es',
                    'is' if num_accs == 1 else 'are')

            if self._binrepr.verbose > 1:
                print 'Stack addresses:', variables.addr_list
        else:
            if self._binrepr.verbose > 0:
                print '\tFunction has a %d-byte stack frame, but doesn\'t use it for local vars\n' % variables.stack_size
            return

        variables.collapse()
        variables.mark_sizes()

        sym_stack_size = clrp.BitVec("stack_size", 64)
        symrepr.add(sym_stack_size >= variables.stack_size)
        symrepr.add(sym_stack_size <= variables.stack_size + (16 * len(variables) + 32))
        symrepr.add(sym_stack_size % (self._binrepr.native_word/8) == 0)
        
        alloc_op.apply_constraints(symrepr)
        symrepr.add(vexutils.SExtTo(64, alloc_op.symval) == -sym_stack_size)
        for op in dealloc_ops:
            op.apply_constraints(symrepr)
            symrepr.add(op.symval == 0)

        variables.old_size = variables.stack_size
        variables.stack_size = sym_stack_size
        variables.sym_link()
        
        # OKAY HERE WE GO
        if self._binrepr.verbose > 1:
            print '\nConstraints:'
            vexutils.columnize(str(x) for x in symrepr.constraints)
            print

        if not symrepr.satisfiable():
            print '*** SUPERCRITICAL (%x): Safe constraints unsatisfiable, fix this NOW' % funcaddr
            raise Exception("You're a terrible programmer")

        # FIXME: THIS is the bottleneck in patching right now. Can we do better?
        for constraint in variables.unsafe_constraints:
            if symrepr.satisfiable(extra_constraints=[constraint]):
                symrepr.add(constraint)
                if self._binrepr.verbose > 1:
                    print 'Added unsafe constraint:', constraint
            else:
                if self._binrepr.verbose > 1:
                    print "DIDN'T add unsafe constraint:", constraint


        if self._binrepr.verbose > 0:
            print '\tResized stack from', variables.old_size, 'to', symrepr.any_value(variables.stack_size).value

        if self._binrepr.verbose > 1:
            for addr in variables.addr_list:
                fixedval = symrepr.any_value(variables.variables[addr].address)
                fixedval = self._binrepr.resign_int(fixedval.value, fixedval.size())
                print 'moved', addr, 'size', variables.variables[addr].size, 'to', fixedval

        self._stack_patch_data += alloc_op.get_patch_data(symrepr)
        for dealloc in dealloc_ops:
            dealloc.gotime = True
            self._stack_patch_data += dealloc.get_patch_data(symrepr)
        self._stack_patch_data += variables.get_patches()
        if self._binrepr.verbose > 0: print

