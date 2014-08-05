import sys, os
import executable, vexutils
from binary_patch import binary_patch
import bisect
import claripy

def patch(infile, outfile, safe=False, verbose=1, whitelist=[], blacklist=[], debug=False):
    if verbose >= 0: print 'Loading %s...' % infile
    binrepr = executable.Executable(infile)
    if debug:
        import ipdb; ipdb.set_trace()
    if binrepr.error:
        print >>sys.stderr, '*** CRITICAL: Not an executable'
        return
    binrepr.verbose = verbose
    binrepr.safe = safe
    funcs = binrepr.funcman.functions.keys()
    patch_data = []
    for funcaddr in funcs:
        if funcaddr == binrepr.get_entry_point():
            continue    # don't touch _start. Seriously.
        sec = binrepr.locate_physaddr(funcaddr)
        if sec is None or sec[1].name != '.text':
            continue
        # TODO: Do a real name lookup instead of a fake one
        funcname = 'sub_%x' % funcaddr
        if (len(whitelist) > 0 and funcname not in whitelist) or \
           (len(blacklist) > 0 and funcname in blacklist):
            continue
        if binrepr.verbose >= 0: print 'Parsing %s...' % funcname
        patch_data += patch_function(binrepr, funcaddr)

    if binrepr.verbose > 0:
        print 'Accumulated %d patches, %d bytes of data' % (len(patch_data), sum(map(lambda x: len(x[1]), patch_data)))
    binary_patch(infile, patch_data, outfile)

    try:
        binrepr.ida.close()   # I added a close() function to my local version of idalink so it'll close the databases properly
    except:
        pass


def patch_function(binrepr, funcaddr):
    binrepr.claripy = claripy.ClaripyStandalone()
    binrepr.claripy.unique_names = False
    binrepr.symrepr = binrepr.claripy.solver()
    alloc_op = None   # the instruction that performs a stack allocation
    dealloc_ops = []  # the instructions that perform a stack deallocation
    variables = VarList(binrepr, 0)
    for tag, bindata in binrepr.find_tags(funcaddr):
        if tag == '': continue
        if binrepr.verbose > 1:
            print '\t%8.0x    %s: %s' % (bindata.memaddr, tag, hex(bindata.value))

        if tag == 'STACK_ALLOC':
            #if len(variables) > 0: # allow multiple allocs because ARM has limited immediates
            #    print '\t*** CRITICAL: Stack alloc after stack access\n'
            #    return []
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
            # TODO: Make sure to keep ALL variables outside the canonial frame frozen
            if bindata.value < -variables.stack_size:
                if binrepr.verbose > 0:
                    print '\t*** WARNING: Instruction accessing above stack frame, discarding'
                    continue
            Access(bindata, binrepr, variables)

        elif tag == 'STACK_ALLOCA':
            if binrepr.verbose > 0: print '\t*** WARNING: Function appears to use alloca, abandoning\n'
            return []

        else:
            print '\t*** CRITICAL: You forgot to update parse_function(), jerkface!\n'

    if alloc_op is None:
        if binrepr.verbose > 0: print '\tFunction does not appear to have a stack frame (No alloc)\n'
        return []

    if len(dealloc_ops) == 0:
        if binrepr.verbose > 0: print '\t*** WARNING: Function does not ever deallocate stack frame\n'
    
# Find the lowest sp-access that isn't an argument to the next function
# By starting at accesses to [esp] and stepping up a word at a time
    if binrepr.is_convention_stack_args():
        wordsize = binrepr.native_word
        i = variables.stack_size
        while True:
            if i in variables:
                variables[i].special = True
                i += wordsize
            else:
                break

    num_vars = len(variables)
    if num_vars > 0:
        if binrepr.verbose > 0:
            num_accs = variables.num_accesses()
            print '''\tFunction has a stack frame of %d bytes.
\t%d access%s to %d address%s %s made.''' % \
            (variables.stack_size, 
            num_accs, '' if num_accs == 1 else 'es',
            num_vars, '' if num_vars == 1 else 'es',
            'is' if num_accs == 1 else 'are')

        if binrepr.verbose > 1:
            print 'Stack addresses:', variables.addr_list
    else:
        if binrepr.verbose > 0:
            print '\tFunction has a %d-byte stack frame, but doesn\'t use it for local vars\n' % variables.stack_size
        return []

    variables.collapse()
    variables.mark_sizes()

    sym_stack_size = binrepr.claripy.BitVec("stack_size", 64)
    binrepr.symrepr.add(sym_stack_size >= variables.stack_size)
    binrepr.symrepr.add(sym_stack_size <= variables.stack_size + (16 * len(variables) + 32))
    binrepr.symrepr.add(sym_stack_size % (binrepr.native_word/8) == 0)
    
    alloc_op.apply_constraints(binrepr.symrepr)
    binrepr.symrepr.add(vexutils.SExtTo(64, alloc_op.symval) == -sym_stack_size)
    for op in dealloc_ops:
        op.apply_constraints(binrepr.symrepr)
        binrepr.symrepr.add(op.symval == 0)

    variables.old_size = variables.stack_size
    variables.stack_size = sym_stack_size
    variables.sym_link()
    
    # OKAY HERE WE GO
    if binrepr.verbose > 1:
        print '\nConstraints:'
        vexutils.columnize(str(x) for x in binrepr.symrepr.constraints)
        print

    if not binrepr.symrepr.satisfiable():
        print '*** SUPERCRITICAL (%x): Safe constraints unsatisfiable, fix this NOW'
        raise Exception('You\'re a terrible programmer and should check yo\'self before you wreck yo\'self and your team\'s chances of sanity')

    for constraint in variables.unsafe_constraints:
        if binrepr.symrepr.satisfiable(extra_constraints=[constraint]):
            binrepr.symrepr.add(constraint)
            if binrepr.verbose > 1:
                print 'Added unsafe constraint:', constraint
        else:
            if binrepr.verbose > 1:
                print "DIDN'T add unsafe constraint:", constraint


    if binrepr.verbose > 0:
        print '\tResized stack from', variables.old_size, 'to', binrepr.symrepr.any_value(variables.stack_size).value

    if binrepr.verbose > 1:
        for addr in variables.addr_list:
            fixedval = binrepr.symrepr.any_value(variables.variables[addr].address)
            fixedval = binrepr.resign_int(fixedval.value, fixedval.size())
            print 'moved', addr, 'size', variables.variables[addr].size, 'to', fixedval

    out = []
    out += alloc_op.get_patch_data(binrepr.symrepr)
    for dealloc in dealloc_ops:
        dealloc.gotime = True
        out += dealloc.get_patch_data(binrepr.symrepr)
    out += variables.get_patches()
    if binrepr.verbose > 0: print
    return out

class Access():
    def __init__(self, bindata, binrepr, varlist):
        self.bindata = bindata
        self.value = bindata.value
        self.binrepr = binrepr
        self.symrepr = binrepr.symrepr
        self.varlist = varlist

        self.access_flags = bindata.access_flags   # get access flags
        Variable(varlist, self)                                 # make a variable or add it to an existing one
        self.variable = varlist[self.address()]                 # get reference to variable
        self.offset_variable = 0

    def address(self):
        return self.value

    def sym_link(self):
        self.value = vexutils.SExtTo(64, self.bindata.symval)
        self.bindata.apply_constraints(self.symrepr)
        self.symrepr.add(self.address() - self.offset_variable == self.variable.address)

    def get_patches(self):
        if self.bindata.value != 0:
            return self.bindata.get_patch_data(self.symrepr)
        else: return []

class Variable():
    def __init__(self, varlist, access):
        if access.address() in varlist:
            varlist[access.address()].add_access(access)
            return
        self.varlist = varlist
        self.binrepr = varlist.binrepr
        self.symrepr = varlist.binrepr.symrepr
        self.address = access.address()
        self.accesses = []
        self.access_flags = 0
        self.add_access(access)
        varlist.add_variable(self)
        self.special = self.address >= 0

    def add_access(self, access):
        self.accesses.append(access)
        access.offset_variable = access.address() - self.address
        if access.access_flags == 1 and self.access_flags == 0:
            self.access_flags = 9
        else:
            self.access_flags |= access.access_flags

    def merge(self, child):
        for access in child.accesses:
            access.offset_variable = access.address() - self.address
            self.accesses.append(access)
            access.variable = self

    def sym_link(self):
        org_addr = self.address
        name_prefix = 'var' if org_addr < 0 else 'arg'
        self.address = self.binrepr.claripy.BitVec('%s_%x' % (name_prefix, abs(org_addr)), 64)
        for access in self.accesses: access.sym_link()
        if self.special:
            if org_addr >= 0:
                self.symrepr.add(self.address == org_addr)
            else:
                self.symrepr.add(self.address == (org_addr - self.varlist.old_size) + self.varlist.stack_size)
            if self.next is not None:
                self.next.sym_link()
            return
        if not self.varlist.done_first:
            self.varlist.done_first = True
            self.symrepr.add(self.address >= (org_addr + self.varlist.old_size) - self.varlist.stack_size)
        if org_addr % (self.binrepr.native_word / 8) == 0:
            self.symrepr.add(self.address % (self.binrepr.native_word/8) == 0)
        self.varlist.unsafe_constraints.append(self.address < org_addr)
        if self.next is None or self.next.special:
            self.symrepr.add(self.address <= org_addr)
        if self.next is not None:
            self.next.sym_link()
        if self.next is not None and not self.next.special:
            if self.binrepr.safe:
                self.symrepr.add(self.address + self.size == self.next.address)
            else:
                self.symrepr.add(self.address + self.size <= self.next.address)

    def get_patches(self):
        return sum((access.get_patches() for access in self.accesses), [])

class VarList():
    def __init__(self, binrepr, stack_size):
        self.variables = {} # all the variables, indexed by address
        self.addr_list = [] # all the addresses, kept sorted
        self.binrepr = binrepr
        self.stack_size = stack_size
        self.old_size = stack_size

    def __getitem__(self, key):
        return self.variables[key]

    def __delitem__(self, key):
        del self.variables[key]
        self.addr_list.remove(key)

    def __contains__(self, val):
        return val in self.variables

    def __len__(self):
        return len([0 for x in self.variables if not self.variables[x].special])

    def add_variable(self, var):
        self.variables[var.address] = var
        bisect.insort(self.addr_list, var.address)

    def num_accesses(self):
        return sum(map(lambda x: len(x.accesses), self.get_all_vars()))

    def get_all_vars(self):
        return map(lambda x: self.variables[x], self.addr_list)

    def sym_link(self):
        self.done_first = False
        first = self.variables[self.addr_list[0]]
        self.unsafe_constraints = []
        first.sym_link()        # yaaay recursion and list linkage!

    def collapse(self):
        i = 0               # old fashioned loop because we're removing items
        while i < len(self.addr_list) - 1:
            i += 1
            var = self.variables[self.addr_list[i]]
            if var.special:
                continue
            if var.address % (self.binrepr.native_word / 8) != 0:
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
        if self.binrepr.verbose > 1:
            print '\tMerged %d into %d' % (child.address, parent.address)

    def merge_down(self, i):
        child = self.variables.pop(self.addr_list.pop(i))
        parent = self.variables[self.addr_list[i]]
        parent.merge(child)
        if self.binrepr.verbose > 1:
            print '\tMerged %d down to %d' % (child.address, parent.address)

    def get_patches(self):
        return sum((var.get_patches() for var in self.get_all_vars()), [])

    def __str__(self):
        return '\n'.join(str(x) for x in self.vars)

    def __repr__(self):
        return str(self)

    def mark_sizes(self):
        for i, addr in enumerate(self.addr_list[:-1]):
            var = self.variables[addr]
            var.next = self.variables[self.addr_list[i+1]]
            var.size = var.next.address - var.address
        var = self.variables[self.addr_list[-1]]
        var.next = None
        var.size = self.stack_size - var.address


