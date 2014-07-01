#!/usr/bin/python

import sys, os
import executable
import bisect
import symexec

def main(filename, options):
    print '\n\n\nLoading %s...' % filename
    binrepr = executable.Executable(filename)
    if binrepr.error:
        print '*** CRITICAL: Not an executable'
        return
    binrepr.verbose = options["verbose"]
    textsec = binrepr.get_section_by_name('.text')
    textrange = (textsec.header.sh_addr, textsec.header.sh_addr + textsec.header.sh_size)
    textfuncs = binrepr.ida.idautils.Functions(*textrange)
    for func in textfuncs:
        parse_function(binrepr, func)

    try:
        binrepr.ida.close()   # I added a close() function to my local version of idalink so it'll close the databases properly
    except:
        pass


def parse_function(binrepr, funcaddr):
    print 'Parsing %s...' % binrepr.ida.idc.Name(funcaddr)
    symrepr = symexec.Solver()
    binrepr.symrepr = symrepr
    bp_based = False
    size_offset = None
    bp_offset = 0     # in some cases the base pointer will be at a different place than size bytes from sp
    alloc_ops = []    # the instruction(s???) that performs a stack allocation
    dealloc_ops = []  # the instructions that perform a stack deallocation
    #bp_accesses = []  # the stack accesses using the base pointer
    #sp_accesses = []  # the stack accesses using the stack pointer
    #use_accesses = [] # the accesses that actually constitute local vars
    #addresses = set() # the stack offsets of all the accessed local vars
    variables = VarList(binrepr, 0)
    for ins in binrepr.iterate_instructions(funcaddr):
        typ = binrepr.identify_instr(ins)
        if binrepr.verbose > 2:
            print '%0.8x:       %s' % (ins.ea, binrepr.ida.idc.GetDisasm(ins.ea))
        if typ[0] == '': continue
        if binrepr.verbose > 1:
            print '       %s: %s' % typ

        if typ[0] == 'STACK_TYPE_BP':
            bp_based = True
            bp_offset = typ[1]

        elif typ[0] == 'STACK_FRAME_ALLOC':
            if len(variables) > 0: # allow multiple allocs because ARM has limited immediates
                print '\t*** CRITICAL (%x): Stack alloc after stack access\n' % ins.ea
                return
            if len(alloc_ops) == 0:
                size_offset = -binrepr.ida.idc.GetSpd(ins.ea)
            alloc_ops.append(typ[1])
            variables.stack_size += typ[1].value

        elif typ[0] == 'STACK_FRAME_DEALLOC':
            dealloc_ops.append(typ[1])
            if typ[1].value != variables.stack_size:  # I don't think there are manual deallocs on ARM!
                print '\t*** CRITICAL (%x): Stack dealloc does not match alloc??\n' % ins.ea
                return

        elif typ[0] == 'STACK_SP_ACCESS':
            if variables.stack_size == 0:
                if binrepr.verbose > 0: print '\tFunction does not appear to have a stack frame (1)\n'
                return
            offset = binrepr.ida.idc.GetSpd(ins.ea) + variables.stack_size + size_offset if size_offset is not None else 0
            if offset + typ[1].value < 0:
                if binrepr.verbose > 0: print '\t*** Warning (%x): Function appears ' + \
                        'to be accessing above its stack frame, discarding instruction' % ins.ea
                continue
            if offset + typ[1].value > variables.stack_size:
                continue        # this is one of the function's arguments
            # Do not filter out args to the next function here because we need to have everythign first
            Access(typ[1], False, offset, binrepr, variables)

        elif typ[0] == 'STACK_BP_ACCESS':
            if variables.stack_size == 0:
                if binrepr.verbose > 0: print '\tFunction does not appear to have a stack frame (2)\n'
                return
            if not bp_based:
                continue        # silently ignore bp access in sp frame
            if typ[1].value > 0:
                continue        # this is one of the function's arguments
            Access(typ[1], True, variables.stack_size + bp_offset, binrepr, variables)

        else:
            print '\t*** CRITICAL: You forgot to update parse_function(), jerkface!\n'

    if len(alloc_ops) == 0:
        if binrepr.verbose > 0: print '\tFunction does not appear to have a stack frame (3)\n'
        return
    
# Find the lowest sp-access that isn't an argument to the next function
# By starting at accesses to [esp] and stepping up a word at a time
    if binrepr.is_convention_stack_args():
        wordsize = executable.word_size[binrepr.native_dtyp]
        i = 0
        while True:
            if i in variables and variables[i].all_sp:
                del variables[i]
                i += wordsize
            else:
                break

    num_vars = len(variables)
    if num_vars > 0:
        if binrepr.verbose > 0:
            num_accs = variables.num_accesses()
            print '''\tFunction has a %s-based stack frame of %d bytes.
\t%d access%s to %d address%s %s made.
\tThere is %s deallocation.''' % \
            ('bp' if bp_based else 'sp', variables.stack_size, 
            num_accs, '' if num_accs == 1 else 'es',
            num_vars, '' if num_vars == 1 else 'es',
            'is' if num_accs == 1 else 'are',
            'an automatic' if len(dealloc_ops) == 0 else 'a manual')

        if binrepr.verbose > 1:
            print 'Stack addresses:', variables.addr_list
    else:
        if binrepr.verbose > 0:
            print '\tFunction has a %d-byte stack frame, but doesn\'t use it for local vars\n' % variables.stack_size
        return

    variables.collapse()

    print

class Access():
    def __init__(self, bindata, bp, offset, binrepr, varlist):
        self.bindata = bindata
        self.ea = bindata.memaddr
        self.opn = bindata.opn
        self.bp = bp
        self.value = bindata.value
        self.offset_inherant = offset
        self.binrepr = binrepr
        self.varlist = varlist

        self.access_flags = binrepr.get_access_flags(self.ea, self.opn)   # get access flags
        Variable(varlist, self)                                 # make a variable or add it to an existing one
        self.variable = varlist[self.address()]                 # get reference to variable
        self.offset_variable = 0

    def address(self):
        return self.offset_inherant + self.value

class Variable():
    def __init__(self, varlist, access):
        if access.address() in varlist:
            varlist[access.address()].add_access(access)
            return
        self.varlist = varlist
        self.address = access.address()
        self.accesses = []
        self.access_flags = 0
        self.all_sp = True
        self.add_access(access)
        varlist.add_variable(self)

    def add_access(self, access):
        self.accesses.append(access)
        if self.all_sp and access.bp:
            self.all_sp = False
        access.offset_variable = access.address() - self.address
        if access.access_flags == 1 and self.access_flags == 0:
            self.access_flags = 9
        else:
            self.access_flags |= access.access_flags

    def merge(self, child):
        for access in child.accesses:
            access.offset_variable = access.address() - self.address
            self.accesses.append(access)


class VarList():
    def __init__(self, binrepr, stack_size):
        self.variables = {} # all the variables, indexed by address
        self.addr_list = [] # all the addresses, kept sorted
        self.binrepr = binrepr
        self.stack_size = stack_size

    def __getitem__(self, key):
        return self.variables[key]

    def __delitem__(self, key):
        del self.variables[key]
        self.addr_list.remove(key)

    def __contains__(self, val):
        return val in self.variables

    def __len__(self):
        return len(self.variables)

    def add_variable(self, var):
        self.variables[var.address] = var
        bisect.insort(self.addr_list, var.address)

    def num_accesses(self):
        return sum(map(lambda x: len(x.accesses), self.get_all_vars()))

    def get_all_vars(self):
        return map(lambda x: self.variables[x], self.addr_list)

    def collapse(self):
        i = 0               # old fashioned loop because we're removing items
        while i < len(self.addr_list) - 1:
            i += 1
            var = self.variables[self.addr_list[i]]
            if var.address < 0:
                self.merge_down(i)
                i -= 1
            elif var.address % executable.word_size[self.binrepr.native_dtyp] != 0:
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

    def __str__(self):
        return '\n'.join(str(x) for x in self.vars)

    def __repr__(self):
        return str(self)

def addopt(options, option):
    if option in ('v', 'verbose'):
        options["verbose"] += 1
    elif option in ('q', 'quiet'):
        options["verbose"] -= 1
    elif option in ('h', 'help'):
        usage()
        os.exit(0)
    elif option in ('safe'):
        options['safe'] = True
    else:
        print 'Bad argument: %s' % option
        os.exit(1)

def usage():
    print """Fidget: The Binary Tweaker

Usage: %s [options] filename

Options:
    -h, --help              View this usage information and exit
    -v, --verbose           More output
    -q, --quiet             Less output
    --safe                  Make conservative modifications
""" % sys.argv[0]

if __name__ == '__main__':
    if len(sys.argv) < 2:
        usage()
    else:
        options = {"verbose": 0, "safe": False}
        filenames = []
        for arg in sys.argv[1:]:
            if arg.startswith('--'):
                addopt(options, arg[:2])
            elif arg.startswith('-'):
                for flag in arg[1:]: addopt(options, flag)
            else:
                filenames.append(arg)
        if len(filenames) == 0:
            print 'You must specify a file to operate on!'
            os.exit(1)
        for filename in filenames:
            main(filename, options)
