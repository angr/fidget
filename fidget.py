#!/usr/bin/python

import sys, os
import executable

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
    bp_based = False
    size = 0
    size_offset = None
    bp_offset = 0     # in some cases the base pointer will be at a different place than size bytes from sp
    alloc_ops = []    # the instruction(s???) that performs a stack allocation
    dealloc_ops = []  # the instructions that perform a stack deallocation
    bp_accesses = []  # the stack accesses using the base pointer
    sp_accesses = []  # the stack accesses using the stack pointer
    use_accesses = [] # the accesses that actually constitute local vars
    addresses = set() # the stack offsets of all the accessed local vars
    for ins in binrepr.iterate_instructions(funcaddr):
        typ = binrepr.identify_instr(ins)
        if binrepr.verbose > 2:
            print '%0.8x:       %s' % (ins.ea, binrepr.ida.idc.GetDisasm(ins.ea))
        if typ[0] == '': continue
        if binrepr.verbose > 1:
            print '%0.8x:       %s' % (ins.ea, str(typ))
        if typ[0] == 'STACK_TYPE_BP':
            bp_based = True
            bp_offset = typ[1]
        elif typ[0] == 'STACK_FRAME_ALLOC':
            if len(sp_accesses) > 0 or len(bp_accesses) > 0: # allow multiple allocs because ARM has limited immediates
                print '\t*** CRITICAL (%x): Stack alloc after stack access\n' % ins.ea
                return
            if len(alloc_ops) == 0:
                size_offset = -binrepr.ida.idc.GetSpd(ins.ea)
            alloc_ops.append(ins)
            size += typ[1]
        elif typ[0] == 'STACK_FRAME_DEALLOC':
            dealloc_ops.append(ins)
            if typ[1] != size:
                print '\t*** CRITICAL (%x): Stack dealloc does not match alloc??\n' % ins.ea
                return
        elif typ[0] == 'STACK_SP_ACCESS':
            if size == 0:
                if binrepr.verbose > 0: print '\tFunction does not appear to have a stack frame (1)\n'
                return
            offset = binrepr.ida.idc.GetSpd(ins.ea) + typ[1] + size + size_offset if size_offset is not None else 0
            if offset < 0:
                if binrepr.verbose > 0: print '\t*** Warning (%x): Function appears to be accessing above its stack frame, discarding instruction' % ins.ea
                continue
            # Do not filter out arg accesses here because those will need to be adjusted
            sp_accesses.append([ins, offset, typ[2]])
        elif typ[0] == 'STACK_BP_ACCESS':
            if size == 0:
                print 'aaa'
                if binrepr.verbose > 0: print '\tFunction does not appear to have a stack frame (2)\n'
                return
            if not bp_based:
                continue        # silently ignore bp access in sp frame
            if typ[1] > 0:
                continue        # this is one of the function's arguments
            bp_accesses.append([ins, typ[1] + size + bp_offset, typ[2]])
        else:
            print '\t*** CRITICAL: You forgot to update parse_function(), jerkface!\n'
    if len(alloc_ops) == 0:
        if binrepr.verbose > 0: print '\tFunction does not appear to have a stack frame (3)\n'
        return
    if bp_based:
        #arg_accesses = filter(lambda x: x[1] > 0, bp_accesses)
        addresses = set(map(lambda x: x[1], bp_accesses))
        use_accesses = [x for x in bp_accesses]
    
# Find the lowest sp-access that isn't an argument to the next function
# By starting at accesses to [esp] and stepping up a word at a time
# When it misses a step, that's when we're onto the stack vars
# So start adding elements into addresses and use_accesses

    wordsize = executable.word_size[binrepr.native_dtyp]
    sp_iter = iter(sorted(sp_accesses, key=lambda x: x[1]))
    last = -wordsize          # first one should be 0, so this is the one "before it"
    still_args = binrepr.is_convention_stack_args()
        # short-circuit this if the calling convention
        # doesn't pass arguments on the stack
    for sp_access in sp_iter:
        if still_args:
            if last != sp_access[1] and sp_access[1] - last != wordsize:
                still_args = False
            last = sp_access[1]
        if not still_args:
            if sp_access[1] > size:
                break                 # Don't count this or anything past it, it's args  
            addresses.add(sp_access[1])
            use_accesses.append(sp_access)

    if len(use_accesses) > 0:
        if binrepr.verbose > 0: print '\tFunction has a %s-based stack frame of %d bytes.\n\t%d access%s to %d address%s %s made.\n\tThere is %s deallocation.' % \
            ('bp' if bp_based else 'sp', size, 
            len(use_accesses), '' if len(use_accesses) == 1 else 'es',
            len(addresses), '' if len(addresses) == 1 else 'es',
            'is' if len(use_accesses) == 1 else 'are',
            'an automatic' if len(dealloc_ops) == 0 else 'a manual')

        if binrepr.verbose > 1:
            print 'Stack addresses:', sorted(addresses)
    else:
        if binrepr.verbose > 0: print '\tFunction has a %d-byte stack frame, but doesn\'t use it for local vars\n' % size
        return

    # MOVING ON
    # We now have all the addresses we care about
    # let's organize them into variables
    
    vars = VarList(binrepr, size)
    vars.add_vars(addresses)
    vars.add_accesses(use_accesses)
    vars.collapse()

    print



class VarList():
    def __init__(self, binrepr, stack_size):
        self.vars = []
        self.binrepr = binrepr
        self.stack_size = stack_size

    def add_vars(self, addrlist):
        for addr in sorted(addrlist):
            self.add_var(addr)

    def add_var(self, addr):
        assert addr < self.stack_size # we dropped the requirement that addr >= 0 because ARM IS A BUTT
        if len(self.vars) == 0:
            self.vars = [{"addr": addr, "size": self.stack_size - addr, "accesses": [], "flags": 0}]
        elif addr < self.vars[0]["addr"]:
            self.vars = [{"addr": addr, "size": self.vars[0]["addr"] - addr, "accesses": [], "flags": 0}] + self.vars
        elif addr > self.vars[-1]["addr"]:
            self.vars[-1]["size"] = addr - self.vars[-1]["addr"]
            self.vars.append({"addr": addr, "size": self.stack_size - addr, "accesses": [], "flags": 0})
        else:       # TODO: Optimize with binary search
            for i, item in enumerate(self.vars):
                if i == 0: continue
                if addr < item["addr"]:
                    self.vars[i-1]["size"] = addr - self.vars[i-1]["addr"]
                    self.vars = self.vars[:i] + [{"addr": addr, "size": item["addr"] - addr, "accesses": [], flags: 0}] + self.vars[i:]
                    break

    def add_accesses(self, accesslist):
        for access in accesslist:
            self.add_access(access)

    def add_access(self, access):  # access is a list [ins, addr, opn]
        var = self.get_var(access[1])   # it'll become [ins, offset, opn]
        if var is None:
            print '\t*** CRITICAL (%x): Access has not been documented??' % access[0].ea
            return
        access[1] = 0
        var["accesses"].append(access)
        newflags = self.binrepr.get_access_flags(access[0], access[2])
        if newflags == 1 and var["flags"] == 0:
            var["flags"] = 9
        else:
            var["flags"] |= newflags


    def get_var(self, addr): # TODO: Optimize with binary search
        for var in self.vars:
            if var["addr"] == addr:
                return var
        return None

    def collapse(self):
        i = 0               # old fashioned loop because we're removing items
        while i < len(self.vars) - 1:
            i += 1
            var = self.vars[i]
            if var["addr"] < 0:
                self.merge_down(i)
                i -= 1
            elif var["addr"] % executable.word_size[self.binrepr.native_dtyp] != 0:
                self.merge_up(i)
                i -= 1
            elif var["flags"] & 8:
                self.merge_up(i)
                i -= 1
            elif var["flags"] & 4:
                pass
            elif var["flags"] != 3:
                self.merge_up(i)
                i -= 1

    def merge_up(self, i):
        child = self.vars.pop(i)
        parent = self.vars[i-1]
        for access in child["accesses"]:
            access[1] += parent["size"] # adjust offset
            parent["accesses"].append(access)
        parent["size"] += child["size"]
        if self.binrepr.verbose > 1:
            print '\tMerged %d into %d' % (child["addr"], parent["addr"])

    def merge_down(self, i):
        child = self.vars.pop(i)
        parent = self.vars[i]
        for access in child["accesses"]:
            access[1] -= child["size"]
            parent["accesses"].append(access)
        if self.binrepr.verbose > 1:
            print '\tMerged %d down to %d' % (child["addr"], parent["addr"])

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
