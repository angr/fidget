#!/usr/bin/python

import sys
import executable

def main(filename):
    binrepr = executable.Executable(filename)
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
    alloc_op = None   # the instruction that performs a stack allocation
    dealloc_ops = []  # the instructions that perform a stack deallocation
    bp_accesses = []  # the stack accesses using the base pointer
    sp_accesses = []  # the stack accesses using the stack pointer
    use_accesses = [] # the accesses that actually constitute local vars
    addresses = set() # the stack offsets of all the accessed local vars
    for ins in binrepr.iterate_instructions(funcaddr):
       # if funcaddr == 0x8049120:
       #     binrepr.verbose = True
        typ = binrepr.identify_instr(ins)
        if typ[0] == '': continue
        elif typ[0] == 'STACK_TYPE_BP':
            bp_based = True
        elif typ[0] == 'STACK_FRAME_ALLOC':
            alloc_op = ins
            size = typ[1]
            size_offset = -binrepr.ida.idc.GetSpd(ins.ea)
        elif typ[0] == 'STACK_FRAME_DEALLOC':
            dealloc_ops.append(ins)
            if typ[1] != size:
                print '\t*** CRITICAL (%x): Stack dealloc does not match alloc??' % ins.ea
                return
        elif typ[0] == 'STACK_SP_ACCESS':
            if size == 0:
                print '\tFunction does not appear to have a stack frame.'
                return
            offset = binrepr.ida.idc.GetSpd(ins.ea) + typ[1] + size + size_offset if size_offset is not None else 0
            if offset < 0:
                print '\t*** Warning (%x): Function appears to be accessing above its stack frame, discarding instruction' % ins.ea
                continue
            # Do not filter out arg accesses here because those will need to be adjusted
            sp_accesses.append((ins, offset))
        elif typ[0] == 'STACK_BP_ACCESS':
            if size == 0:
                print '\tFunction does not appear to have a stack frame.'
                return
            if not bp_based:
                continue        # silently ignore bp access in sp frame
            if typ[1] > 0:
                continue        # this is one of the function's arguments
            bp_accesses.append((ins, typ[1] + size))
        else:
            print '\t*** CRITICAL: You forgot to update parse_function(), jerkface!'
    if alloc_op is None:
        print '\tFunction does not appear to have a stack frame.'
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
    still_args = True
    for sp_access in sp_iter:
        #print 'Looking at %x accessing %d' % (sp_access[0].ea, sp_access[1])
        if still_args:
            #print 'last:',last
            if last != sp_access[1] and sp_access[1] - last != wordsize:
                still_args = False
            last = sp_access[1]
        if not still_args:
            if sp_access[1] > size:
                break                 # Don't count this or anything past it, it's args  
            #print 'Added to list'
            addresses.add(sp_access[1])
            use_accesses.append(sp_access)

    print '\tFunction has a %s-based stack frame of %d bytes.\n\t%d access%s to %d different address%s %s made.\n\tThere is %s deallocation.' % \
        ('bp' if bp_based else 'sp', size, 
        len(use_accesses), '' if len(use_accesses) == 1 else 'es',
        len(addresses), '' if len(addresses) == 1 else 'es',
        'is' if len(use_accesses) == 1 else 'are',
        'an automatic' if len(dealloc_ops) == 0 else 'a manual')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        usage()
    else:
        main(sys.argv[1])
