#!/usr/bin/python

import sys, os
from fidget import patch

def addopt(options, option, argv):
    if option in ('v', 'verbose'):
        options["verbose"] += 1
    elif option in ('q', 'quiet'):
        options["verbose"] -= 1
    elif option in ('h', 'help'):
        usage()
        os.exit(0)
    elif option in ('safe',):
        options['safe'] = True
    elif option in ('o', 'output'):
        options['outfiles'].append(next(argv))
    elif option in ('w',):
        options['whitelist'].append(next(argv))
    elif option in ('b',):
        options['blacklist'].append(next(argv))
    elif option in ('debug',):
        options['debug'] = True
    elif option in ('debugangr',):
        options['debugangr'] = True
    else:
        print 'Bad argument: %s' % option
        sys.exit(1)

def usage():
    print """Fidget: The Binary Tweaker

Usage: python -m fidget [option | filename] [option | filename] ...

Options:
    -h, --help              View this usage information and exit
    -v, --verbose           More output
    -q, --quiet             Less output
    -o, --output [file]     Output patched binary to file (default <input>.out)
    -w [function]           Whitelist a function name
    -b [function]           Blacklist a function name
    --safe                  Make conservative modifications
    --debug                 Pop an ipdb shell at the main function
    --debugangr             Pop an ipdb shell right before calling into angr

Files:
    Each argument that is not part of an option is treated as an input file.
    There must be at least one input file, and if there are multiple inputs,
    they will be processed in the order given. If there are multiple outputs,
    there must not be more output files than inputs. If there are fewer 
    outputs than inputs, the <n> outputs will be matched up with the first <n> 
    inputs, and the rest of the inputs will be outputted as <input>.out.

Verbosity:
    The default verbosity level is 1.
    Each verbose flag increases it by 1, each quiet flag decreases it by 1.

    Level 0 prints out only the file and function names
    Level 1 prints out the above and a summary of each function and some warnings
    Level 2 prints out the above and some debug output
    Level 3 prints out the above and each IR instruction as it is parsed
    
    The verbosity settings are also used to determine how much of the logs from
    angr, simuvex, claripy, etc are shown.

Whitelisting/Blacklisting:
    There is no actual function name lookup, so all function names are of the
    form "sub_xxxx", where xxxx is the hexidecimal (lowercase) address of the
    function.

    The entry point will never be patched, so there is no need to blacklist it,
    with the exception of some MIPS binaries, which have a stub for an entry 
    point which calls the real _start function. You'll want to blacklist that.

    You cannot use both a whitelist and a blacklist, obviously.

    Protip: instead of "-w sub_a -w sub_b -w sub_c" you can
    use "-www sub_a sub_b sub_c" for the same effect.

Safety:
    Fidget works by rearranging stack variables, which can get sketchy
    because even identifying where the variables on the stack are is a 
    difficult problem to begin with. The danger arises that fidget might 
    seperate, say, an access to my_arr[4] from the rest of my_arr because 
    it thinks it's a seperate variable.

    The --safe flag will counteract this by keeping all accesses in the 
    same place relative to eachother. It will still attempt to move them 
    all up relative to the stack base, preventing buffer overflows 
    messing with eip, but will be ineffective against overflows that merely 
    modify or leak other stack variables.
""" % sys.argv[0]

def main():
    if len(sys.argv) < 2:
        usage()
    else:
        options = {"verbose": 1, "safe": False, "infiles": [], "outfiles": [], "whitelist": [], "blacklist": [], "debug": False, 'debugangr': False}
        argv = iter(sys.argv)
        next(argv)
        for arg in argv:
            if arg.startswith('--'):
                addopt(options, arg[2:], argv)
            elif arg.startswith('-'):
                for flag in arg[1:]: addopt(options, flag, argv)
            else:
                options["infiles"].append(arg)
        if len(options['whitelist']) > 0 and len(options['blacklist']) > 0:
            print 'Cannot use both a whitlist and a blacklist!'
            sys.exit(1)
        if len(options["infiles"]) == 0:
            print 'You must specify a file to operate on!'
            sys.exit(1)
        if len(options["outfiles"]) > len(options["infiles"]):
            print 'More output files specified than input files!'
            sys.exit(1)
        outfiles = options['outfiles']
        infiles = options['infiles']
        del options['outfiles']
        del options['infiles']
        import logging
        logging.basicConfig(level=10*(5-options['verbose']))
        outfiles += [None] * (len(infiles) - len(outfiles))
        for infile, outfile in zip(infiles, outfiles):
            patch(infile, outfile, **options)

if __name__ == '__main__':
    main()
