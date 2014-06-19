#!/usr/bin/python

import sys
from executable import Executable

def main(filename):
    binrepr = Executable(filename)
    textsec = binrepr.get_section_by_name('.text')
    textrange = (textsec.header.sh_addr, textsec.header.sh_addr + textsec.header.sh_size)
    textfuncs = list(binrepr.ida.idautils.Functions(*textrange))

    # this is as far as I go for today. Pretty good for a day 1!

    print 'There are %d functions in the .text section.' % len(textfuncs)
    try:
        binrepr.ida.close()
    except:
        pass    # I added a close() function to my local version of idalink so it'll close the databases properly


if __name__ == '__main__':
    if len(sys.argv) < 2:
        usage()
    else:
        main(sys.argv[1])
