# functions that provide the interface for messing with
# binaries and stuff, via whatever tools.

from elftools.elf.elffile import ELFFile
from elftools.elf.descriptions import describe_e_machine
from elftools.common import exceptions
import symexec
import struct

from angr import Project
from binary_data import BinaryData, BinaryDataConglomerate
from sym_tracking import BlockState, SmartExpression

#hopefully the only processors we should ever have to target
processors = ['i386', 'x86_64', 'arm', 'ppc', 'mips']

word_size = {0: 1, 1: 2, 2: 4, 7: 8}
dtyp_by_width = {8: 0, 16: 1, 32: 2, 64: 7}

# Executable
# not actually a class! fakes being a class because it
# basically just looks at the filetype, determines what kind
# of binary it is (ELF, PE, w/e) and switches control to an
# appropriate class, all of which inherit from _Executable,
# the actual class

def Executable(filename):
    return ElfExecutable(filename) # ...

class _Executable():
    def find_tags(self, funcaddr):
        for blockaddr in sorted(self.funcman.functions[funcaddr].basic_blocks):
            blockstate = BlockState(self)
            mark = None
            pathindex = 0
            block = self.angr.block(blockaddr)
            for stmt in block.statements():
                if stmt.tag == 'Ist_Imark':
                    mark = stmt
                    pathindex = 0
                    continue

                elif stmt.tag == 'Ist_NoOp':
                    continue

                elif stmt.tag in ('Ist_WrTmp', 'Ist_Store', 'Ist_Put'):
                    pathindex += 1

                else:
                    stmt.pp()
                    raise Exception("Unknown vex instruction???")

                this_expression = SmartExpression(blockstate, stmt.data, mark, [pathindex, 'data'])
                blockstate.assign(stmt, this_expression)

            blockstate.end()
            for tag in blockstate.tags:
                yield tag

    def resign_int(self, n, word_size=None):
        if word_size is None: word_size = self.native_word
        top = (1 << word_size) - 1
        if (n > top):
            return None
        if (n < top/2): # woo int division
            return int(n)
        return int(-((n ^ top) + 1))

    def is_convention_stack_args(self):
        return self.processor == 0

class ElfExecutable(_Executable):
    def __init__(self, filename):
        self.verbose = 0
        self.filename = filename
        try:
            self.filestream = open(filename)
            self.elfreader = ELFFile(self.filestream)
            self.error = False
        except exceptions.ELFError:
            self.error = True
            return
        self.native_dtyp = 7 if self.is_64_bit() else 2
        self.native_word = 64 if self.is_64_bit() else 32
        elfproc = self.elfreader.header.e_machine
        if elfproc == 'EM_386':
            self.processor = 0
        elif elfproc == 'EM_X86_64':
            self.processor = 1
        elif elfproc == 'EM_ARM':
            self.processor = 2
        else:
            raise ValueError('Unsupported processor type: %s' % elfproc)

        myproc = __import__('platform').machine()
        try:
            myproc_id = platforms.index(myproc)
            self.nonnative = myproc_id != self.processor
        except:
            self.nonnative = True
        if self.nonnative:
            pass #print "Warning: analysing binary for non-native platform"
        self.angr = Project(filename, use_sim_procedures=True)
        self.cfg = self.angr.construct_cfg()
        self.funcman = self.angr.get_function_manager()

    def is_64_bit(self):
        return self.elfreader.header.e_ident.EI_CLASS == 'ELFCLASS64'

    def relocate_to_physaddr(self, address, section):
        section = self.elfreader.get_section_by_name(section)
        return address - section.header.sh_addr + section.header.sh_offset


