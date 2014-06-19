# functions that provide the interface for messing with
# binaries and stuff, via whatever tools.

from elftools.elf.elffile import ELFFile
import idalink

# Executable
# not actually a class! fakes being a class because it
# basically just looks at the filetype, determines what kind
# of binary it is (ELF, PE, w/e) and switches control to an
# appropriate class, all of which inherit from _Executable,
# the actual class

def Executable(filename):
    return ElfExecutable(filename) # ...

class _Executable():
    pass

class ElfExecutable(_Executable):
    def __init__(self, filename):
        self.filename = filename
        self.elfreader = ELFFile(open(filename))
        self.ida = idalink.IDALink(filename, "idal64" if self.is_64_bit() else "idal")
        self.get_section_by_name = self.elfreader.get_section_by_name

    def is_64_bit(self):
        return self.elfreader.header.e_ident.EI_CLASS == 'ELFCLASS64'
