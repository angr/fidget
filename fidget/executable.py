# functions that provide the interface for messing with
# binaries and stuff, via whatever tools.

import struct

from angr import Project
import pyvex

from .errors import FidgetUnsupportedError

import logging
l = logging.getLogger('fidget.executable')

#hopefully the only processors we should ever have to target
processors = ['X86', 'AMD64', 'ARM', 'PPC32', 'MIPS32', 'PPC64']

class Executable(object):
    def __init__(self, filename, debugangr=False):
        l.info("Loading %s", filename)
        self.verbose = 0
        self.filename = filename
        if debugangr:
            import ipdb; ipdb.set_trace()

        self.angr = Project(filename)
        self.native_word = self.angr.arch.bits
        self.cfg = self.angr.analyze('CFG').cfg
        self.funcman = self.cfg.function_manager
        if self.angr.arch.name not in processors:
            raise FidgetUnsupportedError("Unsupported archetecture " + self.angr.arch.name)
        self.processor = processors.index(self.angr.arch.name)

    def locate_physaddr(self, address):
        return self.angr.main_binary.in_which_segment(address)

    def relocate_to_physaddr(self, address):
        return self.angr.main_binary.addr_to_offset(address)

    def relocate_to_memaddr(self, address):
        return self.angr.main_binary.offset_to_addr(address)

    def make_irsb(self, byte_string, thumb=False):
        offset = 0
        addr = 0
        if thumb:
            addr += 1
            offset += 1
        return pyvex.IRSB(bytes=byte_string, arch=self.angr.arch.vex_arch, bytes_offset=offset, mem_addr=addr, endness=self.angr.arch.vex_endness)

    def resign_int(self, n, word_size=None):
        if word_size is None: word_size = self.native_word
        top = (1 << word_size) - 1
        if n > top:
            return None
        if n < top/2: # woo int division
            return int(n)
        return int(-((n ^ top) + 1))

    def unsign_int(self, n, word_size=None):
        if word_size is None: word_size = self.native_word
        if n < 0:
            n += 1 << word_size
        return int(n)

    def is_convention_stack_args(self):
        return self.processor == 0

    def pack_format(self, val, size):
        fmt = ('<' if self.is_little_endian() else '>') + {1: 'B', 2: 'H', 4: 'I', 8: 'Q'}[size]
        return struct.pack(fmt, val)

    def unpack_format(self, val, size):
        fmt = ('<' if self.is_little_endian() else '>') + {1: 'B', 2: 'H', 4: 'I', 8: 'Q'}[size]
        return struct.unpack(fmt, val)[0]

    def is_64_bit(self):
        return self.angr.arch.bits == 64

    def is_little_endian(self):
        return self.angr.arch.memory_endness == 'Iend_LE'

    def call_pushes_ret(self):
        return self.processor in (0, 1)

    def get_entry_point(self):
        return self.angr.entry

    def read_memory(self, addr, size):
        return ''.join(self.angr.main_binary.memory[addr + i] for i in xrange(size))
