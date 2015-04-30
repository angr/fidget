# functions that provide the interface for messing with
# binaries and stuff, via whatever tools.

import struct

from angr import Project
import pyvex

from .errors import FidgetUnsupportedError

import logging
l = logging.getLogger('fidget.executable')

#hopefully the only processors we should ever have to target
processors = ['X86', 'AMD64', 'ARMEL', 'ARMHF', 'PPC32', 'MIPS32', 'PPC64']

class Executable(object):
    def __init__(self, filename, debugangr=False):
        l.info("Loading %s", filename)
        self.verbose = 0
        self.filename = filename
        if debugangr:
            import ipdb; ipdb.set_trace()

        self.angr = Project(filename, load_options={'auto_load_libs': False})
        self.angr.arch.cache_irsb = False
        self.native_word = self.angr.arch.bits
        self.cfg = self.angr.analyses.CFG() # pylint: disable=no-member
        self.funcman = self.cfg.function_manager
        if self.angr.arch.name not in processors:
            raise FidgetUnsupportedError("Unsupported architecture " + self.angr.arch.name)

    def locate_physaddr(self, address):
        return self.angr.main_binary.in_which_segment(address)

    def relocate_to_physaddr(self, address):
        return self.angr.main_binary.addr_to_offset(address)

    def make_irsb(self, byte_string, thumb=False):
        offset = 0
        addr = 0
        if thumb:
            addr += 1
            offset += 1
        bb = pyvex.IRSB(bytes=byte_string, arch=self.angr.arch, bytes_offset=offset, mem_addr=addr)
        return self.angr.vexer._post_process(bb)

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

    def pack_format(self, val, size):
        fmt = ('<' if self.is_little_endian() else '>') + {1: 'B', 2: 'H', 4: 'I', 8: 'Q'}[size]
        return struct.pack(fmt, val)

    def unpack_format(self, val, size):
        fmt = ('<' if self.is_little_endian() else '>') + {1: 'B', 2: 'H', 4: 'I', 8: 'Q'}[size]
        return struct.unpack(fmt, val)[0]

    def is_little_endian(self):
        return self.angr.arch.memory_endness == 'Iend_LE'

    def read_memory(self, addr, size):
        return ''.join(self.angr.ld.memory[addr + i] for i in xrange(size))
