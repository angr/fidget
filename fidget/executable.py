# functions that provide the interface for messing with
# binaries and stuff, via whatever tools.

import struct

from angr import Project
import pyvex

#hopefully the only processors we should ever have to target
processors = ['X86', 'AMD64', 'ARM', 'PPC32', 'MIPS32', 'PPC64']

class Executable(object):
    def __init__(self, filename, debugangr=False):
        self.verbose = 0
        self.irsb_calls = 0
        self.error = False
        self.error_cfg = False
        self.error_loading = False
        self.error_processor = False
        self.filename = filename
        if debugangr:
            import ipdb; ipdb.set_trace()
        try:
            self.angr = Project(filename, use_sim_procedures=True,
                    exclude_sim_procedure=lambda x: x not in ('__libc_start_main','pthread_create'))
            self.native_word = self.angr.arch.bits
        except Exception as e:
            print '****** Error loading binary:'
            print e
            self.error = True
            self.error_loading = True
            return
        try:
            self.cfg = self.angr.construct_cfg()
            self.funcman = self.cfg.get_function_manager()
        except Exception as e:
            print '****** Error generating CFG:'
            print e
            self.error = True
            self.error_cfg = True
            return
        try:
            self.processor = processors.index(self.angr.arch.name)
        except:
            print '****** Error: Unsupported processor:', self.angr.arch.name
            self.error = True
            self.error_processor = True
            return

    def locate_physaddr(self, address):
        return self.angr.main_binary.in_which_segment(address)

    def relocate_to_physaddr(self, address):
        return self.angr.main_binary.addr_to_offset(address)

    def relocate_to_memaddr(self, address):
        return self.angr.main_binary.offset_to_addr(address)

    def make_irsb(self, bytes, thumb=False):
        offset = 0
        addr = 0
        if thumb:
            addr += 1
            offset += 1
        self.irsb_calls += 1
        return pyvex.IRSB(bytes=bytes, arch=self.angr.arch.vex_arch, bytes_offset=offset, mem_addr=addr, endness=self.angr.arch.vex_endness)

    def resign_int(self, n, word_size=None):
        if word_size is None: word_size = self.native_word
        top = (1 << word_size) - 1
        if (n > top):
            return None
        if (n < top/2): # woo int division
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
