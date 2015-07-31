# functions that provide the interface for messing with
# binaries and stuff, via whatever tools.

import superstruct as struct
import pickle

from angr import Project
import pyvex

import logging
l = logging.getLogger('fidget.executable')

class Executable(object):
    def __init__(self, filename, cache=False, cfg_options=None, debugangr=False):
        l.info("Loading %s", filename)
        self.verbose = 0
        self.filename = filename
        if debugangr:
            import ipdb; ipdb.set_trace()

        cfgname = filename + '.fcfg'
        if cfg_options is None:
            cfg_options = {}
        try:
            if not cache: raise IOError('fuck off')
            fh = open(cfgname, 'rb')
            self.angr, self.cfg = pickle.load(fh)
            fh.close()
        except (IOError, OSError, pickle.UnpicklingError):
            self.angr = Project(filename, load_options={'auto_load_libs': False})
            self.angr.arch.cache_irsb = False
            self.cfg = self.angr.analyses.CFG(**cfg_options) # pylint: disable=no-member
            try:
                fh = open(cfgname, 'wb')
                pickle.dump((self.angr, self.cfg), fh)
                fh.close()
            except (IOError, OSError, pickle.PicklingError):
                l.exception('Error pickling CFG')

        self.funcman = self.cfg.function_manager

    def relocate_to_physaddr(self, address):
        return self.angr.loader.main_bin.addr_to_offset(address)

    def make_irsb(self, byte_string, thumb=False):
        offset = 0
        addr = 0
        if thumb:
            addr += 1
            offset += 1
        bb = pyvex.IRSB(bytes=byte_string, arch=self.angr.arch, bytes_offset=offset, mem_addr=addr)
        return self.angr.factory._lifter._post_process(bb)

    def pack_format(self, val, size):
        fmt = ('<' if self.is_little_endian() else '>') + {1: 'B', 2: 'H', 4: 'I', 8: 'Q', 16: 'X', 32: 'Y', 64: 'Z'}[size]
        return struct.pack(fmt, val)

    def unpack_format(self, val, size):
        fmt = ('<' if self.is_little_endian() else '>') + {1: 'B', 2: 'H', 4: 'I', 8: 'Q', 16: 'X', 32: 'Y', 64: 'Z'}[size]
        return struct.unpack(fmt, val)[0]

    def is_little_endian(self):
        return self.angr.arch.memory_endness == 'Iend_LE'

    def read_memory(self, addr, size):
        return ''.join(self.angr.loader.memory[addr + i] for i in xrange(size))
