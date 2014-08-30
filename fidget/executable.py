# functions that provide the interface for messing with
# binaries and stuff, via whatever tools.

import pyvex
import struct

from angr import Project, AngrMemoryError
from binary_data import BinaryData, BinaryDataConglomerate
from sym_tracking import BlockState, SmartExpression
import vexutils

#hopefully the only processors we should ever have to target
processors = ['X86', 'AMD64', 'ARM', 'PPC32', 'MIPS32', 'PPC64']

word_size = {0: 1, 1: 2, 2: 4, 7: 8}
dtyp_by_width = {8: 0, 16: 1, 32: 2, 64: 7}

# Executable
# not actually a class! fakes being a class because it
# basically just looks at the filetype, determines what kind
# of binary it is (ELF, PE, w/e) and switches control to an
# appropriate class, all of which inherit from _Executable,
# the actual class

def Executable(*args):
    return ElfExecutable(*args) # ...

class _Executable:
    def find_tags(self, funcaddr):
        queue = [BlockState(self, funcaddr)]
        cache = set()
        while len(queue) > 0:
            blockstate = queue.pop(0)
            if blockstate.addr in cache:
                continue
            mark = None
            pathindex = 0
            block = self.angr.block(blockstate.addr)
            for stmt in block.statements():
                if stmt.tag == 'Ist_IMark':
                    mark = stmt
                    cache.add(mark.addr)
                    pathindex = -1
                    if self.verbose > 2:
                        sys.stdout.flush()
                        stmt.pp()
                        print
                    continue

                pathindex += 1
                if self.verbose > 2:
                    import sys;
                    sys.stdout.write('%.3d  ' % pathindex)
                    stmt.pp()
                    print
                if stmt.tag in ('Ist_NoOp', 'Ist_AbiHint'):
                    pass

                elif stmt.tag == 'Ist_Exit':
                    if stmt.jumpkind == 'Ijk_Boring':
                        dest = SmartExpression(blockstate, stmt.dst, mark, [pathindex, 'dst'])
                        try:
                            queue.append(blockstate.copy(dest.cleanval))
                        except AngrMemoryError:
                            pass
                    else:
                        print '*** WARNING (%x): Not sure what to do with jumpkind "%s"' % (mark.addr, stmt.jumpkind)

                elif stmt.tag in ('Ist_WrTmp', 'Ist_Store', 'Ist_Put'):
                    this_expression = SmartExpression(blockstate, stmt.data, mark, [pathindex, 'data'])
                    blockstate.assign(stmt, this_expression, pathindex)

                elif stmt.tag == 'Ist_LoadG':
                    # Conditional loads. Lots of bullshit.
                    this_expression = SmartExpression(blockstate, stmt.addr, mark, [pathindex, 'addr'])
                    blockstate.access(this_expression, 1)
                    tmp_size = vexutils.extract_int(block.tyenv.typeOf(stmt.dst))
                    this_expression.dirtyval = vexutils.ZExtTo(tmp_size, this_expression.dirtyval)
                    blockstate.temps[stmt.dst] = this_expression
                    SmartExpression(blockstate, stmt.guard, mark, [pathindex, 'guard'])
                    SmartExpression(blockstate, stmt.alt, mark, [pathindex, 'alt'])

                elif stmt.tag == 'Ist_StoreG':
                    # Conditional store
                    addr_expr = SmartExpression(blockstate, stmt.addr, mark, [pathindex, 'addr'])
                    value_expr = SmartExpression(blockstate, stmt.data, mark, [pathindex, 'data'])
                    blockstate.access(addr_expr, 2)
                    if addr_expr.stack_addr:
                        blockstate.stack_cache[addr_expr.cleanval] = value_expr
                    if value_expr.stack_addr:
                        blockstate.access(value_expr, 4)

                    SmartExpression(blockstate, stmt.guard, mark, [pathindex, 'guard'])


                else:
                    stmt.pp()
                    import pdb; pdb.set_trace()
                    raise Exception("Unknown vex instruction???")

            # The last argument is wrong but I dont't think it matters
            if block.jumpkind == 'Ijk_Boring':
                dest = SmartExpression(blockstate, block.next, mark, [pathindex, 'next'])
                if dest.cleanval not in self.angr.sim_procedures:
                    try:
                        queue.append(blockstate.copy(dest.cleanval))
                    except AngrMemoryError:
                        pass
            elif block.jumpkind in ('Ijk_Ret', 'Ijk_NoDecode'):
                pass
            elif block.jumpkind == 'Ijk_Call':
                if self.call_pushes_ret():
                    # Pop the return address off the stack and keep going
                    stack = blockstate.get_reg(self.angr.arch.sp_offset)
                    popped = stack.deps[0] if stack.deps[0].stack_addr else stack.deps[1]
                    blockstate.regs[self.angr.arch.sp_offset] = popped
                    # Discard the last two tags -- they'll be an alloc and an access for the call (the push and the retaddr)
                    blockstate.tags = blockstate.tags[:-2]

                for simirsb, jumpkind in self.cfg.get_successors_and_jumpkind(self.cfg.get_any_irsb(blockstate.addr), False):
                    if jumpkind != 'Ijk_FakeRet':
                        continue
                    try:
                        queue.append(blockstate.copy(simirsb.addr))
                    except AngrMemoryError:
                        pass
            else:
                raise Exception('*** CRITICAL (%x): Can\'t proceed from unknown jumpkind "%s"' % (mark.addr, block.jumpkind))

            blockstate.end()
            for tag in blockstate.tags:
                yield tag

    def make_irsb(self, bytes, thumb=False):
        offset = 0
        addr = 0
        if thumb:
            addr += 1
            offset += 1
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

class ElfExecutable(_Executable):
    def __init__(self, filename, debugangr=False):
        self.verbose = 0
        self.error = False
        self.filename = filename
        if debugangr:
            import ipdb; ipdb.set_trace()
        try:
            self.angr = Project(filename, use_sim_procedures=True,
                    exclude_sim_procedure=lambda x: x not in ('__libc_start_main','pthread_create'))
            self.cfg = self.angr.construct_cfg()
            self.funcman = self.cfg.get_function_manager()
            self.native_word = self.angr.arch.bits
            try:
                self.processor = processors.index(self.angr.arch.name)
            except:
                raise ValueError('Unsupported Architecture: %s' % self.angr.arch.name)
        except:
            self.error = True
            return

    def locate_physaddr(self, address):
        return self.angr.main_binary.in_which_segment(address)

    def relocate_to_physaddr(self, address):
        return self.angr.main_binary.addr_to_offset(address)
