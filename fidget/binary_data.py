import struct
import claripy

from . import vexutils
from .errors import FidgetError, FidgetUnsupportedError

import logging
l = logging.getLogger('fidget.binary_data')

# BinaryData
# The fundemental link between binary data and things that know what binary data should be
# Knows how to tell if an instruction contains a particular value
# And if it does, how to change it
# And also how to apply the constraints for each value, i.e. range

# Further down is BinaryDataConglomerate
# Which is a simple way to pass around values that actually depend
# on multiple numbers in the binary

class BinaryData():
    def __init__(self, mark, path, cleanval, dirtyval, binrepr, symrepr):
        if not isinstance(cleanval, (int, long)):
            raise ValueError('cleanval must be an int or long!')
        self.mark = mark
        self.path = path
        self.value = cleanval
        self.symval = dirtyval
        self.binrepr = binrepr
        self.symrepr = symrepr

        self.inslen = mark.len
        self.memaddr = mark.addr
        self.physaddr = binrepr.relocate_to_physaddr(self.memaddr)

        self.armthumb = self.binrepr.cfg.is_thumb_addr(self.memaddr)
        self.insbytes = self.binrepr.read_memory(self.memaddr, self.inslen)
        self.insvex = self.binrepr.make_irsb(self.insbytes, self.armthumb)

        self.already_patched = False
        self.modconstraint = 1
        self.constraints = []

        self.bit_length = None
        self.bit_shift = None
        self.bit_offset = None
        self.armins = None
        self.armop = None
        self.symval8 = None
        try:
            self.search_value()         # This one is the biggie
        except BinaryData.ValueNotFoundError:
            self.constraints = [dirtyval == cleanval]
            self.constant = True
            return
        self.constant = False

        # allow search_value to set the constraints if it really wants to
        if len(self.constraints) == 0:
            rng = self.get_range()
            if rng[0] != -(1 << (self.symval.size()-1)):
                self.constraints.append(self.symval >= rng[0])
            if rng[1] !=  (1 << (self.symval.size()-1)):
                self.constraints.append(self.symval <= rng[1] - 1)
            if self.modconstraint != 1:
                self.constraints.append(self.symval % self.modconstraint == 0)

    def apply_constraints(self, symrepr):
        if list(self.symval.variables)[0] in symrepr.variables:
            return
        for constraint in self.constraints:
            symrepr.add(constraint)

    class ValueNotFoundError(FidgetError):
        pass

    class FuzzingAssertionFailure(FidgetError):
        pass

    def search_value(self):
        if self.binrepr.processor == 2:
            self.bit_length = 32
            if len(self.insbytes) == 4:
                self.armins = struct.unpack('I', self.insbytes)[0]
            elif len(self.insbytes) == 2:
                self.armins = struct.unpack('H', self.insbytes)[0]
            else:
                raise FidgetError("Holy crap ARM what???")
            if not self.armthumb and self.armins & 0x0C000000 == 0x04000000:
                # LDR
                self.armop = 1
                thoughtval = self.armins & 0xFFF
                thoughtval *= 1 if self.armins & 0x00800000 else -1
                if thoughtval != self.value:
                    raise BinaryData.ValueNotFoundError
            elif not self.armthumb and self.armins & 0x0E000000 == 0x02000000:
                # Data processing w/ immediate
                self.armop = 2
                shiftval = ((self.armins & 0xF00) >> 7)
                thoughtval = self.armins & 0xFF
                thoughtval = (thoughtval >> shiftval) | (thoughtval << (32 - shiftval))
                thoughtval &= 0xFFFFFFFF
                if thoughtval != self.value:
                    raise BinaryData.ValueNotFoundError
                self.bit_shift = self.symrepr._claripy.BitVec(hex(self.memaddr)[2:] + '_shift', 4)
                #self.symval = self.binrepr.claripy.BitVec(hex(self.memaddr)[2:] + '_imm', 32)
                self.symval8 = self.symrepr._claripy.BitVec(hex(self.memaddr)[2:] + '_imm8', 8)
                self.constraints.append(self.symval == self.symrepr._claripy.RotateRight(self.symval8.zero_extend(32-8), self.bit_shift.zero_extend(32-4)*2))
            elif not self.armthumb and self.armins & 0x0E400090 == 0x00400090:
                # LDRH
                self.armop = 3
                thoughtval = (self.armins & 0xF) | ((self.armins & 0xF00) >> 4)
                thoughtval *= 1 if self.armins & 0x00800000 else -1
                if thoughtval != self.value:
                    raise BinaryData.ValueNotFoundError
            elif not self.armthumb and self.armins & 0x0E000000 == 0x0C000000:
                # Coprocessor data transfer
                # i.e. FLD/FST
                self.armop = 4
                thoughtval = self.armins & 0xFF
                thoughtval *= 4 if self.armins & 0x00800000 else -4
                if thoughtval != self.value:
                    raise BinaryData.ValueNotFoundError
                self.modconstraint = 4
            elif self.armthumb and self.armins & 0xF000 in (0x9000, 0xA000):
                # SP-relative LDR/STR, also SP-addiition
                self.armop = 5
                thoughtval = self.armins & 0xFF
                thoughtval *= 4
                if thoughtval != self.value:
                    raise BinaryData.ValueNotFoundError
                self.modconstraint = 4
            elif self.armthumb and self.armins & 0xFF00 == 0xB000:
                # Add/sub offset to SP
                # I'm gonna cheat here because I'm worried about how IDA might interpret... various things
                # TODO: Is the cheating still necessary w/o ida?
                self.armop = 6
                thoughtval = self.armins & 0x7F
                thoughtval *= 4
                if thoughtval != self.value:
                    raise BinaryData.ValueNotFoundError
                self.modconstraint = 4
            elif self.armthumb and self.armins & 0x0000FFE0 == 0x0000E840:
                # Thumb32 - LDREX/STREX ...
                self.armop = 7
                thoughtval = (self.armins & 0x00FF0000) >> 16
                thoughtval *= 4
                if thoughtval != self.value:
                    raise BinaryData.ValueNotFoundError
                self.modconstraint = 4
            elif self.armthumb and self.armins & 0x0000FE40 == 0x0000E840:
                # Thumb32 - LDRD/STRD
                self.armop = 8
                thoughtval = (self.armins & 0x00FF0000) >> 16
                thoughtval *= 4 if self.armins & 0x00000080 else -4
                if thoughtval != self.value:
                    raise BinaryData.ValueNotFoundError
                self.modconstraint = 4
            elif self.armthumb and self.armins & 0x0800FE80 == 0x0800F800 and self.armins & 0x05000000 != 0:
                # Thumb32 - something something LDR/STR
                self.armop = 9
                thoughtval = (self.armins & 0x00FF0000) >> 16
                if self.armins & 0x00000100:
                    thoughtval = self.binrepr.resign_int(thoughtval, 8)
                if self.armins & 0x02000000 == 0:
                    thoughtval *= -1
                if thoughtval != self.value:
                    raise BinaryData.ValueNotFoundError
            elif self.armthumb and self.armins & 0x0000FE80 == 0x0000F880:
                # Thumb32 - LDR/STR with 12-bit imm
                self.armop = 10
                thoughtval = (self.armins & 0x0FFF0000) >> 16
                if self.armins & 0x00000100:
                    thoughtval = self.binrepr.resign_int(thoughtval, 12)
                if thoughtval != self.value:
                    raise BinaryData.ValueNotFoundError
            elif self.armthumb and self.armins & 0x8000FA00 == 0x0000F000:
                # Thumb32 - Data processing w/ modified 12 bit imm a.k.a EVIL
                if self.armins & 0x70000400:
                    # stupid cases-- do not touch
                    self.armop = 12
                    #self.symval = self.binrepr.claripy.BitVec(hex(self.memaddr)[2:] + '_' + str(self.opn) + '_nope', self.bit_length)
                    self.constraints.append(self.symval == self.value)
                else:
                    self.armop = 11
                    thoughtval = (self.armins & 0x00FF0000) >> 16
                    if thoughtval != self.value:
                        raise BinaryData.ValueNotFoundError
            elif self.armthumb and self.armins & 0xFC00 == 0x1C00:
                # Thumb - ADD/SUB
                self.armop = 13
                thoughtval = (self.armins & 0x01C0) >> 6
                if thoughtval != self.value:
                    raise BinaryData.ValueNotFoundError
            elif self.armthumb and self.armins & 0x0000EE00 == 0x0000EC00:
                # Thumb32 - Coprocessor stuff
                self.armop = 14
                thoughtval = (self.armins & 0x00FF0000) >> 16
                thoughtval *= 4 if self.armins & 0x00000080 else -4
                if thoughtval != self.value:
                    raise BinaryData.ValueNotFoundError
                self.modconstraint = 4
            elif self.armthumb and self.armins & 0x8000FB40 == 0x0000F200:
                # Thumb32 - ADD/SUB plain 12 bit imm
                self.armop = 15
                thoughtval = (self.armins & 0x00FF0000) >> 16
                thoughtval |= (self.armins & 0x70000000) >> 20
                thoughtval |= (self.armins & 0x00000400) << 1
                if thoughtval != self.value:
                    raise BinaryData.ValueNotFoundError
            else:
                raise BinaryData.ValueNotFoundError
            if not self.sanity_check():
                raise BinaryData.ValueNotFoundError
        else:
            self.armop = 0
            found = False
            for word_size in (64, 32, 16, 8):
                self.bit_length = word_size
                for byte_offset in xrange(len(self.insbytes)):
                    self.modconstraint = 1
                    result = self.extract_bit_value(byte_offset*8, word_size)
                    if result is None: continue
                    if self.binrepr.is_little_endian():
                        result = self.endian_reverse(result, word_size/8)
                    # On PPC64, the lowest two bits of immediate values are used for other things
                    # Mask those out
                    if self.binrepr.processor == 5:
                        result = result & ~3
                        self.modconstraint = 4
                    result = self.binrepr.resign_int(result, word_size)
                    if result != self.value: continue
                    self.bit_offset = byte_offset * 8
                    if self.sanity_check():
                        found = True
                        break
                if found:
                    break
            if not found:
                raise BinaryData.ValueNotFoundError

    def sanity_check(self):
        # Prerequisite
        m = self.path[:]
        basic = vexutils.get_from_path(vexutils.get_stmt_num(self.insvex, m[0]), m[1:])
        if basic is None:
            raise BinaryData.FuzzingAssertionFailure("Can't follow given path!")
        m[-1] = 'type'
        size = vexutils.get_from_path(vexutils.get_stmt_num(self.insvex, m[0]), m[1:])
        size = vexutils.extract_int(size)
        if self.binrepr.resign_int(basic, size) != self.value:
            raise BinaryData.FuzzingAssertionFailure("Can't extract known value from path!")
        # Get challengers
        tog = self.get_range()

        # Round 1
        newblock = self.binrepr.make_irsb(self.get_patched_instruction(tog[0]), self.armthumb)
        i = None
        for oldstmt, newstmt in zip(self.insvex.statements, newblock.statements):
            if i == self.path[0]:
                if not vexutils.equals_except(oldstmt, newstmt, self.path[1:], self.binrepr.unsign_int(tog[0], size)):
                    return False
            # Vex will sometimes read from registers then never use them
            # This messes stuff up, so don't check equality for temp-writes
            # that are never used.
            elif oldstmt.tag == 'Ist_WrTmp' and newstmt.tag == 'Ist_WrTmp' and not vexutils.is_tmp_used(self.insvex, oldstmt.tmp):
                pass
            elif not vexutils.equals(oldstmt, newstmt):
                return False

            if oldstmt.tag == 'Ist_IMark':
                i = 0
            elif i is not None:
                i += 1

        # Round 2
        newblock = self.binrepr.make_irsb(self.get_patched_instruction(tog[1]-1), self.armthumb)
        i = None
        for oldstmt, newstmt in zip(self.insvex.statements, newblock.statements):
            if i == self.path[0]:
                if not vexutils.equals_except(oldstmt, newstmt, self.path[1:], self.binrepr.unsign_int(tog[1]-1, size)):
                    return False
            # Vex will sometimes read from registers then never use them
            # This messes stuff up, so don't check equality for temp-writes
            # that are never used.
            elif oldstmt.tag == 'Ist_WrTmp' and newstmt.tag == 'Ist_WrTmp' and not vexutils.is_tmp_used(self.insvex, oldstmt.tmp):
                pass
            elif not vexutils.equals(oldstmt, newstmt):
                return False

            if oldstmt.tag == 'Ist_IMark':
                i = 0
            elif i is not None:
                i += 1

        # Success!
        return True

    def extract_bit_value(self, bit_offset, bit_length):
        if bit_offset + bit_length > len(self.insbytes) * 8:
            return None
        return (int(self.insbytes.encode('hex'), 16) >> (8*len(self.insbytes) - bit_length - bit_offset)) & ((1 << bit_length) - 1)

    @staticmethod
    def endian_reverse(x, n):
        out = 0
        for _ in xrange(n):
            out <<= 8
            out |= x & 0xFF
            x >>= 8
        return out

    def get_patch_data(self, symrepr):
        if self.constant or self.already_patched:
            return []
        self.already_patched = True
        val = symrepr.any(self.symval)
        val = self.binrepr.resign_int(val.value, val.size())
        l.debug('Patching address %s with value %s', hex(self.memaddr), hex(val))
        patch = self.get_patched_instruction(val)
        if patch == self.insbytes:
            return []
        return [(self.physaddr, patch)]

    def get_patched_instruction(self, value):
        if self.armop == 1:
            newval = self.armins & 0xFF7FF000
            newimm = self.binrepr.resign_int(value)
            if newimm > 0:
                newval |= 0x00800000
            newval |= abs(newimm)
            return struct.pack('I', newval)
        elif self.armop == 2:
            newval = self.armins & 0xFFFFF000
            clrp = claripy.ClaripyStandalone('fidget_quicksolve_%x' % self.memaddr)
            symrepr = clrp.solver()
            self.apply_constraints(symrepr)
            symrepr.add(self.symval == value)
            newimm = symrepr.any(self.symval8).value
            newimm = self.binrepr.resign_int(newimm)
            newshift = symrepr.any(self.bit_shift).value
            newval |= newshift << 8
            newval |= newimm
            return struct.pack('I', newval)
        elif self.armop == 3:
            newval = self.armins & 0xFF7FF0F0
            newimm = self.binrepr.resign_int(value)
            if newimm > 0:
                newval |= 0x00800000
            newimm = abs(newimm)
            newval |= newimm & 0xF
            newval |= (newimm & 0xF0) << 4
            return struct.pack('I', newval)
        elif self.armop == 4:
            newval = self.armins & 0xFF7FFF00
            newimm = self.binrepr.resign_int(value / 4)
            if newimm > 0:
                newval |= 0x00800000
            newval |= abs(newimm)
            return struct.pack('I', newval)
        elif self.armop == 5:
            newval = self.armins & 0xFF00
            newval |= value / 4
            return struct.pack('H', newval)
        elif self.armop == 6:
            newval = self.armins & 0xFF80
            newval |= value / 4
            return struct.pack('H', newval)
        elif self.armop == 7:
            newval = self.armins & 0xFF00FFFF
            newimm = value / 4
            newval |= newimm << 16
            return struct.pack('I', newval)
        elif self.armop == 8:
            newval = self.armins & 0xFF00FF7F
            newimm = value / 4
            if newimm > 0:
                newval |= 0x00000080
            newval |= abs(newimm) << 16
            return struct.pack('I', newval)
        elif self.armop == 9:
            newval = self.armins & 0xFD00FEFF
            newimm = value
            if newimm > 0:
                newval |= 0x02000000
            else:
                newimm = abs(newimm)
            newval |= newimm << 16
            return struct.pack('I', newval)
        elif self.armop == 10:
            newval = self.armins & 0xF000FEFF
            newimm = value
            if newimm < 0:
                newimm = 0x1000 + newimm
                newval |= 0x00000100
            newval |= newimm << 16
            return struct.pack('I', newval)
        elif self.armop == 11:
            newval = self.armins & 0xFF00FFFF
            newimm = value
            newval |= newimm << 16
            return struct.pack('I', newval)
        elif self.armop == 12:
            return []
        elif self.armop == 13:
            newval = self.armins & 0xFE3F
            newimm = value
            newval |= newimm << 6
            return struct.pack('H', newval)
        elif self.armop == 14:
            newval = self.armins & 0xFF00FF7F
            newimm = value / 4
            if newimm > 0:
                newval |= 0x00000080
            else:
                newimm = abs(newimm)
            newval |= newimm << 16
            return struct.pack('I', newval)
        elif self.armop == 15:
            newval = self.armins & 0x8F00FBFF
            newimm = value
            newval |= (newimm & 0x800) >> 1
            newval |= (newimm & 0x700) << 20
            newval |= (newimm & 0xFF) << 16
            return struct.pack('I', newval)
        elif self.bit_offset % 8 == 0 and self.bit_length % 8 == 0:
            value = self.binrepr.unsign_int(value, self.bit_length)
            puts = self.binrepr.pack_format(value, self.bit_length / 8)
            outs = [x for x in self.insbytes]
            offset = self.bit_offset/8
            for i, c in enumerate(puts):
                outs[i+offset] = c
            if self.binrepr.processor == 5:
                orgval = self.binrepr.unpack_format(self.insbytes, len(self.insbytes))
                newval = self.binrepr.unpack_format(''.join(outs), len(outs))
                newval |= orgval & 3
                outs = self.binrepr.pack_format(newval, len(outs))
            return ''.join(outs)
        else:
            raise FidgetUnsupportedError("Unaligned writes unimplemented")

    def get_range(self):
        if self.armop == 1:
           return (-0xFFF, 0x1000)
        elif self.armop == 2:
            return (0, 0xFF000001)
        elif self.armop in (3, 9):
            return (-0xFF, 0x100)
        elif self.armop in (4, 8, 14):
            return (-0x3FF, 0x400)
        elif self.armop in (5, 7):
            return (0, 0x400)
        elif self.armop == 6:
            return (0, 0x200)
        elif self.armop == 10:
            return (-0x7FF, 0x1000)
        elif self.armop == 11:
            return (0, 0x100)
        elif self.armop == 12:
            return (self.value, self.value+1)
        elif self.armop == 13:
            return (0, 8)
        elif self.armop == 15:
            return (0, 0x1000)
        else:
            half = (1 << self.bit_length) / 2
            tophalf = half
            while (tophalf - 1) % self.modconstraint != 0:
                tophalf -= 1
            return (-half, tophalf)

    def __reversed__(self):
        return reversed(xrange(*self.get_range()))

    def __str__(self):
        return '%d at 0x%0.8x' % (self.value, self.memaddr)

class BinaryDataConglomerate:
    def __init__(self, cleanval, dirtyval, flags):
        if not isinstance(cleanval, (int, long)):
            raise ValueError("cleanval must be an int or long!")
        self.value = cleanval
        self.symval = dirtyval
        self.dependencies = []
        self.access_flags = flags

    def add(self, binrepr):
        self.dependencies.append(binrepr)

    def get_patch_data(self, symrepr):
        return sum((x.get_patch_data(symrepr) for x in self.dependencies), [])

    def apply_constraints(self, symrepr):
        for x in self.dependencies:
            x.apply_constraints(symrepr)

    def __repr__(self):
        return 'BinaryData(%x)' % self.value
