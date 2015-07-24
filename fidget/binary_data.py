import struct
from math import log
from . import vexutils
from .errors import FidgetError, \
                    FidgetUnsupportedError, \
                    ValueNotFoundError, \
                    FuzzingAssertionFailure
from pyvex import PyVEXError

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

# http://www.falatic.com/index.php/108/python-and-bitwise-rotation
# Rotate left: 0b1001 --> 0b0011
rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

# Rotate right: 0b1001 --> 0b1100
ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

ARM_IMM32_MASKS = [ror(0xff, y, 32) for y in xrange(0, 32, 2)]

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
        except ValueNotFoundError:
            del self.insvex
            l.debug("Value not found: 0x%x at 0x%x", self.value, self.memaddr)
            self.constraints = [dirtyval == cleanval]
            self.constant = True
            return
        self.constant = False
        del self.insvex

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

    def search_value(self):
        if self.binrepr.angr.arch.name.startswith('ARM'):
            self.bit_length = 32
            # Extract self.armins, the int representation of the bytes as appears in the instruction manuals
            if self.armthumb:
                self.armins = 0
                for i in xrange(0, len(self.insbytes), 2):
                    self.armins <<= 16
                    self.armins |= struct.unpack(self.binrepr.angr.arch.struct_fmt(16), self.insbytes[i:i+2])[0]
            else:
                self.armins = struct.unpack(self.binrepr.angr.arch.struct_fmt(32), self.insbytes)[0]

            if not self.armthumb:
                # ARM instructions
                if self.armins & 0x0C000000 == 0x04000000:
                    # LDR
                    thoughtval = self.armins & 0xFFF
                    if thoughtval != self.value:
                        raise ValueNotFoundError
                    self.armop = 1
                elif self.armins & 0x0E000000 == 0x02000000:
                    # Data processing w/ immediate
                    shiftval = ((self.armins & 0xF00) >> 7)
                    thoughtval = self.armins & 0xFF
                    thoughtval = (thoughtval >> shiftval) | (thoughtval << (32 - shiftval))
                    thoughtval &= 0xFFFFFFFF
                    if thoughtval != self.value:
                        raise ValueNotFoundError
                    self.armop = 2
                    self.bit_shift = self.symrepr._claripy.BitVec('%x_shift' % self.memaddr, 4)
                    self.symval8 = self.symrepr._claripy.BitVec('%x_imm8' % self.memaddr, 8)
                    self.constraints.append(self.symval ==
                            self.symrepr._claripy.RotateRight(
                                self.symval8.zero_extend(32-8),
                                self.bit_shift.zero_extend(32-4)*2
                            )
                        )
                elif self.armins & 0x0E400090 == 0x00400090:
                    # LDRH
                    thoughtval = (self.armins & 0xF) | ((self.armins & 0xF00) >> 4)
                    thoughtval *= 1 if self.armins & 0x00800000 else -1
                    if thoughtval != self.value:
                        raise ValueNotFoundError
                    self.armop = 3
                elif self.armins & 0x0E000000 == 0x0C000000:
                    # Coprocessor data transfer
                    # i.e. FLD/FST
                    thoughtval = self.armins & 0xFF
                    thoughtval *= 4 if self.armins & 0x00800000 else -4
                    if thoughtval != self.value:
                        raise ValueNotFoundError
                    self.armop = 4
                    self.modconstraint = 4
                else:
                    raise ValueNotFoundError

            else:
                # THUMB instructions
                # https://ece.uwaterloo.ca/~ece222/ARM/ARM7-TDMI-manual-pt3.pdf
                if len(self.insbytes) == 2:
                    # 16 bit instructions
                    if self.armins & 0xF000 in (0x9000, 0xA000):
                        # SP-relative LDR/STR, also SP-addiition
                        # page 26, 28
                        # unsigned offsets only, 10 bit imm stored w/o last two bits
                        thoughtval = self.armins & 0xFF
                        thoughtval *= 4
                        if thoughtval != self.value:
                            raise ValueNotFoundError
                        self.armop = 5
                        self.modconstraint = 4
                    elif self.armins & 0xFF00 == 0xB000:
                        # Add/sub offset to SP
                        # page 30
                        # uses sign bit, 9 bit imm stored w/o last two bits
                        thoughtval = self.armins & 0x7F
                        thoughtval *= 4
                        if thoughtval != self.value:
                            raise ValueNotFoundError
                        self.armop = 6
                        self.modconstraint = 4
                    elif self.armins & 0xFC00 == 0x1C00:
                        # ADD/SUB (immediate format)
                        # page 7
                        # uses sign bit, 3 bit immediate
                        thoughtval = (self.armins & 0x01C0) >> 6
                        if thoughtval != self.value:
                            raise ValueNotFoundError
                        self.armop = 7
                    elif self.armins & 0xE000 == 0x2000:
                        # Move/Compare/Add/Subtract immediate
                        # page 9
                        # Unsigned 8 bit immediate
                        thoughtval = self.armins & 0xFF
                        if thoughtval != self.value:
                            raise ValueNotFoundError
                        self.armop = 14
                    else:
                        raise ValueNotFoundError

                elif len(self.insbytes) == 4:
                    # 32 bit instructions
                    # http://read.pudn.com/downloads159/doc/709030/Thumb-2SupplementReferenceManual.pdf
                    if self.armins & 0xFE1F0000 == 0xF81F0000 or \
                       self.armins & 0xFE800000 == 0xF8800000:
                        # Load/Store
                        # page 66, formats 1-2
                        # imm12 with designated sign bit
                        thoughtval = self.armins & 0xFFF
                        if thoughtval != self.value:
                            raise ValueNotFoundError
                        self.armop = 8
                    elif self.armins & 0xFE800900 == 0xF8000800:
                        # Load/Store
                        # page 66, formats 3-4
                        # imm8 with designated sign bit
                        thoughtval = self.armins & 0xFF
                        if thoughtval != self.value:
                            raise ValueNotFoundError
                        self.armop = 9
                    elif self.armins & 0xFE800900 == 0xF8000900:
                        # Load/Store
                        # page 66, formats 5-6
                        # imm8, sign extended
                        thoughtval = self.armins & 0x7F
                        if self.armins & 0x80 == 0x80:
                            thoughtval = (thoughtval ^ 0x7F) + 1
                        if thoughtval != self.value:
                            raise ValueNotFoundError
                        self.armop = 10
                    elif self.armins & 0xFB408000 == 0xF2000000:
                        # Add/Sub
                        # page 53, format 2
                        # 12 bit immediate split into 3 bitfields
                        thoughtval = self.armins & 0xFF
                        thoughtval |= (self.armins & 0x7000) >> 4
                        thoughtval |= (self.armins & 0x04000000) >> 15
                        if thoughtval != self.value:
                            raise ValueNotFoundError
                        self.armop = 11
                    elif self.armins & 0xFB408000 == 0xF2400000:
                        # Move
                        # page 53, format 3
                        # 16 bit imediate split into 4 bitfields
                        thoughtval = self.armins & 0xFF
                        thoughtval |= (self.armins & 0x7000) >> 4
                        thoughtval |= (self.armins & 0x04000000) >> 15
                        thoughtval |= (self.armins & 0xF0000) >> 4
                        if thoughtval != self.value:
                            raise ValueNotFoundError
                        self.armop = 12
                    elif self.armins & 0xFA008000 == 0xF0000000:
                        # Data processing, modified 12 bit imm, aka EVIL
                        # page 53
                        # wow. just. wow.
                        imm12 = self.armins & 0xFF
                        imm12 |= (self.armins & 0x7000) >> 4
                        imm12 |= (self.armins & 0x04000000) >> 15
                        # decoding algorithm from page 93
                        if imm12 & 0xC00 == 0:
                            if imm12 & 0x300 == 0:
                                thoughtval = imm12
                            elif imm12 & 0x300 == 0x100:
                                thoughtval = imm12 & 0xFF
                                thoughtval |= thoughtval << 16
                            elif imm12 & 0x300 == 0x200:
                                thoughtval = (imm12 & 0xFF) << 8
                                thoughtval |= thoughtval << 16
                            elif imm12 & 0x300 == 0x300:
                                thoughtval = imm12 & 0xFF
                                thoughtval |= thoughtval << 8
                                thoughtval |= thoughtval << 16
                        else:
                            thoughtval = ror(0x80 | (imm12 & 0x7F), imm12 >> 7, 32)
                        if thoughtval != self.value:
                            raise ValueNotFoundError
                        self.armop = 13
                        self.symval8 = self.symrepr._claripy.BitVec('%x_imm12' % self.memaddr, 12)
                        ITE = self.symrepr._claripy.If
                        CAT = self.symrepr._claripy.Concat
                        ROR = self.symrepr._claripy.RotateRight
                        BVV = self.symrepr._claripy.BVV
                        imm8 = self.symval8[7:0]
                        imm7 = self.symval8[6:0]
                        zero = BVV(0, 8)
                        bit = BVV(1, 1)
                        form1 = self.symval8[7:0].zero_extend(32-8)
                        form2 = CAT(zero, imm8, zero, imm8)
                        form3 = CAT(imm8, zero, imm8, zero)
                        form4 = CAT(imm8, imm8, imm8, imm8)
                        form5 = ROR(CAT(bit, imm7).zero_extend(32-8), self.symval8[11:7].zero_extend(32-5))
                        monster = ITE(self.symval8[11:10] == 0,
                                    ITE(self.symval8[9:9] == 0,
                                        ITE(self.symval8[8:8] == 0,
                                            form1,
                                            form2
                                        ),
                                        ITE(self.symval8[8:8] == 0,
                                            form3,
                                            form4
                                        )
                                    ),
                                    form5
                                  )
                        self.constraints.append(self.symval == monster)
                    else:
                        raise ValueNotFoundError
                else:
                    raise FidgetUnsupportedError("You found a THUMB instruction longer than 32 bits!")

            if not self.sanity_check():
                raise ValueNotFoundError
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
                    if self.binrepr.angr.arch.name == 'PPC64':
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
                raise ValueNotFoundError

    def sanity_check(self):
        # Prerequisite
        m = self.path[:]
        try:
            basic = vexutils.get_from_path(self.insvex.statements, m)
        except (IndexError, AttributeError, KeyError) as _:
            raise FuzzingAssertionFailure("Can't follow given path!")
        m[-1] = 'type'
        size = vexutils.get_from_path(self.insvex.statements, m)
        size = vexutils.extract_int(size)
        if self.binrepr.resign_int(basic, size) != self.value:
            raise FuzzingAssertionFailure("Can't extract known value from path!")
        # Get challengers
        tog = self.get_range()

        for challenger in (tog[0], tog[1]-1):
            if challenger == 0:
                challenger = 4  # zero will cause problems. 4 should be in range?
            try:
                newblock = self.binrepr.make_irsb(self.get_patched_instruction(challenger), self.armthumb)
            except PyVEXError:
                return False
            okay = (basic, self.binrepr.unsign_int(challenger, size))
            try:
                if vexutils.get_from_path(newblock.statements, self.path) != okay[1]:
                    return False
            except (IndexError, AttributeError, KeyError) as _:
                return False
            for a, b in vexutils.equals(self.insvex, newblock):
                if a == b:
                    continue
                if (a, b) == okay:
                    continue
                return False

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
        # ARM instructions
        if self.armop == 1:
            newval = self.armins & 0xFFFFF000
            newval |= value
            return struct.pack(self.binrepr.angr.arch.struct_fmt(32), newval)
        elif self.armop == 2:
            newval = self.armins & 0xFFFFF000
            newimm = self.binrepr.unsign_int(value)
            for i, mask in enumerate(ARM_IMM32_MASKS):
                if newimm & mask == newimm:
                    newrot = i
                    newimm = rol(newimm, i*2, 32)
                    break
            else:
                raise FidgetError("Unrepresentable ARM immediate!")
            newval |= newrot << 8
            newval |= newimm
            return struct.pack(self.binrepr.angr.arch.struct_fmt(32), newval)
        elif self.armop == 3:
            newval = self.armins & 0xFF7FF0F0
            newimm = self.binrepr.resign_int(value)
            if newimm > 0:
                newval |= 0x00800000
            newimm = abs(newimm)
            newval |= newimm & 0xF
            newval |= (newimm & 0xF0) << 4
            return struct.pack(self.binrepr.angr.arch.struct_fmt(32), newval)
        elif self.armop == 4:
            newval = self.armins & 0xFF7FFF00
            newimm = self.binrepr.resign_int(value / 4)
            if newimm > 0:
                newval |= 0x00800000
            newval |= abs(newimm)
            return struct.pack(self.binrepr.angr.arch.struct_fmt(32), newval)
        # THUMB instructions, 16 bit
        elif self.armop == 5:
            newval = self.armins & 0xFF00
            newval |= value / 4
            return struct.pack(self.binrepr.angr.arch.struct_fmt(16), newval)
        elif self.armop == 6:
            newval = self.armins & 0xFF80
            newval |= value / 4
            return struct.pack(self.binrepr.angr.arch.struct_fmt(16), newval)
        elif self.armop == 7:
            newval = self.armins & 0xFE3F
            newval |= value << 6
            return struct.pack(self.binrepr.angr.arch.struct_fmt(16), newval)
        elif self.armop == 14:
            newval = self.armins & 0xFF00
            newval |= value
            return struct.pack(self.binrepr.angr.arch.struct_fmt(16), newval)
        # THUMB instructions, 32 bit
        elif self.armop == 8:
            newval = self.armins & 0xFFFFF000
            newval |= value
            return struct.pack(self.binrepr.angr.arch.struct_fmt(16), newval >> 16) + \
                   struct.pack(self.binrepr.angr.arch.struct_fmt(16), newval & 0xFFFF)
        elif self.armop == 9:
            newval = self.armins & 0xFFFFFF00
            newval |= value
            return struct.pack(self.binrepr.angr.arch.struct_fmt(16), newval >> 16) + \
                   struct.pack(self.binrepr.angr.arch.struct_fmt(16), newval & 0xFFFF)
        elif self.armop == 10:
            newval = self.armins & 0xFFFFFF80
            newval |= value
            return struct.pack(self.binrepr.angr.arch.struct_fmt(16), newval >> 16) + \
                   struct.pack(self.binrepr.angr.arch.struct_fmt(16), newval & 0xFFFF)
        elif self.armop == 11:
            newval = self.armins & 0xFBFF8F00
            imm8 = value & 0xFF
            imm3 = (value & 0x700) << 4
            imm1 = (value & 0x800) << 15
            newval |= imm8 | imm3 | imm1
            return struct.pack(self.binrepr.angr.arch.struct_fmt(16), newval >> 16) + \
                   struct.pack(self.binrepr.angr.arch.struct_fmt(16), newval & 0xFFFF)
        elif self.armop == 12:
            newval = self.armins & 0xFBF08F00
            imm8 = value & 0xFF
            imm3 = (value & 0x700) << 4
            imm1 = (value & 0x800) << 15
            imm4 = (value & 0xF000) << 4
            newval |= imm8 | imm3 | imm1 | imm4
            return struct.pack(self.binrepr.angr.arch.struct_fmt(16), newval >> 16) + \
                   struct.pack(self.binrepr.angr.arch.struct_fmt(16), newval & 0xFFFF)
        elif self.armop == 13:
            newval = self.armins & 0xFBFF8F00
            imm8 = value & 0xFF
            if imm8 == value:
                newval |= imm8
            else:
                if value == (imm8 | (imm8 << 16)):
                    newval |= imm8 | 0x1000
                elif value == ((imm8 << 8) | (imm8 << 24)):
                    newval |= imm8 | 0x2000
                elif value == (imm8 | (imm8 << 8) | (imm8 << 16) | (imm8 << 24)):
                    newval |= imm8 | 0x3000
                else:
                    top_bit = int(log(newval, 2))
                    shift_qty = (15 - top_bit) % 32
                    if shift_qty < 8 or shift_qty > 31:
                        raise ValueNotFoundError
                    imm7 = rol(value, shift_qty, 32)
                    if imm7 & 0xFF != imm7:
                        raise ValueNotFoundError
                    newval |= (imm7 & 0x7F) | ((shift_qty & 1) << 7) | ((shift_qty & 14) << 11) | ((shift_qty & 16) << 22)
            return struct.pack(self.binrepr.angr.arch.struct_fmt(16), newval >> 16) + \
                   struct.pack(self.binrepr.angr.arch.struct_fmt(16), newval & 0xFFFF)
        elif self.bit_offset % 8 == 0 and self.bit_length % 8 == 0:
            # Generic encodings
            value = self.binrepr.unsign_int(value, self.bit_length)
            puts = self.binrepr.pack_format(value, self.bit_length / 8)
            outs = [x for x in self.insbytes]
            offset = self.bit_offset/8
            for i, c in enumerate(puts):
                outs[i+offset] = c
            if self.binrepr.angr.arch.name == 'PPC64':
                orgval = self.binrepr.unpack_format(self.insbytes, len(self.insbytes))
                newval = self.binrepr.unpack_format(''.join(outs), len(outs))
                newval |= orgval & 3
                outs = self.binrepr.pack_format(newval, len(outs))
            return ''.join(outs)
        else:
            raise FidgetUnsupportedError("Unaligned writes unimplemented")

    def get_range(self):
        # ARM instructions
        if self.armop == 1:
           return (0, 0x1000)
        elif self.armop == 2:
            return (0, 0xFF000001)
        elif self.armop == 3:
            return (-0xFF, 0x100)
        elif self.armop == 4:
            return (-0x3FF, 0x400)
        # THUMB instructions, 16 bit
        elif self.armop == 5:
            return (0, 0x3FD)
        elif self.armop == 6:
            return (0, 0x1FD)
        elif self.armop == 7:
            return (0, 8)
        elif self.armop == 14:
            return (0, 0x100)
        # THUMB instructions, 32 bit
        elif self.armop == 8:
            return (0, 0x1000)
        elif self.armop == 9:
            return (0, 0x100)
        elif self.armop == 10:
            return (0, 0x80)
        elif self.armop == 11:
            return (0, 0x1000)
        elif self.armop == 12:
            return (0, 0x10000)
        elif self.armop == 13:
            return (0, 0x100000000)
        else:
            half = (1 << self.bit_length) / 2
            tophalf = half
            while (tophalf - 1) % self.modconstraint != 0:
                tophalf -= 1
            return (-half, tophalf)

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

    def __str__(self):
        return 'BinaryData(%x)' % self.value
