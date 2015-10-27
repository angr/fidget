import struct
from . import vexutils
from .errors import FidgetUnsupportedError, \
                    ValueNotFoundError, \
                    FuzzingAssertionFailure
from pyvex import PyVEXError
import claripy
from claripy import BVV

import logging
l = logging.getLogger('fidget.binary_data')

# http://www.falatic.com/index.php/108/python-and-bitwise-rotation
# Rotate left: 0b1001 --> 0b0011
rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

# Rotate right: 0b1001 --> 0b1100
ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def resign_int(n, word_size):
    top = (1 << word_size) - 1
    if n > top:
        return None
    if n < top/2: # woo int division
        return int(n)
    return int(-((n ^ top) + 1))

def unsign_int(n, word_size):
    if n < 0:
        n += 1 << word_size
    return int(n)


class BinaryData(object):
    '''
    The fundemental link between an instruction and the immediates and offsets encoded in it.
    When you initialize this class, if the constructor returns correctly, the returned instance
    contains the information necessary to change the value you specified into any value supported
    by the instruction's encoding.

    The properties and methods you care about are:
    - binarydata.patch_value_expression: a claripy AST, based on some arbitrary variables,
        that can take on all the values representable by the instruction's encoding. If you have a
        claripy solver you're using to constraint-solve for a correct state, you can simply add the
        constraint that this expression must be equal to whatever variable you're using to
        represent the value produced by decoding this instruction.
    - binarydata.patch_bytes_expression: Not actually very useful to the end user, but this is
        another AST, based on the same variables as the previous, that will produce the actual
        instruction bytes that will end up in the binary.
    - binarydata.get_patch_data(): get the actual bytes for the instruction, patched with a
        certain value. Check its docstring for details.
    '''
    def __init__(self, project, addr, value, block=None, path=None, skip=0):
        '''
        :param project: The angr.Project to operate on.
        :param addr:    The address of the instruction to operate on. If this is a THUMB
                        instruction, it should be odd.
        :param value:   The value, currently present in the instruction, that you'd like to be
                        able to change with this tool.
        :param block:   Optional: the angr.lifter.Block instance representing the lift of the
                        single instruction at address addr.
        :param path:    Optional: please don't touch this, this is for fidget
        :param skip:    Optional: In the rare case that you specify the value property, and the
                        BinaryData instance that gets returned is tuned to change a different
                        field of that value present in the instruction than the one you want,
                        increment this value in your next call to this constructor, and that value
                        will be skipped over.
        '''
        if not isinstance(value, (int, long)) or value < 0:
            raise ValueError('value must be an unsigned int or long!')
        self._project = project
        self.unsigned_value = value
        self.value = None
        self.addr = addr

        self._arm = project.arch.name.startswith('ARM') or project.arch.name == 'AARCH64'
        self._armthumb = self._arm and addr & 1 == 1
        self._arm64 = project.arch.name == 'AARCH64'

        if not block:
            block = project.factory.block(addr, num_inst=1, max_size=400, opt_level=1)
        self._block = block
        self._insvex = block.vex
        self._insbytes = self._block.bytes
        self._inslen = len(self._insbytes)

        self.patch_bytes_expression = None
        self.patch_value_expression = None
        self._test_values = ()
        self._already_patched = False

        # this is some weird logic to make some potentially dumb behavior
        # transparent to the user.
        if not path:
            # if you don't provide a path, search for the value. The "path" it generates will
            # actually go through the .constants array, which should hopefully be stable between
            # lifts. It should. Hopefully.
            # The thing is that there can be more than one of the same constant present in a block!
            # this is what the skip property is for. The thing is, though, that some of these constants
            # are unchangable, for example, the stack shift in a push/pop instruction. Don't let the user
            # see these!! They are not useful. The user-provided skip value should only affect the
            # changable values.
            internal_skip = 0
            while True:
                # if this call raises an error it means we're well and truly done. Let the user see.
                try:
                    co, path = vexutils.search_block(self._insvex, self.unsigned_value, internal_skip)
                except ValueNotFoundError:
                    self._error()
                self._path = path
                self.bits = co.size
                self.value = resign_int(self.unsigned_value, self.bits)
                try:
                    # if this function raises an error, it means the current constant shouldn't
                    # be considered. in that case do not touch the user's skip value.
                    self._search_value()
                except ValueNotFoundError:
                    internal_skip += 1
                    continue
                # if we get this far, the constant is changable! nice!
                if skip == 0:
                    break
                else:
                    skip -= 1
                    internal_skip += 1
                    continue
        else:
            self._path = path
            type_path = path[:-1] + ['size']
            try:
                # if this function raises an error, the user fucked up the path.
                self.bits = vexutils.get_from_path(self._insvex, type_path)
                self.value = resign_int(self.unsigned_value, self.bits)
                # if this function raises an error, the user gave an unmodifiable path
                self._search_value()
            except ValueNotFoundError:
                self._error()

        # if we got this far, we are modifiable!! clean up a bit
        del self._block
        del self._insvex
        del self._test_values

    def get_patch_data(self, value=None, solver=None):
        '''
        Produce the actual patch data for a modified instruction, in the form of a list of tuples
        [(physaddr, patch_bytes), ...], where physaddr is the offset into the actual object file
        and patch_bytes is a string to be written into the binary at that address.

        There are two ways to call this function, one with :param value:, which should be the
        integer you'd like to patch into the instruction, or :param solver:, which is a
        claripy.Solver instance that can be queried for the value of self.patch_bytes_expression.
        You must provide exactly one of these arguments.
        '''
        if not (value is None) ^ (solver is None):
            raise ValueError('Must provide a value xor a solver!')
        if self._already_patched:
            return []

        patch_bytes = self._get_patched_instruction(value=value, solver=solver)
        if value is None:
            value = solver.eval_to_ast(self.patch_value_expression, 1)[0]._model_concrete.signed
        l.debug('Patching address %#x with value %#x', self.addr, value)
        if patch_bytes == self._insbytes:
            return []
        physaddr = self._project.loader.main_bin.addr_to_offset(self.addr)
        if self._armthumb: physaddr -= 1
        self._already_patched = True
        return [(physaddr, patch_bytes)]

    def _error(self):
        raise ValueNotFoundError('Value not found: %#x at %#x' % (self.unsigned_value, self.addr))

    def _imm(self, size, name=None):
        if name is None:
            name = 'imm%d' % size
        return claripy.BVS('%x_%s' % (self.addr, name), size)

    def _search_value(self):
        if self._arm:
            armins = self._string_to_insn(self._insbytes)
            if not self._arm64:
                if not self._armthumb:
                    # ARM instructions
                    if armins & 0x0C000000 == 0x04000000:
                        # LDR
                        thoughtval = armins & 0xFFF
                        if thoughtval != self.value:
                            raise ValueNotFoundError
                        imm12 = self._imm(12)
                        self.patch_value_expression = imm12.zero_extend(self.bits-12)
                        self.patch_bytes_expression = claripy.Concat(
                                BVV(armins >> 12, 20),
                                imm12
                            )
                        self._test_values = (1, 0xfff)
                    elif armins & 0x0E000000 == 0x02000000:
                        # Data processing w/ immediate
                        shiftval = (armins & 0xF00) >> 7
                        thoughtval = armins & 0xFF
                        thoughtval = ror(thoughtval, shiftval, 32)
                        if thoughtval != self.value:
                            raise ValueNotFoundError
                        shift = self._imm(4, 'shift')
                        imm8 = self._imm(8)
                        self.patch_value_expression = claripy.RotateRight(
                                imm8.zero_extend(32-8), shift.zero_extend(32-4)*2
                            )
                        self.patch_bytes_expression = claripy.Concat(
                                BVV(armins >> 12, 20),
                                shift,
                                imm8
                            )
                        self._test_values = (1, 0xff, 0xff000000)
                    elif armins & 0x0E400090 == 0x00400090:
                        # LDRH
                        thoughtval = (armins & 0xF) | ((armins & 0xF00) >> 4)
                        if thoughtval != self.value:
                            raise ValueNotFoundError
                        hinib = self._imm(4, 'hinib')
                        lonib = self._imm(4, 'lonib')
                        self.patch_value_expression = claripy.Concat(hinib, lonib).zero_extend(self.bits-8)
                        self.patch_bytes_expression = claripy.Concat(
                                BVV(armins >> 12, 20),
                                hinib,
                                BVV((armins >> 4) & 0xF, 4),
                                lonib
                            )
                        self._test_values = (1, 0xff)
                    elif armins & 0x0E000000 == 0x0C000000:
                        # Coprocessor data transfer
                        # i.e. FLD/FST
                        thoughtval = armins & 0xFF
                        thoughtval *= 4
                        if thoughtval != self.value:
                            raise ValueNotFoundError
                        imm8 = self._imm(8)
                        self.patch_value_expression = imm8.zero_extend(self.bits-8) << 2
                        self.patch_bytes_expression = claripy.Concat(
                                BVV(armins >> 8, 24),
                                imm8
                            )
                        self._test_values = (4, 0x3fc)
                    else:
                        raise ValueNotFoundError

                else:
                    # THUMB instructions
                    # https://ece.uwaterloo.ca/~ece222/ARM/ARM7-TDMI-manual-pt3.pdf
                    if self._inslen == 2:
                        # 16 bit instructions
                        if armins & 0xF000 in (0x9000, 0xA000):
                            # SP-relative LDR/STR, also SP-addiition
                            # page 26, 28
                            # unsigned offsets only, 10 bit imm stored w/o last two bits
                            thoughtval = armins & 0xFF
                            thoughtval *= 4
                            if thoughtval != self.value:
                                raise ValueNotFoundError
                            imm8 = self._imm(8)
                            self.patch_value_expression = imm8.zero_extend(self.bits-8) << 2
                            self.patch_bytes_expression = claripy.Concat(
                                    BVV(armins >> 8, 8),
                                    imm8
                                )
                            self._test_values = (4, 0x3fc)
                        elif armins & 0xFF00 == 0xB000:
                            # Add/sub offset to SP
                            # page 30
                            # uses sign bit, 9 bit imm stored w/o last two bits
                            thoughtval = armins & 0x7F
                            thoughtval *= 4
                            if thoughtval != self.value:
                                raise ValueNotFoundError
                            imm7 = self._imm(7)
                            self.patch_value_expression = imm7.zero_extend(self.bits-7) << 2
                            self.patch_bytes_expression = claripy.Concat(
                                    BVV(armins >> 7, 9),
                                    imm7
                                )
                            self._test_values = (4, 0x1fc)
                        elif armins & 0xFC00 == 0x1C00:
                            # ADD/SUB (immediate format)
                            # page 7
                            # uses sign bit, 3 bit immediate
                            thoughtval = (armins & 0x01C0) >> 6
                            if thoughtval != self.value:
                                raise ValueNotFoundError
                            imm3 = self._imm(3)
                            self.patch_value_expression = imm3.zero_extend(self.bits-3)
                            self.patch_bytes_expression = claripy.Concat(
                                    BVV(armins >> 9, 7),
                                    imm3,
                                    BVV(armins & 0x3F, 6)
                                )
                            self._test_values = (1, 7)
                        elif armins & 0xE000 == 0x2000:
                            # Move/Compare/Add/Subtract immediate
                            # page 9
                            # Unsigned 8 bit immediate
                            thoughtval = armins & 0xFF
                            if thoughtval != self.value:
                                raise ValueNotFoundError
                            imm8 = self._imm(8)
                            self.patch_value_expression = imm8.zero_extend(self.bits-8)
                            self.patch_bytes_expression = claripy.Concat(
                                    BVV(armins >> 8, 8),
                                    imm8
                                )
                            self._test_values = (1, 0xff)
                        elif armins & 0xF000 == 0x6000:
                            # Register-relative LDR/STR
                            # page 22
                            # unsigned 7 bit imm stored w/o last two bits
                            thoughtval = ((armins >> 6) & 0x1F) << 2
                            if thoughtval != self.value:
                                raise ValueNotFoundError
                            imm5 = self._imm(5)
                            self.patch_value_expression = imm5.zero_extend(self.bits-5) << 2
                            self.patch_bytes_expression = claripy.Concat(
                                    BVV(armins >> 11, 5),
                                    imm5,
                                    BVV(armins & 0x3F, 6)
                                )
                            self._test_values = (4, 0x7c)
                        elif armins & 0xF000 == 0x7000:
                            # Register-relative LDRB/STRB
                            # page 22
                            # unsigned 5 bit imm
                            thoughtval = (armins >> 6) & 0x1F
                            if thoughtval != self.value:
                                raise ValueNotFoundError
                            imm5 = self._imm(5)
                            self.patch_value_expression = imm5.zero_extend(self.bits-5)
                            self.patch_bytes_expression = claripy.Concat(
                                    BVV(armins >> 11, 5),
                                    imm5,
                                    BVV(armins & 0x3F, 6)
                                )
                            self._test_values = (1, 0x1f)
                        else:
                            raise ValueNotFoundError

                    elif self._inslen == 4:
                        # 32 bit instructions
                        # http://read.pudn.com/downloads159/doc/709030/Thumb-2SupplementReferenceManual.pdf
                        if armins & 0xFE1F0000 == 0xF81F0000 or \
                           armins & 0xFE800000 == 0xF8800000:
                            # Load/Store
                            # page 66, formats 1-2
                            # imm12 with designated sign bit
                            thoughtval = armins & 0xFFF
                            if thoughtval != self.value:
                                raise ValueNotFoundError
                            imm12 = self._imm(12)
                            self.patch_value_expression = imm12.zero_extend(self.bits-12)
                            self.patch_bytes_expression = claripy.Concat(
                                    BVV(armins >> 12, 20),
                                    imm12
                                )
                            self._test_values = (1, 0xfff)
                        elif armins & 0xFE800900 == 0xF8000800:
                            # Load/Store
                            # page 66, formats 3-4
                            # imm8 with designated sign bit
                            thoughtval = armins & 0xFF
                            if thoughtval != self.value:
                                raise ValueNotFoundError
                            imm8 = self._imm(8)
                            self.patch_value_expression = imm8.zero_extend(self.bits-8)
                            self.patch_bytes_expression = claripy.Concat(
                                    BVV(armins >> 8, 24),
                                    imm8
                                )
                            self._test_values = (1, 0xff)
                        elif armins & 0xFE800900 == 0xF8000900:
                            # Load/Store
                            # page 66, formats 5-6
                            # imm8, sign extended
                            thoughtval = armins & 0x7F
                            if armins & 0x80 == 0x80:
                                thoughtval = (thoughtval ^ 0x7F) + 1
                            if thoughtval != self.value:
                                raise ValueNotFoundError
                            imm8 = self._imm(8)
                            self.patch_value_expression = imm8.sign_extend(self.bits-8)
                            self.patch_bytes_expression = claripy.Concat(
                                    BVV(armins >> 8, 24),
                                    imm8
                                )
                            self._test_values = (-0x80, 0x7f)
                        elif armins & 0xFB408000 == 0xF2000000:
                            # Add/Sub
                            # page 53, format 2
                            # 12 bit immediate split into 3 bitfields
                            thoughtval = armins & 0xFF
                            thoughtval |= (armins & 0x7000) >> 4
                            thoughtval |= (armins & 0x04000000) >> 15
                            if thoughtval != self.value:
                                raise ValueNotFoundError
                            imm8 = self._imm(8)
                            imm3 = self._imm(3)
                            imm1 = self._imm(1)
                            self.patch_value_expression = claripy.Concat(
                                    imm1,
                                    imm3,
                                    imm8
                                ).zero_extend(self.bits-12)
                            self.patch_bytes_expression = claripy.Concat(
                                    BVV(armins >> 27, 5),
                                    imm1,
                                    BVV((armins & 0x03FF8000) >> 15, 11),
                                    imm3,
                                    BVV((armins & 0xF00) >> 8, 4),
                                    imm8
                                )
                            self._test_values = (1, 0xfff)
                        elif armins & 0xFB408000 == 0xF2400000:
                            # Move
                            # page 53, format 3
                            # 16 bit immediate split into 4 bitfields
                            thoughtval = armins & 0xFF
                            thoughtval |= (armins & 0x7000) >> 4
                            thoughtval |= (armins & 0x04000000) >> 15
                            thoughtval |= (armins & 0xF0000) >> 4
                            if thoughtval != self.value:
                                raise ValueNotFoundError
                            imm8 = self._imm(8)
                            imm3 = self._imm(3)
                            imm1 = self._imm(1)
                            imm4 = self._imm(1)
                            self.patch_value_expression = claripy.Concat(
                                    imm4,
                                    imm1,
                                    imm3,
                                    imm8
                                ).zero_extend(self.bits-12)
                            self.patch_bytes_expression = claripy.Concat(
                                    BVV(armins >> 27, 5),
                                    imm1,
                                    BVV((armins & 0x03F00000) >> 20, 6),
                                    imm4,
                                    BVV((armins & 0x00008000) >> 15, 1),
                                    imm3,
                                    BVV((armins & 0xF00) >> 8, 4),
                                    imm8
                                )
                            self._test_values = (1, 0xffff)
                        elif armins & 0xFA008000 == 0xF0000000:
                            # Data processing, modified 12 bit imm, aka EVIL
                            # page 53
                            # wow. just. wow.
                            imm12 = armins & 0xFF
                            imm12 |= (armins & 0x7000) >> 4
                            imm12 |= (armins & 0x04000000) >> 15
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
                            imm12 = self._imm(12)
                            ITE = claripy.If
                            CAT = claripy.Concat
                            ROR = claripy.RotateRight
                            imm8 = imm12[7:0]
                            imm7 = imm12[6:0]
                            imm3 = imm12[10:8]
                            imm1 = imm12[11]
                            zero = BVV(0, 8)
                            bit = BVV(1, 1)
                            monster = ITE(imm12[11:10] == 0,
                                        ITE(imm12[9] == 0,
                                            ITE(imm12[8] == 0,
                                                imm12[7:0].zero_extend(32-8),
                                                CAT(zero, imm8, zero, imm8)
                                            ),
                                            ITE(imm12[8] == 0,
                                                CAT(imm8, zero, imm8, zero),
                                                CAT(imm8, imm8, imm8, imm8)
                                            )
                                        ),
                                        ROR(CAT(bit, imm7).zero_extend(32-8),
                                            imm12[11:7].zero_extend(32-5)
                                        )
                                      )
                            self.patch_value_expression = monster
                            self.patch_bytes_expression = claripy.Concat(
                                    BVV(armins >> 27, 5),
                                    imm1,
                                    BVV((armins & 0x03FF8000) >> 15, 11),
                                    imm3,
                                    BVV((armins & 0xF00) >> 8, 4),
                                    imm8
                                )
                            self._test_values = (0xff00ff00, 0x00ff00ff, 0xffffffff, 0xff, 0xff000000)
                        else:
                            raise ValueNotFoundError
                    else:
                        raise FidgetUnsupportedError("You found a THUMB instruction longer than 32 bits??")

            else:
                self.bit_length = 64
                # aarch64 instructions
                # can't find a reference doc?????? I'm pulling these from VEX, guest_arm64_toIR.c
                if armins & 0x7f800000 in (0x28800000, 0x29800000, 0x29000000):
                    # LDP/SDP
                    # line 4791
                    # 7 bit immediate signed offset, scaled by load size (from MSB)
                    shift = 3 if armins & 0x80000000 else 2
                    simm7 = (armins & 0x3f8000) >> 15
                    simm7 = resign_int(simm7, 7)
                    simm7 <<= shift
                    if simm7 != self.value:
                        raise ValueNotFoundError
                    imm7 = self._imm(7)
                    self.patch_value_expression = imm7.sign_extend(self.bits-7) << shift
                    self.patch_bytes_expression = claripy.Concat(
                            BVV((armins & 0xffc00000) >> 22, 10),
                            imm7,
                            BVV(armins & 0x7fff, 15)
                        )
                    self._test_values = (-0x40 << shift, 0x3f << shift)
                elif (armins & 0x3f800000 == 0x39000000) or \
                     (armins & 0x3f800000 == 0x39800000 and \
                          ((armins >> 30) | ((armins >> 22) & 1)) in (4, 2, 3, 0, 1)):
                    # LDR/STR, LDRS
                    # line 4639, 5008
                    # 12 bit immediate unsigned offset, scaled by load size (from 2 MSB)
                    shift = (armins & 0xc0000000) >> 30
                    offs = (armins & 0x3ffc00) >> 10
                    offs <<= shift
                    if offs != self.value:
                        raise ValueNotFoundError
                    imm12 = self._imm(12)
                    self.patch_value_expression = imm12.zero_extend(self.bits-12) << shift
                    self.patch_bytes_expression = claripy.Concat(
                            BVV((armins & 0xffc00000) >> 22, 10),
                            imm12,
                            BVV(armins & 0x3ff, 10)
                        )
                    self._test_values = (1 << shift, 0xfff << shift)
                elif armins & 0x1f000000 == 0x11000000:
                    # ADD/SUB imm
                    # line 2403
                    # 12 bit shifted unsigned immediate
                    if not armins & 0x80000000:
                        self.bit_length = 32
                    shift = (armins >> 22) & 3
                    imm12 = (armins >> 10) & 0xfff
                    imm12 <<= 12*shift
                    if imm12 != self.value:
                        raise ValueNotFoundError
                    shift = self._imm(1, 'shift')
                    imm12 = self._imm(12)
                    shift_full = shift.zero_extend(self.bits-1)*12
                    self.patch_value_expression = imm12.zero_extend(self.bits-12) << shift_full
                    self.patch_bytes_expression = claripy.Concat(
                            BVV(armins >> 24, 8),
                            BVV(0, 1),
                            shift,
                            imm12,
                            BVV(armins & 0x3ff, 10)
                        )
                    self._test_values = (1, 0xfff, 0xfff000)
                elif armins & 0x3fa00000 == 0x38000000:
                    # LDUR/STUR
                    # Line 4680
                    # 9 bit signed immediate offset
                    imm9 = (armins >> 12) & 0x1ff
                    imm9 = resign_int(imm9, 9)
                    if imm9 != self.value:
                        raise ValueNotFoundError
                    imm9 = self._imm(9)
                    self.patch_value_expression = imm9.sign_extend(self.bits-9)
                    self.patch_bytes_expression = claripy.Concat(
                            BVV(armins >> 21, 11),
                            imm9,
                            BVV(armins & 0xfff, 12)
                        )
                    self._test_values = (-0x100, 0xff)

                else:
                    raise ValueNotFoundError


            if not self.sanity_check():
                raise ValueNotFoundError
        else:
            insn = self._string_to_insn(self._insbytes)
            insn = BVV(insn, self._inslen*8)
            for word_size in (64, 32, 16, 8):
                if word_size > self.bits:
                    continue
                for bit_offset in xrange(0, insn.length-word_size+1, 8):
                    result = insn[bit_offset+word_size-1:bit_offset]
                    result = result.sign_extend(self.bits-word_size)
                    if claripy.is_true(result == self.value):
                        imm = self._imm(word_size)
                        self.patch_value_expression = imm.sign_extend(self.bits-word_size)
                        if bit_offset + word_size >= insn.length:
                            acc = imm
                        else:
                            acc = claripy.Concat(insn[insn.length-1:bit_offset+word_size], imm)
                        if bit_offset != 0:
                            acc = claripy.Concat(acc, insn[bit_offset-1:0])
                        self.patch_bytes_expression = acc
                        self._test_values = (-(1 << word_size) >> 1, ((1 << word_size) >> 1) - 1)

                        if self.sanity_check():
                            break   # found

                    if self._project.arch.name == 'PPC64':
                        # On PPC64, the lowest two bits of immediate values can be used for other things
                        # Mask those out
                        result = (result & ~3).sign_extend(self.bits-word_size)
                        if not claripy.is_true(result == self.value):
                            continue
                        imm = self._imm(word_size-2)
                        self.patch_value_expression = claripy.Concat(
                                imm,
                                BVV(0, 2)
                            ).sign_extend(self.bits-word_size)
                        if bit_offset + word_size >= insn.length:
                            acc = imm
                        else:
                            acc = claripy.Concat(insn[insn.length-1:bit_offset+word_size], imm)
                        acc = claripy.Concat(acc, insn[bit_offset+1:0])
                        self.patch_bytes_expression = acc
                        self._test_values = (-(1 << word_size) >> 1, ((1 << word_size) >> 1) - 4)
                        if self.sanity_check():
                            break   # found
                else:
                    # inner loop did not break: not found
                    continue
                # inner loop broke: found
                break
            else:
                # outer loop did not break: inner loop did not break: not found
                raise ValueNotFoundError
            # outer loop broke: inner loop broke: found
            return

    def sanity_check(self):
        # make sure I programmed the expression generation correctly
        assert self.patch_value_expression.length == self.bits
        assert self.patch_bytes_expression.length == self._inslen*8
        # Prerequisite
        m = self._path[:]
        try:
            basic = vexutils.get_from_path(self._insvex, m)
        except ValueNotFoundError:
            raise FuzzingAssertionFailure("Can't follow given path!")
        m[-1] = 'size'
        size = vexutils.get_from_path(self._insvex, m)
        if basic != self.unsigned_value:
            raise FuzzingAssertionFailure("Can't extract known value from path!")
        # Get challengers
        for challenger in self._test_values:
            try:
                newblock = self._project.factory.block(
                        self.addr,
                        insn_bytes=self._get_patched_instruction(challenger),
                        opt_level=1
                    ).vex
            except PyVEXError:
                return False
            okay = (basic, unsign_int(challenger, size))
            try:
                if vexutils.get_from_path(newblock, self._path) != okay[1]:
                    return False
            except ValueNotFoundError:
                return False
            for a, b in vexutils.equals(self._insvex, newblock):
                if a == b:
                    continue
                if (a, b) == okay:
                    continue
                return False

        # Success!
        return True

    def _get_patched_instruction(self, value=None, solver=None):
        if not (value is None) ^ (solver is None):
            raise ValueError('Must provide a value xor a solver!')
        if value is not None:
            solver = claripy.Solver()
            solver.add(value == self.patch_value_expression)
        try:
            insn_int = solver.eval(self.patch_bytes_expression, 1)[0]
        except claripy.UnsatError:
            raise ValueNotFoundError('Unsat on solve!')
        return self._insn_to_string(insn_int)

    def _string_to_insn(self, string):
        if self._arm:
            if self._armthumb:
                armins = 0
                for i in xrange(0, self._inslen, 2):
                    armins <<= 16
                    armins |= struct.unpack(self._project.arch.struct_fmt(16), string[i:i+2])[0]
                return armins
            else:
                return struct.unpack(self._project.arch.struct_fmt(32), string)[0]
        else:
            insn = 0
            biter = string if self._project.arch.memory_endness == 'Iend_BE' else reversed(string)
            for c in biter:
                insn <<= 8
                insn |= ord(c)
            return insn

    def _insn_to_string(self, insn):
        if self._arm:
            if self._armthumb:
                armstr = ''
                for _ in xrange(0, self._inslen, 2):
                    armstr = struct.pack(self._project.arch.struct_fmt(16), insn & 0xffff) + armstr
                    insn >>= 16
                return armstr
            else:
                return struct.pack(self._project.arch.struct_fmt(32), insn)
        else:
            string = ''
            if self._project.arch.memory_endness == 'Iend_BE':
                for _ in xrange(self._inslen):
                    string = chr(insn & 0xFF) + string
                    insn >>= 8
            else:
                for _ in xrange(self._inslen):
                    string += chr(insn & 0xFF)
                    insn >>= 8
            return string

    def __repr__(self):
        return '<BinaryData for %#0.8x: %d>' % (self.addr, self.value)

class BinaryDataConglomerate(object):
    def __init__(self, addr, value, symval, access_flags):
        if not isinstance(value, (int, long)):
            raise ValueError("value must be an int or long!")
        self.addr = addr
        self.value = value
        self.symval = symval
        self.access_flags = access_flags
        self.dependencies = []
        self.constraints = []

    def add(self, bindata, sym_value):
        if isinstance(bindata, (int, long)):
            # This represents a value not found and must stay constant
            self.constraints.append(bindata == sym_value)
        else:
            self.dependencies.append(bindata)
            self.constraints.append(bindata.patch_value_expression == sym_value)

    def get_patch_data(self, solver):
        return sum((x.get_patch_data(solver=solver) for x in self.dependencies), [])

    def apply_constraints(self, solver):
        for x in self.constraints:
            solver.add(x)

    def __str__(self):
        return 'BinaryData(%x)' % self.value

bd_cache = {}

class PendingBinaryData(object):
    __slots__ = ('project', 'addr', 'value', 'sym_value', 'path', '_hash')
    def __init__(self, project, addr, values, path):
        self.project = project
        self.addr = addr
        self.value = values.as_unsigned
        self.sym_value = values.dirtyval
        self.path = tuple(path)
        self._hash = None

    def __hash__(self):
        if not self._hash: self._hash = hash(('pbd', self.project.filename, self.addr, self.value, self.path))
        return self._hash

    def __eq__(self, other):
        return self.project.filename == other.project.filename and self.addr == other.addr and self.value == other.value and self.path == other.path

    def resolve(self):
        if self in bd_cache:
            return bd_cache[self]
        else:
            try:
                binary_data = BinaryData(
                        self.project,
                        self.addr,
                        self.value,
                        path=list(self.path) + ['con', 'value']
                    )
            except ValueNotFoundError as e:
                l.debug(e.message)
                binary_data = self.value
            out = (self.sym_value, binary_data)
            bd_cache[self] = out
            return out

    @staticmethod
    def make_bindata(values, addr, flags):
        # flags is the access type
        data = BinaryDataConglomerate(addr, values.as_signed, values.dirtyval, flags)
        for resolver in values.taints['deps']:
            dirtyval, bindata = resolver.resolve()
            data.add(bindata, dirtyval)
        return data
