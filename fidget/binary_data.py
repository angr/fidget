# BinaryData
# The fundemental link between binary data and things that know what binary data should be
# Knows how to tell if an instruction contains a particular value
# And if it does, how to change it
# And also how to apply the constraints for each value, i.e. range

# Further down is BinaryDataConglomerate
# Which is a simple way to pass around values that actually depend
# on multiple numbers in the binary

class BinaryData():
    def __init__(self, mark, valaddr, value, binrepr):
        self.mark = mark
        self.inslen = mark.len
        self.valaddr = valaddr
        self.memaddr = memaddr
        self.value = value
        self.ovalue = value
        self.binrepr = binrepr
        self.symrepr = binrepr.symrepr

        self.physaddr = binrepr.relocate_to_physaddr(memaddr, '.text')
        self.inslen = ins.size

        self.access_flags = binrepr.get_access_flags(memaddr, opn)

        self.gotime = False
        self.symval = None

        binrepr.filestream.seek(self.physaddr)
        self.insbytes = binrepr.filestream.read(self.inslen)

        if value is not None:
            if value is True:
                self.value = binrepr.ida.idc.GetOperandValue(self.memaddr, self.opn)
            self.search_value()
            self.signed = True  # god damn it, intel!

            if self.symval is None:     # allow search_value to set the symvalues if it really wants to
                self.symval = symexec.BitVec(hex(memaddr)[2:] + '_' + str(opn), self.bit_length)
                rng = self.get_range()
                binrepr.symrepr.add(self.symval >= rng[0])
                binrepr.symrepr.add(self.symval <= rng[1] - 1)
        else:
            self.value = 0

    def search_value(self):
        self.bit_shift = 0
        if self.binrepr.processor == 2:
            self.bit_length = 32
            if len(self.insbytes) == 4:
                self.armins = struct.unpack('I', self.insbytes)[0]
            elif len(self.insbytes) == 2:
                self.armins = struct.unpack('H', self.insbytes)[0]
            else:
                raise Exception("Holy crap ARM what???")
            self.armthumb = self.binrepr.ida.idc.GetReg(self.memaddr, "T") == 1
            if not self.armthumb and self.armins & 0x0C000000 == 0x04000000:
                # LDR
                self.armop = 1
                thoughtval = self.armins & 0xFFF
                thoughtval *= 1 if self.armins & 0x00800000 else -1
                if thoughtval != self.value:
                    print 'case 1'
                    print hex(thoughtval), hex(self.value), hex(self.armins)
                    raise Exception("(%x) Either IDA or I really don't understand this instruction!" % self.memaddr)
            elif not self.armthumb and self.armins & 0x0E000000 == 0x02000000:
                # Data processing w/ immediate
                self.armop = 2
                shiftval = ((self.armins & 0xF00) >> 7)
                thoughtval = self.armins & 0xFF
                thoughtval = (thoughtval >> shiftval) | (thoughtval << (32 - shiftval))
                thoughtval &= 0xFFFFFFFF
                if thoughtval != self.value:
                    print 'case 2'
                    print hex(thoughtval), hex(self.value), hex(self.armins)
                    raise Exception("(%x) Either IDA or I really don't understand this instruction!" % self.memaddr)
                self.bit_shift = symexec.BitVec(hex(self.memaddr)[2:] + '_shift', 4)
                self.symval = symexec.BitVec(hex(self.memaddr)[2:] + '_imm', 32)
                self.symval8 = symexec.BitVec(hex(self.memaddr)[2:] + '_imm8', 8)
                self.symrepr.add(self.symval == symexec.RotateRight(symexec.ZeroExt(32-8, self.symval8), symexec.ZeroExt(32-4, self.bit_shift)*2))
            elif not self.armthumb and self.armins & 0x0E400090 == 0x00400090:
                # LDRH
                self.armop = 3
                thoughtval = (self.armins & 0xF) | ((self.armins & 0xF00) >> 4)
                thoughtval *= 1 if self.armins & 0x00800000 else -1
                if thoughtval != self.value:
                    print 'case 3'
                    print hex(thoughtval), hex(self.value), hex(self.armins)
                    raise Exception("(%x) Either IDA or I really don't understand this instruction!" % self.memaddr)
            elif not self.armthumb and self.armins & 0x0E000000 == 0x0C000000:
                # Coprocessor data transfer
                # i.e. FLD/FST
                self.armop = 4
                thoughtval = self.armins & 0xFF
                thoughtval *= 4 if self.armins & 0x00800000 else -4
                if thoughtval != self.value:
                    print 'case 4'
                    print hex(thoughtval), hex(self.value), hex(self.armins)
                    raise Exception("(%x) Either IDA or I really don't understand this instruction!" % self.memaddr)
                self.symval = symexec.BitVec(hex(self.memaddr)[2:] + '_' + str(self.opn), self.bit_length)
                rng = self.get_range()
                self.symrepr.add(self.symval >= rng[0])
                self.symrepr.add(self.symval <= rng[1] - 1)
                self.symrepr.add(self.symval % 4 == 0)
            elif self.armthumb and self.armins & 0xF000 in (0x9000, 0xA000):
                # SP-relative LDR/STR, also SP-addiition
                self.armop = 5
                thoughtval = self.armins & 0xFF
                thoughtval *= 4
                if thoughtval != self.value:
                    print 'case 5'
                    print hex(thoughtval), hex(self.value), hex(self.armins)
                    raise Exception("(%x) Either IDA or I really don't understand this instruction!" % self.memaddr)
                self.symval = symexec.BitVec(hex(self.memaddr)[2:] + '_' + str(self.opn), self.bit_length)
                rng = self.get_range()
                self.symrepr.add(self.symval >= rng[0])
                self.symrepr.add(self.symval <= rng[1] - 1)
                self.symrepr.add(self.symval % 4 == 0)
            elif self.armthumb and self.armins & 0xFF00 == 0xB000:
                # Add/sub offset to SP
                # I'm gonna cheat here because I'm worried about how IDA might interpret... various things
                self.armop = 6
                thoughtval = self.armins & 0x7F
                thoughtval *= 4
                if thoughtval != self.value:
                    print 'case 6'
                    print hex(thoughtval), hex(self.value), hex(self.armins)
                    raise Exception("(%x) Either IDA or I really don't understand this instruction!" % self.memaddr)
                self.symval = symexec.BitVec(hex(self.memaddr)[2:] + '_' + str(self.opn), self.bit_length)
                rng = self.get_range()
                self.symrepr.add(self.symval >= rng[0])
                self.symrepr.add(self.symval <= rng[1] - 1)
                self.symrepr.add(self.symval % 4 == 0)
            elif self.armthumb and self.armins & 0x0000FFE0 == 0x0000E840:
                # Thumb32 - LDREX/STREX ...
                self.armop = 7
                thoughtval = (self.armins & 0x00FF0000) >> 16
                thoughtval *= 4
                if thoughtval != self.value:
                    print 'case 7'
                    print hex(thoughtval), hex(self.value), hex(self.armins)
                    raise Exception("(%x) Either IDA or I really don't understand this instruction!" % self.memaddr)
                self.symval = symexec.BitVec(hex(self.memaddr)[2:] + '_' + str(self.opn), self.bit_length)
                rng = self.get_range()
                self.symrepr.add(self.symval >= rng[0])
                self.symrepr.add(self.symval <= rng[1] - 1)
                self.symrepr.add(self.symval % 4 == 0)
            elif self.armthumb and self.armins & 0x0000FE40 == 0x0000E840:
                # Thumb32 - LDRD/STRD
                self.armop = 8
                thoughtval = (self.armins & 0x00FF0000) >> 16
                thoughtval *= 4 if self.armins & 0x00000080 else -4
                if thoughtval != self.value:
                    print 'case 8'
                    print hex(thoughtval), hex(self.value), hex(self.armins)
                    raise Exception("(%x) Either IDA or I really don't understand this instruction!" % self.memaddr)
                self.symval = symexec.BitVec(hex(self.memaddr)[2:] + '_' + str(self.opn), self.bit_length)
                rng = self.get_range()
                self.symrepr.add(self.symval >= rng[0])
                self.symrepr.add(self.symval <= rng[1] - 1)
                self.symrepr.add(self.symval % 4 == 0)
            elif self.armthumb and self.armins & 0x0800FE80 == 0x0800F800 and self.armins & 0x05000000 != 0:
                # Thumb32 - something something LDR/STR
                self.armop = 9
                thoughtval = (self.armins & 0x00FF0000) >> 16
                if self.armins & 0x00000100:
                    thoughtval = self.binrepr.resign_int(thoughtval, 8)
                if self.armins & 0x02000000 == 0:
                    thoughtval *= -1
                if thoughtval != self.value:
                    print 'case 9'
                    print hex(thoughtval), hex(self.value), hex(self.armins)
                    raise Exception("(%x) Either IDA or I really don't understand this instruction!" % self.memaddr)
            elif self.armthumb and self.armins & 0x0000FE80 == 0x0000F880:
                # Thumb32 - LDR/STR with 12-bit imm
                self.armop = 10
                thoughtval = (self.armins & 0x0FFF0000) >> 16
                if self.armins & 0x00000100:
                    thoughtval = self.binrepr.resign_int(thoughval, 12)
                if thoughtval != self.value:
                    print 'case 10'
                    print hex(thoughtval), hex(self.value), hex(self.armins)
                    raise Exception("(%x) Either IDA or I really don't understand this instruction!" % self.memaddr)
            elif self.armthumb and self.armins & 0x8000FA00 == 0x0000F000:
                # Thumb32 - Data processing w/ modified 12 bit imm a.k.a EVIL
                if self.armins & 0x70000400:
                    # stupid cases-- do not touch
                    self.armop = 12
                    self.symval = symexec.BitVec(hex(self.memaddr)[2:] + '_' + str(self.opn) + '_nope', self.bit_length)
                    self.symrepr.add(self.symval == self.value)
                else:
                    self.armop = 11
                    thoughtval = (self.armins & 0x00FF0000) >> 16
                    if thoughtval != self.value:
                        print 'case 11'
                        print hex(thoughtval), hex(self.value), hex(self.armins)
                        raise Exception("(%x) Either IDA or I really don't understand this instruction!" % self.memaddr)
            elif self.armthumb and self.armins & 0xFC00 == 0x1C00:
                # Thumb - ADD/SUB
                self.armop = 13
                thoughtval = (self.armins & 0x01C0) >> 6
                if thoughtval != self.value:
                    print 'case 13'
                    print hex(thoughtval), hex(self.value), hex(self.armins)
                    raise Exception("(%x) Either IDA or I really don't understand this instruction!" % self.memaddr)
            elif self.armthumb and self.armins & 0x0000EE00 == 0x0000EC00:
                # Thumb32 - Coprocessor stuff
                self.armop = 14
                thoughtval = (self.armins & 0x00FF0000) >> 16
                thoughtval *= 4 if self.armins & 0x00000080 else -4
                if thoughtval != self.value:
                    print 'case 14'
                    print hex(thoughtval), hex(self.value), hex(self.armins), len(self.insbytes)
                    raise Exception("(%x) Either IDA or I really don't understand this instruction!" % self.memaddr)
                self.symval = symexec.BitVec(hex(self.memaddr)[2:] + '_' + str(self.opn), self.bit_length)
                rng = self.get_range()
                self.symrepr.add(self.symval >= rng[0])
                self.symrepr.add(self.symval <= rng[1] - 1)
                self.symrepr.add(self.symval % 4 == 0)
            elif self.armthumb and self.armins & 0x8000FB40 == 0x0000F200:
                # Thumb32 - ADD/SUB plain 12 bit imm
                self.armop = 15
                thoughtval = (self.armins & 0x00FF0000) >> 16
                thoughtval |= (self.armins & 0x70000000) >> 20
                thoughtval |= (self.armins & 0x00000400) << 1
                if thoughtval != self.value:
                    print 'case 15'
                    print hex(thoughtval), hex(self.value), hex(self.armins), len(self.insbytes)
                    raise Exception("(%x) Either IDA or I really don't understand this instruction!" % self.memaddr)
            else:
                raise Exception("(%x) Unsupported ARM instruction!" % self.memaddr)
        else:
            self.armop = 0
            found = False
            for word_size in (64, 32, 16, 8):
                self.bit_length = word_size
                for byte_offset in xrange(len(self.insbytes)):
                    self.set_uvalue()
                    result = self.extract_bit_value(byte_offset*8, word_size)
                    if result is None: continue
                    result = self.endian_reverse(result, word_size/8)
                    if result != self.uvalue: continue
                    self.value = (1 << word_size) / 3 # TODO: Do this less hardcodedly
                    self.bit_offset = byte_offset * 8
                    if self.sanity_check():
                        found = True
                        break
                if found:
                    break
            if not found:
                raise Exception('*** CRITICAL (%x): Absolutely could not find value %d' % (self.memaddr, self.value))

    def set_uvalue(self):
        if self.gotime: self.uvalue = self.binrepr.symrepr.eval(self.symval).as_long()
        else: self.uvalue = self.value if self.value >= 0 else 1 + (-self.value ^ ((1 << self.bit_length) - 1))

    def sanity_check(self):
        if self.binrepr.verbose > 1: print '\tsanity checking for operand', self.opn
        self.patch_value()
        if self.binrepr.ida.idc.GetMnem(self.memaddr) != self.s[0]:
            if self.binrepr.verbose > 1: print 'failed mnem check'
            self.restore_value()
            return False
        for i in xrange(6):
            if i == self.opn:
                self.binrepr.ida.idc.OpDecimal(self.memaddr, i)
                if not str(self.value) in self.binrepr.ida.idc.GetOpnd(self.memaddr, i):
                    if self.binrepr.verbose > 1:
                        print 'failed expectation check'
                        print self.value, 'not in', self.binrepr.ida.idc.GetOpnd(self.memaddr, i)
                    self.restore_value()
                    return False
            else:
                if self.binrepr.ida.idc.GetOpnd(self.memaddr, i) != self.s[i+1]:
                    if self.binrepr.verbose > 1:
                        print 'failed regression check for opnd', i
                        print self.binrepr.ida.idc.GetOpnd(self.memaddr, i), '!=', self.s[i+1]
                    self.restore_value()
                    return False
        self.restore_value()
        return True

    def extract_bit_value(self, bit_offset, bit_length):
        if bit_offset + bit_length > len(self.insbytes) * 8:
            return None
        return (int(self.insbytes.encode('hex'), 16) >> (8*len(self.insbytes) - bit_length - bit_offset)) & ((1 << bit_length) - 1)

    def endian_reverse(self, x, n):
        out = 0
        for _ in xrange(n):
            out <<= 8
            out |= x & 0xFF
            x >>= 8
        return out

    def patch_value(self):
        if self.bit_offset % 8 == 0 and self.bit_length % 8 == 0:
            self.set_uvalue()
            ltodo = self.bit_length
            otodo = self.bit_offset/8
            vtodo = self.uvalue
            while ltodo >= 32:
                self.binrepr.ida.idc.PatchDword(self.memaddr + otodo, vtodo & 0xFFFFFFFF)
                otodo += 4
                ltodo -= 32
                vtodo >>= 32
            while ltodo > 0:
                self.binrepr.ida.idc.PatchByte(self.memaddr + otodo, vtodo & 0xFF)
                otodo += 1
                ltodo -= 8
                vtodo >>= 8
        else:
            raise Exception("Unaligned writes unimplemented")

    def get_patch_data(self):
        if self.armop == 1:
            newval = self.armins & 0xFF7FF000
            newimm = self.symrepr.eval(self.symval).as_long()
            newimm = self.binrepr.resign_int(newimm)
            if newimm > 0:
                newval |= 0x00800000
            newval |= abs(newimm)
            return [(self.physaddr, struct.pack('I', newval))]
        elif self.armop == 2:
            newval = self.armins & 0xFFFFF000
            newimm = self.symrepr.eval(self.symval8).as_long()
            newimm = self.binrepr.resign_int(newimm)
            newshift = self.symrepr.eval(self.bit_shift).as_long()
            newval |= newshift << 8
            newval |= newimm
            return [(self.physaddr, struct.pack('I', newval))]
        elif self.armop == 3:
            newval = self.armins & 0xFF7FF0F0
            newimm = self.symrepr.eval(self.symval).as_long()
            newimm = self.binrepr.resign_int(newimm)
            if newimm > 0:
                newval |= 0x00800000
            newimm = abs(newimm)
            newval |= newimm & 0xF
            newval |= (newimm & 0xF0) << 4
            return [(self.physaddr, struct.pack('I', newval))]
        elif self.armop == 4:
            newval = self.armins & 0xFF7FFF00
            newimm = self.symrepr.eval(self.symval).as_long() / 4
            newimm = self.binrepr.resign_int(newimm)
            if newimm > 0:
                newval |= 0x00800000
            newval |= abs(newimm)
            return [(self.physaddr, struct.pack('I', newval))]
        elif self.armop == 5:
            newval = self.armins & 0xFF00
            newimm = self.symrepr.eval(self.symval).as_long() / 4
            newval |= newimm
            return [(self.physaddr, struct.pack('H', newval))]
        elif self.armop == 6:
            newval = self.armins & 0xFF80
            newimm = self.symrepr.eval(self.symval).as_long() / 4
            newval |= newimm
            return [(self.physaddr, struct.pack('H', newval))]
        elif self.armop == 7:
            newval = self.armins & 0xFF00FFFF
            newimm = self.symrepr.eval(self.symval).as_long() / 4
            newval |= newimm << 16
            return [(self.physaddr, struct.pack('I', newval))]
        elif self.armop == 8:
            newval = self.armins & 0xFF00FF7F
            newimm = self.symrepr.eval(self.symval).as_long() / 4
            if newimm > 0:
                newval |= 0x00000080
            newval |= abs(newimm) << 16
            return [(self.physaddr, struct.pack('I', newval))]
        elif self.armop == 9:
            newval = self.armins & 0xFD00FEFF
            newimm = self.symrepr.eval(self.symval).as_long()
            if newimm > 0:
                newval |= 0x02000000
            else:
                newimm = abs(newimm)
            newval |= newimm << 16
            return [(self.physaddr, struct.pack('I', newval))]
        elif self.armop == 10:
            newval = self.armins & 0xF000FEFF
            newimm = self.symrepr.eval(self.symval).as_long()
            if newimm < 0:
                newimm = 0x1000 + newimm
                newval |= 0x00000100
            newval |= newimm << 16
            return [(self.physaddr, struct.pack('I', newval))]
        elif self.armop == 11:
            newval = self.armins & 0xFF00FFFF
            newimm = self.symrepr.eval(self.symval).as_long()
            newval |= newimm << 16
            return [(self.physaddr, struct.pack('I', newval))]
        elif self.armop == 12:
            return []
        elif self.armop == 13:
            newval = self.armins & 0xFE3F
            newimm = self.symrepr.eval(self.symval).as_long()
            newval |= newimm << 6
            return [(self.physaddr, struct.pack('H', newval))]
        elif self.armop == 14:
            newval = self.armins & 0xFF00FF7F
            newimm = self.symrepr.eval(self.symval).as_long() / 4
            if newimm > 0:
                newval |= 0x00000080
            else:
                newimm = abs(newimm)
            newval |= newimm << 16
            return [(self.physaddr, struct.pack('I', newval))]
        elif self.armop == 15:
            newval = self.armins & 0x8F00FBFF
            newimm = self.symrepr.eval(self.symval).as_long()
            newval |= (newimm & 0x800) >> 1
            newval |= (newimm & 0x700) << 20
            newval |= (newimm & 0xFF) << 16
            return [(self.physaddr, struct.pack('I', newval))]
        elif self.bit_offset % 8 == 0 and self.bit_length % 8 == 0:
            self.set_uvalue()
            outs = [x for x in self.insbytes]
            ltodo = self.bit_length
            otodo = self.bit_offset/8
            vtodo = self.uvalue
            while ltodo > 0:
                outs[otodo] = chr(vtodo & 0xFF)
                otodo += 1
                ltodo -= 8
                vtodo >>= 8
            return [(self.physaddr, ''.join(outs))]
        else:
            raise Exception("Unaligned writes unimplemented")

    def restore_value(self):
        self.value = self.ovalue
        ptr = self.memaddr
        bts = self.insbytes
        while len(bts) >= 4:
            self.binrepr.ida.idc.PatchDword(ptr, struct.unpack('I', bts[:4])[0])
            bts = bts[4:]
            ptr += 4
        for char in bts:
            self.binrepr.ida.idc.PatchByte(ptr, ord(char))
            ptr += 1

    def get_range(self):
        if self.armop == 1:
           return (-0xFFF, 0x1000)
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
        elif self.signed or self.armop == 2:
            half = (1 << self.bit_length) / 2
            return (-half, half, 1 << self.bit_shift)
        else:
            return (0, 1 << self.bit_length, 1 << self.bit_shift)

    def __contains__(self, val):        # allows checking if an address is in-range with the `in` operator
        bot, top, step = self.get_range()
        if val < bot or val >= top: return False
        if (val - bot) % step != 0: return False
        return True

    def __iter__(self):                 # CAREFUL-- Don't use these for constraint solving unless you KNOW WHAT YOU'RE DOING
        return xrange(*self.get_range())  # This quickly turn into a fuckall-deep nested loop nest and everything will die

    def __reversed__(self):
        return reversed(xrange(*self.get_range()))

    def __str__(self):
        return '%s at $%0.8x' % (self.value, self.memaddr)

class BinaryDataConglomerate:
    def __init__(self, name, initial):
        self.binrepr = initial.binrepr
        self.symrepr = self.binrepr.symrepr
        self.symval = initial.symval
        self.dependencies = [initial]
        self.signed = True
        self.value = initial.value
        self.memaddr = initial.memaddr
        self.access_flags = 4

    def add(self, binrepr):
        self.dependencies.append(binrepr)

    def get_patch_data(self):
        return sum((x.get_patch_data() for x in self.dependencies), [])

    def __repr__(self):
        return 'Conglomeration summing to %d starting at $%x' % (self.value, self.memaddr)
