# Home of the BlockState and SmartExpression classes
# Basically stuff for tracking data flow through a basic block and generating tags for it

class BlockState:
    def __init__(self, binrepr, use_bp):
        self.binrepr = binrepr
        self.regs = {}
        self.temps = {}

    def get_reg(self, regnum):
        pass

    def get_tmp(self, tmpnum):
        return self.temps[tmpnum]

class SmartExpression:
    def __init__(self, blockstate, vexpression, mark, path):
        self.blockstate = blockstate
        self.vexpression = vexpression
        self.mark = mark
        self.path = path
        self.cleanval = 0
        self.dirtyval = 0
        if vexpression.tag == 'Iex_Get':
            self += self.blockstate.get_reg(vexpression.offset)
        elif vexpression.tag == 'Iex_RdTmp':
            self += self.blockstate.get_tmp(vexpression.tmp)
        elif vexpression.tag == 'Iex_Load':
            

class ConstExpression:
    def __init__(self, val=0):
        self.cleanval = val
        self.dirtyval = val
