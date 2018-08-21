# me
import claripy
from collections import defaultdict

# pylint: disable=unidiomatic-typecheck
class BiHead(claripy.Bits):
    def __new__(cls, cleanval, dirtyval):
        self = object.__new__(cls)
        self.__init__(cleanval, dirtyval)
        return self

    def __init__(self, cleanval, dirtyval):
        assert type(cleanval) == type(dirtyval)
        assert cleanval.length == dirtyval.length
        super(BiHead, self).__init__(length=cleanval.length)

        self.cleanval = cleanval
        self.dirtyval = dirtyval
        self.taints = defaultdict(bool, deps=[])
        self._hash = hash((cleanval, dirtyval))
        self.symbolic = True

    def __dir__(self):
        return dir(self.cleanval) + ['cleanval', 'dirtyval']

    def __repr__(self, **kwargs):
        return 'BiHead(%s, %s)' % (self.cleanval.__repr__(**kwargs), self.dirtyval.__repr__(**kwargs))

    def __getattribute__(self, k):
        if k == 'op':
            return 'BVV'      # claim to be a simple value
        if k in ('cleanval', 'dirtyval', 'length', 'taints', '_hash', '__init__', 'make_uuid', 'raw_to_bv', 'raw_to_fp', 'to_bv') or (k in dir(BiHead) and k not in dir(claripy.Bits)):
            return object.__getattribute__(self, k)
        if hasattr(self.cleanval, k):
            cleanres, dirtyres = getattr(self.cleanval, k), getattr(self.dirtyval, k)
            if hasattr(cleanres, '__call__'):
                return self.bi_wrap(cleanres, dirtyres)
            if isinstance(cleanres, claripy.Bits) and type(cleanres) == type(dirtyres):
                return BiHead(cleanres, dirtyres)
            if cleanres == dirtyres:
                return cleanres

        if k in dir(BiHead):
            return object.__getattribute__(self, k)

    def __getitem__(self, where):
        out = BiHead(self.cleanval[where], self.dirtyval[where])
        out.taints['concrete'] = self.taints['concrete']
        out.taints['deps'] = self.taints['deps']
        return out

    def concat(self, *others):
        others = list(others)
        cleans = map(lambda x: x.cleanval, others)
        dirtys = map(lambda x: x.dirtyval, others)
        out = BiHead(self.cleanval.concat(*cleans), self.dirtyval.concat(*dirtys))
        out.taints['concrete'] = all(map(lambda x: x.taints['concrete'], [self] + others))
        out.taints['deps'] = sum(map(lambda x: x.taints['deps'], [self] + others), [])
        return out

    @property
    def reversed(self):
        out = BiHead(self.cleanval.reversed, self.dirtyval.reversed)
        out.taints['concrete'] = self.taints['concrete']
        out.taints['deps'] = self.taints['deps']
        out.taints['reversed_pointer'] = self.taints['pointer']
        out.taints['pointer'] = self.taints['reversed_pointer']
        out.taints['it'] = self.taints['it']
        return out

    def raw_to_bv(self):
        if isinstance(self.cleanval, claripy.ast.BV):
            return self
        out = BiHead(self.cleanval.to_bv(), self.cleanval.to_bv())
        out.taints['deps'] = self.taints['deps']
        out.taints['concrete'] = self.taints['concrete']
        return out

    def raw_to_fp(self):
        if isinstance(self.cleanval, claripy.ast.FP):
            return self
        out = BiHead(self.cleanval.raw_to_fp(), self.cleanval.raw_to_fp())
        out.taints['deps'] = self.taints['deps']
        out.taints['concrete'] = self.taints['concrete']
        return out

    def val_to_bv(self, *args, **kwargs):
        if isinstance(self.cleanval, claripy.ast.BV):
            return self
        out = BiHead(self.cleanval.val_to_bv(*args, **kwargs), self.cleanval.val_to_bv(*args, **kwargs))
        out.taints['deps'] = self.taints['deps']
        out.taints['concrete'] = self.taints['concrete']
        return out

    def val_to_fp(self, *args, **kwargs):
        if isinstance(self.cleanval, claripy.ast.FP):
            return self
        out = BiHead(self.cleanval.val_to_fp(*args, **kwargs), self.cleanval.val_to_fp(*args, **kwargs))
        out.taints['deps'] = self.taints['deps']
        out.taints['concrete'] = self.taints['concrete']
        return out

    @property
    def as_unsigned(self):
        return self.cleanval._model_concrete.value

    @property
    def as_signed(self):
        return self.cleanval._model_concrete.signed

    def make_uuid(self, uuid=None):   # pylint: disable=unused-argument
        pass

    @staticmethod
    def op_wrap(op):
        def inner_func(self, *args, **kwargs):
            if any(map(lambda arg: isinstance(arg, BiHead), args)):
                cleanargs = map(lambda arg: arg.cleanval if isinstance(arg, BiHead) else arg, args)
                dirtyargs = map(lambda arg: arg.dirtyval if isinstance(arg, BiHead) else arg, args)
                cleanres = getattr(self.cleanval, op)(*cleanargs, **kwargs)
                dirtyres = getattr(self.dirtyval, op)(*dirtyargs, **kwargs)
                return BiHead.make_result(cleanres, dirtyres)
            else:
                return BiHead.bi_wrap(getattr(self.cleanval, op), getattr(self.dirtyval, op))(*args, **kwargs)
        return inner_func

    @staticmethod
    def bi_wrap(cleanfunc, dirtyfunc):
        def inner_func(*args, **kwargs):
            cleanres = cleanfunc(*args, **kwargs)
            dirtyres = dirtyfunc(*args, **kwargs)
            return BiHead.make_result(cleanres, dirtyres)
        return inner_func

    @staticmethod
    def make_result(cleanres, dirtyres):
        assert type(cleanres) == type(dirtyres)
        if isinstance(cleanres, claripy.Bits):
            return BiHead(cleanres, dirtyres)
        if cleanres == dirtyres:
            return cleanres
        assert False

    @staticmethod
    def default(ty):
        size = int(''.join(c for c in ty if c in '0123456789'))
        fp = ty.startswith('Ity_F')
        if not fp:
            return BiHead(claripy.BVV(0, size), claripy.BVV(0, size))
        else:
            if size == 32:
                sort = claripy.fp.FSORT_FLOAT
            elif size == 64:
                sort = claripy.fp.FSORT_DOUBLE
            else:
                raise ValueError("Bad float size: %d" % size)
            return BiHead(claripy.FPV(0.0, sort), claripy.FPV(0.0, sort))

opname = None
for opname in ('abs', 'add', 'and', 'div', 'divmod', 'eq', 'floordiv', 'ge', 'gt', 'invert', 'le', 'len', 'lshift', 'lt', 'mod', 'mul', 'ne', 'neg', 'nonzero', 'or', 'pow', 'pos', 'radd', 'rand', 'rdivmod', 'rfloordiv', 'rlshift', 'rmod', 'rmul', 'ror', 'rpow', 'rrshift', 'rshift', 'rsub', 'truediv', 'rxor', 'sub', 'truediv', 'xor'):
    dundername = '__%s__' % opname
    setattr(BiHead, dundername, BiHead.op_wrap(dundername))
del opname
