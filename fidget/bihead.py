# me
import claripy

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

    def __dir__(self):
        return dir(self.cleanval) + ['cleanval', 'dirtyval']

    def __repr__(self):
        return 'BiHead(%s, %s)' % (repr(self.cleanval), repr(self.dirtyval))

    def __getattr__(self, k):
        if k in ('cleanval', 'dirtyval', 'length'):
            return object.__getattribute__(self, k)
        cleanres, dirtyres = getattr(self.cleanval, k), getattr(self.dirtyval, k)
        if hasattr(cleanres, '__call__'):
            return self.bi_wrap(cleanres, dirtyres)
        if cleanres == dirtyres:
            return cleanres
        assert False

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

for op in ('abs', 'add', 'and', 'div', 'divmod', 'eq', 'floordiv', 'ge', 'gt', 'invert', 'le', 'len', 'lshift', 'lt', 'mod', 'mul', 'ne', 'neg', 'nonzero', 'or', 'pow', 'pos', 'radd', 'rand', 'rdivmod', 'rfloordiv', 'rlshift', 'rmod', 'rmul', 'ror', 'rpow', 'rrshift', 'rshift', 'rsub', 'truediv', 'rxor', 'sub', 'truediv', 'xor', 'getitem'):
    dundername = '__%s__' % op
    setattr(BiHead, dundername, BiHead.op_wrap(dundername))
del op
