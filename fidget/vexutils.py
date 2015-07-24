from pyvex import IRSB
import claripy
from .errors import FidgetUnsupportedError

# These are a giant mess of utility functions that are used in multiple spots.
# A lot are only good to make dealing with comparisons between vex structs tolerable.

# equals
# Compares two IRSBs.
# Returns an iterator that yields sets of tuples of primitive values
# If all the tuples it yields have the same values, then they are equal

def equals(item1, item2):
    if not isinstance(item1, IRSB) or not isinstance(item2, IRSB):
        yield (True, False)
        return
    queue = zip(item1.statements, item2.statements)

    while len(queue) > 0:
        a, b = queue.pop()
        yield (a.tag, b.tag)
        if a.tag == 'Ist_NoOp':
            pass
        elif a.tag == 'Ist_IMark':
            yield (a.len, b.len)
            yield (a.addr, b.addr)
        elif a.tag == 'Ist_WrTmp':
            queue.append((a.data, b.data))
        elif a.tag == 'Ist_Store':
            queue.append((a.addr, b.addr))
            queue.append((a.data, b.data))
        elif a.tag == 'Ist_Put':
            yield (a.offset, b.offset)
            queue.append((a.data, b.data))
        elif a.tag == 'Ist_PutI':
            yield (str(a), str(b))      # Nope.
        elif a.tag == 'Ist_Exit':
            yield (a.jk, b.jk)
            queue.append((a.dst, b.dst))
            queue.append((a.guard, b.guard))
        elif a.tag == 'Ist_StoreG':
            yield (a.end, b.end)
            queue.append((a.addr, b.addr))
            queue.append((a.data, b.data))
            queue.append((a.guard, b.guard))
        elif a.tag == 'Ist_LoadG':
            yield (a.dst, b.dst)
            yield (a.cvt, b.cvt)
            yield (a.end, b.end)
            queue.append((a.addr, b.addr))
            queue.append((a.alt, b.alt))
            queue.append((a.guard, b.guard))
        elif a.tag == 'Iex_Get':
            yield (a.offset, b.offset)
        elif a.tag == 'Iex_RdTmp':
            pass
        elif a.tag == 'Iex_Const':
            yield (a.con.value, b.con.value)
        elif a.tag == 'Iex_Load':
            queue.append((a.addr, b.addr))
        elif a.tag in ('Iex_Unop', 'Iex_Binop', 'Iex_Triop', 'Iex_Quop'):
            yield (a.op, b.op)
            queue += zip(a.args, b.args)
        elif a.tag == 'Iex_CCall':
            pass     # Nope.
        elif a.tag == 'Iex_ITE':
            queue.append((a.iftrue, b.iftrue))
            queue.append((a.iffalse, b.iffalse))
            queue.append((a.cond, b.cond))
        elif a.tag == 'Iex_GetI':
            yield (str(a), str(b))  # fuck it
        elif a.tag.startswith('Ico'):
            yield (a.size, b.size)
            yield (a.value, b.value)
        else:
            raise FidgetUnsupportedError("Unknown tag (comparison): {}".format(a.tag))

# get_from_path
# pass it any python objects and a list of keys
# it will traverse the object's tree with either attribute lookups
# or dict/list indexes and return the value at the end of the path.
# Horriby hackish, but I'm not sure how else to do it :/

def get_from_path(obj, path):
    return _get_from_path(obj, list(path))  # make a copy of the path so it can be mutilated

def _get_from_path(obj, path):
    if len(path) == 0: return obj
    key = path.pop(0)
    if isinstance(key, (int, dict)):
        return _get_from_path(obj[key], path)
    return _get_from_path(getattr(obj, key), path)

def ZExtTo(size, vec):
    if isinstance(vec, (int, long)): return vec
    if vec.size() == size: return vec
    return ExtTo(size, vec, vec.zero_extend)

def SExtTo(size, vec):
    if isinstance(vec, (int, long)): return vec
    if vec.size() == size: return vec
    return ExtTo(size, vec, vec.sign_extend)

def ExtTo(size, vec, func):
    if vec.size() > size:
        return vec[size-1:0]
    return vec if vec.size() == size else func(size - vec.size())

def extract_int(s):
    return int(''.join(d for d in s if d.isdigit()))

def make_default_value(clrp, ty):
    if 'F' in ty:
        if '32' in ty:
            return clrp.FPV(0.0, claripy.FSORT_FLOAT)
        elif '64' in ty:
            return clrp.FPV(0.0, claripy.FSORT_DOUBLE)
        else:
            raise ValueError("Unknown float type %s" % ty)
    else:
        return clrp.BVV(0, extract_int(ty))
