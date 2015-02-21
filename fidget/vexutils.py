import os

from .errors import FidgetUnsupportedError
import logging
l = logging.getLogger('fidget.vexutils')

# These are a giant mess of utility functions that are used in multiple spots.
# A lot are only good to make dealing with comparisons between vex structs tolerable.

# equals
# Compares two vex structs.
# it should be able to handle any two Statement or Expression structs.
# Disregards differences in temp numbers and IMark addresses.

def equals(a, b):
    if a.tag != b.tag: return False
    if a.tag == 'Ist_NoOp':
        return True
    elif a.tag == 'Ist_IMark':
        return a.len == b.len
    elif a.tag == 'Ist_WrTmp':
        return equals(a.data, b.data)
    elif a.tag == 'Ist_Store':
        return equals(a.addr, b.addr) and equals(a.data, b.data)
    elif a.tag == 'Ist_Put':
        return a.offset == b.offset and equals(a.data, b.data)
    elif a.tag == 'Ist_PutI':
        return str(a) == str(b)     # Nope.
    elif a.tag == 'Ist_Exit':
        return a.jk == b.jk and a.is_flat == b.is_flat and \
            equals(a.dst, b.dst) and equals(a.guard, b.guard)
    elif a.tag == 'Iex_Get':
        return a.offset == b.offset
    elif a.tag == 'Iex_RdTmp':
        return True
    elif a.tag == 'Iex_Const':
        return a.con.value == b.con.value
    elif a.tag == 'Iex_Load':
        return equals(a.addr, b.addr)
    elif a.tag == 'Iex_Unop':
        return a.op == b.op and equals(a.args[0], b.args[0])
    elif a.tag == 'Iex_Binop':
        return a.op == b.op and equals(a.args[0], b.args[0]) and equals(a.args[1], b.args[1])
    elif a.tag == 'Iex_Triop':
        return a.op == b.op and equals(a.args[0], b.args[0]) and equals(a.args[1], b.args[1]) and equals(a.args[2], b.args[2])
    elif a.tag == 'Iex_CCall':
        return True     # Nope.
    elif a.tag == 'Iex_ITE':
        return equals(a.iftrue, b.iftrue) and equals(a.iffalse, b.iffalse) and equals(a.cond, b.cond)
    elif a.tag == 'Iex_GetI':
        return str(a) == str(b) # fuck it
    elif a.tag.startswith('Ico'):
        return a.size == b.size and a.value == b.value
    else:
        raise FidgetUnsupportedError("Unknown tag (comparison): {}".format(a.tag))

def is_tmp_used(block, tmp):
    for stmt in block.statements:
        for expr in stmt.expressions:
            if expr.tag == 'Iex_RdTmp' and expr.tmp == tmp:
                return True
    return False

# {get,set}_from_path
# pass it any python objects and a list of keys
# it will traverse the object's tree with either attribute lookups
# or dict/list indexes and either return or assign to the value at the end of the path.
# Horriby hackish, but I'm not sure how else to do it :/

def get_from_path(obj, path):
    return _get_from_path(obj, list(path))  # make a copy of the path so it can be mutilated

def _get_from_path(obj, path):
    if len(path) == 0: return obj
    key = path.pop(0)
    if type(key) == int or type(obj) == dict:
        try:
            item = obj[key]
        except:
            return None
        return _get_from_path(item, path)
    if not hasattr(obj, key): return None
    return _get_from_path(getattr(obj, key), path)

def set_from_path(obj, path, value):
    return _set_from_path(obj, list(path), value)

def _set_from_path(obj, path, value):
    key = path.pop(0)
    if type(key) == int or type(obj) == dict:
        if path == []:
            obj[key] = value
        else:
            _set_from_path(obj[key], path, value)
    else:
        if path == []:
            setattr(obj, key, value)
        else:
            _set_from_path(getattr(obj, key), path, value)

# equals_except
# pass it two pyvex objects, a path (for the above functions), and a value
# it will return true if the value of b at that path is the passed value,
# and excepting that value, the two objects are identical.

def equals_except(a, b, path, val):
    if get_from_path(b, path) != val: return False
    oldval = get_from_path(a, path)
    if oldval is None: return False
    set_from_path(a, path, val)
    result = equals(a, b)
    set_from_path(a, path, oldval)
    return result

# get_stmt_num
# pass it a pyvex IRSB and a number-- it'll pull out the nth statement after
# the first Imark. Useful for when you're got an unoptimized pyvex and there
# are frigging no-ops everywhere.

def get_stmt_num(block, n):
    stmt_iterator = iter(block.statements)
    for stmt in stmt_iterator:
        if stmt.tag == 'Ist_IMark':
            break
    i = 0
    for stmt in stmt_iterator:
        if i == n:
            return stmt
        i += 1

def ZExtTo(size, vec):
    if type(vec) in (int, long): return vec
    return ExtTo(size, vec, vec.zero_extend)

def SExtTo(size, vec):
    if type(vec) in (int, long): return vec
    return ExtTo(size, vec, vec.sign_extend)

def ExtTo(size, vec, func):
    if vec.size() > size:
        return vec[size-1:0]
    return vec if vec.size() == size else func(size - vec.size())

def columnize(data):
    open('.coldat','w').write('\n'.join(data))
    _, columns = os.popen('stty size').read().split()
    os.system('column -c %d < .coldat 2>/dev/null' % int(columns))

def extract_int(s):
    return int(''.join(d for d in s if d.isdigit()))
