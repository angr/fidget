# These are a giant mess of utility functions to make dealing with comparisons
# between vex structs. The most important are by far the equals and equals_except functions

# equals
# Compares two vex structs.
# it should be able to handle any two Statement or Expression structs.

def equals(a, b):
    if a.tag != b.tag: return False
    if a.tag == 'Ist_NoOp':
        return True
    elif a.tag == 'Ist_IMark':
        return a.len == b.len
    elif a.tag == 'Ist_WrTmp':
        return a.tmp == b.tmp and equals(a.data, b.data)
    elif a.tag == 'Ist_Store':
        return equals(a.addr, b.addr) and equals(a.data, b.data)
    elif a.tag == 'Ist_Put':
        return a.offset == b.offset and equals(a.data, b.data)
    elif a.tag == 'Iex_Get':
        return a.offset == b.offset
    elif a.tag == 'Iex_BinOp':
        return a.op == b.op and equals(a.arg1, b.arg1) and equals(a.arg2, b.arg2)
    elif a.tag == 'Iex_RdTmp':
        return a.tmp == b.tmp
    elif a.tag == 'Iex_Const':
        return a.con.value == b.con.value
    elif a.tag == 'Iex_Load':
        return equals(a.addr, b.addr)
    elif a.tag == 'Iex_Unop':
        return a.op == b.op and equals(a.arg1, b.arg1)
    elif a.tag == 'Iex_Triop':
        return a.op == b.op and equals(a.arg1, b.arg1) and equals(a.arg2, b.arg2) and equals(a.arg3, b.arg3)
    else:
        raise Exception("Unknown tag: %s" % a.tag)

# {get,set}_from_path
# pass it any python objects and a list of keys
# it will traverse the object's tree with either attribute lookups
# or dict/list indexes and either return or assign to the value at the end of the path.
# Horriby hackish, but I'm not sure how else to do it :/

def get_from_path(obj, path):
    if len(path) == 0: return obj
    key = path.pop(0)
    if type(key) == int or type(obj) == dict:
        if key not in obj: return None
        return get_from_path(obj[key], path)
    if not hasattr(obj, key): return None
    return get_from_path(getattr(obj, key), path)

def set_from_path(obj, path, value):
    key = path.pop(0)
    if type(key) == int or type(obj) == dict:
        if path == []:
            obj[key] = value
        else:
            set_from_path(obj[key], path, value)
    else:
        if path == []:
            setattr(obj, key, value)
        else:
            set_from_path(getattr(obj, key), path)

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
