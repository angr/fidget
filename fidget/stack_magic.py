import bisect

import logging
l = logging.getLogger('fidget.stack_magic')

class Access(object):
    def __init__(self, bindata):
        self.bindata = bindata
        self.offset = 0
        self.special = False

    @property
    def access_flags(self):
        return self.bindata.access_flags

    @property
    def conc_addr(self):
        return self.bindata.value

    @property
    def sym_addr(self):
        return self.bindata.symval

    def get_patches(self, symrepr):
        return self.bindata.get_patch_data(symrepr)

    def sym_link(self, variable, symrepr):
        self.bindata.apply_constraints(symrepr)
        symrepr.add(self.sym_addr - self.offset == variable.sym_addr)

class Variable(object):
    def __init__(self, address, sym_addr):
        self.conc_addr = address
        self.sym_addr = sym_addr

        self.accesses = []
        self.access_flags = 0
        self.special = self.conc_addr >= 0
        self.size = None
        self.unsafe_constraints = []

    def add_access(self, access):
        self.accesses.append(access)
        access.offset = access.conc_addr - self.conc_addr
        if access.access_flags == 1 and self.access_flags == 0:
            self.access_flags = 9
        else:
            self.access_flags |= access.access_flags

    def merge(self, child):
        for access in child.accesses:
            self.add_access(access)

    def sym_link(self, symrepr, stack):
        for access in self.accesses:
            access.sym_link(self, symrepr)

        if self.special:
            if self.conc_addr >= 0:   # fix in place relative to the base pointer
                symrepr.add(self.sym_addr == self.conc_addr)
            else:               # fix in place relative to the stack pointer
                symrepr.add(self.sym_addr == (self.conc_addr - stack.conc_size) + stack.sym_size)
            return

        self.unsafe_constraints.append(self.sym_addr < self.conc_addr)

    def get_patches(self, symrepr):
        return sum((access.get_patches(symrepr) for access in self.accesses), [])

class Stack():
    def __init__(self, binrepr, symrepr, stack_size):
        self.variables = {} # all the variables, indexed by address
        self.addr_list = [] # all the addresses, kept sorted
        self.binrepr = binrepr
        self.symrepr = symrepr
        self.conc_size = stack_size
        self.sym_size = symrepr._claripy.BV("stack_size", binrepr.angr.arch.bits)
        self.unsafe_constraints = [self.sym_size > self.conc_size]

    def __iter__(self):
        for addr in self.addr_list:
            yield self.variables[addr]

    def access(self, bindata):
        access = Access(bindata)
        if access.conc_addr < - self.conc_size:
            access.special = True

        if access.conc_addr not in self.variables:
            name_prefix = 'var' if access.conc_addr < 0 else 'arg'
            sym_addr = self.symrepr._claripy.BV('%s_%x' % (name_prefix, abs(access.conc_addr)), self.binrepr.angr.arch.bits)
            self.add_variable(Variable(access.conc_addr, sym_addr))
        self.variables[access.conc_addr].add_access(access)

    def add_variable(self, var):
        self.variables[var.conc_addr] = var
        bisect.insort(self.addr_list, var.conc_addr)

    @property
    def all_accs(self):
        return sum(map(lambda x: x.accesses, self.all_vars), [])

    @property
    def all_vars(self):
        return map(lambda x: self.variables[x], self.addr_list)

    @property
    def num_accs(self):
        return len(self.all_accs)

    @property
    def num_vars(self):
        return len(self.variables)

    @property
    def patches(self):
        return sum((var.get_patches(self.symrepr) for var in self), [])

    def sym_link(self):
        self.symrepr.add(self.sym_size >= self.conc_size)
        self.symrepr.add(self.sym_size <= self.conc_size + (16 * self.num_vars + 32))
        self.symrepr.add(self.sym_size % (self.binrepr.angr.arch.bytes) == 0)

        first = self.variables[self.addr_list[0]]
        self.symrepr.add(first.sym_addr >= (first.conc_addr + self.conc_size) - self.sym_size)
        var_list = list(self)
        for var, next_var in zip(var_list, var_list[1:] + [None]):
            var.sym_link(self.symrepr, self)
            self.unsafe_constraints.extend(var.unsafe_constraints)
            if var.conc_addr % (self.binrepr.angr.arch.bytes) == 0:
                self.symrepr.add(var.sym_addr % (self.binrepr.angr.arch.bytes) == 0)

            if var.special:
                # We're one of the args that needs to stay fixed relative somewhere
                pass
            elif next_var is None or next_var.special:
                # If we're the last free-floating variable, set a solid bottom
                self.symrepr.add(var.sym_addr <= var.conc_addr)
            else:
                # Otherwise we're one of the free-floating variables
                if self.binrepr.safe:
                    self.symrepr.add(var.sym_addr + var.size == next_var.sym_addr)
                else:
                    self.symrepr.add(var.sym_addr + var.size <= next_var.sym_addr)

    def collapse(self):
        i = 0               # old fashioned loop because we're removing items
        while i < len(self.addr_list) - 1:
            i += 1
            var = self.variables[self.addr_list[i]]
            if var.special:
                continue
            if var.conc_addr % (self.binrepr.angr.arch.bytes) != 0:
                self.merge_up(i)
                i -= 1
            elif var.access_flags & 8:
                self.merge_up(i)
                i -= 1
            elif var.access_flags & 4:
                pass
            elif var.access_flags != 3:
                self.merge_up(i)
                i -= 1

    def merge_up(self, i):
        child = self.variables.pop(self.addr_list.pop(i))
        parent = self.variables[self.addr_list[i-1]]
        parent.merge(child)
        l.debug('Merged %s into %s', hex(child.conc_addr), hex(parent.conc_addr))

    def merge_down(self, i):
        child = self.variables.pop(self.addr_list.pop(i))
        parent = self.variables[self.addr_list[i]]
        parent.merge(child)
        l.debug('Merged %s down to %s', hex(child.conc_addr), hex(parent.conc_addr))

    def mark_sizes(self):
        for i, addr in enumerate(self.addr_list[:-1]):
            var = self.variables[addr]
            next_var = self.variables[self.addr_list[i+1]]
            var.size = next_var.conc_addr - var.conc_addr
        var = self.variables[self.addr_list[-1]]
        var.size = None


