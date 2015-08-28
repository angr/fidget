import claripy
import bisect

import logging
l = logging.getLogger('fidget.stack_magic')

class Access(object):
    def __init__(self, bindata):
        self.bindata = bindata
        self.offset = 0

    @property
    def access_flags(self):
        return self.bindata.access_flags

    @property
    def conc_addr(self):
        return self.bindata.value

    @property
    def sym_addr(self):
        return self.bindata.symval

    def get_patches(self, solver):
        return self.bindata.get_patch_data(solver)

    def sym_link(self, variable, solver):
        self.bindata.apply_constraints(solver)
        solver.add(self.sym_addr - self.offset == variable.sym_addr)

class Variable(object):
    def __init__(self, address, sym_addr):
        self.conc_addr = address
        self.sym_addr = sym_addr

        self.accesses = []
        self.access_flags = 0
        self.special_bottom = self.conc_addr >= 0
        self.special_top = False
        self.size = None
        self.unsafe_constraints = []

    @property
    def special(self):
        return self.special_bottom or self.special_top

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

    def sym_link(self, solver, stack):
        for access in self.accesses:
            access.sym_link(self, solver)

        if self.special_bottom:
            solver.add(self.sym_addr == self.conc_addr)
        if self.special_top:
            solver.add(self.sym_addr == (self.conc_addr - stack.conc_size) + stack.sym_size)
        if self.special:
            return

        #self.unsafe_constraints.append(self.sym_addr < self.conc_addr)

    def get_patches(self, solver):
        return sum((access.get_patches(solver) for access in self.accesses), [])

class Stack():
    def __init__(self, binrepr, solver, stack_size):
        self.variables = {} # all the variables, indexed by address
        self.addr_list = [] # all the addresses, kept sorted
        self.binrepr = binrepr
        self.solver = solver
        self.conc_size = stack_size
        self.sym_size = claripy.BV("stack_size", binrepr.angr.arch.bits)
        self.unsafe_constraints = []

    def __iter__(self):
        for addr in self.addr_list:
            yield self.variables[addr]

    def __reversed__(self):
        for addr in reversed(self.addr_list):
            yield self.variables[addr]

    def access(self, bindata):
        access = Access(bindata)
        #if access.conc_addr < -self.conc_size:
        #    access.special_top = True

        if access.conc_addr not in self.variables:
            name_prefix = 'var' if access.conc_addr < 0 else 'arg'
            sym_addr = claripy.BV('%s_%x' % (name_prefix, abs(access.conc_addr)), self.binrepr.angr.arch.bits)
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
        return sum((var.get_patches(self.solver) for var in self), [])

    def sym_link(self, safe=False):
        self.solver.add(self.sym_size >= self.conc_size)
        self.solver.add(self.sym_size % (self.binrepr.angr.arch.bytes) == 0)
        self.unsafe_constraints.append(self.sym_size > self.conc_size)

        first = self.variables[self.addr_list[0]]
        self.solver.add(first.sym_addr >= (first.conc_addr + self.conc_size) - self.sym_size)
        var_list = list(self)
        for var, next_var in zip(var_list, var_list[1:] + [None]):
            var.sym_link(self.solver, self)
            self.unsafe_constraints.extend(var.unsafe_constraints)
            if var.conc_addr % (self.binrepr.angr.arch.bytes) == 0:
                self.solver.add(var.sym_addr % (self.binrepr.angr.arch.bytes) == 0)

            if var.special:
                # We're one of the args that needs to stay fixed relative somewhere
                pass
            elif next_var is None or next_var.special:
                # If we're the last free-floating variable, set a solid bottom
                self.solver.add(var.sym_addr <= var.conc_addr)
                if var.size is not None:
                    self.solver.add(var.sym_addr <= var.sym_addr + var.size)
                    self.solver.add(var.sym_addr + var.size <= next_var.sym_addr)
                    self.unsafe_constraints.append(var.sym_addr + var.size < next_var.sym_addr)
            else:
                # Otherwise we're one of the free-floating variables
                self.solver.add(var.sym_addr <= var.sym_addr + var.size)
                self.unsafe_constraints.append(var.sym_addr + var.size < next_var.sym_addr)
                if safe:
                    self.solver.add(var.sym_addr + var.size == next_var.sym_addr)
                else:
                    self.solver.add(var.sym_addr + var.size <= next_var.sym_addr)

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

    def mark_sizes(self):
        for i, addr in enumerate(self.addr_list[:-1]):
            var = self.variables[addr]
            next_var = self.variables[self.addr_list[i+1]]
            var.size = next_var.conc_addr - var.conc_addr
        var = self.variables[self.addr_list[-1]]
        var.size = None


