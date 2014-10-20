import bisect

from . import vexutils

import logging
l = logging.getLogger('fidget.stack_magic')

class Access():
    def __init__(self, bindata, varlist, special=False):
        self.bindata = bindata
        self.value = bindata.value
        self.varlist = varlist
        self.binrepr = varlist.binrepr
        self.symrepr = varlist.symrepr

        self.access_flags = bindata.access_flags   # get access flags
        Variable(varlist, self, special)           # make a variable or add it to an existing one
        self.variable = varlist[self.address()]    # get reference to variable
        self.offset_variable = 0

    def address(self):
        return self.value

    def sym_link(self):
        self.value = vexutils.SExtTo(64, self.bindata.symval)
        self.bindata.apply_constraints(self.symrepr)
        self.symrepr.add(self.address() - self.offset_variable == self.variable.address)

    def get_patches(self):
        return self.bindata.get_patch_data(self.symrepr)

class Variable():
    def __init__(self, varlist, access, special=False):
        if access.address() in varlist:
            varlist[access.address()].add_access(access)
            return
        self.varlist = varlist
        self.binrepr = varlist.binrepr
        self.symrepr = varlist.symrepr
        self.address = access.address()
        self.accesses = []
        self.access_flags = 0
        self.add_access(access)
        varlist.add_variable(self)
        self.special = self.address >= 0 or special
        self.next = None
        self.size = None

    def add_access(self, access):
        self.accesses.append(access)
        access.offset_variable = access.address() - self.address
        if access.access_flags == 1 and self.access_flags == 0:
            self.access_flags = 9
        else:
            self.access_flags |= access.access_flags

    def merge(self, child):
        for access in child.accesses:
            access.offset_variable = access.address() - self.address
            self.accesses.append(access)
            access.variable = self

    def sym_link(self):
        org_addr = self.address
        name_prefix = 'var' if org_addr < 0 else 'arg'
        self.address = self.symrepr._claripy.BitVec('%s_%x' % (name_prefix, abs(org_addr)), 64)
        for access in self.accesses: access.sym_link()
        if self.special:
            if org_addr >= 0:
                self.symrepr.add(self.address == org_addr)
            else:
                self.symrepr.add(self.address == (org_addr - self.varlist.old_size) + self.varlist.stack_size)
            if self.next is not None:
                self.next.sym_link()
            return
        if not self.varlist.done_first:
            self.varlist.done_first = True
            self.symrepr.add(self.address >= (org_addr + self.varlist.old_size) - self.varlist.stack_size)
        if org_addr % (self.binrepr.native_word / 8) == 0:
            self.symrepr.add(self.address % (self.binrepr.native_word/8) == 0)
        self.varlist.unsafe_constraints.append(self.address < org_addr)
        if self.next is None or self.next.special:
            self.symrepr.add(self.address <= org_addr)
        if self.next is not None:
            self.next.sym_link()
        if self.next is not None and not self.next.special:
            if self.binrepr.safe:
                self.symrepr.add(self.address + self.size == self.next.address)
            else:
                self.symrepr.add(self.address + self.size <= self.next.address)

    def get_patches(self):
        return sum((access.get_patches() for access in self.accesses), [])

class VarList():
    def __init__(self, binrepr, symrepr, stack_size):
        self.variables = {} # all the variables, indexed by address
        self.addr_list = [] # all the addresses, kept sorted
        self.binrepr = binrepr
        self.symrepr = symrepr
        self.stack_size = stack_size
        self.old_size = stack_size
        self.unsafe_constraints = []
        self.done_first = False

    def __getitem__(self, key):
        return self.variables[key]

    def __delitem__(self, key):
        del self.variables[key]
        self.addr_list.remove(key)

    def __contains__(self, val):
        return val in self.variables

    def __len__(self):
        return len([0 for x in self.variables if not self.variables[x].special])

    def add_variable(self, var):
        self.variables[var.address] = var
        bisect.insort(self.addr_list, var.address)

    def num_accesses(self):
        return sum(map(lambda x: len(x.accesses), self.get_all_vars()))

    def get_all_vars(self):
        return map(lambda x: self.variables[x], self.addr_list)

    def sym_link(self):
        first = self.variables[self.addr_list[0]]
        first.sym_link()        # yaaay recursion and list linkage!

    def collapse(self):
        i = 0               # old fashioned loop because we're removing items
        while i < len(self.addr_list) - 1:
            i += 1
            var = self.variables[self.addr_list[i]]
            if var.special:
                continue
            if var.address % (self.binrepr.native_word / 8) != 0:
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
        l.debug('Merged %s into %s', hex(child.address), hex(parent.address))

    def merge_down(self, i):
        child = self.variables.pop(self.addr_list.pop(i))
        parent = self.variables[self.addr_list[i]]
        parent.merge(child)
        l.debug('Merged %s down to %s', hex(child.address), hex(parent.address))

    def get_patches(self):
        return sum((var.get_patches() for var in self.get_all_vars()), [])

    def mark_sizes(self):
        for i, addr in enumerate(self.addr_list[:-1]):
            var = self.variables[addr]
            var.next = self.variables[self.addr_list[i+1]]
            var.size = var.next.address - var.address
        var = self.variables[self.addr_list[-1]]
        var.next = None
        var.size = self.stack_size - var.address


