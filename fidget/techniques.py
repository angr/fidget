import claripy

import logging
l = logging.getLogger('fidget.techniques')

class FidgetTechnique(object):
    project = None
    def constrain_variables(self, func, solver, stack):
        raise NotImplementedError()

    def set_project(self, project):
        self.project = project

class FidgetDefaultTechnique(FidgetTechnique):
    def __init__(self, largemode=False, safe=False):
        self.largemode = largemode
        self.safe = safe

    def constrain_variables(self, func, solver, stack):
        # Find the lowest sp-access that isn't an argument to the next function
        # By starting at accesses to [esp] and stepping up a word at a time
        if self.project.arch.name == 'X86':
            last_addr = -stack.conc_size
            for var in stack:
                if var.conc_addr != last_addr:
                    break
                last_addr += self.project.arch.bytes
                #var.special_top = True
                #l.debug("Marked TOP addr %d as special", var.conc_addr)

        #last_addr = None
        #for var in reversed(stack):
        #    if last_addr is None:
        #        if var.conc_addr < 0:
        #            break       # why would this happen
        #        last_addr = var.conc_addr
        #    if var.conc_addr != last_addr:
        #        break
        #    last_addr -= self.project.arch.bytes
        #    var.special_bottom = True
        #    l.debug("Marked BOTTOM addr %d as special", var.conc_addr)

        self.collapse(stack)
        self.mark_sizes(stack)

        stack.alloc_op.apply_constraints(solver)
        solver.add(stack.alloc_op.symval == -stack.sym_size)
        for op in stack.dealloc_ops:
            op.apply_constraints(solver)
            solver.add(op.symval == 0)

        if self.largemode and not self.safe:
            solver.add(stack.sym_size <= stack.conc_size + (1024 * stack.num_vars + 2048))
            stack.unsafe_constraints.append(stack.sym_size >= stack.conc_size + (1024 * stack.num_vars))
            stack.unsafe_constraints.append(stack.sym_size >= 0x78)
            stack.unsafe_constraints.append(stack.sym_size >= 0xF8)
        elif self.largemode and self.safe:
            solver.add(stack.sym_size <= stack.conc_size + 1024*16)
            stack.unsafe_constraints.append(stack.sym_size >= stack.conc_size + 1024*8)
            stack.unsafe_constraints.append(stack.sym_size >= 0x78)
            stack.unsafe_constraints.append(stack.sym_size >= 0xF0)
        elif not self.largemode and self.safe:
            solver.add(stack.sym_size <= stack.conc_size + 256)
        elif not self.largemode and not self.safe:
            solver.add(stack.sym_size <= stack.conc_size + (16 * stack.num_vars + 32))

        self.sym_link(stack, solver)

    def sym_link(self, stack, solver):
        solver.add(stack.sym_size >= stack.conc_size)
        solver.add(stack.sym_size % (stack.arch.bytes) == 0)
        stack.unsafe_constraints.append(stack.sym_size > stack.conc_size)

        first = stack.variables[stack.addr_list[0]]
        solver.add(first.sym_addr >= (first.conc_addr + stack.conc_size) - stack.sym_size)
        var_list = list(stack)
        for var, next_var in zip(var_list, var_list[1:] + [None]):
            var.sym_link(solver, stack)
            stack.unsafe_constraints.extend(var.unsafe_constraints)
            if var.conc_addr % (stack.arch.bytes) == 0:
                solver.add(var.sym_addr % (stack.arch.bytes) == 0)

            if var.special:
                # We're one of the args that needs to stay fixed relative somewhere
                pass
            elif next_var is None or next_var.special:
                # If we're the last free-floating variable, set a solid bottom
                solver.add(var.sym_addr <= var.conc_addr)
                if var.size is not None:
                    solver.add(claripy.SLE(var.sym_addr, var.sym_addr + var.size))
                    solver.add(var.sym_addr + var.size <= next_var.sym_addr)
                    stack.unsafe_constraints.append(var.sym_addr + var.size < next_var.sym_addr)
            else:
                # Otherwise we're one of the free-floating variables
                solver.add(var.sym_addr <= var.sym_addr + var.size)
                stack.unsafe_constraints.append(var.sym_addr + var.size < next_var.sym_addr)
                if self.safe:
                    solver.add(var.sym_addr + var.size == next_var.sym_addr)
                else:
                    solver.add(var.sym_addr + var.size <= next_var.sym_addr)

    @staticmethod
    def collapse(stack):
        i = 0               # old fashioned loop because we're removing items
        while i < len(stack.addr_list) - 1:
            i += 1
            var = stack.variables[stack.addr_list[i]]
            if var.special:
                continue
            #if var.conc_addr % (stack.arch.bytes) != 0:
            #    stack.merge_up(i)
            #    i -= 1
            if var.access_flags & 8:
                stack.merge_up(i)
                i -= 1
            elif var.access_flags & 4:
                pass
            elif var.access_flags != 3:
                stack.merge_up(i)
                i -= 1

    @staticmethod
    def mark_sizes(stack):
        for i, addr in enumerate(stack.addr_list[:-1]):
            var = stack.variables[addr]
            next_var = stack.variables[stack.addr_list[i+1]]
            var.size = next_var.conc_addr - var.conc_addr
        var = stack.variables[stack.addr_list[-1]]
        var.size = None


class FidgetManualTechnique(FidgetTechnique):
    def __init__(self, funcdata):
        """
        :param funcdata:    A dict mapping functions to dicts {addr: (size, fix, align)} of var info
                            - addr is an offset relative to the stack pointer at function entry
                            - size is the size in bytes
                            - fix is a string "TOP", "BOTTOM" or None, describing if a var needs
                            to be fixed relative to the top (low addresses) or bottom (high addrs)
                            of the stack frame
                            - align is the alignment required for the variable
        """
        self.funcdata = funcdata
        self.offsets = None
        self.bounds_marked = None
        self.stack = None
        self.solver = None

    def constrain_variables(self, func, solver, stack):
        self.offsets = self.funcdata[func.addr]
        self.bounds_marked = set()
        self.stack = stack
        self.solver = solver

        # do some sanity checking first
        top = min(self.offsets)
        for addr in stack.addr_list:
            if addr < top:
                raise Exception("Provided vars miss an access (off the top!)")
            base_addr = addr
            while base_addr not in self.offsets:
                base_addr -= 1
            this_offset = addr - base_addr
            if this_offset >= self.offsets[base_addr][0]:
                raise Exception("Provided vars miss an access (between the cracks!)")

        i = 0
        while i < len(stack.addr_list):
            addr = stack.addr_list[i]
            if addr in self.offsets:
                if i != 0 and self.offsets[stack.addr_list[i-1]][0] + stack.addr_list[i-1] > addr:
                    raise Exception("Provided vars have an overlap!")
                i += 1
                continue
            stack.merge_up(i)

        # standard stuff
        stack.alloc_op.apply_constraints(solver)
        solver.add(stack.alloc_op.symval == -stack.sym_size)
        for op in stack.dealloc_ops:
            op.apply_constraints(solver)
            solver.add(op.symval == 0)

        solver.add(stack.sym_size % stack.arch.bytes == 0)
        solver.add(claripy.SGE(stack.sym_size, stack.conc_size))
        stack.unsafe_constraints.append(claripy.SGT(stack.sym_size, stack.conc_size))
        stack.unsafe_constraints.append(claripy.SGE(stack.sym_size, stack.conc_size * 2))
        stack.unsafe_constraints.append(claripy.SLT(stack.sym_size, stack.conc_size * 3))

        # loop through variables, add the important constraints!
        i = 0
        while i < len(stack.addr_list):
            addr = stack.addr_list[i]
            var = stack.variables[addr]
            var.size = self.offsets[addr][0]
            fix = self.offsets[addr][1]
            if fix == 'TOP':
                var.special_top = True
            elif fix == 'BOTTOM':
                var.special_bottom = True

            align = self.offsets[addr][2]
            if align != 1:
                solver.add(var.sym_addr % align == 0)
            var.sym_link(solver, stack) # this hooks up the constrains to actual immediates
            # also the top/bottom fixing happens in there

            if i != 0:
                prev_var = stack.variables[stack.addr_list[i-1]]
                self.mark_boundaries(prev_var, var)
            if i != len(stack.addr_list) - 1:
                next_var = stack.variables[stack.addr_list[i+1]]
                self.mark_boundaries(var, next_var)

                # ew. ew ew ew ew ew ew!!!
                diff = next_var.conc_addr - var.conc_addr
                solver.add(claripy.SLT(var.sym_addr, var.sym_addr + diff))
            if i == 0:
                solver.add(claripy.SLE(-stack.sym_size, var.sym_addr))


            i += 1

    def mark_boundaries(self, var_1, var_2):
        key = (var_1.conc_addr, var_2.conc_addr)
        if key in self.bounds_marked:
            return
        self.bounds_marked.add(key)
        diff = var_2.conc_addr - var_1.conc_addr
        self.solver.add(claripy.SLE(var_1.sym_addr + diff, var_2.sym_addr))
        self.stack.unsafe_constraints.append(claripy.SLT(var_1.sym_addr + diff, var_2.sym_addr))
