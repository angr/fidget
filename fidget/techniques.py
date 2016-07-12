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

        for var in stack:
            if var.conc_addr < 0:
                continue
            var.special_bottom = True
            l.debug("Marked BOTTOM addr %d as special", var.conc_addr)

        stack.collapse()
        stack.mark_sizes()

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

        stack.sym_link(solver, safe=self.safe)

