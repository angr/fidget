import angr
import simuvex
from simuvex import s_type_backend, s_type
import logging
import collections

l = logging.getLogger('angr.analyses.offset_analysis')

class AnalysisFailure(Exception):
    pass

class Access(object):
    def __init__(self, addr, idx, is_write):
        self.addr = addr
        self.idx = idx
        self.is_write = is_write
        self.struct = None

    def __repr__(self):
        return 'Access(%#x, %d, %s)' % (self.addr, self.idx, str(self.is_write))

class SimStructAbstract(s_type.SimType):
    def __init__(self, label=None):
        super(SimStructAbstract, self).__init__(label)
        self.offsets = collections.defaultdict(list)

    def __repr__(self):
        return '<Abstract Struct with %d offsets%s>' % (len(self.offsets), ' (%s)'%self.label.name if self.label is not None else '')

class ValueSource(object):
    def __init__(self, source, offset, name=None):
        self.source = source
        self.offset = offset
        self.name = name
        self.deeper = None


class OffsetAnalysis(angr.Analysis):
    def __init__(self):
        self.cfg = self.project.analyses.CFGAccurate(keep_state=True, enable_symbolic_back_traversal=True, normalize=True)
        self.accesses = {}
        self.ty_backend = s_type_backend.TypeBackend()
        self.global_struct = SimStructAbstract(label=ValueSource('global', 0, 'global'))

        for func in self.real_functions(self.cfg):
            try:
                l.info("Working on %s", func.name)
                func.normalize()
                self._init_access(func)
                self._classify_stackframe(func)
            except AnalysisFailure:
                pass

    @staticmethod
    def real_functions(cfg):
        project = cfg.project
        funcman = project.kb.functions

        # Find the real _start on MIPS so we don't touch it
        do_not_touch = None
        if project.arch.name == 'MIPS32':
            for context in cfg.get_all_nodes(project.entry):
                for succ, jumpkind in cfg.get_successors_and_jumpkind(context):
                    if jumpkind == 'Ijk_Call':
                        do_not_touch = succ.addr
                        l.debug('Found MIPS entry point stub target %#x', do_not_touch)

        for funcaddr, func in funcman.iteritems():
            # But don't touch _start. Seriously.
            if funcaddr == project.entry:
                l.debug('Skipping entry point')
                continue

            # On MIPS there's another function that's part of the entry point.
            # Trying to mess with it will cause catastrope.
            if funcaddr == do_not_touch:
                l.debug('Skipping MIPS entry point stub target')
                continue

            # Don't try to patch simprocedures
            if project.is_hooked(funcaddr):
                l.debug("Skipping simprocedure %s", project._sim_procedures[funcaddr][0].__name__)
                continue

            # Don't touch functions not in any segment
            if project.loader.main_bin.find_segment_containing(funcaddr) is None:
                l.debug('Skipping function %s not mapped', func.name)
                continue

            # If the text section exists, only patch functions in it
            if '.text' not in project.loader.main_bin.sections_map:
                sec = project.loader.main_bin.find_section_containing(funcaddr)
                if sec is None or sec.name != '.text':
                    l.debug('Skipping function %s not in .text', func.name)
                    continue

            # Don't patch functions in the PLT
            if funcaddr in project.loader.main_bin.plt.values():
                l.debug('Skipping function %s in PLT', func.name)
                continue

            # If the CFG couldn't parse an indirect jump, avoid
            if func.has_unresolved_jumps:
                l.debug("Skipping function %s with unresolved jumps", func.name)
                continue

            # Check if the function starts at a SimProcedure (edge case)
            if cfg.get_any_node(funcaddr).simprocedure_name is not None:
                l.debug('Skipping function %s starting with a SimProcedure', func.name)

            # This function is APPROVED
            yield func


    def _init_access(self, func):
        for block in func.blocks:
            for idx, stmt in enumerate(block.vex.statements):
                if stmt.tag == 'Ist_WrTmp' and stmt.data.tag == 'Iex_Load':
                    self.accesses[(block.addr, idx)] = Access(block.addr, idx, False)
                elif stmt.tag == 'Ist_Store':
                    self.accesses[(block.addr, idx)] = Access(block.addr, idx, True)

    def _classify_stackframe(self, func):
        state = self.project.factory.blank_state(addr=func.addr)
        label = ValueSource('stack frame', func.addr, 'frame_%x'%func.addr)
        state.regs.rsp = state.regs.sp.annotate(s_type_backend.TypeAnnotation(
            s_type.SimTypePointer(SimStructAbstract(label=label))
        ))
        self._analyze(state, func.addr)

    def _analyze(self, state, func):
        state.options.remove(simuvex.o.SIMPLIFY_REGISTER_WRITES)
        state.options.remove(simuvex.o.SIMPLIFY_MEMORY_WRITES)
        state.inspect.b('mem_read', when=simuvex.BP_AFTER, action=self._memory_access)
        state.inspect.b('mem_write', when=simuvex.BP_AFTER, action=self._memory_access)
        pg = self.project.factory.path_group(state)
        pg.use_technique(BlanketExecution(self.cfg))
        pg.use_technique(AbortAtOtherFunctions(self.cfg, func))
        pg.run()

    def _memory_access(self, state):
        if state.scratch.sim_procedure is not None: return
        key = (state.scratch.bbl_addr, state.scratch.stmt_idx)
        l.info("hit access (%#x, %d)...", *key)
        try:
            cur_access = self.accesses[key]
        except KeyError:
            l.error("There's an access I know nothing about!!!!!!! (%#x, %d)", *key)
            import ipdb; ipdb.set_trace()
            return

        if cur_access.is_write:
            pointer = state.inspect.mem_write_address
            #length = state.inspect.mem_write_length
            #data = state.inspect.mem_write_expr
        else:
            pointer = state.inspect.mem_read_address
            #length = state.inspect.mem_read_length
            #data = state.inspect.mem_read_expr

        ptr_ty = self.ty_backend.convert(pointer).ty
        if type(ptr_ty) is s_type.SimTypePointer:
            l.info("...got em!")
            offset = ptr_ty.offset
            subty = ptr_ty.pts_to
            if type(subty) is SimStructAbstract:
                subty.offsets[offset].append(cur_access)
                cur_access.struct = subty
            else:
                l.warning('...pointer is to %s?', repr(subty))
        elif not pointer.symbolic:
            l.info("...global data!")
            self.global_struct.offsets[state.se.any_int(pointer)].append(cur_access)
            cur_access.struct = self.global_struct
        else:
            l.info("...don't got em!")
            if ptr_ty.label is not None and len(ptr_ty.label) > 0:
                l.info("...but we have a source!")

        #if cur_access.is_write:
        #    state.inspect.mem_write_address = pointer
        #    state.inspect.mem_write_length = length
        #    state.inspect.mem_write_expr = data
        #else:
        #    state.inspect.mem_read_address = pointer
        #    state.inspect.mem_read_length = length
        #    state.inspect.mem_read_expr = data


class BlanketExecution(angr.exploration_techniques.ExplorationTechnique):
    def __init__(self, cfg):
        super(BlanketExecution, self).__init__()
        self.seen_addrs = set()
        self.cfg = cfg

    def step(self, pg, stash, **kwargs):
        kwargs['successor_func'] = self.normalized_step
        return pg.step(stash=stash, **kwargs)

    def filter(self, path):
        if path.jumpkind == 'Ijk_Ret':
            return 'finished'

        a = path.addr
        if a in self.seen_addrs:
            return 'not_unique'
        self.seen_addrs.add(a)
        return None

    def normalized_step(self, path):
        node = self.cfg.get_any_node(path.addr)
        path.step(num_inst=len(node.instruction_addrs) if node is not None else None)
        successors = path.successors + path.unconstrained_successors
        real_successors = []
        for succ in successors:
            if succ.jumpkind == 'Ijk_Call':
                succ.state = simuvex.SimProcedures['stubs']['ReturnUnconstrained'](succ.state, addr=succ.addr).successors[0]
                if succ.addr in self.cfg.functions and not self.cfg.functions[succ.addr].returning:
                    succ.history._jumpkind = 'Ijk_Ret'
                    succ.state.scratch.jumpkind = 'Ijk_Ret'
                else:
                    succ.history._jumpkind = 'Ijk_FakeRet'
                    succ.state.scratch.jumpkind = 'Ijk_FakeRet'

        ideal_successors = set()
        for ctx in self.cfg.get_all_nodes(path.addr):
            for succ, jk in self.cfg.get_successors_and_jumpkind(ctx, excluding_fakeret=False):
                if jk in ('Ijk_Call', 'Ijk_Ret'): continue
                ideal_successors.add(succ.addr)

        for succ in successors:
            if succ.jumpkind == 'Ijk_Ret':
                real_successors.append(succ)
            elif succ.addr in ideal_successors:
                ideal_successors.remove(succ.addr)
                real_successors.append(succ)
            else:
                l.error("Off-the-rails successor to %#x at %#x", path.addr, succ.addr)
        if len(ideal_successors) > 0:
            succ_base = None
            try:
                succ_base = real_successors[0]
            except IndexError:
                try:
                    succ_base = successors[0]
                except IndexError:
                    l.error("CFG says there should be successors to %#x but none produced", path.addr)
            if succ_base is not None:
                for succ_addr in ideal_successors:
                    forced_succ = succ_base.copy()
                    forced_succ.state.regs.ip = succ_addr
                    real_successors.append(forced_succ)

        return real_successors

class AbortAtOtherFunctions(angr.exploration_techniques.ExplorationTechnique):
    def __init__(self, cfg, func):
        super(AbortAtOtherFunctions, self).__init__()
        self.cfg = cfg
        self.func = func

    def filter(self, path):
        if path.addr != self.func and path.addr in self.cfg.functions:
            l.error("Function %#x jumps into another function (%#x)", self.func, path.addr)
            raise AnalysisFailure

angr.register_analysis(OffsetAnalysis, 'OffsetAnalysis')
