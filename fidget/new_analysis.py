import angr
from angr.type_backend import TypeBackend, TypeAnnotation
from angr import sim_type
from angr import sim_options as o
import claripy
#from identifier import Identifier
import logging
import collections

l = logging.getLogger('angr.analyses.offset_analysis')

# clarification on labels for simtype objects
# on a struct, the label is the name of the struct, a string
# on a pointer or a top or anything that fits into a register, it's a list of all the source taints.
# a source taint is a ValueSource object, which contains the source and an offset
# - the source is a SimStructAbstract object, or a special string, "register" or "global"
#  - can also be another ValueSource object, indicating there's some double-deref going on
# - the offset is the integer offset into "source" that the value was loaded from

# unification only works when you have disjoint sets that you can slowly merge togther.
# we need to identify these sets.
# the sets are TYPES

class Access(object):
    """
    There should be one of these for each read/write instruction in the whole binary

    (technically it's one per read/write ir statement)
    """
    def __init__(self, addr, idx, is_write, size, mark_addr):
        self.addr = addr
        self.idx = idx
        self.is_write = is_write
        self.size = size
        self.mark_addr = mark_addr
        self.source = None

    def __repr__(self):
        return '<Access: %s %d %#x>' % ('write' if self.is_write else 'read', self.size, self.mark_addr)

class SimStructAbstract(sim_type.SimType):
    """
    This is an abstract struct SimType that tracks all the accesses to the individual offsets

    Objects of this type have a lifetime of the entire analysis. Some of them will get their
    lifetimes cut short when we unify them, but in general when you instanciate this class it's
    for the long haul.
    """
    def __init__(self, label='<unnamed>'):
        super(SimStructAbstract, self).__init__(label)
        self.offsets = collections.defaultdict(set)
        self.base = 0

    def __repr__(self):
        return '<Abstract Struct %s with %d offsets>' % (self.label, len(self.offsets),)# ' (%s)'%self.label.name if self.label is not None else '')

class ValueSource(object):
    """
    This is a source taint
    """
    def __init__(self, source, offset, name=None):
        self.source = source
        #if isinstance(offset, claripy.ast.Base) and not offset.symbolic and offset.op == 'BVV':
        #    offset = offset.args[0]
        self.offset = offset
        self.name = name
        self.deeper = None

    def __repr__(self):
        offset = hex(self.offset) if type(self.offset) in (int, long) else str(self.offset)
        return '<ValueSource %s@%s>' % (str(self.source), offset)

    def __eq__(self, other):
        return self.name == other.name and self.source == other.source and claripy.is_true(self.offset == other.offset)

    def __hash__(self):
        return hash((self.source, self.offset, self.name))

    def write_value(self, oa, value):
        if self.source == 'register':
            oa.function_initial_regs[func][self.offset] = value
        elif self.source == 'return':
            for offset in self.offset:
                oa.function_return_vals[offset] = value
        else:
            oa.initial_state.memory.store(self.source.base + self.offset, value, inspect=False, endness=oa.project.arch.memory_endness)


class OffsetAnalysis(angr.Analysis):
    """
    This is the main analysis. Should give us back a mapping from (bbl addr, stmt idx) -> Access
    """
    def __init__(self):
        #self.cfg = self.project.analyses.CFGAccurate(keep_state=True, enable_symbolic_back_traversal=True, normalize=True)
        self.cfg = self.project.analyses.CFGFast(collect_data_references=True, normalize=True)
        self.accesses = {}
        self.ty_backend = TypeBackend()
        self.global_struct = SimStructAbstract(label='global')
        #self.identer = Identifier(self.project, self.cfg)
        #self.ident_result = list(self.identer.run())

        self.struct_mapping = {}
        self.struct_base = 0x40000000
        self.pass_results = []
        self.function_initial_regs = {}
        self.function_return_vals = {}

        self.syscall_mapping = self.project._simos.syscall_table

        self.initial_state = self.project.factory.blank_state(remove_options={o.SIMPLIFY_MEMORY_WRITES, o.SIMPLIFY_REGISTER_WRITES}, add_options={o.UNSUPPORTED_BYPASS_ZERO_DEFAULT, o.BYPASS_UNSUPPORTED_IROP, o.BYPASS_UNSUPPORTED_IRCCALL, o.AVOID_MULTIVALUED_READS, o.AVOID_MULTIVALUED_WRITES})
        self.initial_state.inspect.b('mem_read', when=angr.BP_AFTER, action=self._memory_access)
        self.initial_state.inspect.b('mem_write', when=angr.BP_AFTER, action=self._memory_access)
        self.initial_state.inspect.b('exit', when=angr.BP_BEFORE, action=self._exit_taken)

        for func in self.real_functions(self.cfg):
            l.info("Working on %s", func.name)
            self._init_analysis(func)

    def pointer_to_abstruct(self, abstruct):
        return claripy.BVV(abstruct.base, self.project.arch.bits).annotate(
                TypeAnnotation(
                    sim_type.SimTypePointer(abstruct, label=[], offset=claripy.BVV(0, self.project.arch.bits))))

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
                l.debug("Skipping simprocedure %s", project.hooked_by(funcaddr).procedure.__name__)
                continue

            # Don't touch functions not in any segment
            if project.loader.main_object.find_segment_containing(funcaddr) is None:
                l.debug('Skipping function %s not mapped', func.name)
                continue

            # If the text section exists, only patch functions in it
            if '.text' not in project.loader.main_object.sections_map:
                sec = project.loader.main_object.find_section_containing(funcaddr)
                if sec is None or sec.name != '.text':
                    l.debug('Skipping function %s not in .text', func.name)
                    continue

            # Don't patch functions in the PLT
            if funcaddr in project.loader.main_object.plt.values():
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

    def _register_addr(self, struct):
        self.struct_mapping[struct.label] = struct
        struct.base = self.struct_base
        self.struct_base += 0x10000

    def _init_analysis(self, func):
        mark_addr = None
        for node in func.nodes:
            if type(node) is not angr.knowledge.codenode.BlockNode:
                continue
            block = self.project.factory.block(node.addr, size=node.size)
            for idx, stmt in enumerate(block.vex.statements):
                if stmt.tag == 'Ist_IMark':
                    mark_addr = stmt.addr
                if stmt.tag == 'Ist_WrTmp' and stmt.data.tag == 'Iex_Load':
                    self.accesses[(block.addr, idx)] = Access(block.addr, idx, False, stmt.data.result_size >> 3, mark_addr)
                elif stmt.tag == 'Ist_Store':
                    self.accesses[(block.addr, idx)] = Access(block.addr, idx, True, stmt.data.result_size >> 3, mark_addr)
                elif stmt.tag == 'Ist_Dirty' and stmt.cee.name == 'x86g_dirtyhelper_loadF80le':
                    self.accesses[(block.addr, idx)] = Access(block.addr, idx, False, 10, mark_addr)
                elif stmt.tag == 'Ist_Dirty' and stmt.cee.name == 'x86g_dirtyhelper_storeF80le':
                    self.accesses[(block.addr, idx)] = Access(block.addr, idx, True, 10, mark_addr)

        frame_struct = SimStructAbstract(label='stack_%x'%func.addr)
        self._register_addr(frame_struct)
        sp_bv = self.pointer_to_abstruct(frame_struct)
        self.function_initial_regs[func.addr] = {'sp': sp_bv}
        self.initial_state.memory.store(sp_bv,
                                        claripy.BVV(0x1234, self.project.arch.bits),
                                        endness=self.project.arch.memory_endness,
                                        inspect=False)

        for reg in self.project.arch.default_symbolic_registers:
            if self.project.arch.registers[reg][0] == self.project.arch.registers['sp'][0]:
                continue
            val = claripy.BVS('reg_%s'%reg, self.project.arch.bits)
            val = val.annotate(TypeAnnotation(
                sim_type.SimTypeTop(label=[ValueSource('register', reg)])
            ))
            self.function_initial_regs[func.addr][reg] = val

        self._analyze(func.addr)

    def _analyze(self, func):
        state = self.initial_state

        rnd = 0
        while True:
            rnd += 1
            l.debug("Analysis round %d", rnd)
            state.regs.ip = func
            for reg, val in self.function_initial_regs[func].iteritems():
                state.registers.store(reg, val)
            pg = self.project.factory.path_group(state)
            blanket = BlanketExecution(self.cfg)
            pg.use_technique(blanket)
            pg.use_technique(AbortAtOtherFunctions(self.cfg, func))
            self.pass_results = []
            pg.run()
            if func in self.function_return_vals:
                if 'finished' in pg.stashes:
                    for finished in pg.finished:
                        self._runtime_unify(finished.state, self.function_return_vals[func], finished.state.regs.eax, overwrite=False)

            if 'not_unique' in pg.stashes:
                for mergable in pg.not_unique:
                    if mergable.addr not in blanket.merge_point_states:
                        import ipdb; ipdb.set_trace()
                        print('the fuck is this')
                    orig_state = blanket.merge_point_states[mergable.addr]
                    for reg in self.project.arch.default_symbolic_registers:
                        self._runtime_unify(state, mergable.state.registers.load(reg), orig_state.registers.load(reg), stack_frame=reg == 'esp', overwrite=False)

            if not self.pass_results:
                break
            handled_regions = set()
            for tag, data in self.pass_results:
                l.debug("Tag: %s, %s", tag, data)
                if tag == 'SOURCE':
                    if data in handled_regions:
                        continue
                    handled_regions.add(data)
                    new_struct = SimStructAbstract(label='struct_%x'%self.struct_base)
                    self._register_addr(new_struct)
                    base = self.pointer_to_abstruct(new_struct)
                    data.write_value(self, base)
                elif tag == 'UNIFY':
                    one, two = data
                    one_ty = self.ty_backend.convert(one).ty
                    two_ty = self.ty_backend.convert(two).ty
                    if type(one_ty) is sim_type.SimTypePointer and type(two_ty) is sim_type.SimTypePointer:
                        import ipdb; ipdb.set_trace()
                        print('uh. gotta do a weird thing here!')
                    else:
                        import ipdb; ipdb.set_trace()
                        print('what the shit is this')
                else:
                    raise Exception("you forgot to update the tag list, jerkface! (%s)" % tag)

    def _memory_access(self, state):
        if state.scratch.sim_procedure is not None: return
        key = (state.scratch.bbl_addr, state.scratch.stmt_idx)
        #l.debug("hit access (%#x, %d)...", *key)
        try:
            cur_access = self.accesses[key]
        except KeyError:
            l.error("There's an access I know nothing about!!!!!!! (%#x, %d)", *key)
            import ipdb; ipdb.set_trace()
            return

        if cur_access.is_write:
            pointer = state.inspect.mem_write_address
            #length = state.inspect.mem_write_length
            data = state.inspect.mem_write_expr
        else:
            pointer = state.inspect.mem_read_address
            #length = state.inspect.mem_read_length
            data = state.inspect.mem_read_expr

        ptr_ty = self.ty_backend.convert(pointer).ty
        if type(ptr_ty) is sim_type.SimTypePointer:
            #l.info("...got em!")
            offset = ptr_ty.offset
            subty = ptr_ty.pts_to
            if type(subty) is SimStructAbstract:
                subty.offsets[offset.cache_key].add(cur_access)
                cur_access.source = ValueSource(subty, offset)

                if data.op == 'BVS' and data.args[0].startswith('mem_') and len(data.annotations) == 0:
                    # this is a fresh read! we need to mark its source.
                    newty = sim_type.SimTypeTop(label=[ValueSource(subty, offset)])
                    data = data.annotate(TypeAnnotation(newty))
                    state.memory.store(pointer, data, inspect=False, endness=state.arch.memory_endness)
            else:
                l.warning('...pointer is to %s?', repr(subty))
        elif not pointer.symbolic:
            #l.info("...global data!")
            self.global_struct.offsets[pointer.cache_key].add(cur_access)
            cur_access.source = ValueSource(self.global_struct, state.se.eval(pointer))
        else:
            #l.info("...don't got em!")
            if ptr_ty.label is not None and len(ptr_ty.label) > 0:
                if len(ptr_ty.label) > 1:
                    import ipdb; ipdb.set_trace()
                    print('not sure how this case can arise but it needs special handling if it does')
                #l.info("...but we have a source!")
                self.pass_results.append(('SOURCE', ptr_ty.label[0]))
        if cur_access.is_write:
            #state.inspect.mem_write_address = pointer
            #state.inspect.mem_write_length = length
            state.inspect.mem_write_expr = data
        else:
            #state.inspect.mem_read_address = pointer
            #state.inspect.mem_read_length = length
            state.inspect.mem_read_expr = data

    def _exit_taken(self, state):
        jk = state.inspect.exit_jumpkind
        target = state.inspect.exit_target
        if target.symbolic:     # shit lmao
            all_targets = tuple(state.se.any_n_int(target, 257))
            if len(all_targets) > 256:
                import ipdb; ipdb.set_trace()
                print('shit!! lmao')
        else:
            all_targets = (state.se.eval(target),)

        if jk == 'Ijk_Call' or jk.startswith('Ijk_Sys'):

            if jk == 'Ijk_Call':
                ret_addr = state.memory.load(state.regs.sp, size=state.arch.bytes, endness=state.arch.memory_endness, inspect=False)
                state.regs.sp += state.arch.bytes
                state.inspect.exit_target = ret_addr
            else:
                sys_num = state.regs.eax
                if sys_num.symbolic:
                    import ipdb; ipdb.set_trace()
                    l.error("SHIT. FUCK. SHIT FUCK.")

                try:
                    all_targets = (self.syscall_mapping[state.se.any_int(sys_num)][0],)
                except KeyError:
                    # ????????????????????
                    all_targets = (0x1234678d,)

            for target in all_targets:
                if target in self.function_initial_regs:
                    for reg, stored in self.function_initial_regs[target].iteritems():
                        self._runtime_unify(state, state.registers.load(reg), stored, stack_frame=reg == 'sp')

            if all(target in self.cfg.functions and not self.cfg.functions[target].returning for target in all_targets):
                state.inspect.exit_jumpkind = 'Ijk_Ret'
            else:
                state.inspect.exit_jumpkind = 'Ijk_FakeRet'

                # okay.
                # go through all the targets. if any of them have return values available,
                # take one of them and drop it into the state, take the rest and unify them
                # if only some of them have return values available, the ones without just
                # inherit the first value. if none of them are available, make a fresh value,
                # give it a source taint, and let the 'SOURCE' tag handle it
                are_any = False
                for target in all_targets:
                    if target in self.function_return_vals:
                        if not are_any:
                            are_any = True
                            state.regs.eax = self.function_return_vals[target]
                        else:
                            import ipdb; ipdb.set_trace()
                            # I don't THINK this should ever happen.... pdb to make sure assumptions are good
                            # reason: there are only multiple call targets if it's a call table. entries in a call table
                            # are typically not reused, and function_return_vals entries are only set from analyses
                            # of the caller.
                            self._runtime_unify(state, state.regs.eax, self.function_return_vals[target], overwrite=False)

                if are_any:
                    for target in all_targets:
                        if target not in self.function_return_vals:
                            self.function_return_vals[target] = state.regs.eax
                else:
                    state.regs.eax = claripy.BVS('retval', 32).annotate(TypeAnnotation(sim_type.SimTypeTop(label=[ValueSource('return', all_targets)])))

    def _runtime_unify(self, state, one, two, stack_frame=False, overwrite=True):
        """
        decide if one and two need to be unified, if so add a 'UNIFY' tag

        :param state:           The analysis state that holds intermediate results
        :param one:             The first value to unify
        :param two:             The second value to unify
        :param stack_frame:     If we're only allowed to look at offsets in front of the pointer
        :param overwrite:       Whether to use the semantics that one is "overwriting" two
        """

        one_ty = self.ty_backend.convert(one).ty
        two_ty = self.ty_backend.convert(two).ty

        # if both of them are pointers!!! this gets very tricky
        if type(one_ty) is type(two_ty) is sim_type.SimTypePointer:
            one_subty = one_ty.pts_to
            two_subty = two_ty.pts_to
            one_offset = one_ty.offset
            two_offset = two_ty.offset

            if one_offset.symbolic or two_offset.symbolic:
                import ipdb; ipdb.set_trace()
                print('yikes! (jesus christ)')

            if one_subty is two_subty:
                if one_offset is not two_subty:
                    import ipdb; ipdb.set_trace()
                    print('yikes? (arrays maybe. recursion probably)')
                else:
                    import ipdb; ipdb.set_trace()
                    print('yikes. (no object identity but yes equality)')

            # these are two different structures that we might have to unify.
            # possible cases:
            # - two structures are actually the same structure.
            # - two stack frames. flag tells us this. only deal with the argument parts
            # - a structure is present in another structure
            # TODO: do some type checking on the two structs to make sure we're not making
            # a huge mistake!!!
            else:
                if claripy.is_true(one_offset == two_offset) and claripy.is_true(one_offset == 0):
                    self.pass_results.append(('UNIFY', (one, two)))
                elif stack_frame:
                    for ckey, _ in two_subty.offsets.iteritems():
                        offset = ckey.ast
                        if not claripy.is_true(claripy.SGT(offset, 0)):
                            continue

                        two_value = state.memory.load(two + offset,
                                                      size=state.arch.bytes,
                                                      inspect=False,
                                                      endness=state.arch.memory_endness)
                        one_value = state.memory.load(one + offset,
                                                      size=state.arch.bytes,
                                                      inspect=False,
                                                      endness=state.arch.memory_endness)

                        # one last edge case consideration: if one_value doesn't have a source
                        # (since we disabled inspect, this might happen)
                        # we should manually give it a source since this is something we know
                        one_value_ty = self.ty_backend.convert(one_value).ty
                        if type(one_value_ty) is not sim_type.SimTypePointer and \
                                len(one_value_ty.label) == 0:
                            one_value = one_value.annotate(
                                    TypeAnnotation(
                                        sim_type.SimTypeTop(label=[ValueSource(two_subty, offset)])))

                        self._runtime_unify(state, one_value, two_value)

                else:
                    import ipdb; ipdb.set_trace()
                    # look through the structs and check offset by offset
                    # do we want to check in the initial state or elsewhere?
                    # think we should check in the current state. everything from the initial state wil be there still?
                    print('okay??')

        # when only one of them is a pointer!
        # if a source is available we should toss it to SOURCE, she'll just drop the other in!
        # if a source is not available, wait. eventually one will be available :)
        elif type(two_ty) is sim_type.SimTypePointer:
            if len(one_ty.label) > 0:
                if len(one_ty.label) > 1:
                    import ipdb; ipdb.set_trace()
                    print('????????????')
                self.pass_results.append(('SOURCE', one_ty.label[0]))

        # this is where overwrite semantics comes into play.
        # if one overwrites two, then we can't mark two as a pointer just because 1 is a pointer.
        # otherwise, this is the same as the previous case I guess?
        # I'm not sure what good this does
        elif type(one_ty) is sim_type.SimTypePointer:
            import ipdb; ipdb.set_trace()
            if not overwrite:
                if len(two_ty.label) > 0:
                    if len(two_ty.label) > 1:
                        import ipdb; ipdb.set_trace()
                        print('????????????')
                    self.pass_results.append(('SOURCE', two_ty.label[0]))

        # If neither of them are pointers bail out. this is not a general type inference :)
        else:
            pass


class BlanketExecution(angr.exploration_techniques.ExplorationTechnique):
    """
    This is the otiegnqwvk that controls the execution. No analysis should happen in here,
    this is all just clerical work to give the analysis what it wants to see

    This is starting to look a lot like a weird inverted implementation of ForwardAnalysis :(
    """
    def __init__(self, cfg):
        super(BlanketExecution, self).__init__()
        self.seen_addrs = set()
        self.cfg = cfg
        self.merge_point_states = collections.defaultdict(list)

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
        ideal_successors = set()
        for ctx in self.cfg.get_all_nodes(path.addr):
            if len(ctx.predecessors) > 1:
                self.merge_point_states[path.addr].append(path.state)
            for succ, jk in self.cfg.get_successors_and_jumpkind(ctx, excluding_fakeret=False):
                if jk in ('Ijk_Call', 'Ijk_Ret'):
                    continue
                elif jk.startswith('Ijk_Sys'):
                    try:
                        ideal_successors.add(succ.successors[0].addr)
                    except IndexError:
                        pass
                else:
                    ideal_successors.add(succ.addr)

        node = self.cfg.get_any_node(path.addr)
        path.step(num_inst=len(node.instruction_addrs) if node is not None else None)
        successors = path.successors + path.unconstrained_successors
        real_successors = []

        for succ in successors:
            if succ.jumpkind == 'Ijk_Ret':
                real_successors.append(succ)
            elif succ.addr in ideal_successors:
                ideal_successors.remove(succ.addr)
                real_successors.append(succ)
            else:
                import ipdb; ipdb.set_trace()
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

    def complete(self, pg):
        return False

class AbortAtOtherFunctions(angr.exploration_techniques.ExplorationTechnique):
    """
    Another otiegnqwvk for clerical work
    """
    def __init__(self, cfg, func):
        super(AbortAtOtherFunctions, self).__init__()
        self.cfg = cfg
        self.func = func

    def filter(self, path):
        if path.addr != self.func and path.addr in self.cfg.functions:
            l.warning("Function %#x jumps into another function (%#x)", self.func, path.addr)
            return 'finished'

angr.register_analysis(OffsetAnalysis, 'OffsetAnalysis')
