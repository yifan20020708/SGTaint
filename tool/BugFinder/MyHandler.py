# -*- coding: utf-8 -*-
from functools import reduce
from typing import Optional, Tuple
import networkx as nx
import claripy
import ailment
from angr.project import Project
from angr.analyses.cfg.cfg_fast import CFGFast
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.analyses.reaching_definitions.function_handler import FunctionHandler
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE
from angr.knowledge_plugins.key_definitions.live_definitions import Definition
from angr.knowledge_plugins.key_definitions.tag import LocalVariableTag, ReturnValueTag
from angr.knowledge_plugins.key_definitions.atoms import Register, SpOffset, MemoryLocation, Atom
from angr.calling_conventions import SimRegArg
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from angr.code_location import CodeLocation
import tool.Config.config as config_sgtaint
from tool.BugFinder.utils import backtrack_definations, get_clinic_block, get_strings
from tool.BugFinder.DefExplorer import DefinitionExplorer


class MyHandler(FunctionHandler):
    def __init__(self):
        self._analysis = None

    def hook(self, rda):
        self._analysis = rda
        return self
    
    # 提高key值的提取能力（针对set-get函数）
    def set_call_sites_dict(self, call_sites_dict):
        call_sites_dict_block_addr = {}
        for set_get_func_name in call_sites_dict:
            call_sites_dict_block_addr[set_get_func_name] = {call_sites_info[2]: call_sites_info for call_sites_info in call_sites_dict[set_get_func_name]}
        self.call_sites_dict = call_sites_dict_block_addr
        
    def get_call_sites_dict(self):
        return self.call_sites_dict
    
    # 将文件中的内容存储在list中，方便后面的自动化处理
    def set_source2sink_path(self, source2sink_path):
        self.source2sink_path = source2sink_path
        
    def get_source2sink_path(self):
        return self.source2sink_path
    
    def set_get2set_path(self, get2set_path):
        self.get2set_path = get2set_path
        
    def get_get2set_path(self):
        return self.get2set_path
    
    def set_start_function(self, start_function) :
        self.start_function = start_function
        
    def set_call_graph(self, call_graph) :
        self.call_graph = call_graph
    
    def set_variable_manager(self, variable_manager):
        self.variable_manager = variable_manager

    def get_variable_manager(self):
        return self.variable_manager
    
    def set_cfg(self, cfg: CFGFast):
        self.cfg = cfg

    def get_cfg(self):
        return self.cfg
    
    def set_clinic(self, clinic):
        self.clinic = clinic

    def get_clinic(self):
        return self.clinic
    
    def set_dec(self,dec):
        self.dec = dec
        
    def get_dec(self):
        return self.dec
    
    def set_rd_on_clinic(self, rd_on_clinic):
        self.rd_on_clinic = rd_on_clinic

    def get_rd_on_clinic(self):
        return self.rd_on_clinic
    
    def set_vfg(self, vfg):
        self.vfg = vfg

    def get_vfg(self):
        return self.vfg
    
    def set_sptracker(self, sptracker):
        self.sptracker = sptracker

    def get_sptracker(self):
        return self.sptracker
    
    def set_current_function(self, cur_fun):
        self.cur_fun = cur_fun

    def get_current_function(self):
        return self.cur_fun

    def set_result_file(self, result_file):
        self.result_file = result_file

    def get_result_file(self):
        return self.result_file
    
    def set_get2set_file(self, get2set_file):
        self.get2set_file = get2set_file

    def get_get2set_file(self):
        return self.get2set_file
    
    def set_get2set_file(self, get2set_file):
        self.get2set_file = get2set_file

    def get_get2set_file(self):
        return self.get2set_file
    
    def set_visited_file(self, visited_file):
        self.visited_file = visited_file

    def get_visited_file(self):
        return self.visited_file
    
    def set_ret_sites(self, ret_sites):
        self._ret_sites = ret_sites
        
    def get_stringby_use_def(self, reg_def, state):
        defs_to_check = set()
        defs_to_check.add(reg_def)
        seen_defs = set()
        bb = ""
        while len(defs_to_check) != 0:
            current_def = defs_to_check.pop()
            seen_defs.add(current_def)
            if type(current_def.atom) == MemoryLocation and 'readonly' in f'{current_def}':
                i = 0
                while str(self.cfg.project.loader.memory.load(current_def.atom.addr, i + 1))[i + 1] != '\\':
                    i += 1
                bb = str(self.cfg.project.loader.memory.load(current_def.atom.addr, i - 1))[2:-1]
                if len(bb) > 2:
                    break
            else:
                if current_def in state.dep_graph.graph.nodes():
                    for pred in state.dep_graph.graph.predecessors(current_def):
                        if pred not in seen_defs:
                            defs_to_check.add(pred)
        return bb
    
    
    def is_defination_tainted(self, d0, function, state):
        is_tainted = False
        def_explorer = DefinitionExplorer(self._analysis.project, state.dep_graph, self.get_cfg())
        def_explorer.set_current_state(state)
        def_explorer.set_current_codeloc(state.current_codeloc)
        def_explorer.set_RDA_handler(self)
        def_explorer.set_current_function(self.cur_fun)

        reg_seen_defs, Paths, visited_functions = backtrack_definations(
            def_explorer,
            reg_defs=[d0],
            result_file=self.get_result_file(),
            memcpy_func_pred=self.get_current_function(),
            FUNCS=[],
            sink=function.name,
            memcpy_addr=state.current_codeloc.ins_addr,
            result_path=self.get_source2sink_path(),
            check_is_tainted_def=True
        )
        for overall_def, path, visited_function in zip(reg_seen_defs, Paths, visited_functions):
            if overall_def[0] == "get2set" or (overall_def[0] == "retval" and overall_def[1] is not None):
                is_tainted = True
                break
        return is_tainted
    
    def get_memoryDef_by_use_def(self, reg_def, state):
        defs_to_check = set()
        defs_to_check.add(reg_def)
        seen_defs = set()
        while len(defs_to_check) != 0:
            current_def = defs_to_check.pop()
            seen_defs.add(current_def)
            if type(current_def.atom) == MemoryLocation and 'stack' in f'{current_def}':
                return current_def
            else:
                if current_def in state.dep_graph.graph.nodes():
                    preds = [d for d in state.dep_graph.graph.predecessors(current_def)]
                    if type(current_def.atom) == Register and len(preds) == 1:
                        for pred in preds:
                            if pred not in seen_defs:
                                defs_to_check.add(pred)
        return None

    def get_functionAddress_by_use_def(self, reg_def, state):
        # Now we need to analyze the definition for this atom
        functions = []
        defs_to_check = set()
        defs_to_check.add(reg_def)
        seen_defs = set()
        while len(defs_to_check) != 0:
            current_def = defs_to_check.pop()
            seen_defs.add(current_def)
            if type(current_def.atom) == MemoryLocation and current_def.atom.size is None and 'readonly' in f'{current_def}':
                try:
                    addr = current_def.atom.addr
                    func = self.cfg.functions.get_by_addr(addr)
                    if func is not None:
                        functions.append(func)
                except Exception as e:
                    print("error at 441 ", e)
                    continue
            else:
                if current_def in state.dep_graph.graph.nodes():
                    preds = [d for d in state.dep_graph.graph.predecessors(current_def)]
                    for pred in preds:
                        if pred not in seen_defs:
                            defs_to_check.add(pred)
        return functions

    def get_def_from_parameter(self, function, parameter_position, state, blk=None):
        flag = False
        try:
            cc = function.calling_convention
            parameter_atom = Atom.from_argument(
                SimRegArg(cc.ARG_REGS[parameter_position], state.arch.bytes),
                self._analysis.project.arch.registers
            )
        except Exception as e:
            flag = True

        try:
            if flag and "MIPS" in state.arch.name:
                ARG_REGS = ["a0", "a1", "a2", "a3"]
                if parameter_position in range(4):
                    oprand = state.arch.registers[ARG_REGS[parameter_position]]
                    parameter_atom = Register(oprand[0], oprand[1])
                elif (
                    blk is not None and hasattr(blk, "statements") and len(blk.statements) > 0 and
                    type(blk.statements[-1]) == ailment.statement.Call and
                    hasattr(blk.statements[-1], "args") and blk.statements[-1].args is not None and
                    len(blk.statements[-1].args) > 0
                ):
                    oprand = blk.statements[-1].args[parameter_position]
                    parameter_atom = Register(oprand.reg_offset, oprand.size)
            elif flag and "ARM" in state.arch.name:
                try:
                    ARG_REGS = ["r0", "r1", "r2", "r3"]
                    if parameter_position in range(4):
                        oprand = state.arch.registers[ARG_REGS[parameter_position]]
                        parameter_atom = Register(oprand.reg_offset, oprand.size)
                    elif (
                        blk is not None and hasattr(blk, "statements") and len(blk.statements) > 0 and
                        type(blk.statements[-1]) == ailment.statement.Call and
                        hasattr(blk.statements[-1], "args") and blk.statements[-1].args is not None and
                        len(blk.statements[-1].args) > 0
                    ):
                        oprand = blk.statements[-1].args[parameter_position]
                        parameter_atom = Register(oprand[0], oprand[1])
                except Exception as e:
                    if parameter_position == 0:
                        parameter_atom = Register(8, 4)
                    elif parameter_position == 1:
                        parameter_atom = Register(12, 4)
                    elif parameter_position == 2:
                        parameter_atom = Register(16, 4)
                    elif parameter_position == 3:
                        parameter_atom = Register(20, 4)
                    elif (
                        blk is not None and hasattr(blk, "statements") and len(blk.statements) > 0 and
                        type(blk.statements[-1]) == ailment.statement.Call and
                        hasattr(blk.statements[-1], "args") and blk.statements[-1].args is not None and
                        len(blk.statements[-1].args) > 0
                    ):
                        oprand = blk.statements[-1].args[parameter_position]
                        parameter_atom = Register(oprand[0], oprand[1])
            def0 = state.get_definitions(parameter_atom)
            d0 = [d for d in def0][0]
        except Exception as e:
            d0 = None
            size: int = state.arch.bits
            top = state.top(size * state.arch.byte_width)
            top = state.annotate_with_def(top, Definition(parameter_atom, state.current_codeloc))
            data: MultiValues = MultiValues(top)
            mv = state.kill_and_add_definition(parameter_atom, state.current_codeloc, data)
            ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
            ff = next(iter(ff_defs))
            return ff
        return d0
    
    def get_clinic_block(self, clinic, addr, flag=True):
        blk = None
        if clinic is not None and flag:
            for block in clinic.graph.nodes():
                if block.addr == addr:
                    blk = block
                    break
            try:
                if (
                    blk is not None and hasattr(blk, "statements") and len(blk.statements) > 0 and
                    type(blk.statements[-1]) == ailment.statement.Call and
                    hasattr(blk.statements[-1], "args") and blk.statements[-1].args is not None and
                    len(blk.statements[-1].args) > 0
                ):
                    return blk
            except Exception as e:
                pass
        try:
            project = self._analysis.project
            manager = ailment.Manager(arch=project.arch)
            block = project.factory.block(addr)
            ail_block = ailment.IRSBConverter.convert(block.vex, manager)
            simp = project.analyses.AILBlockSimplifier(ail_block, self.cur_fun.addr)
            csm = project.analyses.AILCallSiteMaker(simp.result_block)
            if csm.result_block:
                ail_block = csm.result_block
                simp = project.analyses.AILBlockSimplifier(ail_block, self.cur_fun.addr)
            return simp.result_block
        except Exception as e:
            return None

    def _state_from(self, rda, exit_site_addresses):
        assert len(exit_site_addresses) > 0, 'Assuming there is at least one return site'
        exit_states = list(map(
            lambda site_address: rda.observed_results[('node', site_address, OP_BEFORE)],
            exit_site_addresses
        ))
        first_state = exit_states[0]
        try:
            if len(exit_site_addresses) > 1:
                return reduce(
                    lambda acc, state: acc.merge(state),
                    exit_states,
                    first_state.copy(),
                )
            else:
                return first_state
        except Exception as e:
            return first_state


    def get_memory_defination(self, d0, function, state, codeloc, defination_only=False, defination_location=0, blk=None):
        if blk is None:
            blk = self.get_clinic_block(self.clinic, state.current_codeloc.block_addr)
        atom = d0.atom
        if blk is not None and len(blk.statements) > 0:
            call_statement = blk.statements[-1]
            if (
                type(call_statement) == ailment.statement.Call and
                hasattr(call_statement, "args") and
                call_statement.args is not None and
                len(call_statement.args) > defination_location
            ):
                arg0 = call_statement.args[defination_location]
                if type(arg0) == ailment.expression.Const and hasattr(arg0, "value"):
                    ff = None
                    ff_list = []
                    for node in state.dep_graph.nodes():
                        if isinstance(node.atom, MemoryLocation) and node.atom.addr == arg0.value:
                            if node not in ff_list:
                                ff_list.append(node)
                            ff = node
                    # Handle multiple global vars with same addr but diff size
                    if len(ff_list) > 1:
                        pred = [d for d in state.dep_graph.predecessors(d0)]
                        if len(pred) == 1 and type(pred[0].atom) != Register:
                            pred = [d for d in state.dep_graph.predecessors(pred[0])]
                            for defination in pred:
                                if type(defination.atom) == MemoryLocation:
                                    for GF in ff_list:
                                        if GF.atom.addr == defination.atom.addr and defination.size == GF.size:
                                            ff = GF
                                            break
                        else:
                            for defination in pred:
                                for GF in ff_list:
                                    if (
                                        type(defination.atom) == MemoryLocation and
                                        GF.atom.addr == defination.atom.addr and
                                        defination.size == GF.size
                                    ):
                                        ff = GF
                                        break
                    if ff is not None:
                        if defination_only:
                            print("we are return ff only")
                            return ff
                        else:
                            try:
                                tags = {
                                    LocalVariableTag(function=function.addr,
                                                    metadata={'tagged_by': f'{function.name} simulation Effect',
                                                            'block_addr': state.current_codeloc.block_addr})
                                }
                                data: MultiValues = state.memory_definitions.load(ff.atom.addr, size=ff.atom.size)
                                mv = state.kill_and_add_definition(ff.atom, state.current_codeloc, data, tags=tags)
                                ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
                                ff = next(iter(ff_defs))
                            except Exception as e:
                                print("we could not update the golbal varaible, we just return its current defination. this should be fixed")
                            return ff
                    if ff is None:
                        print("could not find the public varabile in graph")
                        block_addr = blk.addr
                        project = self._analysis.project
                        manager = ailment.Manager(arch=project.arch)
                        block = project.factory.block(block_addr)
                        for stmt in block.vex.statements:
                            if hasattr(stmt, 'offset') and state.arch.register_names[stmt.offset] == state.arch.register_names[d0.atom.reg_offset]:
                                break
                        tags = {
                            LocalVariableTag(function=function.addr,
                                            metadata={'tagged_by': f'{function.name} simulation Effect',
                                                    'block_addr': state.current_codeloc.block_addr})
                        }
                        addr = arg0.value
                        size = stmt.data.result_size(block.vex.tyenv) // 8
                        bits = stmt.data.result_size(block.vex.tyenv)
                        top = state.top(bits)
                        data = MultiValues(top)
                        temp_codeloc = CodeLocation(block.addr, stmt.tag_int, d0.codeloc.ins_addr, context=None)
                        atom = MemoryLocation(arg0.value, size)
                        mv = state.kill_and_add_definition(atom, state.current_codeloc, data, tags=tags)
                        ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
                        ff = next(iter(ff_defs))
                        state.dep_graph.add_node(ff)
                        pred = [d for d in state.dep_graph.predecessors(d0)]
                        if len(pred) >= 1:
                            for defination in pred:
                                state.dep_graph.add_edge(ff, defination)
                        return ff
            check_flag = False
            if type(call_statement) == ailment.statement.Call and call_statement.args is None:
                atom = d0.atom
                check_flag = True
            elif type(call_statement) == ailment.statement.Call and len(call_statement.args) > defination_location:
                arg0 = call_statement.args[defination_location]
                if hasattr(arg0, 'base'):
                    atom = MemoryLocation(SpOffset(state.arch.bits, arg0.offset), arg0.size)
                    check_flag = True
                elif hasattr(arg0, 'reg_offset'):
                    reg = state.arch.registers[arg0.tags['reg_name']]
                    temp_def = next(iter(state.get_definitions(Register(reg[0], reg[1]))))
                    atom = temp_def.atom
                    check_flag = True
                elif (
                    type(call_statement.args[0]) == ailment.expression.Load and
                    hasattr(call_statement.args[0], 'addr') and
                    type(call_statement.args[0].addr) == ailment.expression.StackBaseOffset
                ):
                    atom = MemoryLocation(SpOffset(state.arch.bits, call_statement.args[0].addr.offset), arg0.size)
                    check_flag = True
                elif (
                    type(call_statement.args[0]) == ailment.expression.Load and
                    hasattr(call_statement.args[0], 'addr') and
                    type(call_statement.args[0].addr) == ailment.expression.BinaryOp and
                    type(call_statement.args[0].addr.operands[1]) == ailment.expression.Const
                ):
                    atom = MemoryLocation(
                        SpOffset(state.arch.bits, call_statement.args[0].addr.operands[1].value),
                        call_statement.args[0].addr.operands[1].size
                    )
                    check_flag = True
            else:
                for smt in blk.statements:
                    if (
                        type(smt) == ailment.statement.Assignment and
                        type(smt.src) == ailment.expression.StackBaseOffset and
                        smt.dst.tags['reg_name'] == state.arch.register_names[d0.atom.reg_offset]
                    ):
                        atom = MemoryLocation(SpOffset(state.arch.bits, smt.src.offset), smt.src.size)
                        check_flag = True
                        break
        try:
            if defination_only:
                return next(iter(state.get_definitions(atom)))
        except Exception as e:
            return d0
        tags = {
            LocalVariableTag(
                function=function.addr,
                metadata={'tagged_by': f'{function.name} simulation Effect',
                        'block_addr': state.current_codeloc.block_addr}
            )
        }
        data: MultiValues = state.register_definitions.load(d0.atom.reg_offset, size=d0.atom.size)
        tmp_codeloc = state.current_codeloc
        mv = state.kill_and_add_definition(atom, tmp_codeloc, data, tags=tags)
        ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
        ff = next(iter(ff_defs))
        return ff


    def handle_sprintf_xx(self, function, state, codeloc):
        print('inside', function.name)
        extra_defination_flag = False
        cc = function.calling_convention

        parameter_position = 0
        parameter_atom = Atom.from_argument(
            SimRegArg(cc.ARG_REGS[parameter_position], state.arch.bytes),
            self._analysis.project.arch.registers
        )
        parameter_position_1 = 1
        parameter_atom_1 = Atom.from_argument(
            SimRegArg(cc.ARG_REGS[parameter_position_1], state.arch.bytes),
            self._analysis.project.arch.registers
        )
        parameter_position_2 = 2
        parameter_atom_2 = Atom.from_argument(
            SimRegArg(cc.ARG_REGS[parameter_position_2], state.arch.bytes),
            self._analysis.project.arch.registers
        )

        if function.name in ["snprintf", "vsnprintf"]:
            parameter_position_3 = 3
            parameter_atom_3 = Atom.from_argument(
                SimRegArg(cc.ARG_REGS[parameter_position_3], state.arch.bytes),
                self._analysis.project.arch.registers
            )
            def3 = state.get_definitions(parameter_atom_3)
            d3 = [d for d in def3][0]

        def0 = state.get_definitions(parameter_atom)
        d0 = [d for d in def0][0]
        def1 = state.get_definitions(parameter_atom_1)
        d1 = [d for d in def1][0]
        def2 = state.get_definitions(parameter_atom_2)
        d2 = [d for d in def2][0]

        if d1 not in state.dep_graph.nodes():
            state.dep_graph.add_node(d1)
        if d2 not in state.dep_graph.nodes():
            state.dep_graph.add_node(d2)

        blk = self.get_clinic_block(self.clinic, d0.codeloc.block_addr)
        extrs_defination_location = 0

        if function.name in ["snprintf", "vsnprintf"]:
            extrs_defination_location = 3
            dst_def = d3
            arg = blk.statements[-1].args[2]
            try:
                if d2.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
                    bb1 = self.cfg.insn_addr_to_memory_data[d2.codeloc.ins_addr]
                    i = 0
                    while str(self.cfg.project.loader.memory.load(bb1.addr, bb1.size + i))[bb1.size + i + 1] != '\\':
                        i += 1
                    bb = str(self.cfg.project.loader.memory.load(bb1.addr, bb1.size + i - 1))[2:-1]
                elif type(arg) == ailment.expression.Const:
                    i = 0
                    while not (
                        str(self.cfg.project.loader.memory.load(arg.value, i))[i + 1] == '\\' and
                        str(self.cfg.project.loader.memory.load(arg.value, i))[i + 2] == 'x'
                    ):
                        i += 1
                    bb = str(self.cfg.project.loader.memory.load(arg.value, i - 1))[2:-1]
                elif hasattr(arg, 'reg_offset'):
                    for smt in blk.statements:
                        if (
                            type(smt) == ailment.statement.Assignment and
                            smt.dst.tags['reg_name'] == state.arch.register_names[d0.atom.reg_offset] and
                            type(smt.src) == ailment.expression.Const
                        ):
                            i = 0
                            while str(self.cfg.project.loader.memory.load(smt.src.value, i))[i + 1] != '\\':
                                i += 1
                            bb = str(self.cfg.project.loader.memory.load(smt.src.value, i - 1))[2:-1]
                            print("Did I arrived here")
                            break
                else:
                    bb = get_strings(d2, self.cfg, state.dep_graph)

                patttern = bb.split('%')
            except Exception as e:
                bb = ""
                patttern = []
                dst_def = d2
                d3 = d2
        else:
            extrs_defination_location = 2
            dst_def = d2
            arg = blk.statements[-1].args[1]
            try:
                if d1.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
                    bb1 = self.cfg.insn_addr_to_memory_data[d1.codeloc.ins_addr]
                    i = 0
                    while str(self.cfg.project.loader.memory.load(bb1.addr, bb1.size + i))[bb1.size + i + 1] != '\\':
                        i += 1
                    bb = str(self.cfg.project.loader.memory.load(bb1.addr, bb1.size + i - 1))[2:-1]
                elif type(arg) == ailment.expression.Const:
                    i = 0
                    while not (
                        str(self.cfg.project.loader.memory.load(arg.value, i))[i + 1] == '\\' and
                        str(self.cfg.project.loader.memory.load(arg.value, i))[i + 2] == 'x'
                    ):
                        i += 1
                    bb = str(self.cfg.project.loader.memory.load(arg.value, i - 1))[2:-1]
                elif hasattr(arg, 'reg_offset'):
                    for smt in blk.statements:
                        if (
                            type(smt) == ailment.statement.Assignment and
                            smt.dst.tags['reg_name'] == state.arch.register_names[d0.atom.reg_offset] and
                            type(smt.src) == ailment.expression.Const
                        ):
                            i = 0
                            while str(self.cfg.project.loader.memory.load(smt.src.value, i))[i + 1] != '\\':
                                i += 1
                            bb = str(self.cfg.project.loader.memory.load(smt.src.value, i - 1))[2:-1]
                            print("Did I arrived here")
                            break
                else:
                    bb = get_strings(d2, self.cfg, state.dep_graph)

                patttern = bb.split('%')
            except Exception as e:
                bb = ""
                patttern = []
                dst_def = d1
                d2 = d1
        try:
            if (
                1 == 0 and hasattr(blk, "statements") and len(blk.statements) > 0 and
                self.dec is not None and
                (blk.statements[-1], False) in self.dec.codegen.ailexpr2cnode
            ):
                tmp_bb = self.dec.codegen.ailexpr2cnode[(blk.statements[-1], False)].c_repr().split(',')
                print(tmp_bb)
                if function.name in ["sprintf", "sscanf"]:
                    tmp_bb = tmp_bb[1][2:-1]
                else:
                    tmp_bb = tmp_bb[2][2:-1]
                print(tmp_bb)
                if bb != tmp_bb:
                    bb = tmp_bb
                    patttern = bb.split('%') if '%' in bb else []
        except Exception as e:
            print(e)

        if len(bb) == 0:
            try:
                if function.name in ["sprintf", "sscanf"]:
                    bb = self.get_stringby_use_def(d1, state)
                else:
                    bb = self.get_stringby_use_def(d2, state)
                patttern = bb.split('%')
            except Exception as e:
                bb = ""
                patttern = []

        extra_definations = []
        arg_number = len(patttern) - 1

        for stmt in blk.statements:
            if (
                type(stmt) == ailment.statement.Assignment and
                type(stmt.dst) == ailment.expression.Register and
                type(stmt.src) == ailment.expression.StackBaseOffset and
                stmt.src not in blk.statements[-1].args
            ):
                blk.statements[-1].args.append(stmt.src)
            elif type(stmt) == ailment.statement.Store:
                blk.statements[-1].args.append(stmt.addr)

        atom = d0.atom
        if hasattr(blk, "statements") and len(blk.statements) > 0:
            call_statement = blk.statements[-1]
            check_flag = False

            if type(call_statement) == ailment.statement.Call and call_statement.args is None:
                atom = d0.atom
                check_flag = True
            elif (
                type(call_statement) == ailment.statement.Call and
                hasattr(call_statement, "args") and
                call_statement.args is not None and
                len(call_statement.args) > 0
            ):
                arg0 = call_statement.args[0]
                if hasattr(arg0, 'base'):
                    atom = MemoryLocation(SpOffset(state.arch.bits, arg0.offset), arg0.size)
                    check_flag = True
                elif hasattr(arg0, 'reg_offset'):
                    reg = state.arch.registers[arg0.tags['reg_name']]
                    temp_def = next(iter(state.get_definitions(Register(reg[0], reg[1]))))
                    atom = temp_def.atom
                    check_flag = True
                elif (
                    type(arg0) == ailment.expression.Load and
                    hasattr(arg0, 'addr') and
                    type(arg0.addr) == ailment.expression.StackBaseOffset
                ):
                    atom = MemoryLocation(SpOffset(state.arch.bits, arg0.addr.offset), arg0.size)
                    check_flag = True
                elif (
                    type(arg0) == ailment.expression.Load and
                    hasattr(arg0, 'addr') and
                    type(arg0.addr) == ailment.expression.BinaryOp and
                    type(arg0.addr.operands[1]) == ailment.expression.Const
                ):
                    atom = MemoryLocation(
                        SpOffset(state.arch.bits, arg0.addr.operands[1].value),
                        arg0.addr.operands[1].size
                    )
                    check_flag = True
                    
                if arg_number == 0:
                    arg_number = len(call_statement.args) - extrs_defination_location

                if arg_number > 1:
                    for i in range(0, arg_number):
                        try:
                            if extrs_defination_location + i >= len(call_statement.args):
                                continue
                            arg = call_statement.args[extrs_defination_location + i]

                            if hasattr(arg, 'reg_offset'):
                                reg = state.arch.registers[arg.tags['reg_name']]
                                temp_def = [d for d in state.get_definitions(Register(reg[0], reg[1]))]
                                if len(temp_def) > 0:
                                    extra_definations.append(temp_def[0])

                            elif hasattr(arg, 'base'):
                                mem_atom = MemoryLocation(SpOffset(state.arch.bits, arg.offset), arg.size)
                                temp_def = [d for d in state.get_definitions(mem_atom)]
                                if len(temp_def) > 0:
                                    extra_definations.append(temp_def[0])
                                else:
                                    parameter_atom = Atom.from_argument(
                                        SimRegArg(cc.ARG_REGS[extrs_defination_location + i], state.arch.bytes),
                                        self._analysis.project.arch.registers
                                    )
                                    def0 = state.get_definitions(parameter_atom)
                                    temp_def = [d for d in def0]
                                    extra_definations.append(temp_def[0])

                            elif (
                                type(arg) == ailment.expression.Load and hasattr(arg, 'addr') and
                                type(arg.addr) == ailment.expression.StackBaseOffset
                            ):
                                mem_atom = MemoryLocation(SpOffset(state.arch.bits, arg.addr.offset), arg.size)
                                temp_def = [d for d in state.get_definitions(mem_atom)]
                                if len(temp_def) > 0:
                                    extra_definations.append(temp_def[0])
                                else:
                                    if extrs_defination_location + i >= len(cc.ARG_REGS):
                                        continue
                                    parameter_atom = Atom.from_argument(
                                        SimRegArg(cc.ARG_REGS[extrs_defination_location + i], state.arch.bytes),
                                        self._analysis.project.arch.registers
                                    )
                                    def0 = state.get_definitions(parameter_atom)
                                    temp_def = [d for d in def0]
                                    extra_definations.append(temp_def[0])
                        except Exception as e:
                            print('error at 916', e)
                            continue
            else:
                for smt in blk.statements:
                    if (
                        type(smt) == ailment.statement.Assignment and
                        type(smt.src) == ailment.expression.StackBaseOffset and
                        smt.dst.tags['reg_name'] == state.arch.register_names[d0.atom.reg_offset]
                    ):
                        atom = MemoryLocation(SpOffset(state.arch.bits, smt.src.offset), d0.size)
                        check_flag = True
                        break

        if arg_number > 1:
            for i in range(1, arg_number):
                try:
                    parameter_position = extrs_defination_location + i
                    if parameter_position >= len(cc.ARG_REGS):
                        continue
                    parameter_atom = Atom.from_argument(
                        SimRegArg(cc.ARG_REGS[parameter_position], state.arch.bytes),
                        self._analysis.project.arch.registers
                    )
                    def0 = state.get_definitions(parameter_atom)
                    temp_def = [d for d in def0][0]
                    extra_definations.append(temp_def)
                except Exception as e:
                    print('error at 956', e)
                    continue

        length = -1
        if function.name in ["snprintf", "vsnprintf"]:
            if type(blk.statements[-1].args[1]) == ailment.expression.Const:
                length = blk.statements[-1].args[1].value

        print("token= ", bb)

        tags = {
            LocalVariableTag(
                function=function.addr,
                metadata={
                    'tagged_by': f'{function.name} simulation Effect',
                    'block_addr': state.current_codeloc.block_addr,
                    'token': bb,
                    'length': length
                }
            )
        }

        data: MultiValues = state.register_definitions.load(d0.atom.reg_offset, size=d0.atom.size)
        tmp_codeloc = state.current_codeloc
        mv = state.kill_and_add_definition(atom, tmp_codeloc, data, tags=tags)
        ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
        ff = next(iter(ff_defs))

        if ff not in state.dep_graph.graph.nodes():
            state.dep_graph.add_node(ff)
        state.dep_graph.add_edge(d1, ff)
        state.dep_graph.add_edge(d2, ff)

        for i in range(len(extra_definations)):
            state.dep_graph.add_edge(extra_definations[i], ff)

        if function.name in ["snprintf", "vsnprintf"]:
            state.dep_graph.add_edge(d3, ff)

        ff_list = [ff]

        another_ff = self.get_memoryDef_by_use_def(d0, state)
        if another_ff is not None and another_ff.atom != atom:
            mv = state.kill_and_add_definition(another_ff.atom, tmp_codeloc, data, tags=tags)
            ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
            ff = next(iter(ff_defs))
            ff_list.append(ff)

            if ff not in state.dep_graph.graph.nodes():
                state.dep_graph.add_node(ff)
            state.dep_graph.add_edge(d1, ff)
            state.dep_graph.add_edge(d2, ff)
            for i in range(len(extra_definations)):
                state.dep_graph.add_edge(extra_definations[i], ff)
            if function.name in ["snprintf", "vsnprintf"]:
                state.dep_graph.add_edge(d3, ff)

        if function.name in ["sprintf", "sscanf"]:
            print("--------------------Start sprintf--------------------")
            def_explorer = DefinitionExplorer(self._analysis.project, state.dep_graph, self.get_cfg())
            def_explorer.set_current_state(state)
            def_explorer.set_current_codeloc(codeloc)
            def_explorer.set_RDA_handler(self)
            def_explorer.set_current_function(self.cur_fun)
            backtrack_definations(
                def_explorer,
                reg_defs=ff_list,
                result_file=self.get_result_file(),
                memcpy_func_pred=self.get_current_function(),
                FUNCS=[],
                sink=function.name,
                memcpy_addr=state.current_codeloc.ins_addr,
                result_path=self.get_source2sink_path()
            )
            print("----------------------End sprintf--------------------")
        return True, state
    
    def handle_sprintf(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="sprintf")
        return self.handle_sprintf_xx(function, state, codeloc)
    
    def handle_vsnprintf(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="vsnprintf")
        return self.handle_sprintf_xx(function, state, codeloc)
    
    def handle_sscanf(self, state, codeloc):
        print('I am inside sscanf handler')
        function = self._analysis.project.kb.functions.function(name="sscanf")
        flag, state = self.handle_system_xx(function, state, codeloc)

        print("\n now lets connect the rest")
        d1 = self.get_def_from_parameter(function, parameter_position=1, state=state)

        extrs_defination_location = 2
        try:
            bb = ""
            if d1.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
                bb1 = self.cfg.insn_addr_to_memory_data[d1.codeloc.ins_addr]
                i = 0
                while str(self.cfg.project.loader.memory.load(bb1.addr, bb1.size + i))[bb1.size + i + 1] != '\\':
                    i += 1
                bb = str(self.cfg.project.loader.memory.load(bb1.addr, bb1.size + i - 1))[2:-1]
            patttern = bb.split('%')
        except Exception as e:
            print(e)
            bb = ""
            patttern = []
            dst_def = d1
            d2 = d1

        d0 = self.get_def_from_parameter(function, parameter_position=0, state=state)
        blk = self.get_clinic_block(self.clinic, state.current_codeloc.block_addr)
        ff = self.get_memory_defination(
            d0,
            function,
            state,
            codeloc,
            defination_only=True,
            defination_location=0,
            blk=blk
        )

        if (
            (len(patttern) - 1 == 0 or len(patttern) == 0) and
            type(blk.statements[-1]) == ailment.statement.Call and
            hasattr(blk.statements[-1], "args") and
            blk.statements[-1].args is not None and
            len(blk.statements[-1].args) > 1
        ):
            try:
                i = 0
                while str(self.cfg.project.loader.memory.load(blk.statements[-1].args[1].value, i))[i + 1] != '\\':
                    i += 1
                bb = str(self.cfg.project.loader.memory.load(blk.statements[-1].args[1].value, i - 1))[2:-1]
                patttern = bb.split('%')
            except Exception as e:
                print(e, "error at 1347")

        if len(patttern) - 1 == 0 or len(patttern) == 0:
            bb = self.get_stringby_use_def(d1, state)
            patttern = bb.split('%')

        extra_definations = []
        arg_number = len(patttern) - 1
        extrs_defination_location = 2

        if arg_number == 0:
            arg_number = len(blk.statements[-1].args) - 2

        for stmt in blk.statements:
            if (
                type(stmt) == ailment.statement.Assignment and
                type(stmt.dst) == ailment.expression.Register and
                type(stmt.src) == ailment.expression.StackBaseOffset and
                stmt.src not in blk.statements[-1].args
            ):
                blk.statements[-1].args.append(stmt.src)
            elif type(stmt) == ailment.statement.Store:
                blk.statements[-1].args.append(stmt.addr)

        if arg_number > 1:
            for i in range(0, arg_number):
                try:
                    parameter_position = extrs_defination_location + i
                    if parameter_position >= len(blk.statements[-1].args):
                        continue

                    temp_d0 = self.get_def_from_parameter(
                        function,
                        parameter_position=parameter_position,
                        state=state
                    )
                    temp_def = self.get_memory_defination(
                        temp_d0,
                        function,
                        state,
                        codeloc,
                        defination_only=False,
                        defination_location=parameter_position,
                        blk=blk
                    )
                    if temp_def not in state.dep_graph.graph.nodes():
                        state.dep_graph.add_node(temp_def)

                    extra_definations.append(temp_def)
                except Exception as e:
                    print(e)
                    print("error is here inside sscanf")
                    
        for i in range(len(extra_definations)):
            state.dep_graph.add_edge(ff, extra_definations[i])
        return True, state

    def handle_snprintf(self, state, codeloc):
        print("inside snprintf")
        function = self._analysis.project.kb.functions.function(name="snprintf")
        return self.handle_sprintf_xx(function, state, codeloc)

    def handle_system_xx(self, function, state, codeloc, position=0, blk=None):
        print("inside ->", function.name)
        d0 = self.get_def_from_parameter(function, parameter_position=position, state=state)

        if blk is None:
            blk = self.get_clinic_block(self.clinic, state.current_codeloc.block_addr)
        print("for debug")
        print(blk.statements[-1])

        ff_list = [d0]
        ff = self.get_memory_defination(
            d0,
            function,
            state,
            codeloc,
            defination_only=True,
            defination_location=0,
            blk=blk
        )
        ff_list = [d0, ff]
        tmp_ff = self.get_memoryDef_by_use_def(d0, state)
        if tmp_ff is not None:
            ff_defs = [d for d in state.get_definitions(tmp_ff.atom)]
            if len(ff_defs) != 0:
                ff_list.append(ff_defs[0])

        def_explorer = DefinitionExplorer(self._analysis.project, state.dep_graph, self.get_cfg())
        def_explorer.set_current_state(state)
        def_explorer.set_current_codeloc(codeloc)
        def_explorer.set_RDA_handler(self)
        def_explorer.set_current_function(self.cur_fun)

        for item in ff_list:
            backtrack_definations(
                def_explorer,
                reg_defs=[item],
                result_file=self.get_result_file(),
                memcpy_func_pred=self.get_current_function(),
                FUNCS=[],
                sink=function.name,
                memcpy_addr=state.current_codeloc.ins_addr,
                result_path=self.get_source2sink_path()
            )
        return True, state

    def handle_wl_exec_cmd(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="wl_exec_cmd")
        return self.handle_system_xx(function, state, codeloc)

    def xx_handle__eval(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="_eval")
        return self.handle_system_xx(function, state, codeloc)

    def xx_handle_eval(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="eval")
        return self.handle_system_xx(function, state, codeloc)

    def handle_exec_shell_popen_str(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="exec_shell_popen_str")
        return self.handle_system_xx(function, state, codeloc)

    def handle_exec_shell_popen(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="exec_shell_popen")
        return self.handle_system_xx(function, state, codeloc)

    def handle_ExecShell(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="ExecShell")
        return self.handle_system_xx(function, state, codeloc)

    def handle_cgi_deal_popen(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="cgi_deal_popen")
        return self.handle_system_xx(function, state, codeloc)

    def handle_CsteSystem(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="CsteSystem")
        return self.handle_system_xx(function, state, codeloc)

    def handle_system(self, state, codeloc):
        print("inside system")
        function = self._analysis.project.kb.functions.function(name="system")
        return self.handle_system_xx(function, state, codeloc)

    def handle_twsystem(self, state, codeloc, blk=None):
        function = self._analysis.project.kb.functions.function(name="twsystem")
        return self.handle_system_xx(function, state, codeloc, position=0, blk=blk)

    def handle_bstar_system(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="bstar_system")
        return self.handle_system_xx(function, state, codeloc)

    def handle_popen(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="popen")
        return self.handle_system_xx(function, state, codeloc)

    def handle____system(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="___system")
        return self.handle_system_xx(function, state, codeloc)

    def handle_doShell(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="doShell")
        return self.handle_system_xx(function, state, codeloc)
    
    def handle_execve(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="execve")
        return self.handle_system_xx(function, state, codeloc, 1)
    
    def handle_execl(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="execl")
        return self.handle_system_xx(function, state, codeloc, 1)
    
    def handle_ExeCmd(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="ExeCmd")
        return self.handle_system_xx(function, state, codeloc)
    
    def XX_handle_kd_doCommand(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="kd_doCommand")
        return self.handle_system_xx(function, state, codeloc)
    
    def handle_doSystemCmd(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="doSystemCmd")
        patttern = []

        blk = self.get_clinic_block(self.clinic, state.current_codeloc.block_addr)
        print("inside handle local")
        print(blk)
        xx = []
        cc = function.calling_convention
        d1 = self.get_def_from_parameter(function, parameter_position=0, state=state)

        if d1.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
            pred = [d for d in state.dep_graph.predecessors(d1)]
            bb = ""
            if len(pred) == 1 and type(pred[0].atom) != MemoryLocation:
                pred = [d for d in state.dep_graph.predecessors(pred[0])]
            for defination in pred:
                if type(defination.atom) == MemoryLocation and 'readonly' in f'{defination}':
                    i = 0
                    while str(self.cfg.project.loader.memory.load(defination.atom.addr, i + 1))[i + 1] != '\\':
                        i += 1
                    bb = str(self.cfg.project.loader.memory.load(defination.atom.addr, i - 1))[2:-1]
                    break
            if len(bb) == 0:
                i = 0
                while str(self.cfg.project.loader.memory.load(d1.atom.addr, i + 1))[i + 1] != '\\':
                    i += 1
                bb = str(self.cfg.project.loader.memory.load(d1.atom.addr, i - 1))[2:-1]
            if len(bb) > 2:
                patttern = xx = bb.split("%")
            print(xx)

        print("----------")

        try:
            if (
                blk is not None and hasattr(blk, "statements") and len(blk.statements) > 0 and
                type(blk.statements[-1]) == ailment.statement.Call and
                hasattr(blk.statements[-1], "args") and
                blk.statements[-1].args is not None and
                len(blk.statements[-1].args) > 1
            ):
                d0 = self.get_def_from_parameter(function, parameter_position=0, state=state)
                if len(xx) > 1:
                    bb = xx[0]
                elif d0.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
                    bb1 = self.cfg.insn_addr_to_memory_data[d0.codeloc.ins_addr]
                    i = 0
                    while str(self.cfg.project.loader.memory.load(bb1.addr, bb1.size + i))[bb1.size + i + 1] != '\\':
                        i += 1
                    bb = str(self.cfg.project.loader.memory.load(bb1.addr, bb1.size + i - 1))[2:-1]
                else:
                    bb = get_strings(d0, self.cfg, state.dep_graph)

                if "%" in bb:
                    patttern = bb.split('%')

                print("bb =", bb, patttern)

                extrs_defination_location = 1
                extra_definations = []
                arg_number = len(patttern) - 1
                print("arg_number ->", arg_number)

                if arg_number > 0:
                    for i in range(0, arg_number):
                        if not hasattr(blk.statements[-1], 'args'):
                            continue
                        arg = blk.statements[-1].args[extrs_defination_location + i]
                        print(arg)

                        if hasattr(arg, 'reg_offset'):
                            reg = state.arch.registers[arg.tags['reg_name']]
                            temp_def = [d for d in state.get_definitions(Register(reg[0], reg[1]))]
                            if len(temp_def) > 0:
                                extra_definations.append(temp_def[0])

                        elif hasattr(arg, 'base'):
                            mem_atom = MemoryLocation(SpOffset(state.arch.bits, arg.offset), arg.size)
                            temp_def = [d for d in state.get_definitions(mem_atom)]
                            if len(temp_def) > 0:
                                extra_definations.append(temp_def[0])
                            else:
                                temp_def = self.get_def_from_parameter(function, parameter_position=extrs_defination_location + i, state=state)
                                if temp_def is not None:
                                    extra_definations.append(temp_def)

                        elif (
                            type(arg) == ailment.expression.Load and hasattr(arg, 'addr') and
                            type(arg.addr) == ailment.expression.StackBaseOffset
                        ):
                            mem_atom = MemoryLocation(SpOffset(state.arch.bits, arg.addr.offset), arg.size)
                            temp_def = [d for d in state.get_definitions(mem_atom)]
                            if len(temp_def) > 0:
                                extra_definations.append(temp_def[0])
                            else:
                                parameter_atom = Atom.from_argument(
                                    SimRegArg(cc.ARG_REGS[extrs_defination_location + i], state.arch.bytes),
                                    self._analysis.project.arch.registers
                                )
                                def0 = state.get_definitions(parameter_atom)
                                temp_def = [d for d in def0]
                                if len(temp_def) > 0:
                                    extra_definations.append(temp_def[0])

                    print("extra_definations ->", extra_definations)

                    for d0 in extra_definations:
                        def_explorer = DefinitionExplorer(self._analysis.project, state.dep_graph, self.get_cfg())
                        def_explorer.set_current_state(state)
                        def_explorer.set_current_codeloc(codeloc)
                        def_explorer.set_RDA_handler(self)
                        def_explorer.set_current_function(self.cur_fun)

                        backtrack_definations(
                            def_explorer,
                            reg_defs=[d0],
                            result_file=self.get_result_file(),
                            memcpy_func_pred=self.get_current_function(),
                            FUNCS=[],
                            sink=function.name,
                            memcpy_addr=state.current_codeloc.ins_addr,
                            result_path=self.get_source2sink_path()
                        )
                    return True, state

            elif len(patttern) > 0:
                extrs_defination_location = 1
                extra_definations = []
                arg_number = len(patttern) - 1
                print("arg_number ->", arg_number)

                if arg_number > 0:
                    for i in range(0, arg_number):
                        d1 = self.get_def_from_parameter(function, parameter_position=extrs_defination_location + i, state=state)
                        extra_definations.append(d1)

                    for d0 in extra_definations:
                        def_explorer = DefinitionExplorer(self._analysis.project, state.dep_graph, self.get_cfg())
                        def_explorer.set_current_state(state)
                        def_explorer.set_current_codeloc(codeloc)
                        def_explorer.set_RDA_handler(self)
                        def_explorer.set_current_function(self.cur_fun)

                        backtrack_definations(
                            def_explorer,
                            reg_defs=[d0],
                            result_file=self.get_result_file(),
                            memcpy_func_pred=self.get_current_function(),
                            FUNCS=[],
                            sink=function.name,
                            memcpy_addr=state.current_codeloc.ins_addr,
                            result_path=self.get_source2sink_path()
                        )
                return True, state
            else:
                return self.handle_system_xx(function, state, codeloc)

        except Exception as e:
            print(e)
            return True, state

    def handle_doSystem(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="doSystem")
        cc = function.calling_convention

        parameter_position = 0
        parameter_atom = Atom.from_argument(
            SimRegArg(cc.ARG_REGS[parameter_position], state.arch.bytes),
            self._analysis.project.arch.registers
        )
        def0 = state.get_definitions(parameter_atom)
        d0 = [d for d in def0][0]

        if d0.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
            bb1 = self.cfg.insn_addr_to_memory_data[d0.codeloc.ins_addr]
            i = 0
            while str(self.cfg.project.loader.memory.load(bb1.addr, bb1.size + i))[bb1.size + i + 1] != '\\':
                i += 1
            bb = str(self.cfg.project.loader.memory.load(bb1.addr, bb1.size + i - 1))[2:-1]
        else:
            bb = get_strings(d0, self.cfg, state.dep_graph)

        patttern = bb.split('%')
        extrs_defination_location = 1
        extra_definations = []
        arg_number = len(patttern)

        if arg_number > 1:
            for i in range(1, arg_number):
                if i >= len(cc.ARG_REGS):
                    break
                parameter_position = i
                parameter_atom = Atom.from_argument(
                    SimRegArg(cc.ARG_REGS[parameter_position], state.arch.bytes),
                    self._analysis.project.arch.registers
                )
                def0 = state.get_definitions(parameter_atom)
                d0 = [d for d in def0][0]
                extra_definations.append(d0)

            for d0 in extra_definations:
                def_explorer = DefinitionExplorer(self._analysis.project, state.dep_graph, self.get_cfg())
                def_explorer.set_RDA_handler(self)
                def_explorer.set_current_function(self.cur_fun)
                backtrack_definations(
                    def_explorer,
                    reg_defs=[d0],
                    result_file=self.get_result_file(),
                    memcpy_func_pred=self.get_current_function(),
                    FUNCS=[],
                    sink=function.name,
                    memcpy_addr=state.current_codeloc.ins_addr,
                    result_path=self.get_source2sink_path()
                )
        return True, state

    def handle__system(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="_system")
        cc = function.calling_convention
        parameter_position = 0
        parameter_atom = Atom.from_argument(
            SimRegArg(cc.ARG_REGS[parameter_position], state.arch.bytes),
            self._analysis.project.arch.registers
        )
        def0 = state.get_definitions(parameter_atom)
        d0 = [d for d in def0][0]

        if d0.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
            bb1 = self.cfg.insn_addr_to_memory_data[d0.codeloc.ins_addr]
            i = 0
            while str(self.cfg.project.loader.memory.load(bb1.addr, bb1.size + i))[bb1.size + i + 1] != '\\':
                i += 1
            bb = str(self.cfg.project.loader.memory.load(bb1.addr, bb1.size + i - 1))[2:-1]
        else:
            bb = get_strings(d0, self.cfg, state.dep_graph)

        patttern = bb.split('%')
        extrs_defination_location = 1
        extra_definations = []
        arg_number = len(patttern)

        if arg_number > 1:
            for i in range(1, arg_number):
                if i >= len(cc.ARG_REGS):
                    break

                parameter_position = i
                parameter_atom = Atom.from_argument(
                    SimRegArg(cc.ARG_REGS[parameter_position], state.arch.bytes),
                    self._analysis.project.arch.registers
                )
                def0 = state.get_definitions(parameter_atom)
                d0 = [d for d in def0][0]
                extra_definations.append(d0)

            for d0 in extra_definations:
                def_explorer = DefinitionExplorer(self._analysis.project, state.dep_graph, self.get_cfg())
                def_explorer.set_RDA_handler(self)
                def_explorer.set_current_function(self.cur_fun)

                backtrack_definations(
                    def_explorer,
                    reg_defs=[d0],
                    result_file=self.get_result_file(),
                    memcpy_func_pred=self.get_current_function(),
                    FUNCS=[],
                    sink=function.name,
                    memcpy_addr=state.current_codeloc.ins_addr,
                    result_path=self.get_source2sink_path()
                )
        return True, state
    
    def handle_strchr_xx(self, function, state, codeloc):
        print("inside ->", function.name)
        d0 = self.get_def_from_parameter(function, parameter_position=0, state=state)
        dd0 = d0
        data: MultiValues = state.register_definitions.load(dd0.atom.reg_offset, size=d0.atom.size)
        ret_register_name = state.arch.register_names[state.arch.ret_offset]
        ret_register_name_size = state.arch.registers[ret_register_name]
        atom = Register(ret_register_name_size[0], ret_register_name_size[1])

        tags_2 = {
            LocalVariableTag(
                function=function.addr,
                metadata={
                    'tagged_by': f'{function.name} simulation Effect',
                    'block_addr': state.current_codeloc.block_addr
                }
            )
        }
        if d0.atom == atom:
            d0.tags.clear()
            d0.tags.update(tags_2)
            new_rax = d0
        try:
            new_rax = d0
            mv = state.kill_and_add_definition(atom, state.current_codeloc, data, tags=tags_2)
            ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
            new_rax = [d for d in ff_defs][0]
        except Exception as e:
            print(e)
        state.dep_graph.add_edge(d0, new_rax)
        return True, state

    def handle_strdup(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="strdup")
        return self.handle_strchr_xx(function, state, codeloc)
    
    def handle_strndup(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="strndup")
        return self.handle_strchr_xx(function, state, codeloc)
    
    def handle_strrchr(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="strrchr")
        return self.handle_strchr_xx(function, state, codeloc)
    
    def handle_strstr(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="strstr")
        return self.handle_strchr_xx(function, state, codeloc)
    
    def handle_stristr(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="stristr")
        return self.handle_strchr_xx(function, state, codeloc)
    
    def handle_strpbrk(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="strpbrk")
        return self.handle_strchr_xx(function, state, codeloc)
    
    def handle_atoi(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="atoi")
        return self.handle_strchr_xx(function, state, codeloc)
    
    def handle_strspn(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="strspn")
        return self.handle_strchr_xx(function, state, codeloc)

    def handle_strchr(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="strchr")
        return self.handle_strchr_xx(function, state, codeloc)
    
    def handle_getTokens(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="getTokens")
        d0 = self.get_def_from_parameter(function, parameter_position=0, state=state)
        d2 = self.get_def_from_parameter(function, parameter_position=2, state=state)
        blk = self.get_clinic_block(self.clinic, state.current_codeloc.block_addr)
        d0 = self.get_memory_defination(
            d0,
            function,
            state,
            codeloc,
            defination_only=True,
            defination_location=0
        )
        ff = self.get_memory_defination(d2, function, state, codeloc)
        tags = {
            LocalVariableTag(
                function=function.addr,
                metadata={
                    'tagged_by': f'{function.name} simulation Effect',
                    'block_addr': state.current_codeloc.block_addr
                }
            )
        }
        ff.tags.update(tags)
        state.dep_graph.add_node(ff)
        state.dep_graph.add_edge(d0, ff)
        return True, state

    def handle_strcpy_xx(self, function, state, codeloc):
        print("inside", function.demangled_name)
        d0 = self.get_def_from_parameter(function, parameter_position=0, state=state)
        d1 = self.get_def_from_parameter(function, parameter_position=1, state=state)
        dd1 = self.get_def_from_parameter(function, parameter_position=1, state=state)
        try:
            d2 = self.get_def_from_parameter(function, parameter_position=2, state=state)
        except Exception as e:
            d2 = None
        bb = ""
        try:
            if d1.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
                bb1 = self.cfg.insn_addr_to_memory_data[d1.codeloc.ins_addr]
                bb = str(bb1.content)[2:-1]
                i = 0
                while str(self.cfg.project.loader.memory.load(bb1.addr, bb1.size + i))[bb1.size + i + 1] != '\\':
                    i += 1
                    bb = str(self.cfg.project.loader.memory.load(bb1.addr, bb1.size + i - 1))[2:-1]
            else:
                bb = get_strings(d2, self.cfg, state.dep_graph)
        except Exception as e:
            bb = ""

        print("state.current_", state.current_codeloc)

        blk = self.get_clinic_block(self.clinic, state.current_codeloc.block_addr)
        d1 = self.get_memory_defination(d1, function, state, codeloc, defination_only=True, defination_location=1)
        ff = self.get_memory_defination(d0, function, state, codeloc, defination_only=False, defination_location=0, blk=blk)
        config_sgtaint.strcpy_counter[0] += 1
        length = -1
        is_tainted_falg = False

        try:
            if function.name in ["strncpy", "strlcpy", "strncat", "memcpy", "memmove"]:
                if type(blk.statements[-1].args[2]) == ailment.expression.Const:
                    length = blk.statements[-1].args[2].value
                    tags = {
                        LocalVariableTag(
                            function=function.addr,
                            metadata={
                                'tagged_by': f'{function.name} simulation Effect',
                                'block_addr': state.current_codeloc.block_addr,
                                'length': length
                            }
                        )
                    }
                    ff.tags.update(tags)
                else:
                    d2 = self.get_def_from_parameter(function, parameter_position=2, state=state)
                    d2 = self.get_memory_defination(d2, function, state, codeloc, defination_only=True, defination_location=2)
                    is_tainted_falg = self.is_defination_tainted(d2, function, state)
        except Exception as e:
            print("error 1570", e)
            tags = {
                LocalVariableTag(
                    function=function.addr,
                    metadata={
                        'tagged_by': f'{function.name} simulation Effect',
                        'block_addr': state.current_codeloc.block_addr,
                        'length': length
                    }
                )
            }
            ff.tags.update(tags)

        if len(bb) > 5 and isinstance(ff.atom, MemoryLocation):
            tags = {
                LocalVariableTag(
                    function=function.addr,
                    metadata={
                        'tagged_by': f'{function.name} simulation Effect',
                        'block_addr': state.current_codeloc.block_addr,
                        'length': length
                    }
                )
            }
            ff.tags.update(tags)

        state.dep_graph.add_node(ff)
        if "cat" in function.demangled_name:
            state.dep_graph.add_edge(d0, ff)
        state.dep_graph.add_edge(d1, ff)
        if dd1.atom != d1.atom:
            state.dep_graph.add_edge(dd1, ff)

        state.add_memory_use_by_defs([ff], state.current_codeloc)
        state.add_use_by_def(ff, state.current_codeloc, None)

        try:
            if function.name in ["strcpy", "strcat"] or is_tainted_falg:
                def_explorer = DefinitionExplorer(self._analysis.project, state.dep_graph, self.get_cfg())
                def_explorer.set_current_state(state)
                def_explorer.set_current_codeloc(codeloc)
                def_explorer.set_RDA_handler(self)
                def_explorer.set_current_function(self.cur_fun)

                backtrack_definations(
                    def_explorer,
                    reg_defs=[ff],
                    result_file=self.get_result_file(),
                    memcpy_func_pred=self.get_current_function(),
                    FUNCS=[],
                    sink=function.name,
                    memcpy_addr=state.current_codeloc.ins_addr,
                    result_path=self.get_source2sink_path()
                )
        except Exception as e:
            print("error 1628", e)
            raise e
        return True, state
    
    def handle_strcpy(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="strcpy")
        return self.handle_strcpy_xx(function, state, codeloc)

    def handle_strncpy(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="strncpy")
        return self.handle_strcpy_xx(function, state, codeloc)

    def handle_strlcpy(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="strlcpy")
        return self.handle_strcpy_xx(function, state, codeloc)
    
    def handle_strlcat(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="strlcat")
        return self.handle_strcpy_xx(function, state, codeloc)
    
    def handle_strcat(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="strcat")
        return self.handle_strcpy_xx(function, state, codeloc)

    def handle_strncat(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="strncat")
        return self.handle_strcpy_xx(function, state, codeloc)
    
    def handle_memcpy(self, state, codeloc): 
        function = self._analysis.project.kb.functions.function(name="memcpy")
        return self.handle_strcpy_xx(function, state, codeloc)
    
    def handle_memmove(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="memmove")
        return self.handle_strcpy_xx(function, state, codeloc)
    
    def handle_webGetVarString(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="webGetVarString")
        print("inside ->", function.name)
        d0 = self.get_def_from_parameter(function, parameter_position=0, state=state)
        d1 = self.get_def_from_parameter(function, parameter_position=1, state=state)
        if d0.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
            d0 = d1
        tags_2 = {
            ReturnValueTag(
                function=function.addr,
                metadata={
                    'tagged_by': f'{function.name} simulation Effect',
                    'block_addr': state.current_codeloc.block_addr
                }
            )
        }
        ret_register_name = state.arch.register_names[state.arch.ret_offset]
        ret_register_name_size = state.arch.registers[ret_register_name]
        atom = Register(ret_register_name_size[0], ret_register_name_size[1])

        data: MultiValues = state.register_definitions.load(d1.atom.reg_offset, size=d1.atom.size)
        mv = state.kill_and_add_definition(atom, d1.codeloc, data, tags=tags_2)
        ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
        new_rax = [d for d in ff_defs][0]

        state.dep_graph.add_edge(d0, new_rax)
        state.dep_graph.add_edge(d1, new_rax)
        state.add_use_by_def(d0, d0.codeloc, None)
        state.add_use_by_def(d1, d1.codeloc, None)
        return True, state

    def xx_handle_find_val(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="find_val")
        d1 = self.get_def_from_parameter(function, parameter_position=1, state=state)
        tags_2 = {
            ReturnValueTag(
                function=function.addr,
                metadata={
                    'tagged_by': f'{function.name} simulation Effect',
                    'block_addr': state.current_codeloc.block_addr
                }
            )
        }
        ret_register_name = state.arch.register_names[state.arch.ret_offset]
        ret_register_name_size = state.arch.registers[ret_register_name]
        atom = Register(ret_register_name_size[0], ret_register_name_size[1])

        data: MultiValues = state.register_definitions.load(d1.atom.reg_offset, size=d1.atom.size)
        mv = state.kill_and_add_definition(atom, d1.codeloc, data, tags=tags_2)
        ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
        new_rax = [d for d in ff_defs][0]
        state.dep_graph.add_edge(d1, new_rax)
        state.add_use_by_def(d1, d1.codeloc, None)
        return True, state

    # 通过value_position进行参数传递
    def handle_get_cgi_xx(self, function, state, codeloc, position=0, value_position=None):
        print("inside ->", function.name)
        d0 = self.get_def_from_parameter(function, parameter_position=position, state=state)
        blk = self.get_clinic_block(self.clinic, state.current_codeloc.block_addr)

        # 拿到最后一条调用语句，后面可能用到 args
        call_stmt = None
        if hasattr(blk, "statements") and blk.statements:
            call_stmt = blk.statements[-1]

        if value_position is None:
            reg_name = state.arch.register_names[state.arch.ret_offset]
            reg_off, reg_size = state.arch.registers[reg_name]
            atom = Register(reg_off, reg_size)
        else:
            if call_stmt is not None \
                and type(call_stmt) == ailment.statement.Call \
                and hasattr(call_stmt, "args") \
                and call_stmt.args is not None \
                and len(call_stmt.args) > value_position:
                    arg = call_stmt.args[value_position]
                    # 如果它是一个基于 SP 的内存地址（典型的缓冲区指针）
                    if hasattr(arg, 'base'):
                        atom = MemoryLocation(
                            SpOffset(state.arch.bits, arg.offset),
                            arg.size
                        )
                    else: # fallback：拿原来的定义（可能是寄存器或其它）
                        defn = self.get_def_from_parameter(function, parameter_position=value_position, state=state)
                        atom = defn.atom
                                     
        config_sgtaint.getenv_counter[0] += 1

        if function.name == "nvram_get" and len(function.arguments) == 2 and d0.codeloc.ins_addr not in self.cfg.insn_addr_to_memory_data:
            d0 = self.get_def_from_parameter(function, parameter_position=1, state=state)

        token = "" # 存储对应的key值
        tags_2 = {
            ReturnValueTag(
                function=function.addr,
                metadata={
                    'tagged_by': f'{function.name} simulation Effect',
                    'block_addr': state.current_codeloc.block_addr
                }
            )
        }

        if d0.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
            bb1 = self.cfg.insn_addr_to_memory_data[d0.codeloc.ins_addr]
            i = 0
            while str(self.cfg.project.loader.memory.load(bb1.addr, bb1.size + i))[bb1.size + i + 1] != '\\':
                i += 1
            token = str(self.cfg.project.loader.memory.load(bb1.addr, bb1.size + i - 1))[2:-1]
            if len(token) == 0:
                arg = blk.statements[-1].args[0]
                if hasattr(arg, 'reg_offset'):
                    for smt in blk.statements:
                        if (
                            isinstance(smt, ailment.statement.Assignment) and
                            smt.dst.tags['reg_name'] == state.arch.register_names[d0.atom.reg_offset] and
                            isinstance(smt.src, ailment.expression.Const)
                        ):
                            i = 0
                            while str(self.cfg.project.loader.memory.load(smt.src.value, i))[i + 1] != '\\':
                                i += 1
                            token = str(self.cfg.project.loader.memory.load(smt.src.value, i - 1))[2:-1]
                            print("Did I arrived here")
                            break
            tags_2 = {
                ReturnValueTag(
                    function=function.addr,
                    metadata={
                        'tagged_by': f'{function.name} simulation Effect',
                        'block_addr': state.current_codeloc.block_addr,
                        'token': token
                    }
                )
            }
            print("d0 in salt")

        elif d0.codeloc.ins_addr not in self.cfg.insn_addr_to_memory_data:
            pred = [d for d in state.dep_graph.predecessors(d0)]
            if len(pred) == 1 and not isinstance(pred[0].atom, MemoryLocation):
                pred = [d for d in state.dep_graph.predecessors(pred[0])]
                for definition in pred:
                    if isinstance(definition.atom, MemoryLocation) and 'readonly' in str(definition):
                        i = 0
                        while str(self.cfg.project.loader.memory.load(definition.atom.addr, i + 1))[i + 1] != '\\':
                            i += 1
                        token = str(self.cfg.project.loader.memory.load(definition.atom.addr, i - 1))[2:-1]
                        tags_2 = {
                            ReturnValueTag(
                                function=function.addr,
                                metadata={
                                    'tagged_by': f'{function.name} simulation Effect',
                                    'block_addr': state.current_codeloc.block_addr,
                                    'token': token
                                }
                            )
                        }
                        print("fixing the salt")
                        break
            elif len(pred) >= 1:
                for definition in pred:
                    if definition.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
                        tags_2 = definition.tags
                        d0 = definition
                        break
                    elif isinstance(definition.atom, MemoryLocation):
                        curr_tag = (definition.tags.copy()).pop()
                        if curr_tag.function and 'token' in curr_tag.metadata:
                            token = curr_tag.metadata['token']
                            tags_2 = {
                                ReturnValueTag(
                                    function=function.addr,
                                    metadata={
                                        'tagged_by': f'{function.name} simulation Effect',
                                        'block_addr': state.current_codeloc.block_addr,
                                        'token': token
                                    }
                                )
                            }
                            print("got gold there")
                            break
            else:
                tags_2 = {
                    ReturnValueTag(
                        function=function.addr,
                        metadata={
                            'tagged_by': f'{function.name} simulation Effect',
                            'block_addr': state.current_codeloc.block_addr,
                            'token': token
                        }
                    )
                }

        if token == "" and hasattr(blk, "statements") and len(blk.statements) > 0:
            for smt in blk.statements:
                if (
                    isinstance(smt, ailment.statement.Assignment) and
                    isinstance(smt.dst, ailment.expression.Register) and
                    smt.dst.tags['reg_name'] == state.arch.register_names[d0.atom.reg_offset] and
                    isinstance(smt.src, ailment.expression.Const)
                ):
                    i = 0
                    try:
                        while str(self.cfg.project.loader.memory.load(smt.src.value, i + 1))[i + 1] != '\\':
                            i += 1
                    except Exception:
                        i -= 1
                    token = str(self.cfg.project.loader.memory.load(smt.src.value, i - 1))[2:-1]
                    tags_2 = {
                        ReturnValueTag(
                            function=function.addr,
                            metadata={
                                'tagged_by': f'{function.name} simulation Effect',
                                'block_addr': state.current_codeloc.block_addr,
                                'token': token
                            }
                        )
                    }
                    print("further fix")
                    break

        if token == "":
            # 可以从SGGraph中读取对应的token值
            if function.name in self.call_sites_dict:
                call_sites_dict_block_addr = self.call_sites_dict[function.name]
                if state.current_codeloc.block_addr in call_sites_dict_block_addr:
                    call_site_info = call_sites_dict_block_addr[state.current_codeloc.block_addr]
                    if call_site_info[3] != -1:
                        token = call_site_info[3]
                    else:
                        token = self.get_stringby_use_def(d0, state)
                else:
                    token = self.get_stringby_use_def(d0, state)
            else:
                token = self.get_stringby_use_def(d0, state)
            tags_2 = {
                ReturnValueTag(
                    function=function.addr,
                    metadata={
                        'tagged_by': f'{function.name} simulation Effect',
                        'block_addr': state.current_codeloc.block_addr,
                        'token': token
                    }
                )
            }
        if d0.atom == atom:
            d0.tags.update(tags_2)
            new_rax = d0
        data: MultiValues = state.register_definitions.load(d0.atom.reg_offset, size=d0.atom.size)

        try:
            mv = state.kill_and_add_definition(atom, state.current_codeloc, data, tags=tags_2)
        except Exception as e:
            print("error in kill-and-add-definition", e)
            # 创建一个新的 Definition 并 annotate
            missing_def = Definition(atom, state.current_codeloc)
            bvv = claripy.BVV(token.encode(), len(token) * state.arch.byte_width)
            annotated = state.annotate_with_def(bvv, missing_def)
            mv = state.kill_and_add_definition(atom,
                                               state.current_codeloc,
                                               MultiValues(annotated),
                                               tags=tags_2)

        ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
        new_rax = [d for d in ff_defs][0]
        state.dep_graph.add_edge(d0, new_rax)
        d0.tags.update(tags_2)
        new_rax.tags.update(tags_2)
        state.add_use_by_def(d0, d0.codeloc, None)
        print("token ->", token)
        print("new_rax\n", new_rax)
        print("tags_2\n", tags_2)
        return True, state
    
    def handle_acosNvramConfig_read_xx(self, function, state, codeloc, key_parameter=0, buf_parameter=1): # 处理将值存储在参数的情况
        print("inside ->", function.name)
        d1 = self.get_def_from_parameter(function, parameter_position=key_parameter, state=state)
        blk = self.get_clinic_block(self.clinic, state.current_codeloc.block_addr)
        if hasattr(blk, "statements") and len(blk.statements) > 0:
            call_statement = blk.statements[-1]
            if (
                isinstance(call_statement, ailment.statement.Call)
                and hasattr(call_statement, "args")
                and call_statement.args is not None
                and len(call_statement.args) > buf_parameter
            ):
                arg0 = call_statement.args[buf_parameter]
                if hasattr(arg0, "base"): # 基于栈的局部变量
                    atom = MemoryLocation(SpOffset(state.arch.bits, arg0.offset), arg0.size)
                    bb = ""
                    if self.dec is not None:
                        xx = self.dec.codegen.ailexpr2cnode[(call_statement, False)].c_repr()
                        if 'reference_variable' in call_statement.args[key_parameter].tags:
                            bb = xx.split('"')[1]
                    # 从set-get graph中读取字符值
                    if not bb:
                        if function.name in self.call_sites_dict:
                            call_sites_dict_block_addr = self.call_sites_dict[function.name]
                            if state.current_codeloc.block_addr in call_sites_dict_block_addr:
                                call_site_info = call_sites_dict_block_addr[state.current_codeloc.block_addr]
                                if call_site_info[3] != -1:
                                    bb = call_site_info[3] # 从SG图中获取对应的键值
                    tags = {
                        ReturnValueTag(
                            function=function.addr,
                            metadata={
                                'tagged_by': f'{function.name} simulation Effect',
                                'block_addr': state.current_codeloc.block_addr,
                                'token': bb
                            }
                        )
                    }
                    print("tags\n", tags)
                    data: MultiValues = state.register_definitions.load(
                        d1.atom.reg_offset, size=d1.atom.size
                    )
                    tmp_codeloc = state.current_codeloc
                    mv = state.kill_and_add_definition(atom, d1.codeloc, data, tags=tags)
                    ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
                    ff = next(iter(ff_defs))
                    state.dep_graph.add_node(ff)
                    state.dep_graph.add_edge(d1, ff)
                    return True, state
    
    # 动态创建getter函数的handle
    def _create_getter_handle(self, function_name, key_index, value_index):
        def _handler(state: "ReachingDefinitionsState", codeloc):
            function = self._analysis.project.kb.functions.function(name=function_name)
            if value_index is None:
                return self.handle_get_cgi_xx(function, state, codeloc, position=key_index)
            return self.handle_acosNvramConfig_read_xx(function, state, codeloc, key_parameter=key_index, buf_parameter=value_index)
        return _handler
    
    def getter_handle_dynamic(self, function_name, key_index, value_index):
        method_name = f"handle_{function_name}"
        if not hasattr(self, method_name):
            handler = self._create_getter_handle(function_name, key_index, value_index)
            setattr(self, method_name, handler)
    
    def handle_acosNvramConfig_read(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="acosNvramConfig_read")
        return self.handle_acosNvramConfig_read_xx(function, state, codeloc)
    
    def handle_nvram_get_ex2(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="nvram_get_ex2")
        return self.handle_acosNvramConfig_read_xx(function, state, codeloc)
    
    def handle_sub_1d170(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="sub_1d170")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_get_cgi(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="get_cgi")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_nvram_default_get(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="nvram_default_get")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_nvram_pf_get(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="nvram_pf_get")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_acosNvramConfig_get(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="acosNvramConfig_get")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_config_get(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="config_get")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_uciGet(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="uciGet")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_entry(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="entry")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_wpa_config_get(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="wpa_config_get")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_httpGenListDataGet(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="httpGenListDataGet")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_vici_find_str(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="vici_find_str")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_DoHardwareComponent(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="DoHardwareComponent")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_device_get_string_value(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="device_get_string_value")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_cJSON_Parse(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="cJSON_Parse")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_OM_ValGet(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="OM_ValGet")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_acosUciConfig_get(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="acosUciConfig_get")
        return self.handle_get_cgi_xx(function, state, codeloc)
    
    def handle_CAL_abstract_get(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="CAL_abstract_get")
        return self.handle_get_cgi_xx(function, state, codeloc)
    
    def handle_OM_ValFind(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="OM_ValFind")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_get_parameter(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="get_parameter")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_get_wlan_setting(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="get_wlan_setting")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_av_dict_get(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="av_dict_get")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_cgi_value(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="cgi_value")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_stringOut(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="stringOut")
        return self.handle_get_cgi_xx(function, state, codeloc)
    
    def handle_cJSON_GetObjectItem(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="cJSON_GetObjectItem")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_sw_getValueByName(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="sw_getValueByName")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_querystr(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="querystr")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_find_val(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="find_val")
        return self.handle_get_cgi_xx(function, state, codeloc, 1)

    def handle_log_query(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="log_query")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_value_parser_by_index_D7000(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="value_parser_by_index_D7000")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_getoption(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="getoption")
        return self.handle_get_cgi_xx(function, state, codeloc)
    
    def handle_WEB_GetVar(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="WEB_GetVar")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_av_opt_get(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="av_opt_get")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_paramValueFromObjGet(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="paramValueFromObjGet")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_help_getObjPtr(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="help_getObjPtr")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_NCONF_get_string(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="NCONF_get_string")
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_av_metadata_get(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="av_metadata_get")
        return self.handle_get_cgi_xx(function, state, codeloc)
    
    def handle_httpGetEnv(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="httpGetEnv")  
        return self.handle_get_cgi_xx(function, state, codeloc)
    
    def handle_nvram_get(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="nvram_get")  
        return self.handle_get_cgi_xx(function, state, codeloc)
    
    def handle_config_get(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="config_get")  
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_nvram_safe_get(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="nvram_safe_get")  
        return self.handle_get_cgi_xx(function, state, codeloc)
    
    def handle_bcm_nvram_get(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="bcm_nvram_get")  
        return self.handle_get_cgi_xx(function, state, codeloc)
    
    def handle_getenv(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="getenv")  
        return self.handle_get_cgi_xx(function, state, codeloc)
    
    def handle_nvram_default_get(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="nvram_default_get")  
        return self.handle_get_cgi_xx(function, state, codeloc)
    
    def handle_gets(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="gets")  
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_recv(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="recv")
        return self.handle_get_cgi_xx(function, state, codeloc, 1)
        
    def handle_recvfrom(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="recvfrom")
        return self.handle_get_cgi_xx(function, state, codeloc, 1)
        
    def handle_recvmsg(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="recvmsg")
        return self.handle_get_cgi_xx(function, state, codeloc, 1)
        
    def handle_recvmmsg(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="recvmmsg")
        return self.handle_get_cgi_xx(function, state, codeloc, 1)
    
    def handle_json_object_object_get_ex(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="json_object_object_get_ex")
        return self.handle_get_cgi_xx(function, state, codeloc, 2)

    def handle_sub_42af24(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="sub_42af24")  
        return self.handle_get_cgi_xx(function, state, codeloc)

    def handle_fgets(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="fgets")
        cc = function.calling_convention
        parameter_position = 0
        parameter_atom = Atom.from_argument(
            SimRegArg(cc.ARG_REGS[parameter_position], state.arch.bytes),
            self._analysis.project.arch.registers
        )
        parameter_position_1 = 1
        parameter_atom_1 = Atom.from_argument(
            SimRegArg(cc.ARG_REGS[parameter_position_1], state.arch.bytes),
            self._analysis.project.arch.registers
        )
        parameter_position_2 = 2
        parameter_atom_2 = Atom.from_argument(
            SimRegArg(cc.ARG_REGS[parameter_position_2], state.arch.bytes),
            self._analysis.project.arch.registers
        )

        def0 = state.get_definitions(parameter_atom)
        d0 = [d for d in def0][0]
        def1 = state.get_definitions(parameter_atom_2)
        d2 = [d for d in def1][0]

        ff = self.get_memory_defination(d0, function, state, codeloc)
        tags_2 = {
            ReturnValueTag(
                function=function.addr,
                metadata={
                    'tagged_by': f'{function.name} simulation Effect',
                    'block_addr': state.current_codeloc.block_addr
                }
            )
        }
        ret_register_name = state.arch.register_names[state.arch.ret_offset]
        ret_register_name_size = state.arch.registers[ret_register_name]
        atom = Register(ret_register_name_size[0], ret_register_name_size[1])
        data: MultiValues = state.register_definitions.load(d0.atom.reg_offset, size=d0.atom.size)
        mv = state.kill_and_add_definition(atom, d0.codeloc, data, tags=tags_2)
        ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
        new_rax = [d for d in ff_defs][0]
        state.dep_graph.add_edge(new_rax, ff)
        state.add_use_by_def(new_rax, d0.codeloc, None)
        return True, state

    def handle_websGetVar(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="websGetVar")
        d1 = self.get_def_from_parameter(function, parameter_position=1, state=state)
        return  self.process_sub_42a978(function, state, codeloc, d1)

    def handle_nvram_set_xx(self, function, state, codeloc, function_name, key_position=0, value_position=1):
        blk = self.get_clinic_block(self.clinic, state.current_codeloc.block_addr)
        print("inside ->", function.name)
        d0 = self.get_def_from_parameter(function, parameter_position=key_position, state=state, blk=blk)
        d1 = self.get_def_from_parameter(function, parameter_position=value_position, state=state, blk=blk)
        if d0 is None or d1 is None:
            return True, state

        d0_token = ""
        d1_constantCheckFlag = False

        if hasattr(blk, "statements") and len(blk.statements) > 0:
            call_statement = blk.statements[-1]
            try:
                if isinstance(call_statement, ailment.statement.Call):
                    if (
                        hasattr(call_statement, "args")
                        and call_statement.args is not None
                        and len(call_statement.args) > value_position
                        and 'reference_variable' not in call_statement.args[value_position].tags
                    ):
                        d1_constantCheckFlag = True
                    else:
                        return True, state
                    if (
                        self.dec is not None
                        and (call_statement, False) in self.dec.codegen.ailexpr2cnode
                    ):
                        xx = self.dec.codegen.ailexpr2cnode[(call_statement, False)].c_repr()
                        if 'reference_variable' in call_statement.args[key_position].tags:
                            d0_token = xx.split('"')[1]
            except Exception as e:
                d1_constantCheckFlag = False

        if not d1_constantCheckFlag and d1.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
            return True, state

        # 若d0_token为空，可从SGGraph中进行读取
        if not d0_token:
            if function_name in self.call_sites_dict:
                call_sites_dict_block_addr = self.call_sites_dict[function_name]
                if state.current_codeloc.block_addr in call_sites_dict_block_addr:
                    call_site_info = call_sites_dict_block_addr[state.current_codeloc.block_addr]
                    if call_site_info[3] != -1:
                        d0_token = call_site_info[3] # 从SG图中获取对应的键值
                        
        print("d0_token ->", d0_token)
        print("---------- Start Nvram_set ----------")
        def_explorer = DefinitionExplorer(self._analysis.project, state.dep_graph, self.get_cfg())
        def_explorer.set_d0(d0)
        if d0_token != "":
            def_explorer.set_d0_token(d0_token)
        def_explorer.set_d1(d1)
        def_explorer.set_transitive_funtion_name(function_name)
        def_explorer.set_current_codeloc(codeloc)
        def_explorer.set_current_function(self.cur_fun)
        def_explorer.set_current_state(state)
        def_explorer.set_RDA_handler(self)

        backtrack_definations(
            def_explorer,
            reg_defs=[d1],
            result_file=self.get_get2set_file(),
            memcpy_func_pred=self.get_current_function(),
            FUNCS=[],
            sink=function_name,
            memcpy_addr=state.current_codeloc.ins_addr,
            result_path=self.get_get2set_path()
        )
        print("---------- End Nvram_set ----------")
        return True, state
    
    # 动态创建getter函数的handle
    def _create_setter_handle(self, function_name, key_index, value_index):
        def _handler(state: "ReachingDefinitionsState", codeloc):
            function = self._analysis.project.kb.functions.function(name=function_name)
            return self.handle_nvram_set_xx(function, state, codeloc, function_name, key_index, value_index)
        return _handler
    
    def setter_handle_dynamic(self, function_name, key_index, value_index):
        method_name = f"handle_{function_name}"
        if not hasattr(self, method_name):
            handler = self._create_setter_handle(function_name, key_index, value_index)
            setattr(self, method_name, handler)

    def handle_nvram_set(self, state, codeloc):
        function_name = "nvram_set"
        function = self._analysis.project.kb.functions.function(name=function_name)
        return self.handle_nvram_set_xx(function, state, codeloc, function_name)

    def handle_SetValue(self, state, codeloc):
        function_name = "SetValue"
        function = self._analysis.project.kb.functions.function(name=function_name)
        return self.handle_nvram_set_xx(function, state, codeloc, function_name)

    def handle_config_set(self, state, codeloc):
        function_name = "config_set"
        function = self._analysis.project.kb.functions.function(name=function_name)
        return self.handle_nvram_set_xx(function, state, codeloc, function_name)

    def handle_setenv(self, state, codeloc):
        function_name = "setenv"
        function = self._analysis.project.kb.functions.function(name=function_name)
        return self.handle_nvram_set_xx(function, state, codeloc, function_name)

    def handle_nvram_safe_set(self, state, codeloc):
        function_name = "nvram_safe_set"
        function = self._analysis.project.kb.functions.function(name=function_name)
        return self.handle_nvram_set_xx(function, state, codeloc, function_name)

    def handle_nvram_pf_set(self, state, codeloc):
        function_name = "nvram_pf_set"
        function = self._analysis.project.kb.functions.function(name=function_name)
        return self.handle_nvram_set_xx(function, state, codeloc, function_name)

    def handle_artblock_set(self, state, codeloc):
        function_name = "artblock_set"
        function = self._analysis.project.kb.functions.function(name=function_name)
        return self.handle_nvram_set_xx(function, state, codeloc, function_name)

    def handle_acos_nvram_set(self, state, codeloc):
        function_name = "acos_nvram_set"
        function = self._analysis.project.kb.functions.function(name=function_name)
        return self.handle_nvram_set_xx(function, state, codeloc, function_name)

    def handle_acosNvramConfig_set(self, state, codeloc):
        function_name = "acosNvramConfig_set"
        print("inside ->", function_name)
        function = self._analysis.project.kb.functions.function(name=function_name)
        return self.handle_nvram_set_xx(function, state, codeloc, function_name)

    def handle_acosNvramConfig_write(self, state, codeloc):
        function_name = "acosNvramConfig_write"
        function = self._analysis.project.kb.functions.function(name=function_name)
        return self.handle_nvram_set_xx(function, state, codeloc, function_name)

    def handle_envz_add(self, state, codeloc):
        function_name = "envz_add"
        function = self._analysis.project.kb.functions.function(name=function_name)
        return self.handle_nvram_set_xx(function, state, codeloc, function_name)

    def handle_config_set(self, state, codeloc):
        function_name = "config_set"
        function = self._analysis.project.kb.functions.function(name=function_name)
        return self.handle_nvram_set_xx(function, state, codeloc, function_name)

    def handle_uciSet(self, state, codeloc):
        function_name = "uciSet"
        function = self._analysis.project.kb.functions.function(name=function_name)
        return self.handle_nvram_set_xx(function, state, codeloc, function_name)

    def handle_device_set_string_value(self, state, codeloc):
        function_name = "device_set_string_value"
        function = self._analysis.project.kb.functions.function(name=function_name)
        return self.handle_nvram_set_xx(function, state, codeloc, function_name)

    def handle_wpa_config_set(self, state, codeloc):
        function_name = "wpa_config_set"
        function = self._analysis.project.kb.functions.function(name=function_name)
        return self.handle_nvram_set_xx(function, state, codeloc, function_name)

    def handle_scfgmgr_set_by_index_D7000(self, state, codeloc):
        function_name = "scfgmgr_set_by_index_D7000"
        function = self._analysis.project.kb.functions.function(name=function_name)
        return self.handle_nvram_set_xx(function, state, codeloc, function_name)

    def handle_acosUciConfig_set(self, state, codeloc):
        function_name = "acosUciConfig_set"
        function = self._analysis.project.kb.functions.function(name=function_name)
        return self.handle_nvram_set_xx(function, state, codeloc, function_name)

    def handle_OM_ValSet(self, state, codeloc):
        function_name = "OM_ValSet"
        function = self._analysis.project.kb.functions.function(name=function_name)
        return self.handle_nvram_set_xx(function, state, codeloc, function_name)

    def handle_CAL_abstract_set(self, state, codeloc):
        function_name = "CAL_abstract_set"
        function = self._analysis.project.kb.functions.function(name=function_name)
        return self.handle_nvram_set_xx(function, state, codeloc, function_name)

    def handle_malloc_xx(self, function, state, codeloc):
        d0 = self.get_def_from_parameter(function, parameter_position=0, state=state)
        print("inside", function.name)
        ret_register_name = state.arch.register_names[state.arch.ret_offset]
        ret_register_name_size = state.arch.registers[ret_register_name]
        atom = Register(ret_register_name_size[0], ret_register_name_size[1])
        tags = {
            ReturnValueTag(
                function=function.addr,
                metadata={
                    'tagged_by': f'{function.name} simulation Effect',
                    'block_addr': state.current_codeloc.block_addr
                }
            )
        }
        mv = state.kill_and_add_definition(
            atom,
            d0.codeloc,
            MultiValues(state.top(atom.size * state.arch.byte_width)),
            tags=tags
        )
        ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
        ff = [d for d in ff_defs][0]
        state.dep_graph.add_edge(d0, ff)
        return True, state

    def handle_malloc(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="malloc")
        return self.handle_malloc_xx(function, state, codeloc)

    def handle_strtok(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="strtok")
        return self.handle_malloc_xx(function, state, codeloc)

    def handle_strtok_r(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="strtok_r")
        return self.handle_malloc_xx(function, state, codeloc)

    def handle_realloc(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="realloc")
        return self.handle_malloc_xx(function, state, codeloc)

    def handle_strlen(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="strlen")
        print("inside", function.demangled_name)
        cc = function.calling_convention
        parameter_position = 0
        parameter_atom = Atom.from_argument(
            SimRegArg(cc.ARG_REGS[parameter_position], state.arch.bytes),
            self._analysis.project.arch.registers
        )
        def0 = state.get_definitions(parameter_atom)
        d0 = [d for d in def0][0]

        ret_register_name = state.arch.register_names[state.arch.ret_offset]
        ret_register_offset, ret_register_size = state.arch.registers[ret_register_name]
        atom = Register(ret_register_offset, ret_register_size)
        tags = {
            ReturnValueTag(
                function=function.addr,
                metadata={
                    'tagged_by': f'{function.name} simulation Effect',
                    'block_addr': state.current_codeloc.block_addr
                }
            )
        }
        data = state.register_definitions.load(d0.atom.reg_offset, size=d0.atom.size)
        mv = state.kill_and_add_definition(atom, d0.codeloc, data, tags=tags)
        ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
        new_rax = [d for d in ff_defs][0]
        state.dep_graph.add_edge(d0, new_rax)
        state.add_use_by_def(d0, d0.codeloc, None)
        return True, state

    def handle_indirect_call(self, state: "ReachingDefinitionsState", src_codeloc: Optional["CodeLocation"] = None):
        print("inside indirect", src_codeloc)
        function = None
        recovered_functions = []
        blk = self.get_clinic_block(self.clinic, src_codeloc.block_addr)
        print(blk.statements[-1])
        # Case 1: Direct jump target
        if hasattr(blk, 'statements') and hasattr(blk.statements[-1], 'target') and hasattr(blk.statements[-1].target, 'value'):
            try:
                function = self.cfg.functions.get_by_addr(addr=blk.statements[-1].target.value)
                print("handled in indirect way -->", function.name)
                recovered_functions.append(function)
            except Exception:
                print("cannot recover the function from direct target.")
                print(blk.statements[-1])
                return True, state
        # Case 2: target is t9 register
        elif hasattr(blk.statements[-1], 'target') and isinstance(blk.statements[-1].target, ailment.expression.Register):
            if blk.statements[-1].target.reg_offset == state.arch.registers['t9'][0]:
                defs = state.tmp_definitions[0].copy()
                while defs:
                    recovered_functions += self.get_functionAddress_by_use_def(defs.pop(), state)
                recovered_functions = list(set(recovered_functions))
        # Case 3: fallback check all tmp_definitions for t9
        else:
            for i in state.tmp_definitions.keys():
                dd = state.tmp_definitions[i].copy().pop()
                if isinstance(dd.atom, Register) and dd.atom.reg_offset == state.arch.registers['t9'][0]:
                    defs = state.tmp_definitions[i].copy()
                    while defs:
                        recovered_functions += self.get_functionAddress_by_use_def(defs.pop(), state)
                    recovered_functions = list(set(recovered_functions))
                    if recovered_functions:
                        print("did something useful")
                    break
        # Final dispatch
        if recovered_functions:
            if len(recovered_functions) == 1:
                function = recovered_functions[0]
                try:
                    flag, state, *_ = self.handle_local_function(
                        state, function.addr, 0, 5,
                        self._analysis.visited_blocks,
                        self._analysis.dep_graph,
                        src_codeloc.ins_addr, src_codeloc
                    )
                except Exception:
                    return True, state
                return flag, state
            else:
                for function in recovered_functions:
                    tmp_state = state.copy()
                    try:
                        flag, tmp_state, *_ = self.handle_local_function(
                            tmp_state, function.addr, 0, 5,
                            self._analysis.visited_blocks,
                            self._analysis.dep_graph,
                            src_codeloc.ins_addr, src_codeloc
                        )
                    except Exception as e:
                        print("error at indirect function fallback:", e)
        return True, state

    def handle_GetValue(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="GetValue")
        d1 = self.get_def_from_parameter(function, parameter_position=0, state=state)
        blk = self.get_clinic_block(self.clinic, state.current_codeloc.block_addr)
        if hasattr(blk, "statements") and len(blk.statements) > 0:
            call_statement = blk.statements[-1]
            if isinstance(call_statement, ailment.statement.Call) and \
            hasattr(call_statement, "args") and \
            call_statement.args is not None and \
            len(call_statement.args) > 1:
                arg1 = call_statement.args[1]  # second argument, likely a buffer
                if hasattr(arg1, 'base'):
                    atom = MemoryLocation(SpOffset(state.arch.bits, arg1.offset), arg1.size)
                    bb = ""

                    if d1.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
                        preds = list(state.dep_graph.predecessors(d1))
                        if len(preds) == 1 and not isinstance(preds[0].atom, MemoryLocation):
                            preds = list(state.dep_graph.predecessors(preds[0]))
                        for definition in preds:
                            if isinstance(definition.atom, MemoryLocation) and "readonly" in str(definition):
                                i = 0
                                try:
                                    while str(self.cfg.project.loader.memory.load(definition.atom.addr, i + 1))[i + 1] != '\\':
                                        i += 1
                                    bb = str(self.cfg.project.loader.memory.load(definition.atom.addr, i - 1))[2:-1]
                                except Exception:
                                    bb = ""
                                break
                    tags = {
                        ReturnValueTag(
                            function=function.addr,
                            metadata={
                                'tagged_by': f'{function.name} simulation Effect',
                                'block_addr': state.current_codeloc.block_addr,
                                'token': bb
                            }
                        )
                    }
                    try:
                        data = state.register_definitions.load(d1.atom.reg_offset, size=d1.atom.size)
                        mv = state.kill_and_add_definition(atom, d1.codeloc, data, tags=tags)
                    except Exception:
                        missing_def = Definition(atom, state.current_codeloc)
                        val = bb
                        bvv = claripy.BVV(val.encode(), len(val) * state.arch.byte_width)
                        annotated = state.annotate_with_def(bvv, missing_def)
                        mv = state.kill_and_add_definition(atom, d1.codeloc, MultiValues(annotated), tags=tags)
                    ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
                    ff = next(iter(ff_defs))
                    state.dep_graph.add_node(ff)
                    state.dep_graph.add_edge(d1, ff)
        return True, state

    def handle_sub_1de00(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="sub_1de00")
        blk = self.get_clinic_block(self.clinic, state.current_codeloc.block_addr)
        d1 = self.get_def_from_parameter(function, parameter_position=0, state=state)
        d2 = self.get_def_from_parameter(function, parameter_position=1, state=state)

        if hasattr(blk, "statements") and len(blk.statements) > 0:
            call_statement = blk.statements[-1]
            print("call_statement -> ", call_statement)
            if isinstance(call_statement, ailment.statement.Call) and hasattr(call_statement, "args") and \
                    call_statement.args is not None and len(call_statement.args) > 2:
                arg0 = call_statement.args[0]
                if isinstance(arg0, ailment.expression.Const) and hasattr(arg0, "value"):
                    ff = None
                    ff_list = []
                    for node in state.dep_graph.nodes():
                        if isinstance(node.atom, MemoryLocation) and node.atom.addr == arg0.value:
                            if node not in ff_list:
                                ff_list.append(node)
                            ff = node
                    if len(ff_list) == 2 and ff_list[0].atom.addr == ff_list[1].atom.addr:
                        ff = ff_list[0] if ff_list[0].size > ff_list[1].size else ff_list[1]
                    elif len(ff_list) > 1:
                        pred = [d for d in state.dep_graph.predecessors(d2)]
                        if len(pred) == 1 and not isinstance(pred[0].atom, Register):
                            pred = [d for d in state.dep_graph.predecessors(pred[0])]
                        for definition in pred:
                            if isinstance(definition.atom, MemoryLocation):
                                for gf in ff_list:
                                    if gf.atom.addr == definition.atom.addr and definition.size == gf.size:
                                        ff = gf
                                        break

                    bb = ""
                    if self.dec is not None:
                        xx = self.dec.codegen.ailexpr2cnode[(call_statement, False)].c_repr()
                        if '"' in xx:
                            bb = xx.split('"')[1]
                        else:
                            pred = [d for d in state.dep_graph.predecessors(d1)]
                            if len(pred) == 1 and not isinstance(pred[0].atom, MemoryLocation):
                                pred = [d for d in state.dep_graph.predecessors(pred[0])]
                            for definition in pred:
                                if isinstance(definition.atom, MemoryLocation) and 'readonly' in f'{definition}':
                                    i = 0
                                    while str(self.cfg.project.loader.memory.load(definition.atom.addr, i + 1))[i + 1] != '\\':
                                        i += 1
                                    bb = str(self.cfg.project.loader.memory.load(definition.atom.addr, i - 1))[2:-1]
                    print(bb, " \n --- \n  ----\n")
                    length = -1
                    if isinstance(call_statement.args[2], ailment.expression.Const):
                        length = call_statement.args[2].value
                    tags = {
                        ReturnValueTag(
                            function=function.addr,
                            metadata={
                                'tagged_by': f'{function.name} simulation Effect',
                                'block_addr': state.current_codeloc.block_addr,
                                'token': bb,
                                'length': length,
                                'ins_addr': state.current_codeloc.ins_addr
                            }
                        )
                    }
                    if ff is None:
                        print("could not find the public variable in graph")
                        block_addr = blk.addr
                        project = self._analysis.project
                        manager = ailment.Manager(arch=project.arch)
                        block = project.factory.block(block_addr)
                        for stmt in block.vex.statements:
                            if hasattr(stmt, 'offset') and \
                                    state.arch.register_names[stmt.offset] == state.arch.register_names[d2.atom.reg_offset]:
                                break
                        addr = arg0.value
                        size = stmt.data.result_size(block.vex.tyenv) // 8
                        bits = stmt.data.result_size(block.vex.tyenv)
                        top = state.top(bits)
                        data = MultiValues(top)
                        temp_codeloc = CodeLocation(block.addr, stmt.tag_int, d1.codeloc.ins_addr, context=None)
                        atom = MemoryLocation(arg0.value, size)
                        mv = state.kill_and_add_definition(atom, temp_codeloc, data, tags=tags)
                        ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
                        ff = next(iter(ff_defs))
                        state.dep_graph.add_node(ff)
                        pred = [d for d in state.dep_graph.predecessors(d2)]
                        if len(pred) >= 1:
                            for definition in pred:
                                state.dep_graph.add_edge(ff, definition)

                    ff.tags.update(tags)
                    d1.tags.update(tags)
                    d2.tags.update(tags)
                    if ff not in state.dep_graph.nodes():
                        state.dep_graph.add_node(ff)
                    state.dep_graph.add_edge(d1, ff)
                    print(ff)
                    print(d1)
                    print(" \n #### \n  #######\n")
                    return True, state

                if hasattr(arg0, 'base'):
                    atom = MemoryLocation(SpOffset(state.arch.bits, arg0.offset), arg0.size)
                    bb = ""
                    length = -1
                    if isinstance(call_statement.args[1], ailment.expression.Const):
                        length = call_statement.args[1].value
                    tags = {
                        ReturnValueTag(
                            function=function.addr,
                            metadata={
                                'tagged_by': f'{function.name} simulation Effect',
                                'block_addr': state.current_codeloc.block_addr,
                                'token': bb,
                                'length': length
                            }
                        )
                    }
                    try:
                        size = atom.size
                        bits = size * state.arch.byte_width
                        top = state.top(bits)
                        def_ = Definition(atom, state.current_codeloc)
                        top = state.annotate_with_def(top, def_)
                        state.add_memory_use_by_def(def_, state.current_codeloc)
                        data = MultiValues(top)
                    except Exception as e:
                        print("error 3698", e)
                        missing_def = Definition(atom, state.current_codeloc)
                        val = bb
                        data = MultiValues(
                            state.annotate_with_def(
                                claripy.BVV(val, len(bb) * state.arch.byte_width),
                                missing_def
                            )
                        )
                    mv = state.kill_and_add_definition(atom, d1.codeloc, data, tags=tags)
                    ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
                    ff = next(iter(ff_defs))
                    print("New memory definition", ff)
                    state.dep_graph.add_node(ff)
                    state.dep_graph.add_edge(d1, ff)
                    ff.tags.update(tags)
                    d1.tags.update(tags)
                    try:
                        ret_register_name = state.arch.register_names[state.arch.ret_offset]
                        ret_register_name_size = state.arch.registers[ret_register_name]
                        ret_atom = Register(ret_register_name_size[0], ret_register_name_size[1])
                        mv = state.kill_and_add_definition(ret_atom, d1.codeloc, data, tags=tags)
                        ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
                        new_rax = [d for d in ff_defs][0]
                        state.dep_graph.add_edge(ff, new_rax)
                        if function.name not in config_sgtaint.New_input_getters:
                            config_sgtaint.New_input_getters.append(function.name)
                    except Exception as e:
                        print(e)
                    return True, state

    def handle_NK_query_entry_get(self, state, codeloc):
        function = self._analysis.project.kb.functions.function(name="NK_query_entry_get")
        blk = self.get_clinic_block(self.clinic, state.current_codeloc.block_addr)
        d1 = self.get_def_from_parameter(function, parameter_position=0, state=state)
        d2 = self.get_def_from_parameter(function, parameter_position=1, state=state)

        if hasattr(blk, "statements") and len(blk.statements) > 0:
            call_statement = blk.statements[-1]
            print("call_statement -> ", call_statement)
            if isinstance(call_statement, ailment.statement.Call) and hasattr(call_statement, "args") and \
                    call_statement.args is not None and len(call_statement.args) > 2:
                arg0 = call_statement.args[1]
                if isinstance(arg0, ailment.expression.Const) and hasattr(arg0, "value"):
                    ff = None
                    ff_list = []
                    for node in state.dep_graph.nodes():
                        if isinstance(node.atom, MemoryLocation) and node.atom.addr == arg0.value:
                            if node not in ff_list:
                                ff_list.append(node)
                            ff = node
                    if len(ff_list) == 2 and ff_list[0].atom.addr == ff_list[1].atom.addr:
                        ff = ff_list[0] if ff_list[0].size > ff_list[1].size else ff_list[1]
                    elif len(ff_list) > 1:
                        pred = [d for d in state.dep_graph.predecessors(d2)]
                        if len(pred) == 1 and not isinstance(pred[0].atom, Register):
                            pred = [d for d in state.dep_graph.predecessors(pred[0])]
                        for definition in pred:
                            if isinstance(definition.atom, MemoryLocation):
                                for gf in ff_list:
                                    if gf.atom.addr == definition.atom.addr and definition.size == gf.size:
                                        ff = gf
                                        break
                    bb = ""
                    if self.dec is not None:
                        xx = self.dec.codegen.ailexpr2cnode[(call_statement, False)].c_repr()
                        if '"' in xx:
                            bb = xx.split('"')[1]
                        else:
                            pred = [d for d in state.dep_graph.predecessors(d1)]
                            if len(pred) == 1 and not isinstance(pred[0].atom, MemoryLocation):
                                pred = [d for d in state.dep_graph.predecessors(pred[0])]
                            for definition in pred:
                                if isinstance(definition.atom, MemoryLocation) and 'readonly' in f'{definition}':
                                    i = 0
                                    while str(self.cfg.project.loader.memory.load(definition.atom.addr, i + 1))[i + 1] != '\\':
                                        i += 1
                                    bb = str(self.cfg.project.loader.memory.load(definition.atom.addr, i - 1))[2:-1]

                    print(bb, "\n --- \n ----\n")
                    length = -1
                    if isinstance(call_statement.args[2], ailment.expression.Const):
                        length = call_statement.args[2].value
                    tags = {
                        ReturnValueTag(
                            function=function.addr,
                            metadata={
                                'tagged_by': f'{function.name} simulation Effect',
                                'block_addr': state.current_codeloc.block_addr,
                                'token': bb,
                                'length': length,
                                'ins_addr': state.current_codeloc.ins_addr
                            }
                        )
                    }
                    if ff is None:
                        print("could not find the public variable in graph")
                        block = self._analysis.project.factory.block(blk.addr)
                        for stmt in block.vex.statements:
                            if hasattr(stmt, 'offset') and \
                                    state.arch.register_names[stmt.offset] == state.arch.register_names[d2.atom.reg_offset]:
                                break
                        addr = arg0.value
                        size = stmt.data.result_size(block.vex.tyenv) // 8
                        bits = stmt.data.result_size(block.vex.tyenv)
                        top = state.top(bits)
                        data = MultiValues(top)
                        temp_codeloc = CodeLocation(block.addr, stmt.tag_int, d1.codeloc.ins_addr, context=None)
                        atom = MemoryLocation(addr, size)
                        mv = state.kill_and_add_definition(atom, temp_codeloc, data, tags=tags)
                        ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
                        ff = next(iter(ff_defs))
                        state.dep_graph.add_node(ff)
                        pred = [d for d in state.dep_graph.predecessors(d2)]
                        for definition in pred:
                            state.dep_graph.add_edge(ff, definition)

                    ff.tags.update(tags)
                    d1.tags.update(tags)
                    d2.tags.update(tags)
                    if ff not in state.dep_graph.nodes():
                        state.dep_graph.add_node(ff)
                    state.dep_graph.add_edge(d1, ff)
                    print(ff)
                    print(d1)
                    print("\n #### \n #######\n")
                    return True, state
                elif hasattr(arg0, "base"):
                    atom = MemoryLocation(SpOffset(state.arch.bits, arg0.offset), arg0.size)
                    bb = ""
                    if self.dec is not None:
                        xx = self.dec.codegen.ailexpr2cnode[(call_statement, False)].c_repr()
                        bb = xx.split('"')[1]
                    print(bb, "\n --- \n ----\n")
                    length = -1
                    if isinstance(call_statement.args[2], ailment.expression.Const):
                        length = call_statement.args[2].value
                    tags = {
                        ReturnValueTag(
                            function=function.addr,
                            metadata={
                                'tagged_by': f'{function.name} simulation Effect',
                                'block_addr': state.current_codeloc.block_addr,
                                'token': bb,
                                'length': length
                            }
                        )
                    }
                    try:
                        size = atom.size
                        bits = size * state.arch.byte_width
                        top = state.top(bits)
                        def_ = Definition(atom, state.current_codeloc)
                        top = state.annotate_with_def(top, def_)
                        state.add_memory_use_by_def(def_, state.current_codeloc)
                        data = MultiValues(top)
                    except Exception as e:
                        print("error 2841", e)
                        missing_def = Definition(atom, state.current_codeloc)
                        val = bb
                        data = MultiValues(
                            state.annotate_with_def(
                                claripy.BVV(val, len(bb) * state.arch.byte_width),
                                missing_def
                            )
                        )
                    tmp_codeloc = state.current_codeloc
                    mv = state.kill_and_add_definition(atom, d1.codeloc, data, tags=tags)
                    ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
                    ff = next(iter(ff_defs))
                    print("New memory definition", ff)
                    state.dep_graph.add_node(ff)
                    state.dep_graph.add_edge(d1, ff)
                    ff.tags.update(tags)
                    d1.tags.update(tags)
                    try:
                        ret_register_name = state.arch.register_names[state.arch.ret_offset]
                        ret_register_name_size = state.arch.registers[ret_register_name]
                        ret_atom = Register(ret_register_name_size[0], ret_register_name_size[1])
                        mv = state.kill_and_add_definition(ret_atom, d1.codeloc, data, tags=tags)
                        ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
                        new_rax = [d for d in ff_defs][0]
                        state.dep_graph.add_edge(ff, new_rax)
                        if function.name not in config_sgtaint.New_input_getters:
                            config_sgtaint.New_input_getters.append(function.name)
                    except Exception as e:
                        print(e)
                    return True, state

    def get_simp_blk(self, block_addr):
        project: Project = self._analysis.project
        manager = ailment.Manager(arch=project.arch)
        block = project.factory.block(block_addr)
        ail_block = ailment.IRSBConverter.convert(block.vex, manager)
        simp = project.analyses.AILBlockSimplifier(ail_block, self.cur_fun.addr)
        csm = project.analyses.AILCallSiteMaker(simp.result_block)
        return csm.result_block  # <-- 保留 AILBlock 返回
    
    def process_sub_42a978(self, function, state, codeloc, d1, blk=None):
        d1 = self.get_def_from_parameter(function, parameter_position=1, state=state)
        if blk is None:
            blk = self.get_clinic_block(self.clinic, state.current_codeloc.block_addr)
        print(blk.statements[-1])
        if hasattr(blk, "statements") and len(blk.statements) > 0:
            call_statement = blk.statements[-1]
            if (
                isinstance(call_statement, ailment.statement.Call)
                and hasattr(call_statement, "args")
                and call_statement.args is not None
                and len(call_statement.args) > 2
            ):
                arg0 = call_statement.args[2]
                if hasattr(arg0, "base"):
                    atom = MemoryLocation(SpOffset(state.arch.bits, arg0.offset), arg0.size)
                    bb = ""
                    if d1.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
                        bb1 = self.cfg.insn_addr_to_memory_data[d1.codeloc.ins_addr]
                        i = 0
                        while str(self.cfg.project.loader.memory.load(bb1.addr, bb1.size + i))[bb1.size + i + 1] != '\\':
                            i += 1
                        bb = str(self.cfg.project.loader.memory.load(bb1.addr, bb1.size + i - 1))[2:-1]
                        if len(bb) == 0:
                            arg = call_statement.args[0]
                            if hasattr(arg, "reg_offset"):
                                for smt in blk.statements:
                                    if (
                                        isinstance(smt, ailment.statement.Assignment)
                                        and smt.dst.tags["reg_name"] == state.arch.register_names[d1.atom.reg_offset]
                                        and isinstance(smt.src, ailment.expression.Const)
                                    ):
                                        i = 0
                                        while str(self.cfg.project.loader.memory.load(smt.src.value, i))[i + 1] != '\\':
                                            i += 1
                                        bb = str(self.cfg.project.loader.memory.load(smt.src.value, i - 1))[2:-1]
                                        print("Did I arrived here")
                                        break
                    try:
                        if bb == "":
                            bb = self.get_stringby_use_def(d1, state)
                    except Exception:
                        bb = ""

                    length = -1
                    try:
                        if len(call_statement.args) == 4 and isinstance(call_statement.args[3], ailment.expression.Const):
                            length = call_statement.args[3].value
                        else:
                            d3 = self.get_def_from_parameter(function, parameter_position=3, state=state)
                            if len(call_statement.args) == 3 and len(blk.statements) == 1:
                                simp_blk = self.get_simp_blk(block_addr=blk.addr)
                            else:
                                simp_blk = blk.statements
                            for stmt in simp_blk.statements:
                                if (
                                    isinstance(stmt, ailment.statement.Assignment)
                                    and hasattr(stmt.dst, "reg_offset")
                                    and stmt.dst.reg_offset == d3.offset
                                    and isinstance(stmt.src, ailment.expression.Const)
                                ):
                                    length = stmt.src.value
                                    break
                    except Exception as e:
                        print(e)
                        print("error in 2658")

                    tags = {
                        ReturnValueTag(
                            function=function.addr,
                            metadata={
                                "tagged_by": f"{function.name} simulation Effect",
                                "block_addr": state.current_codeloc.block_addr,
                                "token": bb,
                                "length": length,
                            },
                        )
                    }

                    data = state.register_definitions.load(d1.atom.reg_offset, size=d1.atom.size)
                    tmp_codeloc = state.current_codeloc
                    try:
                        mv = state.kill_and_add_definition(atom, state.current_codeloc, data, tags=tags)
                    except Exception:
                        missing_def = Definition(atom, state.current_codeloc)
                        val = bb
                        data = MultiValues(
                            state.annotate_with_def(claripy.BVV(val, len(bb) * state.arch.byte_width), missing_def)
                        )
                        mv = state.kill_and_add_definition(atom, state.current_codeloc, data, tags=tags)

                    ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
                    ff = next(iter(ff_defs))
                    state.dep_graph.add_node(ff)
                    state.dep_graph.add_edge(d1, ff)
                    print(ff)
                    try:
                        ret_register_name = state.arch.register_names[state.arch.ret_offset]
                        ret_register_name_size = state.arch.registers[ret_register_name]
                        ret_atom = Register(ret_register_name_size[0], ret_register_name_size[1])
                        mv = state.kill_and_add_definition(ret_atom, state.current_codeloc, data, tags=tags)
                        ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
                        new_rax = [d for d in ff_defs][0]
                        state.dep_graph.add_edge(ff, new_rax)
                        if function.name not in config_sgtaint.New_input_getters:
                            config_sgtaint.New_input_getters.append(function.name)
                    except Exception as e:
                        print(e)
                    return True, state
                elif hasattr(arg0, 'reg_offset') or d1.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
                    d1 = self.get_def_from_parameter(function, parameter_position=1, state=state)
                    b = ""
                    if d1.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
                        pred = [d for d in state.dep_graph.predecessors(d1)]
                        bb = ""
                        if len(pred) == 1 and type(pred[0].atom) != MemoryLocation:
                            pred = [d for d in state.dep_graph.predecessors(pred[0])]
                        for defination in pred:
                            if type(defination.atom) == MemoryLocation and 'readonly' in f'{defination}':
                                i = 0
                                while str(self.cfg.project.loader.memory.load(defination.atom.addr, i + 1))[i + 1] != '\\':
                                    i += 1
                                bb = str(self.cfg.project.loader.memory.load(defination.atom.addr, i - 1))[2:-1]
                                break
                        if len(bb) == 0 and d1.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
                            bb = self.cfg.insn_addr_to_memory_data[d1.codeloc.ins_addr].content
                            if len(bb) > 2:
                                bb = bb[2:-1]
                        if len(bb) == 0:
                            arg = blk.statements[-1].args[0]
                            if hasattr(arg, 'reg_offset'):
                                for smt in blk.statements:
                                    if type(smt) == ailment.statement.Assignment and smt.dst.tags['reg_name'] == state.arch.register_names[d1.atom.reg_offset] and type(smt.src) == ailment.expression.Const:
                                        i = 0
                                        while str(self.cfg.project.loader.memory.load(smt.src.value, i))[i + 1] != '\\':
                                            i += 1
                                        bb = str(self.cfg.project.loader.memory.load(smt.src.value, i - 1))[2:-1]
                                        print("Did I arrive here")
                                        break
                        try:
                            if bb == "":
                                bb = self.get_stringby_use_def(d1, state)
                        except Exception as e:
                            bb = ""
                        if len(bb) > 1:
                            tags = {ReturnValueTag(function=function.addr, metadata={'tagged_by': f'{function.name} simulation Effect', 'block_addr': state.current_codeloc.block_addr, 'token': bb, 'length': -1})}
                            ret_register_name = state.arch.register_names[state.arch.ret_offset]
                            ret_register_name_size = state.arch.registers[ret_register_name]
                            atom = Register(ret_register_name_size[0], ret_register_name_size[1])
                            data: MultiValues = state.register_definitions.load(d1.atom.reg_offset, size=d1.atom.size)
                            mv = state.kill_and_add_definition(atom, state.current_codeloc, data, tags=tags)
                            ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
                            new_rax = [d for d in ff_defs][0]
                            d1.tags.update(tags)
                            state.dep_graph.add_edge(d1, new_rax)
                            if function.name not in config_sgtaint.New_input_getters:
                                config_sgtaint.New_input_getters.append(function.name)
                            return True, state

                    for stmt in blk.statements:
                        if type(stmt) == ailment.statement.Assignment and hasattr(stmt.dst, 'reg_offset') and stmt.dst.reg_offset == arg0.reg_offset and hasattr(stmt.src, 'base'):
                            atom = MemoryLocation(SpOffset(state.arch.bits, stmt.src.offset), stmt.src.size)
                            bb = ""
                            if d1.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
                                bb1 = self.cfg.insn_addr_to_memory_data[d1.codeloc.ins_addr]
                                i = 0
                                while str(self.cfg.project.loader.memory.load(bb1.addr, bb1.size + i))[bb1.size + i + 1] != '\\':
                                    i += 1
                                bb = str(self.cfg.project.loader.memory.load(bb1.addr, bb1.size + i - 1))[2:-1]
                            if bb == "":
                                bb = self.get_stringby_use_def(d1, state)
                            length = -1
                            try:
                                d3 = self.get_def_from_parameter(function, parameter_position=3, state=state)
                                if len(call_statement.args) == 3 and len(blk.statements) == 1:
                                    simp_blk = self.get_simp_blk(block_addr=blk.addr)
                                else:
                                    simp_blk = blk.statements
                                for stmt in simp_blk.statements:
                                    if type(stmt) == ailment.statement.Assignment and hasattr(stmt.dst, 'reg_offset') and stmt.dst.reg_offset == d3.offset and type(stmt.src) == ailment.expression.Const:
                                        length = stmt.src.value
                            except Exception as e:
                                print("error in 2724")
                            tags = {ReturnValueTag(function=function.addr, metadata={'tagged_by': f'{function.name} simulation Effect', 'block_addr': state.current_codeloc.block_addr, 'token': bb, 'length': length})}
                            data: MultiValues = state.register_definitions.load(d1.atom.reg_offset, size=d1.atom.size)
                            tmp_codeloc = state.current_codeloc
                            try:
                                mv = state.kill_and_add_definition(atom, d1.codeloc, data, tags=tags)
                            except Exception as e:
                                missing_def = Definition(atom, state.current_codeloc)
                                val = bb
                                data: MultiValues = MultiValues(state.annotate_with_def(claripy.BVV(val, len(bb) * state.arch.byte_width), missing_def))
                                mv = state.kill_and_add_definition(atom, state.current_codeloc, data, tags=tags)
                            ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
                            ff = next(iter(ff_defs))
                            state.dep_graph.add_node(ff)
                            state.dep_graph.add_edge(d1, ff)
                            tags_2 = {ReturnValueTag(function=function.addr, metadata={'tagged_by': f'{function.name} simulation Effect', 'block_addr': state.current_codeloc.block_addr})}
                            ret_register_name = state.arch.register_names[state.arch.ret_offset]
                            ret_register_name_size = state.arch.registers[ret_register_name]
                            atom = Register(ret_register_name_size[0], ret_register_name_size[1])
                            mv = state.kill_and_add_definition(atom, d1.codeloc, data, tags=tags_2)
                            ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
                            new_rax = [d for d in ff_defs][0]
                            state.dep_graph.add_edge(ff, new_rax)
                            if function.name not in config_sgtaint.New_input_getters:
                                config_sgtaint.New_input_getters.append(function.name)
                            return True, state

    def xxx_handle_external_function_name(self, state: "ReachingDefinitionsState", ext_func_name: str, src_codeloc: Optional["CodeLocation"] = None) -> Tuple[bool, "ReachingDefinitionsState"]:
        function = self._analysis.project.kb.functions.function(name=ext_func_name)
        blk = self.get_clinic_block(self.clinic, state.current_codeloc.block_addr)
        d1 = self.get_def_from_parameter(function, parameter_position=0, state=state)
        function_name = function.name
        return True, state

    def handle_generic(self, state: "ReachingDefinitionsState", src_codeloc: Optional["CodeLocation"] = None):
        print("Sorry generic")
        return True, state
    
    def XX_handle_general_plt_function(self, function, state, codeloc, blk=None):
        d0 = self.get_def_from_parameter(function, parameter_position=0, state=state)
        d0 = self.get_memory_defination(
            d0, function, state, codeloc,
            defination_only=True,
            defination_location=0,
            blk=blk
        )
        ret_register_name = state.arch.register_names[state.arch.ret_offset]
        ret_register_name_size = state.arch.registers[ret_register_name]
        atom = Register(ret_register_name_size[0], ret_register_name_size[1])
        tags_2 = {
            ReturnValueTag(
                function=function.addr,
                metadata={
                    'tagged_by': f'{function.name} simulation Effect',
                    'block_addr': state.current_codeloc.block_addr
                }
            )
        }
        if d0.atom == atom:
            d0.tags.clear()
            d0.tags.update(tags_2)
            new_rax = d0
        data: MultiValues = state.register_definitions.load(d0.atom.reg_offset, size=d0.atom.size)
        try:
            mv = state.kill_and_add_definition(atom, d0.codeloc, data, tags=tags_2)
        except Exception as e:
            print(e)
        ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
        new_rax = [d for d in ff_defs][0]
        state.dep_graph.add_edge(d0, new_rax)
        return True, state
    
    def recover_calling_convention(self, blk):
        arguments = []
        recovered_args = []
        flag = False
        try:
            ARG_REGS = blk.statements[-1].calling_convention.ARG_REGS
        except Exception as e:
            flag = True
        try:
            if flag and "MIPS" in self._analysis.project.arch.name:
                ARG_REGS = ["a0", "a1", "a2", "a3"]
            elif flag and "ARM" in self._analysis.project.arch.name:
                ARG_REGS = ["r0", "r1", "r2", "r3"]
        except Exception as e:
            print(e)
        for arg in ARG_REGS:
            parameter = None
            for stmt in blk.statements:
                if (
                    isinstance(stmt, ailment.statement.Assignment)
                    and isinstance(stmt.dst, ailment.expression.Register)
                    and stmt.dst.tags['reg_name'] == arg
                    and (
                        isinstance(stmt.src, ailment.expression.StackBaseOffset)
                        or isinstance(stmt.src, ailment.expression.Const)
                    )
                ):
                    parameter = stmt.src

                if (
                    isinstance(stmt, ailment.statement.Assignment)
                    and isinstance(stmt.dst, ailment.expression.Register)
                    and isinstance(stmt.src, ailment.expression.Register)
                    and stmt.src.tags['reg_name'] == arg
                ):
                    parameter = stmt.src

                if (
                    parameter is None
                    and isinstance(stmt, ailment.statement.Assignment)
                    and isinstance(stmt.dst, ailment.expression.Register)
                    and stmt.dst.tags['reg_name'] == arg
                ):
                    parameter = stmt.dst
            arguments.append(parameter)
        if arguments[0] is not None:
            recovered_args.append(arguments[0])
            if arguments[1] is not None:
                recovered_args.append(arguments[1])
                if arguments[2] is not None:
                    recovered_args.append(arguments[2])
                    if arguments[3] is not None:
                        recovered_args.append(arguments[3])
        for stmt in blk.statements:
            print(stmt)
        print("recovered args are", recovered_args, "block addr ->", hex(blk.addr))
        return recovered_args

    def handle_local_function(self, state, function_address, call_stack, maximum_local_call_depth,
                                visited_blocks, dependency_graph, src_ins_addr=None, codeloc=None):
        function = self._analysis.project.kb.functions.function(function_address)
        if function is None:
            return True, state, visited_blocks, dependency_graph
        function_name = function.demangled_name
        print(
            function_name,
            function_address,
            "- is system call ->",
            function.is_plt,
            f'src_ins_addr={hex(src_ins_addr)}',
            "  codeloc -> ",
            hex(codeloc.block_addr),
            " --> ",
            hex(codeloc.ins_addr),
        )

        if function_name == 'NK_db_write' or function_name == "name_get_value":
            return True, state, visited_blocks, dependency_graph

        if state.current_codeloc is None:
            state.current_codeloc = codeloc

        try:
            blk = self.get_clinic_block(self.clinic, state.current_codeloc.block_addr)
        except Exception as e:
            blk = self.get_clinic_block(self.clinic, codeloc.block_addr)

        if hasattr(blk, "statements") and len(blk.statements) == 0:
            blk = get_clinic_block(self._analysis.project, self.clinic, state.current_codeloc.block_addr)

        # rebuild Calling convention
        if (
            hasattr(blk, "statements")
            and len(blk.statements) > 0
            and hasattr(blk.statements[-1], "args")
            and len(blk.statements[-1].args) == 0
        ):
            recovered_args = self.recover_calling_convention(blk)
            if len(recovered_args) > 0:
                blk.statements[-1].args = recovered_args

        func = getattr(self, 'handle_{}'.format(function_name), None)
        if func is not None:
            try:
                flag, state = func(state, codeloc)
            except Exception as e:
                print(e)
            return True, state, visited_blocks, dependency_graph

        num_arguments = len(function.arguments)
        if len(function.arguments) == 0:
            if (
                blk is not None
                and hasattr(blk, "statements")
                and len(blk.statements) > 0
                and hasattr(blk.statements[-1], "args")
                and blk.statements[-1].args is not None
            ):
                num_arguments = len(blk.statements[-1].args)

        collect_definatins = []
        for ii in range(num_arguments):
            try:
                d0 = self.get_def_from_parameter(function, parameter_position=ii, state=state, blk=blk)
                collect_definatins.append(d0)
                if ii == 0:
                    first_defination = d0

                d0 = self.get_memory_defination(
                    d0, function, state, codeloc, defination_only=True, defination_location=ii, blk=blk
                )
                tags = {
                    LocalVariableTag(
                        function=function.addr,
                        metadata={
                            'tagged_by': f'{function.name} simulation Effect',
                            'block_addr': state.current_codeloc.block_addr
                        }
                    )
                }

                if type(d0.atom) == MemoryLocation:
                    d0.tags.update(tags)
                    collect_definatins.append(d0)
                else:
                    if d0 in state.dep_graph.nodes():
                        pred = [d for d in state.dep_graph.predecessors(d0)]
                        for df in pred:
                            if type(df.atom) == MemoryLocation:
                                df.tags.update(tags)
                                collect_definatins.append(df)
            except Exception as e:
                continue

        if function.has_return and len(collect_definatins) > 0:
            ret_register_name = state.arch.register_names[state.arch.ret_offset]
            ret_register_name_size = state.arch.registers[ret_register_name]
            atom = Register(ret_register_name_size[0], ret_register_name_size[1])

            try:
                tags_2 = {
                    ReturnValueTag(
                        function=function.addr,
                        metadata={
                            'tagged_by': f'{function.name} simulation Effect',
                            'block_addr': state.current_codeloc.block_addr,
                            'parameter_pass': 1
                        }
                    )
                }
            except Exception as e:
                print(e)

            if first_defination is not None:
                if first_defination.atom == atom:
                    first_defination.tags.update(tags_2)
                    new_rax = first_defination

                data: MultiValues = state.register_definitions.load(
                    first_defination.atom.reg_offset,
                    size=first_defination.atom.size
                )
                try:
                    mv = state.kill_and_add_definition(atom, first_defination.codeloc, data, tags=tags_2)
                except Exception as e:
                    print(e)

                ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
                new_rax = [d for d in ff_defs][0]
                for d0 in collect_definatins:
                    state.dep_graph.add_edge(d0, new_rax)
                    
        if function.is_plt and num_arguments == 1 and function.has_return:
            flag, state = self.XX_handle_general_plt_function(function, state, codeloc, blk=blk)
            return True, state, visited_blocks, dependency_graph

        if function.is_plt:
            return True, state, visited_blocks, dependency_graph

        callees = [item.name for item in function.functions_called() if item.name]
        if len(callees) == 1:
            func = getattr(self, 'handle_{}'.format(callees[0]), None)
            if func is not None:
                flag, state = func(state, codeloc)
                return True, state, visited_blocks, dependency_graph
            else:
                tmp_fun = self._analysis.project.kb.functions.function(name=callees[0])
                if tmp_fun.is_plt:
                    return True, state, visited_blocks, dependency_graph

        try:
            if blk is not None and hasattr(blk, "statements") and len(blk.statements) > 0 and type(blk.statements[-1]) == ailment.statement.Call and hasattr(blk.statements[-1], "args") and blk.statements[-1].args is not None and len(blk.statements[-1].args) > 2:
                arg0 = blk.statements[-1].args[2]
                if hasattr(arg0, 'base'):
                    d1 = self.get_def_from_parameter(function, parameter_position=1, state=state)
                    d2 = self.get_def_from_parameter(function, parameter_position=2, state=state)
                    if d1.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
                        self.process_sub_42a978(function, state, codeloc, d1, blk)
                        return True, state, visited_blocks, dependency_graph
                    elif d2.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
                        self.process_sub_42a978(function, state, codeloc, d2, blk)
                        return True, state, visited_blocks, dependency_graph
                    else:
                        project = self._analysis.project
                        manager = ailment.Manager(arch=project.arch)
                        block = project.factory.block(d0.codeloc.block_addr)
                        ail_block = ailment.IRSBConverter.convert(block.vex, manager)
                        simp = project.analyses.AILBlockSimplifier(ail_block, self.cur_fun.addr)
                        csm = project.analyses.AILCallSiteMaker(simp.result_block)
                        if csm.result_block:
                            ail_block = csm.result_block
                        bb = ""
                        for stmt in simp.result_block.statements:
                            if type(stmt) == ailment.statement.Assignment and hasattr(stmt.dst, 'reg_offset') and stmt.dst.reg_offset == arg0.reg_offset and hasattr(stmt.src, 'base'):
                                str_atom = MemoryLocation(SpOffset(state.arch.bits, stmt.src.offset), stmt.src.size)
                                mem_def = [d for d in state.get_definitions(str_atom)][0]
                                curr_tag = (mem_def.tags.copy()).pop()
                                if 'token' in curr_tag.metadata:
                                    bb = curr_tag.metadata['token']
                                    atom = MemoryLocation(SpOffset(state.arch.bits, arg0.offset), arg0.size)
                                    tags = {
                                        ReturnValueTag(
                                            function=function.addr,
                                            metadata={
                                                'tagged_by': f'{function.name} simulation Effect',
                                                'block_addr': state.current_codeloc.block_addr,
                                                'token': bb
                                            }
                                        )
                                    }

                                    data: MultiValues = state.register_definitions.load(d1.atom.reg_offset, size=d1.atom.size)
                                    tmp_codeloc = state.current_codeloc
                                    try:
                                        mv = state.kill_and_add_definition(atom, d1.codeloc, data, tags=tags)
                                    except Exception as e:
                                        missing_def = Definition(atom, state.current_codeloc)
                                        val = bb
                                        data: MultiValues = MultiValues(state.annotate_with_def(claripy.BVV(val, len(bb) * state.arch.byte_width), missing_def))
                                        mv = state.kill_and_add_definition(atom, d1.codeloc, data, tags=tags)
                                    ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
                                    ff = next(iter(ff_defs))
                                    state.dep_graph.add_node(ff)
                                    state.dep_graph.add_edge(d1, ff)
                                    if function.name not in config_sgtaint.New_input_getters:
                                        config_sgtaint.New_input_getters.append(function.name)
                                    return True, state, visited_blocks, dependency_graph

                elif hasattr(arg0, 'reg_offset'):
                    d1 = self.get_def_from_parameter(function, parameter_position=1, state=state)
                    if d1.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
                        for stmt in blk.statements:
                            if type(stmt) == ailment.statement.Assignment and hasattr(stmt.dst, 'reg_offset') and stmt.dst.reg_offset == arg0.reg_offset and hasattr(stmt.src, 'base'):
                                self.process_sub_42a978(function, state, codeloc, d1, blk)
                                return True, state, visited_blocks, dependency_graph

                arg0 = blk.statements[-1].args[1]
                call_statement = blk.statements[-1]
                d1 = self.get_def_from_parameter(function, parameter_position=1, state=state)
                if function.has_return and hasattr(arg0, 'reg_offset'):
                    for stmt in blk.statements:
                        if type(stmt) == ailment.statement.Assignment and hasattr(stmt.dst, 'reg_offset') and stmt.dst.reg_offset == arg0.reg_offset and hasattr(stmt.src, 'value'):
                            address = stmt.src.value
                            i = 1
                            while str(self.cfg.project.loader.memory.load(address, i))[i + 1] != '\\':
                                i += 1
                            bb = str(self.cfg.project.loader.memory.load(address, i - 1))[2:-1]
                            if len(bb) < 4:
                                continue
                            length = -1
                            try:
                                d3 = self.get_def_from_parameter(function, parameter_position=3, state=state)
                                for stmt in blk.statements:
                                    if type(stmt) == ailment.statement.Assignment and hasattr(stmt.dst, 'reg_offset') and stmt.dst.reg_offset == d3.offset and type(stmt.src) == ailment.expression.Const:
                                        length = stmt.src.value
                            except Exception as e:
                                print("error in 3100")
                            tags = {
                                ReturnValueTag(
                                    function=function.addr,
                                    metadata={
                                        'tagged_by': f'{function.name} simulation Effect',
                                        'block_addr': state.current_codeloc.block_addr,
                                        'token': bb,
                                        'length': length
                                    }
                                )
                            }
                            data: MultiValues = state.register_definitions.load(d1.atom.reg_offset, size=d1.atom.size)
                            tmp_codeloc = state.current_codeloc
                            mv = state.kill_and_add_definition(d1.atom, d1.codeloc, data, tags=tags)
                            ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
                            ff = next(iter(ff_defs))
                            ret_register_name = state.arch.register_names[state.arch.ret_offset]
                            ret_register_name_size = state.arch.registers[ret_register_name]
                            ret_atom = Register(ret_register_name_size[0], ret_register_name_size[1])
                            mv = state.kill_and_add_definition(ret_atom, d1.codeloc, data, tags=tags)
                            ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
                            new_rax = [d for d in ff_defs][0]
                            state.dep_graph.add_edge(ff, new_rax)
                            if function.name not in config_sgtaint.New_input_getters:
                                config_sgtaint.New_input_getters.append(function.name)
                            return True, state, visited_blocks, dependency_graph

                    node = None
                    for n in self.dec.clinic.graph.nodes:
                        if n.addr == blk.addr:
                            node = n
                            break
                    if node is not None and self.dec is not None and (node, False) in self.dec.codegen.ailexpr2cnode:
                        address = node.statements[-1].data.args[1].value
                        i = 1
                        while str(self.cfg.project.loader.memory.load(address, i))[i + 1] != '\\':
                            i += 1
                        bb = str(self.cfg.project.loader.memory.load(address, i - 1))[2:-1]
                        if not len(bb) < 4:
                            tags = {
                                ReturnValueTag(
                                    function=function.addr,
                                    metadata={
                                        'tagged_by': f'{function.name} simulation Effect',
                                        'block_addr': state.current_codeloc.block_addr,
                                        'token': bb
                                    }
                                )
                            }
                            data: MultiValues = state.register_definitions.load(d1.atom.reg_offset, size=d1.atom.size)
                            tmp_codeloc = state.current_codeloc
                            mv = state.kill_and_add_definition(d1.atom, d1.codeloc, data, tags=tags)
                            ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
                            ff = next(iter(ff_defs))
                            ret_register_name = state.arch.register_names[state.arch.ret_offset]
                            ret_register_name_size = state.arch.registers[ret_register_name]
                            ret_atom = Register(ret_register_name_size[0], ret_register_name_size[1])
                            mv = state.kill_and_add_definition(ret_atom, d1.codeloc, data, tags=tags)
                            ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
                            new_rax = [d for d in ff_defs][0]
                            state.dep_graph.add_edge(ff, new_rax)
                            if function.name not in config_sgtaint.New_input_getters:
                                config_sgtaint.New_input_getters.append(function.name)
                            return True, state, visited_blocks, dependency_graph
        except Exception as e:
            dddddddddd = 0

        if function_name == "sub_42a978" or function_name == "sub_184d4":
            d1 = self.get_def_from_parameter(function, parameter_position=1, state=state)
            if d1.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
                self.process_sub_42a978(function, state, codeloc, d1)
            else:
                d2 = self.get_def_from_parameter(function, parameter_position=2, state=state)
                if d2.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
                    self.process_sub_42a978(function, state, codeloc, d2)
            return True, state, visited_blocks, dependency_graph

        if (len(function.arguments) == 2 or len(function.arguments) == 1) and function.has_return:
            cc = function.calling_convention
            parameter_position = 0
            parameter_atom = Atom.from_argument(
                SimRegArg(cc.ARG_REGS[parameter_position], state.arch.bytes),
                self._analysis.project.arch.registers
            )
            def0 = state.get_definitions(parameter_atom)
            d0 = [d for d in def0][0]
            callees = [item.name for item in function.functions_called() if item.name in config_sgtaint.SOURCES]

            if len(callees) != 0:
                temp_function = self._analysis.project.kb.functions.function(name=callees[0])
                tags_2 = {
                    ReturnValueTag(
                        function=temp_function.addr,
                        metadata={
                            'tagged_by': f'{temp_function.name} simulation Effect',
                            'block_addr': state.current_codeloc.block_addr
                        }
                    )
                }
                ret_register_name = state.arch.register_names[state.arch.ret_offset]
                ret_register_name_size = state.arch.registers[ret_register_name]
                atom = Register(ret_register_name_size[0], ret_register_name_size[1])

                if d0.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
                    if d0.atom == atom:
                        d0.tags.update(tags_2)
                        new_rax = d0
                    else:
                        data: MultiValues = state.register_definitions.load(d0.atom.reg_offset, size=d0.atom.size)
                        mv = state.kill_and_add_definition(atom, d0.codeloc, data, tags=tags_2)
                        ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
                        new_rax = [d for d in ff_defs][0]
                        state.dep_graph.add_edge(d0, new_rax)
                    if function.name not in config_sgtaint.New_input_getters:
                        config_sgtaint.New_input_getters.append(function.name)
                    return True, state, visited_blocks, dependency_graph

                elif not d0.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
                    d1 = self.get_def_from_parameter(function, parameter_position=1, state=state)
                    if d1.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
                        data: MultiValues = state.register_definitions.load(d1.atom.reg_offset, size=d1.atom.size)
                        mv = state.kill_and_add_definition(atom, d1.codeloc, data, tags=tags_2)
                        ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
                        new_rax = [d for d in ff_defs][0]
                        state.dep_graph.add_edge(d1, new_rax)
                        if function.name not in config_sgtaint.New_input_getters:
                            config_sgtaint.New_input_getters.append(function.name)
                        return True, state, visited_blocks, dependency_graph

            elif d0.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
                tags_2 = {
                    ReturnValueTag(
                        function=function.addr,
                        metadata={
                            'tagged_by': f'{function.name} simulation Effect',
                            'block_addr': state.current_codeloc.block_addr
                        }
                    )
                }
                ret_register_name = state.arch.register_names[state.arch.ret_offset]
                ret_register_name_size = state.arch.registers[ret_register_name]
                atom = Register(ret_register_name_size[0], ret_register_name_size[1])
                if d0.atom == atom:
                    d0.tags.update(tags_2)
                    new_rax = d0
                else:
                    data: MultiValues = state.register_definitions.load(d0.atom.reg_offset, size=d0.atom.size)
                    mv = state.kill_and_add_definition(atom, d0.codeloc, data, tags=tags_2)
                    ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
                    new_rax = [d for d in ff_defs][0]
                    state.dep_graph.add_edge(d0, new_rax)
                if function.name not in config_sgtaint.New_input_getters:
                    config_sgtaint.New_input_getters.append(function.name)
                return True, state, visited_blocks, dependency_graph

        if hasattr(blk, "statements"):
            call_statement = blk.statements[-1]

        if function.has_return and blk is not None and hasattr(blk, "statements") and len(blk.statements) > 0 and type(blk.statements[-1]) == ailment.statement.Call and hasattr(blk.statements[-1], "args") and blk.statements[-1].args is not None and len(blk.statements[-1].args) == 2:
            if len(call_statement.args) == 2:
                bb = ""
                d0 = self.get_def_from_parameter(function, parameter_position=0, state=state)
                if type(d0.atom) == MemoryLocation and 'External' in f'{d0.codeloc}':
                    pred = [d for d in state.dep_graph.predecessors(d0)]
                    if len(pred) == 1 and type(pred[0].atom) == MemoryLocation:
                        for defination in pred:
                            if type(defination.atom) == MemoryLocation:
                                i = 0
                                while str(self.cfg.project.loader.memory.load(defination.atom.addr, i + 1))[i + 1] != '\\':
                                    i += 1
                                bb = str(self.cfg.project.loader.memory.load(defination.atom.addr, i - 1))[2:-1]
                                break
                elif type(d0.atom) != Register:
                    pred = [d for d in state.dep_graph.predecessors(d0)]
                    if len(pred) == 1 and type(pred[0].atom) == MemoryLocation and 'External' in f'{pred[0].codeloc}':
                        pred = [d for d in state.dep_graph.predecessors(pred[0])]
                        if len(pred) == 1 and type(pred[0].atom) == MemoryLocation:
                            for defination in pred:
                                if type(defination.atom) == MemoryLocation:
                                    i = 0
                                    while str(self.cfg.project.loader.memory.load(defination.atom.addr, i + 1))[i + 1] != '\\':
                                        i += 1
                                    bb = str(self.cfg.project.loader.memory.load(defination.atom.addr, i - 1))[2:-1]
                                    break

                if len(bb) > 4:
                    tags_2 = {
                        ReturnValueTag(
                            function=function.addr,
                            metadata={
                                'tagged_by': f'{function.name} simulation Effect',
                                'block_addr': state.current_codeloc.block_addr
                            }
                        )
                    }
                    ret_register_name = state.arch.register_names[state.arch.ret_offset]
                    ret_register_name_size = state.arch.registers[ret_register_name]
                    atom = Register(ret_register_name_size[0], ret_register_name_size[1])

                    if d0.atom == atom:
                        d0.tags.update(tags_2)
                        new_rax = d0
                    else:
                        if type(d0.atom) == Register:
                            data: MultiValues = state.register_definitions.load(d0.atom.reg_offset, size=d0.atom.size)
                        elif type(d0.atom) == MemoryLocation:
                            data: MultiValues = MultiValues(
                                state.annotate_with_def(
                                    claripy.BVV(bb, len(bb) * state.arch.byte_width),
                                    missing_def
                                )
                            )
                        mv = state.kill_and_add_definition(atom, d0.codeloc, data, tags=tags_2)
                        ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
                        new_rax = [d for d in ff_defs][0]
                        state.dep_graph.add_edge(d0, new_rax)

                    if function.name not in config_sgtaint.New_input_getters:
                        config_sgtaint.New_input_getters.append(function.name)

                    return True, state, visited_blocks, dependency_graph

        if len(function.arguments) == 0 and hasattr(blk, "statements") and len(blk.statements) > 0 and hasattr(blk.statements[-1], "args") and len(blk.statements[-1].args) == 0:
            return True, state, visited_blocks, dependency_graph

        to_continue_flag = False
        if len(collect_definatins) > 0:
            def_explorer = DefinitionExplorer(self._analysis.project, state.dep_graph, self.get_cfg())
            def_explorer.set_current_state(state)
            def_explorer.set_current_codeloc(codeloc)
            def_explorer.set_RDA_handler(self)
            def_explorer.set_current_function(self.cur_fun)

            for d0 in collect_definatins:
                if to_continue_flag:
                    break
                ff_list = [d0]
                ff = self.get_memory_defination(d0, function, state, codeloc, defination_only=True, defination_location=0, blk=blk)
                ff_list = [d0, ff]
                tmp_ff = self.get_memoryDef_by_use_def(d0, state)
                if tmp_ff is not None:
                    ff = [d for d in state.get_definitions(tmp_ff.atom)]
                    if len(ff) != 0:
                        ff_list.append(ff[0])
                for item in ff_list:
                    reg_seen_defs, Paths, visited_functions = backtrack_definations(
                        def_explorer,
                        reg_defs=[item],
                        result_file=self.get_result_file(),
                        memcpy_func_pred=self.get_current_function(),
                        FUNCS=[],
                        sink=function.name,
                        memcpy_addr=state.current_codeloc.ins_addr,
                        result_path=self.get_source2sink_path(),
                        check_is_tainted_def=True
                    )
                    for overall_def, path, visited_function in zip(reg_seen_defs, Paths, visited_functions):
                        if overall_def[0] == "get2set" or (overall_def[0] == "retval" and overall_def[1] is not None):
                            to_continue_flag = True
                            break
                    if to_continue_flag:
                        break

        if not to_continue_flag:
            return True, state, visited_blocks, dependency_graph

        if not function.is_plt:
            if self.cur_fun.name == function.name:
                return True, state, visited_blocks, dependency_graph
            try:
                shortest_path = nx.shortest_path(self.call_graph, self.start_function.addr, function.addr)
            except Exception as e:
                shortest_path = []
            if len(shortest_path) > 3:
                return True, state, visited_blocks, dependency_graph
            if len(config_sgtaint.STACK) == 0:
                config_sgtaint.STACK.append((self.cur_fun, self.dec, self.clinic, state))
            elif (self.cur_fun, self.dec, self.clinic, state) in config_sgtaint.STACK:
                return True, state, visited_blocks, dependency_graph
            else:
                config_sgtaint.STACK.append((self.cur_fun, self.dec, self.clinic, state))

            self.cur_fun = function
            try:
                self._analysis.project.analyses.VariableRecoveryFast(function)
                memcpy_addr = function.addr
                memcpy_node = self.cfg.model.get_any_node(memcpy_addr)
                memcpy_node_preds = memcpy_node.predecessors
                memcpy_funcs_preds = list(set([x.function_address for x in memcpy_node_preds]))
                dec = self._analysis.project.analyses.Decompiler(function, cfg=self.cfg)
                self.dec = dec
                self.clinic = self.dec.clinic
            except Exception as e:
                print("error at 3528", e)
                print(function.name)
                self.dec = None
                self.clinic = None

            try:
                child_function_rda = self._analysis.project.analyses.ReachingDefinitions(
                    function_handler=self,
                    observe_all=True,
                    subject=function,
                    cc=function.calling_convention,
                    init_state=state,
                    kb=self._analysis.project.kb,
                    dep_graph=dependency_graph
                )
                state.analysis.observed_results.update(child_function_rda.observed_results)
            except Exception as e:
                print("error at 3491", e)
                self.cur_fun, self.dec, self.clinic, _ = config_sgtaint.STACK.pop()
                return True, state, visited_blocks, dependency_graph

            if function.has_return and len(collect_definatins) > 0:
                ret_register_name = state.arch.register_names[state.arch.ret_offset]
                ret_register_name_size = state.arch.registers[ret_register_name]
                atom = Register(ret_register_name_size[0], ret_register_name_size[1])
                tags_2 = {
                    ReturnValueTag(
                        function=function.addr,
                        metadata={
                            'tagged_by': f'{function.name} simulation Effect',
                            'block_addr': state.current_codeloc.block_addr,
                            'parameter_pass': 1
                        }
                    )
                }
                if first_defination is not None:
                    if first_defination.atom == atom:
                        first_defination.tags.update(tags_2)
                        new_rax = first_defination
                    data: MultiValues = state.register_definitions.load(first_defination.atom.reg_offset, size=first_defination.atom.size)
                    try:
                        mv = state.kill_and_add_definition(atom, first_defination.codeloc, data, tags=tags_2)
                    except Exception as e:
                        print(e)
                    ff_defs = state.live_definitions.extract_defs_from_mv(mv=mv)
                    new_rax = [d for d in ff_defs][0]
                    for d0 in collect_definatins:
                        state.dep_graph.add_edge(d0, new_rax)

        if not function.is_plt:
            self.cur_fun, self.dec, self.clinic, _ = config_sgtaint.STACK.pop()

        return True, state, visited_blocks, dependency_graph