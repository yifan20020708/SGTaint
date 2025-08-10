import re
import os
import json
import queue
import multiprocessing
import ailment
import logging
from collections import defaultdict
from angr.project import Project
from angr.analyses.cfg.cfg_fast import CFGFast
from angr.knowledge_plugins.key_definitions.atoms import Register, SpOffset, MemoryLocation
from angr.knowledge_plugins.key_definitions.tag import ReturnValueTag
import tool.Config.config as config_sgtaint
from tool.SGGraph.utils import dedupe_paths, get_call_site_func_name, get_ins_addr_from_range
from tool.BugFinder.DefExplorer import DefinitionExplorer

logger = logging.getLogger("sgtaint.merge")

def get_clinic_block(project: Project, clinic, addr):
    blk = None
    if clinic is not None:
        for block in clinic.graph.nodes():
            if block.addr == addr:
                blk = block
                break
        try:
            if blk is not None and hasattr(blk, "statements") and len(blk.statements) > 0:
                return blk
        except Exception:
            pass
    try:
        manager = ailment.Manager(arch=project.arch)
        block = project.factory.block(addr)
        ail_block = ailment.IRSBConverter.convert(block.vex, manager)
        simp = project.analyses.AILBlockSimplifier(ail_block, clinic.function.addr)
        csm = project.analyses.AILCallSiteMaker(simp.result_block)
        if csm.result_block:
            ail_block = csm.result_block
            simp = project.analyses.AILBlockSimplifier(ail_block, clinic.function.addr)
        return simp.result_block
    except Exception:
        return None


def get_strings(d0, cfg, rd_ddg_graph):
    b0 = "not_static_string"
    pcd0 = [d for d in rd_ddg_graph.predecessors(d0)]
    memory_def_flag = False
    for df in pcd0:
        if type(df.atom) == MemoryLocation and df.atom.addr in cfg.memory_data:
            memory_def_flag = True
    if not memory_def_flag:
        extended_defs = []
        for df in pcd0:
            extended_defs.extend(rd_ddg_graph.predecessors(df))
        pcd0 = extended_defs
    string_list = []
    for df in pcd0:
        if (type(df.atom) == MemoryLocation and
                df.atom.addr in cfg.memory_data and
                cfg.memory_data[df.atom.addr].content is not None):
            bb0 = cfg.memory_data[df.atom.addr]
            if bb0.content is not None:
                i = 0
                while str(
                    cfg.project.loader.memory.load(bb0.addr, bb0.size + i)
                )[bb0.size + i + 1] != "\\":
                    i += 1
                b0 = str(
                    cfg.project.loader.memory.load(bb0.addr, bb0.size + i - 1)
                )[2:-1]
                string_list.append(b0)
    if len(string_list) > 1:
        b0 = "#".join(string_list)
    return b0


def extract_operands(operand, state=None):
    if type(operand) == list:
        return extract_operands(operand[0], state) + extract_operands(operand[1], state)
    if type(operand) == ailment.expression.BinaryOp:
        return extract_operands(operand.operands)
    elif type(operand) == ailment.expression.Const:
        return []
    elif type(operand) == ailment.expression.Register:
        return [operand]
    elif hasattr(operand, "base"):
        atom = MemoryLocation(SpOffset(state.arch.bits, operand.offset), operand.size)
        return [atom]
    elif type(operand) == ailment.expression.Load and hasattr(operand, "addr") and type(operand.addr) == ailment.expression.StackBaseOffset:
        atom = MemoryLocation(SpOffset(state.arch.bits, operand.addr.offset), operand.size)
        return [atom]
    elif type(operand) == ailment.expression.Load and hasattr(operand, "addr") and type(operand.addr) == ailment.expression.BinaryOp and type(operand.addr.operands[1]) == ailment.expression.Const:
        atom = MemoryLocation(SpOffset(state.arch.bits, operand.addr.operands[1].value), operand.addr.operands[1].size)
        return [atom]
    else:
        return []


def get_path_between_two_nodes(node_A, node_B, function):
    reg_seen_defs = set()
    defs_to_check = [(node_A, [])]
    seen_defs = set()
    paths = []
    while defs_to_check:
        current_def, current_path = defs_to_check.pop()
        seen_defs.add(current_def)
        current_path = current_path + [current_def.addr]
        def_value = current_def == node_B
        if def_value:
            reg_seen_defs.add(def_value)
            paths.append(current_path)
        else:
            if current_def in function.graph.nodes():
                for pred in current_def.predecessors():
                    if pred not in seen_defs:
                        defs_to_check.append((pred, current_path))
    if not paths:
        return []
    return paths[0]


def get_path(desired_blocks, def_explorer):
    RDA_handler = def_explorer.RDA_handler
    final_blocks_list = []
    for addr in desired_blocks:
        if addr not in final_blocks_list:
            final_blocks_list.append(addr)
    connected_blocks = []
    i = 0
    while i + 1 < len(final_blocks_list):
        tmp_fun_0 = RDA_handler.cfg.functions.floor_func(final_blocks_list[i])
        tmp_fun_1 = RDA_handler.cfg.functions.floor_func(final_blocks_list[i + 1])
        if tmp_fun_0 != tmp_fun_1:
            i += 1
            connected_blocks.append(final_blocks_list[i - 1])
            continue
        node_A = tmp_fun_0.get_node(final_blocks_list[i])
        node_B = tmp_fun_0.get_node(final_blocks_list[i + 1])
        i += 1
        if node_A is None or node_B is None:
            continue
        if node_B in node_A.predecessors():
            connected_blocks.append(final_blocks_list[i - 1])
            continue
        else:
            sub_path = get_path_between_two_nodes(node_A, node_B, tmp_fun_0)
            connected_blocks.extend(sub_path[:-1])
    for blk_addr in final_blocks_list:
        if blk_addr not in connected_blocks:
            connected_blocks.append(blk_addr)
    return connected_blocks


def connectDefination_with_sinks(function, project: Project, def_explorer=None, 
                                 desired_blocks=None, desired_definations=None, 
                                 keyword=None, connected_path=None):
    RDA_handler = def_explorer.RDA_handler
    clinic = RDA_handler.dec.clinic
    connected_blocks = connected_path
    type_list = []
    intresting_blks = [] # contianisn condtions blocks addresses
    false_blocks = []  # contianisn false condtions blocks addresses
    path_blk = []
    error_messges_list = []
    fail2captureConditionsTime = 0
    
    for addr in connected_blocks:
        tmp_fun = RDA_handler.cfg.functions.floor_func(addr)
        tmp_clinic = clinic
        tmp_state = def_explorer.current_state
        blk = None
        if tmp_fun != function:
            for item in config_sgtaint.STACK:
                if tmp_fun == item[0]:
                    blk = get_clinic_block(project, item[2], addr)
                    tmp_clinic = item[2]
                    tmp_state = item[3]
                    break
        else:
            blk = get_clinic_block(project, clinic, addr)
            try:
                tmp_state = RDA_handler._analysis.get_reaching_definitions_by_node(addr, 0)
            except Exception as e:
                tmp_state = def_explorer.current_state
        if blk is not None and hasattr(blk,"statements") and len(blk.statements) > 0:
            branch_type = type(blk.statements[-1]) 
            if addr in desired_blocks:
                path_blk.append((blk,branch_type))
            if  branch_type not in [ailment.statement.Call, ailment.statement.Store, ailment.statement.Assignment]:
                intresting_blks.append((blk,branch_type))
                try:
                    if type(blk.statements[-1]) == ailment.statement.Jump:                        
                        continue
                    false_block_address = blk.statements[-1].false_target.value if blk.statements[-1].true_target.value in connected_blocks else blk.statements[-1].true_target.value
                    false_blk = get_clinic_block(project, tmp_clinic, false_block_address)
                    false_blocks.append(false_block_address)
                    if type(false_blk.statements[-1]) == ailment.statement.Return :
                        print("blk_addr =", hex(false_block_address), "  Return -> ", false_blk.statements[-1], " ", false_blk.statements[-1].tags)
                        tmp_error = "return*-1"
                        if tmp_error not in error_messges_list:
                            error_messges_list.append(tmp_error)
                    elif type(false_blk.statements[0]) == ailment.statement.Assignment and type(false_blk.statements[0].src) == ailment.expression.Const and false_blk.statements[0].src.value in RDA_handler.cfg.memory_data:
                            bb0 = RDA_handler.cfg.memory_data[false_blk.statements[0].src.value]
                            b0 = ""
                            if bb0.content is not None:
                                i = 0
                                while str(RDA_handler.cfg.project.loader.memory.load(bb0.addr, bb0.size + i))[bb0.size + i + 1] != '\\':
                                    i += 1
                                b0 = str(RDA_handler.cfg.project.loader.memory.load(bb0.addr, bb0.size + i - 1))[2:-1]
                            tmp_error = "pcvar*"+b0 
                            if tmp_error not in error_messges_list:
                                error_messges_list.append(tmp_error)
                            print("error function is -> ", tmp_error)
                    elif type(false_blk.statements[-1]) == ailment.statement.Call and hasattr(false_blk.statements[-1], 'target') and hasattr(false_blk.statements[-1].target, 'value'):
                        error_function = RDA_handler.cfg.functions.get_by_addr(addr = false_blk.statements[-1].target.value)
                        b0 = ""
                        if error_function is not None and false_blk.statements[-1].args is not None and len(false_blk.statements[-1].args) == 1 and hasattr(false_blk.statements[-1].args[0],'value') and false_blk.statements[-1].args[0].value in RDA_handler.cfg.memory_data:
                            bb0 = RDA_handler.cfg.memory_data[false_blk.statements[-1].args[0].value]
                            b0 = ""
                            if bb0.content is not None:
                                i = 0
                                while str(RDA_handler.cfg.project.loader.memory.load(bb0.addr, bb0.size + i))[bb0.size + i + 1] != '\\':
                                    i += 1
                                b0 = str(RDA_handler.cfg.project.loader.memory.load(bb0.addr, bb0.size + i - 1))[2:-1]
                            tmp_error = error_function.name + "*" + b0
                            if tmp_error not in error_messges_list:
                                error_messges_list.append(tmp_error)
                            print("error function is -> ", error_function.name, "text=",b0)
                        elif error_function is not None and hasattr(false_blk.statements[-1],"args") and false_blk.statements[-1].args is not None and len(false_blk.statements[-1].args) == 1 and type(false_blk.statements[-1].args[0]) == ailment.expression.Const:
                            tmp_error = error_function.name + "*" + str(false_blk.statements[-1].args[0].value)
                            if tmp_error not in error_messges_list:
                                error_messges_list.append(tmp_error)
                            print("error function is -> ", error_function.name, "value=", b0)
                except Exception as e:
                    print("ERROR AT 4131 ->", e)
                    continue
            if branch_type not in type_list:
                type_list.append(branch_type)           
    print(type_list)   
    print("***")
    print("Extracted conditional Blocks")
    for itm in intresting_blks: # 其中可能存在过滤内容的block
        if itm[1] == ailment.statement.ConditionalJump:
            print(itm[0].statements[-1].condition.verbose_op, " -> ", itm[0].statements[-1].condition)
    print("########")
    flag_list = [0]
    reg_name_list = []    
    for item in intresting_blks:
        try:
            cnd_statement = item[0].statements[-1]
            if type(cnd_statement) != ailment.statement.ConditionalJump: # 仅仅对分支块进行相应的处理
                continue
            blk_addr = cnd_statement.tags['vex_block_addr']
            tmp_fun = RDA_handler.cfg.functions.floor_func(blk_addr)
            if tmp_fun == function :
                tmp_state = def_explorer.current_state
            elif tmp_fun != function:
                for stack_item in config_sgtaint.STACK:
                    if tmp_fun == stack_item[0]:
                        tmp_state = stack_item[3]
                        break
            else:
                tmp_state = RDA_handler._analysis.get_reaching_definitions_by_node(blk_addr, 0)
        except Exception as e:
            tmp_state = def_explorer.current_state
            print("error at 4139 ", e)
        operands = cnd_statement.condition.operands
        operands_list = []
        for oprand in operands:
            try:
                if type(oprand) == ailment.expression.BinaryOp:
                    operands_list.extend(extract_operands(oprand.operands,tmp_state))
                elif type(oprand) == ailment.expression.Const:
                    continue
                elif type(oprand) == ailment.expression.Register:
                    operands_list.append(oprand)
                elif hasattr(oprand, 'base') :
                    atom=MemoryLocation(SpOffset(tmp_state.arch.bits, oprand.offset), oprand.size)
                    operands_list.append(atom)
                elif type(oprand) == ailment.expression.Load and hasattr(oprand,'addr') and type(oprand.addr) == ailment.expression.StackBaseOffset:
                    atom=MemoryLocation(SpOffset(tmp_state.arch.bits, oprand.addr.offset), oprand.size)
                    operands_list.append(atom)
                elif type(oprand) == ailment.expression.UnaryOp:
                    operands_list.extend(extract_operands(oprand.operands[0], tmp_state))
                else:
                    print("we did not catch it  -->  ", oprand, " -> ", type(oprand))
            except Exception as e:
                print("error AT 4248 with --> ", oprand, " -> ", type(oprand))
                continue
        for oprand in operands_list:
            try:
                if type(oprand) == ailment.expression.Register:
                    atom_1 = Register(oprand.reg_offset,oprand.size)
                    df1 = next(iter(tmp_state.get_definitions(atom_1)))
                    operand_name = oprand.tags["reg_name"]
                elif type(oprand) == MemoryLocation:
                    df1 = next(iter(tmp_state.get_definitions(oprand)))
                    operand_name = oprand.addr
                if df1 in desired_definations:
                    if len(cnd_statement.condition.operands) == 2 and type(cnd_statement.condition.operands[1]) == ailment.expression.Const and cnd_statement.condition.operands[1].value == 0:
                        no_sanitization_flag = False
                        extrated_tags = df1.tags.copy()
                        if len(extrated_tags) == 0:
                            prd1 = [d for d in def_explorer.RDA_handler._analysis.dep_graph.predecessors(df1)]
                            for dfdf in prd1:
                                if dfdf in desired_definations:
                                    extrated_tags = dfdf.tags.copy()
                                    if len(extrated_tags) == 0:
                                        continue
                                    curr_tag = extrated_tags.pop()
                                    while True:
                                        if len(extrated_tags) == 0:
                                            break
                                        if type(curr_tag) == ReturnValueTag:
                                            break
                                        curr_tag = extrated_tags.pop()
                                    taint_source_name = curr_tag.metadata['tagged_by'].split()[0]
                                    print(taint_source_name)
                                    if taint_source_name in config_sgtaint.SOURCES or taint_source_name in config_sgtaint.New_input_getters:
                                        no_sanitization_flag = True
                        else:
                            curr_tag = extrated_tags.pop()
                            while True:
                                if len(extrated_tags) == 0:
                                    break
                                if type(curr_tag) == ReturnValueTag:
                                    break
                                curr_tag = extrated_tags.pop()
                            taint_source_name = curr_tag.metadata['tagged_by'].split()[0]
                            print(taint_source_name)
                            if taint_source_name in config_sgtaint.SOURCES or taint_source_name in config_sgtaint.New_input_getters:
                                no_sanitization_flag=True
                        if not no_sanitization_flag:
                            flag_list.append(1)
                            reg_name_list.append(f'{operand_name}@{cnd_statement.condition}')
                            print(f'{operand_name}@{cnd_statement.condition}') 
                        else:
                            print(f'{operand_name}@{cnd_statement.condition}  ', curr_tag.metadata['tagged_by'])
                    else:
                        flag_list.append(1)
                        reg_name_list.append(f'{operand_name}@{cnd_statement.condition}')
                elif df1 in def_explorer.RDA_handler._analysis.dep_graph.nodes():
                    check_more = False
                    prd1 = [d for d in def_explorer.RDA_handler._analysis.dep_graph.predecessors(df1)]
                    for tmp_def in prd1:
                        if tmp_def in desired_definations:
                            flag_list.append(1)
                            reg_name_list.append(f'{operand_name}@{cnd_statement.condition}' )
                            print(tmp_def)
                            print("#### we hit here for checking time  :)")
                            check_more=True
                            continue
                        else:
                            reg_def = tmp_def
                            defs_to_check = set()
                            defs_to_check.add(reg_def)
                            seen_defs = set()
                            while len(defs_to_check) != 0:
                                current_def = defs_to_check.pop()
                                seen_defs.add(current_def)
                                if current_def in desired_definations:
                                    flag_list.append(1)
                                    reg_name_list.append(f'{operand_name}@{cnd_statement.condition}' )
                                    print(tmp_def, "--", current_def)
                                    print("#### we hit the second for checking time  :)")
                                else:
                                    if current_def in def_explorer.RDA_handler._analysis.graph.nodes():
                                        for pred in def_explorer.RDA_handler._analysis.graph.predecessors(current_def):
                                            if pred not in seen_defs:
                                                defs_to_check.add(pred)
                    if not check_more:
                        continue         
            except Exception as e:
                print("error ->", e)
                print(oprand)
                fail2captureConditionsTime += 1
                continue
    checking_time = sum(flag_list)
    conditions_str = "#".join(reg_name_list)
    error_messges_str = "#".join(error_messges_list)
    if checking_time > 0:
        print("checking_time =", checking_time, " ", conditions_str)
    return checking_time, fail2captureConditionsTime, conditions_str, error_messges_str
    
    
def backtrack_definations(def_explorer: DefinitionExplorer, reg_defs, result_file,
                          memcpy_func_pred, FUNCS, sink, memcpy_addr, result_path,
                          check_is_tainted_def=False):
    for reg_def in reg_defs:
        OVERALL_DEFS = set()
        function_containing_sink = def_explorer.cfg.kb.functions.floor_func(memcpy_addr)
        if function_containing_sink is not None:
            function_containing_sink_name = function_containing_sink.name
        else:
            function_containing_sink_name = hex(memcpy_addr)

        reg_seen_defs, Paths, visited_functions = def_explorer.resolve_use_def(reg_def)
        if check_is_tainted_def:
            return reg_seen_defs, Paths, visited_functions
        for overall_def, path, visited_function in zip(reg_seen_defs, Paths, visited_functions):
            print(overall_def)
            print("path ->", path)
            print(visited_function)
            print("$$$$$$$$$$$$$$$$$$$")

            if overall_def[0] == "get2set":
                tmp_path = [i.codeloc.block_addr for i in path]
                connected_path = get_path(desired_blocks=tmp_path, def_explorer=def_explorer)
                # 需要进行路径的补全
                str_path_flag = "#".join(str(hex(i)) for i in connected_path)
                str_path = complete_decomplie_path(def_explorer.cfg, connected_path, overall_def[3], overall_def[4])
                print("visited_function ->", visited_function)
                tmp_visited_function = []
                length_visited_function = []
                for vfn in visited_function:
                    if vfn[1] in connected_path and vfn[2] != -1:
                        length_str = f"{vfn[0]}*{vfn[2]}"
                        if length_str not in length_visited_function:
                            length_visited_function.append(length_str)
                    if vfn not in tmp_visited_function and vfn[1] in connected_path:
                        tmp_visited_function.append(vfn)
                tmp_visited_function = [fn[0] for fn in tmp_visited_function]
                str_visited_fnctions = "#".join(tmp_visited_function)
                str_length_visited_function = "#".join(length_visited_function)
                print("\nget2set keyword is ->", overall_def[6])
                print("str_visited_fnctions ->", str_visited_fnctions, tmp_visited_function)
                try:
                    checking_time, fail2captureConditionsTime, conditions_str, error_messges_str = \
                        connectDefination_with_sinks(
                            function=def_explorer.RDA_handler.cur_fun,
                            project=def_explorer.RDA_handler._analysis.project,
                            def_explorer=def_explorer,
                            desired_blocks=tmp_path,
                            desired_definations=path,
                            keyword=overall_def[6],
                            connected_path=connected_path
                        )
                except Exception:
                    checking_time, fail2captureConditionsTime, conditions_str, error_messges_str = -1, -1, "", ""
                # 完成之后进行合并，防止并行操作造成读写异常
                result_dict = {
                    "target_addr": memcpy_func_pred.addr,
                    "target_name": memcpy_func_pred.name,
                    "source_name": overall_def[5],
                    "source_insr_addr": overall_def[3],
                    "source_addr": overall_def[1],
                    "taint_source": overall_def[2],
                    "sink_insr_addr": overall_def[4],
                    "sink_addr": function_containing_sink_name,
                    "sink_name": sink,
                    "checking_time": checking_time,
                    "conditions_str": conditions_str,
                    "visited_functions": str_visited_fnctions,
                    "fail2captureConditionsTime": fail2captureConditionsTime,
                    "error_messges_str": error_messges_str,
                    "str_length_visited_function": str_length_visited_function,
                    "path_flag": str_path_flag,
                    "path": str_path,
                    "source_keyword": overall_def[6],
                    "set_keyword": overall_def[7]
                }
                result_file.write(
                    f"target_addr: {hex(memcpy_func_pred.addr)} ,  "
                    f"target_name: {memcpy_func_pred.name} ,  "
                    f"source_name: {overall_def[5]} ,  "
                    f"source_insr_addr: {hex(overall_def[3])},  "
                    f"source_addr: {hex(overall_def[1])} ,  "
                    f"taint_source: {overall_def[2]} ,  "
                    f"sink_insr_addr: {hex(overall_def[4])}  ,"
                    f"sink_addr: {function_containing_sink_name} ,  "
                    f"sink_name: {sink},  "
                    f"checking_time:{checking_time},  "
                    f"conditions_str:{conditions_str} ,  "
                    f"visited_functions: {str_visited_fnctions},  "
                    f"fail2captureConditionsTime: {fail2captureConditionsTime},  "
                    f"error_messges_str: {error_messges_str},  "
                    f"str_length_visited_function: {str_length_visited_function} ,  "
                    f"path_flag: {str_path_flag} ,  "
                    f"path: {str_path} ,  {overall_def[6]} ,  {overall_def[7]}\n"
                )
                result_path.append(result_dict)
                result_file.flush()

            if overall_def[0] == "retval":
                if overall_def[1] is not None:
                    tmp_path = [i.codeloc.block_addr for i in path]
                    connected_path = get_path(desired_blocks=tmp_path, def_explorer=def_explorer)
                    str_path_flag = "#".join(str(hex(i)) for i in connected_path)
                    str_path = complete_decomplie_path(def_explorer.cfg, connected_path, overall_def[3], overall_def[4])
                    print("connected_path ->", connected_path)
                    print("visited_function ->", visited_function)
                    tmp_visited_function = []
                    length_visited_function = []
                    for vfn in visited_function:
                        if vfn[1] in connected_path and vfn[2] != -1:
                            length_str = f"{vfn[0]}*{vfn[2]}"
                            if length_str not in length_visited_function:
                                length_visited_function.append(length_str)
                        if vfn not in tmp_visited_function and vfn[1] in connected_path:
                            tmp_visited_function.append(vfn)
                    tmp_visited_function = [fn[0] for fn in tmp_visited_function]
                    str_visited_fnctions = "#".join(tmp_visited_function)
                    str_length_visited_function = "#".join(length_visited_function)
                    print("\nkeyword is ->", overall_def[6])
                    print("str_visited_fnctions ->", str_visited_fnctions)
                    try:
                        checking_time, fail2captureConditionsTime, conditions_str, error_messges_str = \
                            connectDefination_with_sinks(
                                function=def_explorer.RDA_handler.cur_fun,
                                project=def_explorer.RDA_handler._analysis.project,
                                def_explorer=def_explorer,
                                desired_blocks=tmp_path,
                                desired_definations=path,
                                keyword=overall_def[6],
                                connected_path=connected_path
                            )
                    except Exception:
                        checking_time, fail2captureConditionsTime, conditions_str, error_messges_str = -1, -1, "", ""
                    # 完成之后进行合并，防止并行操作造成读写异常
                    result_dict = {
                        "target_addr": memcpy_func_pred.addr,
                        "target_name": memcpy_func_pred.name,
                        "source_name": overall_def[5],
                        "source_insr_addr": overall_def[3],
                        "source_addr": overall_def[1],
                        "taint_source": overall_def[2],
                        "sink_insr_addr": overall_def[4],
                        "sink_addr": function_containing_sink_name,
                        "taint_sink": sink,
                        "checking_time": checking_time,
                        "conditions_str": conditions_str,
                        "visited_functions": str_visited_fnctions,
                        "fail2captureConditionsTime": fail2captureConditionsTime,
                        "error_messges_str": error_messges_str,
                        "str_length_visited_function": str_length_visited_function,
                        "path_flag": str_path_flag,
                        "path": str_path,
                        "source_keyword": overall_def[6]
                    }
                    result_file.write(
                        f"target_addr: {hex(memcpy_func_pred.addr)} ,  "
                        f"target_name: {memcpy_func_pred.name} ,  "
                        f"source_name: {overall_def[5]} ,  "
                        f"source_insr_addr: {hex(overall_def[3])},  "
                        f"source_addr: {hex(overall_def[1])} ,  "
                        f"taint_source: {overall_def[2]} ,  "
                        f"sink_insr_addr: {hex(overall_def[4])}  ,"
                        f"sink_addr: {function_containing_sink_name} ,  "
                        f"taint_Sink: {sink},  "
                        f"checking_time:{checking_time},  "
                        f"conditions_str:{conditions_str} ,  "
                        f"visited_functions: {str_visited_fnctions},  "
                        f"fail2captureConditionsTime: {fail2captureConditionsTime},  "
                        f"error_messges_str: {error_messges_str} ,  "
                        f"str_length_visited_function: {str_length_visited_function} ,  "
                        f"path_flag: {str_path_flag} ,  "
                        f"path: {str_path} ,  keyword: {overall_def[6]}\n"
                    )
                    result_path.append(result_dict)
                    result_file.flush()
                    

# 给定任意地址获取所在基本块的起始地址
def get_block_start_from_addr(target_addr, cfg: CFGFast):
    for node in cfg.nodes():
        if node.addr <= target_addr < node.addr + node.size:
            return node.addr
    return None

    
# 进行反编译路径的补充                
def complete_decomplie_path(cfg: CFGFast, connected_path, source_insr_addr, sink_insr_addr):
    decomplie_connected_path = []
    try:
        source_block_start = get_block_start_from_addr(source_insr_addr, cfg)
        sink_block_start = get_block_start_from_addr(sink_insr_addr, cfg)
        if source_block_start and sink_block_start:
            # 获取source的位置
            if source_block_start in connected_path:
                end_index = connected_path.index(source_block_start)
            else:
                for index in range(len(connected_path) - 1, -1, -1):
                    if connected_path[index] > source_block_start:
                        end_index = index + 1
                        break
            # 获取sink的位置
            if sink_block_start in connected_path:
                start_index = connected_path.index(sink_block_start)
            else:
                for index in range(len(connected_path)):
                    if connected_path[index] < sink_block_start:
                        start_index = index - 1
                        break
            decomplie_connected_path = [sink_block_start] + connected_path[start_index + 1 : end_index] + [source_block_start]
            return "#".join(str(hex(i)) for i in decomplie_connected_path)
        return "#".join(str(hex(i)) for i in connected_path)
    except Exception as e:
        print(f"ERROR: {e}")
        return "#".join(str(hex(i)) for i in connected_path)
                
                    
# 获取分析对象
def get_functions_to_analyse(sources, project, cfg):
    observation_points_map = {}         # Maps observation points (instruction) to function name
    function_callers_map = {}           # Maps function addr to list of CFG nodes that call the sink
    function_observation_points = {}    # Maps function addr to list of observation point tuples

    for target_function_name in sources:
        sink_function = project.kb.functions.function(name=target_function_name)
        if sink_function is None:
            continue
        sink_address = sink_function.addr
        sink_node = cfg.model.get_any_node(sink_address)
        if sink_node is None:
            continue
        sink_predecessors = sink_node.predecessors
        caller_function_addresses = list(set(
            pred.function_address for pred in sink_predecessors
        ))
        # Initialize mapping from caller function address to empty list
        for caller_addr in caller_function_addresses:
            function_callers_map[str(caller_addr)] = []
        # Group all predecessor nodes by their caller function
        for pred_node in sink_predecessors:
            function_callers_map[str(pred_node.function_address)].append(pred_node)
        # For each caller function, identify observation points (i.e., call sites)
        for caller_str_addr, call_sites in function_callers_map.items():
            caller_addr = int(caller_str_addr)
            observation_points = []
            for call_node in call_sites:
                last_instr_addr = project.factory.block(call_node.addr).instruction_addrs[-1]
                observation_point = ("insn", last_instr_addr, 0)
                observation_points.append(observation_point)
                observation_points_map[observation_point] = target_function_name
            if caller_addr not in function_observation_points:
                function_observation_points[caller_addr] = observation_points
            else:
                function_observation_points[caller_addr].extend(observation_points)
    return function_callers_map


def run_function_with_timeout(function, args=(), kwargs={}, timeout=10):
    q = multiprocessing.Queue()
    p = multiprocessing.Process(target=worker_function, args=(q, function, args, kwargs))
    p.start()
    p.join(timeout=timeout)
    if p.is_alive():
        p.terminate()
        p.join()
        raise TimeoutError("Function call timed out")
    try:
        status, data = q.get(timeout=1) 
    except queue.Empty: 
        raise TimeoutError("Failed to retrieve function result")
    if status == 'success':
        return data
    elif status == 'error':
        raise data
    
    
def worker_function(queue, function, args, kwargs):
    try:
        result = function(*args, **kwargs)
        queue.put(('success', result))
    except Exception as e:
        queue.put(('error', e))
        

# 将path序列转化为ghidra格式
def transfer_path_to_ghidra(path_str, project: Project, cfg: CFGFast):
    path_str_list = path_str.split("#")
    addr_int_list = [int(addr, 16) for addr in path_str_list if addr]
    addr_int_list.reverse()
    # 构建block缓存
    block_cache = {}
    def get_block(addr):
        if addr not in block_cache:
            block_cache[addr] = project.factory.block(addr)
        return block_cache[addr]
    function_dict = defaultdict(list)
    addr_to_func = {}
    for addr in addr_int_list:
        if addr not in addr_to_func:
            func = cfg.functions.floor_func(addr)
            if func is None:
                continue  # skip if no enclosing function
            addr_to_func[addr] = func.addr
        func_addr = addr_to_func[addr]
        function_dict[func_addr].append(addr)
    function_ghidra_format = []
    for func_addr, block_addrs in function_dict.items():
        start_block = get_block(block_addrs[0])
        end_block = get_block(block_addrs[-1])
        function_ghidra_format.append([
            func_addr,
            start_block.addr, start_block.instruction_addrs[-1],
            end_block.addr, end_block.instruction_addrs[-1]
        ])
    return function_ghidra_format


# 两种正则模式
pattern_source2sink = re.compile(
    r"target_addr:\s*([^,]+)\s*,\s*"
    r"target_name:\s*([^,]+)\s*,\s*"
    r"source_name:\s*([^,]+)\s*,\s*"
    r"source_insr_addr:\s*([^,]+)\s*,\s*"
    r"source_addr:\s*([^,]+)\s*,\s*"
    r"taint_source:\s*([^,]+)\s*,\s*"
    r"sink_insr_addr:\s*([^,]+)\s*,\s*"
    r"sink_addr:\s*([^,]+)\s*,\s*"
    r"taint_Sink:\s*([^,]+)\s*,\s*"
    r"checking_time:\s*([^,]+)\s*,\s*"
    r"conditions_str:\s*(.*?)\s*,\s*"
    r"visited_functions:\s*(.*?)\s*,\s*"
    r"fail2captureConditionsTime:\s*([^,]+)\s*,\s*"
    r"error_messges_str:\s*(.*?)\s*,\s*"
    r"str_length_visited_function:\s*(.*?)\s*,\s*"
    r"path_flag:\s*(.*?)\s*,\s*"
    r"path:\s*(.*?)\s*,\s*"
    r"keyword:\s*(.*?)\s*$"
)


pattern_get2set = re.compile(
    r"target_addr: ([^,]+) ,\s*"
    r"target_name: ([^,]+) ,\s*"
    r"source_name: ([^,]+) ,\s*"
    r"source_insr_addr: ([^,]+),\s*"
    r"source_addr: ([^,]+) ,\s*"
    r"taint_source: ([^,]+) ,\s*"
    r"sink_insr_addr: ([^,]+)  ,\s*"
    r"sink_addr: ([^,]+) ,\s*"
    r"sink_name: ([^,]+),\s*"
    r"checking_time:([^,]+),\s*"
    r"conditions_str:([^,]*?) ,\s*"
    r"visited_functions:\s*(.*?)\s*,\s*"
    r"fail2captureConditionsTime:\s*([^,]+)\s*,\s*"
    r"error_messges_str:\s*(.*?)\s*,\s*"
    r"str_length_visited_function:\s*(.*?)\s*,\s*"
    r"path_flag:\s*(.*?)\s*,\s*"
    r"path: ([^,]*?) ,\s*"
    r"([^,]*?) ,\s*([^,]*?)\s*$"
)


def parse_result_line_auto(line):
    m = pattern_source2sink.match(line)
    if m:
        (
            target_addr, target_name, source_name, source_insr_addr,
            source_addr, taint_source, sink_insr_addr, sink_addr,
            taint_sink, checking_time, conditions_str, visited_functions,
            fail2captureConditionsTime, error_messges_str, str_length_visited_function, path_flag,
            path, source_keyword
        ) = m.groups()
        return {
            "target_addr": target_addr.strip(),
            "target_name": target_name.strip(),
            "source_name": source_name.strip(),
            "source_insr_addr": source_insr_addr.strip(),
            "source_addr": source_addr.strip(),
            "taint_source": taint_source.strip(),
            "sink_insr_addr": sink_insr_addr.strip(),
            "sink_addr": sink_addr.strip(),
            "taint_sink": taint_sink.strip(),
            "checking_time": checking_time.strip(),
            "conditions_str": conditions_str.strip(),
            "visited_functions": visited_functions.strip(),
            "fail2captureConditionsTime": fail2captureConditionsTime.strip(),
            "error_messges_str": error_messges_str.strip(),
            "str_length_visited_function": str_length_visited_function.strip(),
            "path_flag": path_flag.strip(),
            "path": path.strip(),
            "source_keyword": source_keyword.strip(),
            "start_block": int(path.strip().split('#')[0], 16) if path.strip() else None,
            "end_block": int(path.strip().split('#')[-1], 16) if path.strip() else None,
        }
    m = pattern_get2set.match(line)
    if m:
        (
            target_addr, target_name, source_name, source_insr_addr,
            source_addr, taint_source, sink_insr_addr, sink_addr,
            sink_name, checking_time, conditions_str, visited_functions,
            fail2captureConditionsTime, error_messges_str, str_length_visited_function, path_flag,
            path, source_keyword, set_keyword
        ) = m.groups()
        if '#' in set_keyword:
            set_keyword_set = set(set_keyword.split('#'))
            if len(set_keyword_set) == 1:
                set_keyword = set_keyword_set.pop()
            else:
                xx = set_keyword_set.pop()
                set_keyword = set_keyword_set.pop() if '/' in xx else xx
        return {
            "target_addr": target_addr.strip(),
            "target_name": target_name.strip(),
            "source_name": source_name.strip(),
            "source_insr_addr": source_insr_addr.strip(),
            "source_addr": source_addr.strip(),
            "taint_source": taint_source.strip(),
            "sink_insr_addr": sink_insr_addr.strip(),
            "sink_addr": sink_addr.strip(),
            "taint_sink": sink_name.strip(),
            "checking_time": checking_time.strip(),
            "conditions_str": conditions_str.strip(),
            "visited_functions": visited_functions.strip(),
            "fail2captureConditionsTime": fail2captureConditionsTime.strip(),
            "error_messges_str": error_messges_str.strip(),
            "str_length_visited_function": str_length_visited_function.strip(),
            "path_flag": path_flag.strip(),
            "path": path.strip(),
            "source_keyword": source_keyword.strip(),
            "set_keyword": set_keyword.strip(),
            "start_block": int(path.strip().split('#')[-1], 16) if path.strip() else None,
            "end_block": int(path.strip().split('#')[0], 16) if path.strip() else None,
        }
    return None


# path列表进行去重
def deduplicate_paths_by_substring(paths):
    group_dict = defaultdict(list)
    for idx, item in enumerate(paths):
        key = (item['source_insr_addr'], item['sink_insr_addr'])
        group_dict[key].append((item['path_flag'], idx))  # 记录原始索引，便于还原
    dedup_indices = set()
    for (source, sink), path_with_indices in group_dict.items():
        # 按path长度降序，便于先判长串再判子串
        sorted_paths = sorted(path_with_indices, key=lambda x: len(x[0]), reverse=True)
        representatives = []
        rep_indices = []
        for cur_path, cur_idx in sorted_paths:
            already_in_cluster = False
            to_remove = []
            for ridx, (rep_path, rep_idx) in enumerate(representatives):
                if cur_path in rep_path:
                    # cur_path被已有代表包含
                    already_in_cluster = True
                    break
                elif rep_path in cur_path:
                    # 旧代表被当前更长的包含
                    to_remove.append(ridx)
            if already_in_cluster:
                continue
            for ridx in reversed(to_remove):
                representatives.pop(ridx)
                rep_indices.pop(ridx)
            representatives.append((cur_path, cur_idx))
            rep_indices.append(cur_idx)
        # 本组保留的所有代表索引
        dedup_indices.update(rep_indices)
    # 汇总所有保留的path
    dedup_paths = [paths[idx] for idx in sorted(dedup_indices)]
    return dedup_paths


# 解析source2sink文件到source2sink_path路径之中
def parse_source2sink_file_auto(filepath):
    source2sink_results = []
    source2sink_seen = set()
    source2sink_complete_results = []
    source2sink_complete_seen = set()
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f: # 逐行读取文件内容
            line = line.strip()
            result_dict = parse_result_line_auto(line)
            if result_dict is None:
                continue
            checking_time_flag = False
            maybe_sanitized_flag = False
            sanitization_verified_flag = False
            sanitization_by_function_flag = False
            length_flag = False
            # 读取对应的字典字段
            taint_source = result_dict.get("taint_source", "")
            checking_time = int(result_dict.get("checking_time", -1))
            source_keyword = result_dict.get("source_keyword", "")
            conditions_str = result_dict.get("conditions_str", "")
            visited_functions = result_dict.get("visited_functions", "").split("#")
            fail2captureConditionsTime = int(result_dict.get("fail2captureConditionsTime", -1))
            error_messges_str = result_dict.get("error_messges_str", "")
            str_length_visited_function = result_dict.get("str_length_visited_function", "")
            path = result_dict.get("path_flag", "")
            # 收集未过滤的信息
            if path not in source2sink_complete_seen:
                source2sink_complete_results.append(result_dict)
                source2sink_complete_seen.add(path)
            if taint_source in config_sgtaint.taint_sources_remove or taint_source not in config_sgtaint.SOURCES + config_sgtaint.New_input_getters:
                continue
            # 进行分支过滤
            if checking_time > 0: # 存在对应的过滤分支
                checking_time_flag = True
                continue
            # 进行长度限制的过滤
            if len(str_length_visited_function) > 0:
                str_length_visited_function_list = str_length_visited_function.split('#')
                for str_length in str_length_visited_function_list:
                    tmp_length = int(str_length.split('*')[1].strip())
                    if tmp_length < config_sgtaint.STRING_LENGTH_RESTRICTION:
                        length_flag = True
                        break
            # 针对关键字进行过滤
            if source_keyword in ["not_static_string", "empty_function_parameter", "empty_global"] and taint_source != "fgets":
                continue
            error_messages = error_messges_str.split("#") if len(error_messges_str) > 0 else ""
            if len(conditions_str) > 0:
                conditions = conditions_str.split("#")
                operands = []
                integers_list = []
                for con in conditions:
                    math = ""
                    if "!=" in con:
                        math = "!="
                    elif "==" in con:
                        math = "=="
                    elif "<=" in con:
                        math = "<="
                    elif "!=" in con:
                        math = "!4"
                    elif ">=" in con:
                        math = ">="
                    elif " <" in con:
                        math = " <"
                    elif " >" in con:
                        math = " >"
                    if "<s" in con:
                        math = "<s"
                    if "<=s" in con:
                        math = "<=s"
                    parts = con.split(math)
                    if '<32>' in parts[1] or '<63>' in parts[1]:
                        int_value = parts[1][:-5]
                        try:
                            integers_list.append(int(int_value, 16))
                        except Exception as e:
                            if "?" in int_value:
                                parts = int_value.split("?")
                                if '<32>' in parts[1] or '<63>' in parts[1]:
                                    int_value = parts[1][:-5]
                                    integers_list.append(int(int_value, 16))
                    else:
                        operand = parts[1][:-4]
                        operands.append(operand)
                sum_integers = sum(integers_list)
                if (len(integers_list) > 0 and sum_integers > 0) or len(operands) > 0:
                    sanitization_verified_flag = True
                elif sum_integers == 0:
                    if len(error_messages) > 0:
                        sanitization_verified_flag = True
                        sanitization_by_function_flag = True
            # 进行函数过滤
            for sanitization_function in config_sgtaint.sanitization_functions:
                if sanitization_function in visited_functions:
                    sanitization_by_function_flag = True
                    break
            if len(error_messages) > 0:
                sanitization_verified_flag = True
            if fail2captureConditionsTime > 0: # checking_time == -1
                maybe_sanitized_flag = True
            if sanitization_by_function_flag or sanitization_verified_flag or checking_time_flag or maybe_sanitized_flag or length_flag:
                continue
            # 将过滤之后的结果加入到候选集合之中
            if path not in source2sink_seen:
                source2sink_results.append(result_dict)
                source2sink_seen.add(path)
    # 对集合进行去重
    source2sink_results = deduplicate_paths_by_substring(source2sink_results)
    source2sink_complete_results = deduplicate_paths_by_substring(source2sink_complete_results)
    return source2sink_results, source2sink_complete_results
                

# 解析get2set文件到get2set_path路径之中
def parse_get2set_file_auto(filepath):
    get2set_results = []
    get2set_seen = set()
    get2set_complete_results = []
    get2set_complete_seen = set()
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f: # 逐行读取文件内容
            line = line.strip()
            result_dict = parse_result_line_auto(line)
            if result_dict is None:
                continue
            checking_time_flag = False
            maybe_sanitized_flag = False
            sanitization_verified_flag = False
            sanitization_by_function_flag = False
            # 读取对应的字典字段
            taint_source = result_dict.get("taint_source", "")
            checking_time = int(result_dict.get("checking_time", -1))
            source_keyword = result_dict.get("source_keyword", "")
            set_keyword = result_dict.get("set_keyword", "")
            conditions_str = result_dict.get("conditions_str", "")
            visited_functions = result_dict.get("visited_functions", "").split("#")
            fail2captureConditionsTime = int(result_dict.get("fail2captureConditionsTime", -1))
            error_messges_str = result_dict.get("error_messges_str", "")
            path = result_dict.get("path_flag", "")
            # 收集未过滤的信息
            if path not in get2set_complete_seen:
                get2set_complete_results.append(result_dict)
                get2set_complete_seen.add(path)
            if taint_source in config_sgtaint.taint_sources_remove or taint_source not in config_sgtaint.SOURCES + config_sgtaint.New_input_getters:
                continue
            # 进行分支过滤
            if checking_time > 0: # 存在对应的过滤分支
                checking_time_flag = True
                continue
            error_messages = error_messges_str.split("#") if len(error_messges_str) > 0 else ""
            if len(conditions_str) > 0:
                conditions = conditions_str.split("#")
                operands = []
                integers_list = []
                for con in conditions:
                    math = ""
                    if "!=" in con:
                        math = "!="
                    elif "==" in con:
                        math = "=="
                    elif "<=" in con:
                        math = "<="
                    elif "!=" in con:
                        math = "!4"
                    elif ">=" in con:
                        math = ">="
                    elif " <" in con:
                        math = " <"
                    elif " >" in con:
                        math = " >"
                    if "<s" in con:
                        math = "<s"
                    if "<=s" in con:
                        math = "<=s"
                    parts = con.split(math)
                    if '<32>' in parts[1] or '<63>' in parts[1]:
                        int_value = parts[1][:-5]
                        try:
                            integers_list.append(int(int_value, 16))
                        except Exception as e:
                            if "?" in int_value:
                                parts = int_value.split("?")
                                if '<32>' in parts[1] or '<63>' in parts[1]:
                                    int_value = parts[1][:-5]
                                    integers_list.append(int(int_value, 16))
                    else:
                        operand = parts[1][:-4]
                        operands.append(operand)
                sum_integers = sum(integers_list)
                if (len(integers_list) > 0 and sum_integers > 0) or len(operands) > 0:
                    sanitization_verified_flag = True
                elif sum_integers == 0:
                    if len(error_messages) > 0:
                        sanitization_verified_flag = True
                        sanitization_by_function_flag = True
            # 进行函数过滤
            for sanitization_function in config_sgtaint.sanitization_functions:
                if sanitization_function in visited_functions:
                    sanitization_by_function_flag = True
                    break
            if len(error_messages) > 0:
                sanitization_verified_flag = True
            if fail2captureConditionsTime > 0: # checking_time == -1
                maybe_sanitized_flag = True
            if sanitization_by_function_flag or sanitization_verified_flag or checking_time_flag or maybe_sanitized_flag:
                continue
            # 配置键解析
            if (source_keyword == "not_static_string" and taint_source != "fgets") or set_keyword == "not_static_string":
                continue
            # 将过滤之后的结果加入到候选集合之中
            if path not in get2set_seen:
                get2set_results.append(result_dict)
                get2set_seen.add(path)
    # 对集合进行去重
    get2set_results = deduplicate_paths_by_substring(get2set_results)
    get2set_complete_results = deduplicate_paths_by_substring(get2set_complete_results)
    return get2set_results, get2set_complete_results
            

# 单个二进制文件的路径拼接（直接通过内容匹配进行）
def construct_cross_binary_data_flow_single(file_path, potential_path_dict):
    if file_path not in potential_path_dict:
        logger.error(f"RDA Analysis failed for {file_path}")
        return
    # 读取潜在路径结果
    source2sink_path = potential_path_dict[file_path]["source2sink_path"]
    get2set_path = potential_path_dict[file_path]["get2set_path"]
    diffusion_file = potential_path_dict[file_path]["diffusion_file"]
    # 初始化complete_source2sink_path以及complete_get2sink_path
    for source2sink_single_path in source2sink_path:
        if source2sink_single_path["taint_source"] in config_sgtaint.transitive_get:
            path_dict = {file_path: [source2sink_single_path["path"]]} # 键为二进制文件路径，值为对应的路径列表
            vulnerability_type = "command injection" if source2sink_single_path["taint_sink"] in config_sgtaint.CI_SINKS else "buffer overflow"
            potential_path_dict[file_path]["complete_get2sink_path"].append({
                "kind": "intra-single", # 标记为原始的source2sink的路径
                "vulnerability_type": vulnerability_type,
                "checking_time": source2sink_single_path["checking_time"],
                "source_function_name": source2sink_single_path["source_name"], # source调用点所在的函数
                "taint_source": source2sink_single_path["taint_source"], # get函数的名称
                "source_insr_addr": source2sink_single_path["source_insr_addr"], # get函数调用点地址
                "start_block": source2sink_single_path["start_block"], # get函数调用点所在block的起始地址
                "source_keyword": source2sink_single_path["source_keyword"], # get函数的关键字
                "merge": False, # 标记为非合并路径
                "binary": [file_path], # 所在二进制文件的list
                "taint_sink": source2sink_single_path["taint_sink"], # sink函数的名称
                "sink_insr_addr": source2sink_single_path["sink_insr_addr"], # sink函数调用点地址
                "end_block": source2sink_single_path["end_block"], # sink函数调用点所在block的起始地址
                "path": path_dict, # 存储路径信息
                "visited_functions": source2sink_single_path["visited_functions"], # 存储访问过的函数名称的集合
                "decompile_list": source2sink_single_path.get("decompile_list", []), # 存储对应的反汇编片段
                "complete_list": source2sink_single_path.get("complete_list", []), # 存储对应的完整路径片段 
                "range_list": source2sink_single_path.get("range_list", [])
            })
        else: # 直接的潜在路径
            path_dict = {file_path: [source2sink_single_path["path"]]}
            vulnerability_type = "command injection" if source2sink_single_path["taint_sink"] in config_sgtaint.CI_SINKS else "buffer overflow"
            potential_path_dict[file_path]["complete_source2sink_path"].append({
                "kind": "intra-single", # 单个二进制文件内的潜在路径
                "vulnerability_type": vulnerability_type,
                "checking_time": source2sink_single_path["checking_time"],
                "source_function_name": source2sink_single_path["source_name"], # source调用点所在的函数
                "taint_source": source2sink_single_path["taint_source"], # source函数的名称
                "source_insr_addr": source2sink_single_path["source_insr_addr"], # source函数调用点地址
                "start_block": source2sink_single_path["start_block"], # source函数调用点所在block的起始地址
                "source_keyword": source2sink_single_path["source_keyword"], # source函数的关键字
                "merge": False, # 标记为非合并路径
                "binary": [file_path], # 所在二进制文件的list
                "taint_sink": source2sink_single_path["taint_sink"], # sink函数的名称
                "sink_insr_addr": source2sink_single_path["sink_insr_addr"], # sink函数调用点地址
                "end_block": source2sink_single_path["end_block"], # sink函数调用点所在block的起始地址
                "path": path_dict, # 存储路径信息
                "visited_functions": source2sink_single_path["visited_functions"], # 存储访问过的函数名称的集合
                "decompile_list": source2sink_single_path.get("decompile_list", []), # 存储对应的反汇编片段
                "complete_list": source2sink_single_path.get("complete_list", []), # 存储对应的完整路径片段
                "range_list": source2sink_single_path.get("range_list", [])
            })
    # 进行去重
    potential_path_dict[file_path]["complete_get2sink_path"] = dedupe_paths(potential_path_dict[file_path]["complete_get2sink_path"])
    potential_path_dict[file_path]["complete_source2sink_path"] = dedupe_paths(potential_path_dict[file_path]["complete_source2sink_path"])
    # 构建路径对应key的索引字典
    for complete_get2sink_single_path in potential_path_dict[file_path]["complete_get2sink_path"]:
        if complete_get2sink_single_path["source_keyword"] not in potential_path_dict[file_path]["complete_get2sink_path_dict"]:
            potential_path_dict[file_path]["complete_get2sink_path_dict"][complete_get2sink_single_path["source_keyword"]] = []
        potential_path_dict[file_path]["complete_get2sink_path_dict"][complete_get2sink_single_path["source_keyword"]].append(complete_get2sink_single_path)
    diffusion_file_update = [file_path] + diffusion_file # 加入当前文件路径
    new_complete_get2sink_path = [] # 用于存储新的完整的get2sink路径
    # 进行跨文件的路径拼接
    for get2set_single_path in get2set_path:
        if get2set_single_path["set_keyword"] == "not_static_string": # 直接跳过非静态字符串
            logger.warning(f"{file_path} has a non-static string set keyword, skipping path join.")
            continue
        is_find_cross_path = False # 标记是否找到跨二进制文件的路径
        set_keyword = get2set_single_path["set_keyword"]
        for binary_path in diffusion_file_update:
            if binary_path not in potential_path_dict:
                logger.error(f"RDA Analysis failed for {file_path}")
                continue
            binary_get2sink_path_dict = potential_path_dict[binary_path]["complete_get2sink_path_dict"]
            target_path_list = binary_get2sink_path_dict.get(set_keyword, [])[:] # 可以改进成模糊匹配，防止其中包含动态字符串
            if not target_path_list: # 如果没有对应的路径，则跳过
                # 首先进行动态字符串的对比
                dynamic_target_path_list = []
                if '%' not in set_keyword: # 不是动态字符串，和binary_get2sink_path_dict中的动态字符串进行匹配
                    for get_keyword in binary_get2sink_path_dict:
                        if '%' in get_keyword and match_dynamic(get_keyword, set_keyword)[0]:
                            dynamic_target_path_list.extend(binary_get2sink_path_dict[get_keyword])
                else: # 进行模糊匹配
                    for get_keyword in binary_get2sink_path_dict:
                        if '%' not in get_keyword and match_dynamic(set_keyword, get_keyword)[0]:
                            dynamic_target_path_list.extend(binary_get2sink_path_dict[get_keyword]) # 可能存在多个示例
                if not dynamic_target_path_list: # 不存在动态字符串匹配
                    continue
                else:
                    target_path_list = dynamic_target_path_list[:]
            # 遍历所有目标路径进行拼接
            for target_path in target_path_list:
                if (get2set_single_path['taint_sink'], target_path['taint_source']) not in config_sgtaint.SET_GET_INFO: # API不匹配
                    continue
                is_find_cross_path = True
                if file_path not in target_path["binary"]: # 如果目标路径不包含当前二进制文件，则跳过
                    binary_path_list = target_path["binary"] + [file_path] # 合并二进制文件路径
                else:
                    binary_path_list = target_path["binary"][:]
                target_path_path_dict = target_path["path"].copy() # 复制目标路径的路径字典
                if file_path in target_path_path_dict:
                    target_path_path_dict[file_path].append(get2set_single_path["path"])
                else:
                    target_path_path_dict[file_path] = [get2set_single_path["path"]]
                vulnerability_type = "command injection" if target_path["taint_sink"] in config_sgtaint.CI_SINKS else "buffer overflow"
                get2set_checking_time = int(get2set_single_path["checking_time"])
                target_checking_time = int(target_path["checking_time"])
                checking_time = '0' if get2set_checking_time + target_checking_time == 0 else '-1'
                # 构建新的路径字典
                new_path_dict = {
                    "kind": "cross", # 标记为跨二进制文件的路径
                    "vulnerability_type": vulnerability_type,
                    "checking_time": checking_time,
                    "source_function_name": get2set_single_path["source_name"], # source调用点所在的函数
                    "taint_source": get2set_single_path["taint_source"], # get函数的名称
                    "source_insr_addr": get2set_single_path["source_insr_addr"], # get函数调用点地址
                    "start_block": get2set_single_path["start_block"], # source函数调用点所在block的起始地址
                    "source_keyword": get2set_single_path["source_keyword"], # source函数的关键字
                    "merge": f"{get2set_single_path['taint_sink']} ({get2set_single_path['sink_insr_addr']}) --- {target_path['source_keyword']} ---> {target_path['taint_source']} ({target_path['source_insr_addr']})", # 相应的合并信息
                    "binary": binary_path_list, # 所在二进制文件的list
                    "taint_sink": target_path["taint_sink"], # sink函数的名称
                    "sink_insr_addr": target_path["sink_insr_addr"], # sink函数调用点地址
                    "end_block": target_path["end_block"], # sink函数调用点所在block的起始地址
                    "path": target_path_path_dict, # 存储路径信息
                    "visited_functions": f"{get2set_single_path['visited_functions']} --> {target_path['visited_functions']}", # 存储访问过的函数名称的集合
                    "decompile_list": get2set_single_path.get("decompile_list", []) + target_path.get("decompile_list", []), # 存储对应的反汇编片段
                    "complete_list": get2set_single_path.get("complete_list", []) + target_path.get("complete_list", []), # 存储对应的完整路径片段
                    "range_list": get2set_single_path.get("range_list", []) + target_path.get("range_list", [])
                }
                if new_path_dict["taint_source"] in config_sgtaint.transitive_get:
                    # 如果是跨二进制的get2sink路径，则添加到complete_get2sink_path中
                    new_complete_get2sink_path.append(new_path_dict)
                else:
                    # 如果是跨二进制的source2sink路径，则添加到complete_source2sink_path中
                    potential_path_dict[file_path]["complete_source2sink_path"].append(new_path_dict)
        if not is_find_cross_path:
            logger.warning(f"No cross binary path found for {file_path} with set keyword '{set_keyword}'.")
        else:
            logger.info(f"Cross binary path join completed for {file_path} with set keyword '{set_keyword}'.")
    # 合并新的完整的get2sink路径
    potential_path_dict[file_path]["complete_get2sink_path"].extend(new_complete_get2sink_path)
    potential_path_dict[file_path]["complete_get2sink_path"] = dedupe_paths(potential_path_dict[file_path]["complete_get2sink_path"]) # 去重
    potential_path_dict[file_path]["complete_source2sink_path"] = dedupe_paths(potential_path_dict[file_path]["complete_source2sink_path"]) # 去重
    # 更新complete_get2sink_path_dict
    potential_path_dict[file_path]["complete_get2sink_path_dict"].clear() # 清空原有的字典
    for complete_get2sink_single_path in potential_path_dict[file_path]["complete_get2sink_path"]:
        if complete_get2sink_single_path["source_keyword"] not in potential_path_dict[file_path]["complete_get2sink_path_dict"]:
            potential_path_dict[file_path]["complete_get2sink_path_dict"][complete_get2sink_single_path["source_keyword"]] = []
        potential_path_dict[file_path]["complete_get2sink_path_dict"][complete_get2sink_single_path["source_keyword"]].append(complete_get2sink_single_path)
        

# 给定反汇编后的代码行提取对应的函数调用内容
def get_call_site_func_name_from_line(line, call_site_name):
    offset_start = line.find(call_site_name)
    return offset_start, len(line)


# 寻找距离最近的函数调用
def find_nearest_call_site(call_site_dict, start_addr, end_addr):
    call_addrs = list(call_site_dict.keys())
    # 判断是否存在于block内部
    for addr in call_addrs:
        if start_addr <= addr <= end_addr:
            return call_site_dict[addr] 
    # 若不存在，寻找距离边界最近的调用
    nearest_addr = min(call_addrs, key=lambda x: min(abs(x - start_addr), abs(x - end_addr)))
    return call_site_dict[nearest_addr]


def template_to_regex(fmt: str) -> re.Pattern:
    regex = re.escape(fmt)            
    for spec, pat in config_sgtaint.spec_map.items():
        regex = regex.replace(re.escape(spec), pat)
    return re.compile(rf"^{regex}$")  


# 进行动态字符串的匹配
def match_dynamic(fmt: str, candidate: str):
    rex = template_to_regex(fmt)
    m = rex.fullmatch(candidate)
    return (bool(m), m.groupdict() if m else {})


# 根据函数调用名称获取函数调用点地址
def get_call_site_order_by_func_name(lines, pos2addr, call_site_name):
    # 计算每行的起始偏移
    line_starts = []
    offset = 0
    call_site_offset = []
    for idx, ln in enumerate(lines):
        line_starts.append(offset)
        if call_site_name in ln:
            offset_start, offset_finish = get_call_site_func_name_from_line(ln, call_site_name)
            if offset_start and offset_finish:
                # 行数开始偏移，函数调用开始偏移，行数结束
                call_site_offset.append((offset, offset + offset_start, offset + offset_finish, idx))
        offset += len(ln)
    call_site_info = []
    for line_start, call_site_start, line_end, idx in call_site_offset: # 对该行内所有字符逐个扫描
        # 优先向后查找
        pos_range = range(call_site_start, line_end)
        ins_addr = get_ins_addr_from_range(pos_range, pos2addr)
        # 如果后向没找到，再向前查找
        if ins_addr is None:
            pos_range = range(call_site_start - 1, line_start - 1, -1)
            ins_addr = get_ins_addr_from_range(pos_range, pos2addr)
        if ins_addr is not None: # 仅当识别成功的情况下直接加入到集合中
            call_site_info.append((idx, ins_addr)) # 按照识别出的指令地址进行排序，利用相对位置的一致性
    call_site_info = sorted(call_site_info, key=lambda x: x[1])
    return call_site_info


# 获取指定函数的调用点
def get_call_site_decompile_code_from_function(project: Project, cfg: CFGFast, call_site_name, func_addr, dec):
    call_sites = get_call_site_func_name(project, cfg, call_site_name) # 对调用点地址进行修正
    target_func = project.kb.functions.function(addr=func_addr)
    if not target_func:
        logger.error(f"[-] Function at {hex(func_addr)} not found.")
        return None
    # 获取函数之中的调用点
    call_sites_function = [call_site_addr for call_site_addr, caller_addr, _ in call_sites if caller_addr == func_addr] # 按照call_site_addr进行排序
    # 获取反编译与指令的关系
    decompile_code = dec.codegen.text
    lines = decompile_code.splitlines(keepends=True)
    pos2addr = dec.codegen.map_pos_to_addr
    line_tmp = get_call_site_order_by_func_name(lines, pos2addr, call_site_name)
    if len(line_tmp) != len(call_sites_function): # 若不匹配直接返回
        return {ins_addr: idx for idx, ins_addr in line_tmp}
    call_site_decompile_dict = {}
    for idx, call_site_addr in enumerate(call_sites_function): # 使用相对关系进行对应
        line_number = line_tmp[idx][0]
        insn_addr = call_site_addr
        call_site_decompile_dict[insn_addr] = line_number
    return call_site_decompile_dict


# 获取反汇编函数列表
def get_function_decompile_list_by_path(project, cfg, function_angr_format, taint_source, taint_sink):
    function_decompile_list = []
    function_complete_list = []
    range_list = []
    for idx, function_format in enumerate(function_angr_format):
        dec, func_addr, start_block_start, start_block_end, end_block_start, end_block_end = function_format
        pseudo_code_lines = dec.codegen.text.splitlines()
        # 获取start_index
        if idx == 0: # 处理第一个含有source的片段
            call_site_dict = get_call_site_decompile_code_from_function(project, cfg, taint_source, func_addr, dec)
            if not call_site_dict: # 反编译函数中不包含taint_source
                logger.error(f"The decompiled function does not contain the {taint_source} or the address resolution failed.")
                return ["Fail to Decompile by Angr"], ["Fail to Decompile by Angr"], ["Fail to Decompile by Angr"]
            start_index = find_nearest_call_site(call_site_dict, start_block_start, start_block_end)
        else:
            for i, line in enumerate(pseudo_code_lines):
                if line.strip(): # 找到第一个非空的行
                    start_index = i
                    break
        # 获取end_index
        if idx == len(function_angr_format) - 1: # 最后一个代码片段
            target_func_name = taint_sink
        else: # 其他代码片段的结尾为调用函数的函数名称
            next_func_addr = function_angr_format[idx + 1][1]
            next_func = project.kb.functions.get(next_func_addr)
            if not next_func: # 不能识别此函数
                logger.error(f"The decompiled function does not contain the {next_func.name}")
                return ["Fail to Decompile by Angr"], ["Fail to Decompile by Angr"], ["Fail to Decompile by Angr"]
            target_func_name = next_func.name
        call_site_dict_unfilter = get_call_site_decompile_code_from_function(project, cfg, target_func_name, func_addr, dec)
        call_site_dict = {addr: idx for addr, idx in call_site_dict_unfilter.items() if idx >= start_index}
        if not call_site_dict:
            logger.error(f"No valid call instruction to {target_func_name} was identified within the analyzed code.")
            return ["Fail to Decompile by Angr"], ["Fail to Decompile by Angr"], ["Fail to Decompile by Angr"]
        end_index = find_nearest_call_site(call_site_dict, end_block_start, end_block_end)
        # 使用start_index以及end_index截取片段
        if end_index < start_index: # 如果end_index小于start_index，说明没有有效的代码片段
            logger.error(f"The end index {end_index} is less than the start index {start_index}, resulting in an invalid code segment.")
            return ["Invaild code snippet"], ["Invaild code snippet"], ["Invaild code snippet"]
        code_snippet_list = pseudo_code_lines[start_index:end_index + 1]
        code_snippet = "\n".join(code_snippet_list)
        function_decompile_list.append(code_snippet)
        function_complete_list.append("\n".join(pseudo_code_lines))
        range_list.append([start_index + 1, end_index + 1])
    return function_decompile_list, function_complete_list, range_list


# 按照路径涉及的基本块长度进行排序
def sort_by_block_number(path_list):
    def count_blocks(path):
        block_path_dict = path["path"]
        block_number = 0
        for file_path, block_path in block_path_dict.items():
            for block_single_path in block_path:
                block_number += len(block_single_path.split('#'))
        return block_number
    # 排序并返回结果
    sorted_path_list = sorted(path_list, key=count_blocks)
    return sorted_path_list


# 进行潜在路径重要性排序
def get_sorted_potential_path_sanitization(keyword_binary_dict, potential_path):
    sorted_potential_path = [] # 重要性排序后的列表
    sorted_potential_verify = []
    sorted_potential_maybe = []
    ci_keyword_find_path = [] # 前端关键字命中的command injection
    bof_keyword_find_strcpy_xx_path = [] # 前端关键字命中的buffer overflow
    bof_keyword_find_else_xx_path = []
    ci_keyword_miss_webgetvar_xx_path = []
    bof_keyword_miss_webgetvar_strcpy_xx_path = []
    bof_keyword_miss_webgetvar_else_xx_path = []
    ci_keyword_miss_else_xx_path = []
    bof_keyword_miss_else_strcpy_xx_path = []
    bof_keyword_miss_else_else_xx_path = []
    # 对潜在路径进行遍历分类
    for path in potential_path:
        vulnerability_type = path["vulnerability_type"]
        source_keyword = path["source_keyword"]
        source_file = path["binary"][-1] # 最后一个元素为源文件
        taint_sink = path["taint_sink"]
        taint_source = path["taint_source"]
        if vulnerability_type == "command injection":
            if taint_source in config_sgtaint.KEYWORD_SOURCES and source_file in keyword_binary_dict and source_keyword in keyword_binary_dict[source_file]: # 前端关键字命中的command injection
                # 自动关联前端文件
                file_name = "{}_keyword_function.json".format(source_file.replace("/", "_"))
                keyword_file_path = os.path.join(config_sgtaint.TMP_KEYWORD, file_name)
                if os.path.exists(keyword_file_path): # 一定存在
                    with open(keyword_file_path, "r") as file:
                        keyword_function_list = json.load(file)
                    for keyword_function in keyword_function_list: # 一定存在命中项
                        if source_keyword == keyword_function["string"]: # 找到对应的关键字
                            path["front_end_keyword"] = keyword_function["keyword_function"]
                            path["front_end_file_path"] = keyword_function["path"]
                            break
                ci_keyword_find_path.append(path)
            elif taint_source in config_sgtaint.KEYWORD_SOURCES:
                path["front_end_keyword"] = "miss"
                path["front_end_file_path"] = "miss"
                ci_keyword_miss_webgetvar_xx_path.append(path)
            else:
                path["front_end_keyword"] = "miss"
                path["front_end_file_path"] = "miss"
                ci_keyword_miss_else_xx_path.append(path)
        else:
            if taint_source in config_sgtaint.KEYWORD_SOURCES and source_file in keyword_binary_dict and source_keyword in keyword_binary_dict[source_file]:
                # 自动关联前端文件
                file_name = "{}_keyword_function.json".format(source_file.replace("/", "_"))
                keyword_file_path = os.path.join(config_sgtaint.TMP_KEYWORD, file_name)
                if os.path.exists(keyword_file_path): # 一定存在
                    with open(keyword_file_path, "r") as file:
                        keyword_function_list = json.load(file)
                    for keyword_function in keyword_function_list: # 一定存在命中项
                        if source_keyword == keyword_function["string"]: # 找到对应的关键字
                            path["front_end_keyword"] = keyword_function["keyword_function"]
                            path["front_end_file_path"] = keyword_function["path"]
                            break
                if taint_sink in config_sgtaint.STRCPY_SINKS:
                    bof_keyword_find_strcpy_xx_path.append(path)
                else:
                    bof_keyword_find_else_xx_path.append(path)
            elif taint_source in config_sgtaint.KEYWORD_SOURCES:
                path["front_end_keyword"] = "miss"
                path["front_end_file_path"] = "miss"
                if taint_sink in config_sgtaint.STRCPY_SINKS:
                    bof_keyword_miss_webgetvar_strcpy_xx_path.append(path)
                else:
                    bof_keyword_miss_webgetvar_else_xx_path.append(path)
            else:
                path["front_end_keyword"] = "miss"
                path["front_end_file_path"] = "miss"
                if taint_sink in config_sgtaint.STRCPY_SINKS:
                    bof_keyword_miss_else_strcpy_xx_path.append(path)
                else:
                    bof_keyword_miss_else_else_xx_path.append(path)
    # 同一个列表中，按照涉及的基本块长度进行排序
    ci_keyword_find_path = sort_by_block_number(ci_keyword_find_path)
    bof_keyword_find_strcpy_xx_path = sort_by_block_number(bof_keyword_find_strcpy_xx_path)
    bof_keyword_find_else_xx_path = sort_by_block_number(bof_keyword_find_else_xx_path)
    ci_keyword_miss_webgetvar_xx_path = sort_by_block_number(ci_keyword_miss_webgetvar_xx_path)
    bof_keyword_miss_webgetvar_strcpy_xx_path = sort_by_block_number(bof_keyword_miss_webgetvar_strcpy_xx_path)
    bof_keyword_miss_webgetvar_else_xx_path = sort_by_block_number(bof_keyword_miss_webgetvar_else_xx_path)
    ci_keyword_miss_else_xx_path = sort_by_block_number(ci_keyword_miss_else_xx_path)
    bof_keyword_miss_else_strcpy_xx_path = sort_by_block_number(bof_keyword_miss_else_strcpy_xx_path)
    bof_keyword_miss_else_else_xx_path = sort_by_block_number(bof_keyword_miss_else_else_xx_path)
    sorted_potential_path = ci_keyword_find_path + bof_keyword_find_strcpy_xx_path + bof_keyword_find_else_xx_path + ci_keyword_miss_webgetvar_xx_path + bof_keyword_miss_webgetvar_strcpy_xx_path + bof_keyword_miss_webgetvar_else_xx_path + ci_keyword_miss_else_xx_path + bof_keyword_miss_else_strcpy_xx_path + bof_keyword_miss_else_else_xx_path
    for path in sorted_potential_path:
        checking_time = int(path["checking_time"])
        if checking_time == 0:
            sorted_potential_verify.append(path)
        else:
            sorted_potential_maybe.append(path)
    return sorted_potential_verify, sorted_potential_maybe