import tool.Config.config as config_sgtaint
from angr.project import Project
from angr.analyses.cfg.cfg_fast import CFGFast
from angr.knowledge_plugins.key_definitions.tag import LocalVariableTag, ReturnValueTag
from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation


# 对DDG进行逆向回溯
class DefinitionExplorer():
    def __init__(self, project: Project, rd_ddg_graph, cfg: CFGFast):
        self.project = project
        self.rd_ddg_graph = rd_ddg_graph
        self.cfg = cfg
        
    def set_RDA_handler(self, RDA_handler):
        self.RDA_handler = RDA_handler
    
    def set_current_function(self, cur_fun):
        self.cur_fun = cur_fun

    def get_current_function(self):
        return self.cur_fun
        
    def set_d0(self, d0):
        self.d0 = d0
        
    def set_d0_token(self, d0_token):
        self.d0_token = d0_token
        
    def set_d1(self,d1):
        self.d1 = d1
        
    def set_transitive_funtion_name(self, function_name):
        self.transitive_funtion_name = function_name

    def set_current_state(self, state):
        self.current_state = state
        
    def get_current_state(self):
        return self.current_state
    
    def set_current_codeloc(self, codeloc):
        self.current_codeloc=codeloc
        
    def get_current_codeloc(self):
        return self.current_codeloc
    
    def resolve_use_def(self, reg_def):
        reg_seen_defs = set()
        defs_to_check = [(reg_def, [], [])]
        seen_defs = set()
        paths = []
        visited_functions = []
        while defs_to_check:
            current_def, current_path, current_fun = defs_to_check.pop()
            seen_defs.add(current_def)
            current_path = current_path + [current_def]
            extrated_tags = current_def.tags.copy()
            visited_fun = []
            if len(extrated_tags) > 0:
                while True:
                    curr_tag = extrated_tags.pop()
                    if ((isinstance(curr_tag, LocalVariableTag) or
                        isinstance(curr_tag, ReturnValueTag)) and
                        hasattr(curr_tag, "function") and
                        "block_addr" in curr_tag.metadata):
                        length = -1
                        if "length" in curr_tag.metadata:
                            length = curr_tag.metadata["length"]
                        visited_fun.append((
                            curr_tag.metadata["tagged_by"].split()[0],
                            curr_tag.metadata["block_addr"],
                            length
                        ))
                    if len(extrated_tags) == 0:
                        break
            current_fun = current_fun + visited_fun
            def_value = self.check_definition_tag(current_def, reg_def)
            if def_value:
                reg_seen_defs.add(def_value)
                paths.append(current_path)
                visited_functions.append(current_fun)
            else:
                if current_def in self.rd_ddg_graph.graph.nodes():
                    for pred in self.rd_ddg_graph.graph.predecessors(current_def):
                        if pred not in seen_defs:
                            defs_to_check.append((pred, current_path, current_fun))
        return reg_seen_defs, paths, visited_functions
    
    def get_strings(self, d0):
        b0 = "not_static_string"
        pcd0 = [d for d in self.rd_ddg_graph.predecessors(d0)]
        memory_def_flag = False
        for df in pcd0:
            if isinstance(df.atom, MemoryLocation) and df.atom.addr in self.cfg.memory_data:
                memory_def_flag = True
        if not memory_def_flag:
            extended_defs = []
            for df in pcd0:
                extended_defs.extend(self.rd_ddg_graph.predecessors(df))
            pcd0 = extended_defs
        string_list = []
        for df in pcd0:
            if (isinstance(df.atom, MemoryLocation) and
                    df.atom.addr in self.cfg.memory_data and
                    self.cfg.memory_data[df.atom.addr].content is not None):
                bb0 = self.cfg.memory_data[df.atom.addr]
                if bb0.content is not None:
                    i = 0
                    # Find end of string in memory
                    while str(self.cfg.project.loader.memory.load(bb0.addr, bb0.size + i))[bb0.size + i + 1] != '\\':
                        i += 1
                    b0 = str(
                        self.cfg.project.loader.memory.load(bb0.addr, bb0.size + i - 1)
                    )[2:-1]
                    string_list.append(b0)
        if len(string_list) > 1:
            b0 = "#".join(string_list)
        return b0
    
    # Checking the tag over a definition.
    def check_definition_tag(self, definition, reg_def):
        if len(definition.tags) > 0:
            extrated_tags = definition.tags.copy()
            curr_tag = extrated_tags.pop()
            while extrated_tags:
                if isinstance(curr_tag, ReturnValueTag):
                    break
                curr_tag = extrated_tags.pop()
            if not hasattr(curr_tag, "function") or curr_tag.function is None:
                return None
            if isinstance(curr_tag, ReturnValueTag):
                print("ReturnValueTag")
                source_function = self.cfg.functions.floor_func(definition.codeloc.block_addr)
                if source_function is None and "block_addr" in curr_tag.metadata:
                    source_function = self.cfg.functions.floor_func(curr_tag.metadata["block_addr"])
                if hasattr(self, "transitive_funtion_name"):
                    if self.transitive_funtion_name in config_sgtaint.transitive_set:
                        if hasattr(self, "d0_token"):
                            b0 = self.d0_token
                        elif self.d0.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
                            bb0 = self.cfg.insn_addr_to_memory_data[self.d0.codeloc.ins_addr]
                            i = 0
                            while str(
                                self.cfg.project.loader.memory.load(bb0.addr, bb0.size + i)
                            )[bb0.size + i + 1] != "\\":
                                i += 1
                            b0 = str(
                                self.cfg.project.loader.memory.load(bb0.addr, bb0.size + i - 1)
                            )[2:-1]
                        else:
                            b0 = self.get_strings(self.d0)
                        if "token" in curr_tag.metadata:
                            b1 = curr_tag.metadata["token"]
                            print(b1)
                        elif definition.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
                            bb1 = self.cfg.insn_addr_to_memory_data[definition.codeloc.ins_addr]
                            i = 0
                            while str(
                                self.cfg.project.loader.memory.load(bb1.addr, bb1.size + i)
                            )[bb1.size + i + 1] != "\\":
                                i += 1
                            b1 = str(
                                self.cfg.project.loader.memory.load(bb1.addr, bb1.size + i - 1)
                            )[2:-1]
                        else:
                            b1 = self.get_strings(definition)
                        if b1 == "not_static_string" and b0 == "not_static_string":
                            return None
                        taint_source_name = curr_tag.metadata["tagged_by"].split()[0]
                        if taint_source_name.strip() in [
                            "strtok",
                            "strchr",
                            "atoi",
                            "strspn",
                            "strtol",
                            "fork",
                            "rand",
                            "malloc",
                        ]:
                            return None

                        if (
                            taint_source_name.strip() not in config_sgtaint.SOURCES
                            and taint_source_name.strip() not in config_sgtaint.New_input_getters
                        ):
                            return None
                        print(f"b1={b1} and b0={b0}")
                        if definition.codeloc.ins_addr is None and "ins_addr" in curr_tag.metadata:
                            return (
                                "get2set",
                                curr_tag.function,
                                taint_source_name,
                                curr_tag.metadata["ins_addr"],
                                reg_def.codeloc.ins_addr,
                                source_function.name,
                                b1,
                                b0,
                            )
                        return (
                            "get2set",
                            curr_tag.function,
                            taint_source_name,
                            definition.codeloc.ins_addr,
                            reg_def.codeloc.ins_addr,
                            source_function.name,
                            b1,
                            b0,
                        )
                try:
                    func = self.cfg.functions.get_by_addr(curr_tag.function)
                except Exception as e:
                    print(e)
                    return None
                if "token" in curr_tag.metadata:
                    b1 = curr_tag.metadata["token"]
                elif definition.codeloc.ins_addr in self.cfg.insn_addr_to_memory_data:
                    bb1 = self.cfg.insn_addr_to_memory_data[definition.codeloc.ins_addr]
                    i = 0
                    while str(
                        self.cfg.project.loader.memory.load(bb1.addr, bb1.size + i)
                    )[bb1.size + i + 1] != "\\":
                        i += 1
                    b1 = str(
                        self.cfg.project.loader.memory.load(bb1.addr, bb1.size + i - 1)
                    )[2:-1]
                else:
                    b1 = self.get_strings(definition)
                if func.name in [
                    "strtok",
                    "strchr",
                    "atoi",
                    "strspn",
                    "strtol",
                    "fork",
                    "rand",
                    "malloc",
                ]:
                    return None
                if func.name not in config_sgtaint.SOURCES and func.name not in config_sgtaint.New_input_getters:
                    return None
                if definition.codeloc.ins_addr is None:
                    other_ins_addr = 0
                    if "ins_addr" in curr_tag.metadata:
                        other_ins_addr = curr_tag.metadata["ins_addr"]
                    elif "block_addr" in curr_tag.metadata:
                        other_ins_addr = curr_tag.metadata["block_addr"]
                    return (
                        "retval",
                        curr_tag.function,
                        func.name,
                        other_ins_addr,
                        self.current_state.current_codeloc.ins_addr,
                        source_function.name,
                        b1,
                    )
                return (
                    "retval",
                    curr_tag.function,
                    func.name,
                    definition.codeloc.ins_addr,
                    self.current_state.current_codeloc.ins_addr,
                    source_function.name,
                    b1,
                )
            else:
                return None