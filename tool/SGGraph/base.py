# -*- coding: utf-8 -*-
import os
import time
import datetime
import logging
import json
import filecmp
from typing import Any, Callable, Iterable
import angr
import angr.analyses.reaching_definitions.dep_graph as dep_graph
import tool.Config.config as config_sgtaint
from tool.BugFinder.utils import get_functions_to_analyse, run_function_with_timeout, parse_result_file_auto, transfer_path_to_ghidra, get_function_decompile_list_by_path
from tool.SGGraph.utils import execute, get_call_site_func_name
from tool.BugFinder.MyHandler import MyHandler

logger = logging.getLogger("sgtaint.sggraph")

# 需要分析的二进制文件类
class AnalysisBinary():
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.project: angr.Project = None
        self.cfg: angr.analyses.CFG = None
        # 加载或创建Angr对象以及CFG对象（RDA分析时，不可直接从pickle对象中获取相应的对象）
        try:
            logger.info(f"Initializing angr Project/CFG for '{self.binary_path}'...")
            start_time = time.time()
            self.project = angr.Project(self.binary_path, auto_load_libs=False,  use_sim_procedures=True, default_analysis_mode='symbolic', load_options={'auto_load_libs': False})
            self.project.analyses.CompleteCallingConventions(recover_variables=True, analyze_callsites=True) # 针对RDA分析是必要的
            self.cfg = self.project.analyses.CFG(resolve_indirect_jumps=True, cross_references=True,
                                    force_complete_scan=False,
                                    normalize=True, symbols=True, data_references=True)
            elapsed = time.time() - start_time
            logger.info(f"Successfully initialized angr Project/CFG for '{self.binary_path}' in {elapsed:.2f}s")
        except Exception as e:
            logger.error(f"Failed to initialize angr Project/CFG for '{self.binary_path}': {e}")
            raise RuntimeError(f"Failed to initialize ANG R project/CFG for '{self.binary_path}': {e}") from e
        # 可以直接从tmp中的BinaryKeyword中的json文件中获取
        self.binary_function_keyword = set() # 存储边界二进制文件中的关键字
        # 用于加快SG图构建的速度
        self.set_get_call_sites_dict = {} # 字典的键为对应的set函数
        self.relate_file_path = set() # 其中存储存在数据依赖关系的文件
        self.is_board_binary = False
        self.is_set_role = False # 需要进行对应的更新
        self.construct_intra_graph_tag = False # 是否需要单独构建文件内的SG图
        self.diffusion_file = set() # 存储向外扩散的文件
        # 将SG函数信息识别过程与相关的反编译函数结合在一起
        self.set_get_code_snippet = {} # 字典的键为set或get函数，用于辅助ghidra生成parse
        self.ghidra_func_identify_failed = {} # 存储ghidra无法识别的函数，字典的键值为set或get函数
        self.ghidra_project = False # 存储ghidra的项目对象
        # 创建对应的handle程序
        self.get_set_function_info = [] # 需要存储对应二进制文件的set-get函数的信息
        # 存储二进制文件的敏感路径信息
        self.source2sink_path = [] # 对应的文件为result.txt
        self.get2set_path = [] # 对应的文件为get2set.txt
        self.visited_function_list = []
        self.angr_dec_cache = {} # angr的反编译工具缓存
    
    # 保存全局属性
    def save_config(self):
        config = {
            "binary_path": self.binary_path,
            "binary_function_keyword": list(self.binary_function_keyword),
            "set_get_call_sites_dict": self.set_get_call_sites_dict,
            "relate_file_path": list(self.relate_file_path),
            "is_board_binary": self.is_board_binary,
            "is_set_role": self.is_set_role,
            "construct_intra_graph_tag": self.construct_intra_graph_tag,
            "diffusion_file": list(self.diffusion_file),
            "set_get_code_snippet": self.set_get_code_snippet,
            "ghidra_func_identify_failed": self.ghidra_func_identify_failed,
            "ghidra_project": self.ghidra_project,
            "get_set_function_info": self.get_set_function_info,
            "source2sink_path": self.source2sink_path,
            "get2set_path": self.get2set_path,
            "visited_function_list": self.visited_function_list,
        }
        file_process = self.binary_path.replace("/", "_")  # 替换路径中的斜杠
        file_path = os.path.join(config_sgtaint.BINARY_CONFIG_DIR, f"{file_process}_analysis_binary_config.json")
        try:
            with open(file_path, 'w', encoding='utf-8') as file:
                json.dump(config, file, indent=4)
            logger.info(f"Saved AnalysisBinary config to {file_path}")
        except Exception as e:
            logger.error(f"Failed to save AnalysisBinary config to {file_path}: {e}")
            raise
            
    # 从配置文件中加载全局属性
    def load_config(self):
        file_process = self.binary_path.replace("/", "_")  # 替换路径中的斜杠
        file_path = os.path.join(config_sgtaint.BINARY_CONFIG_DIR, f"{file_process}_analysis_binary_config.json")
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                config = json.load(file)
            self.binary_function_keyword = set(config["binary_function_keyword"])
            self.set_get_call_sites_dict = config["set_get_call_sites_dict"]
            self.relate_file_path = set(config["relate_file_path"])
            self.is_board_binary = config["is_board_binary"]
            self.is_set_role = config["is_set_role"]
            self.construct_intra_graph_tag = config["construct_intra_graph_tag"]
            self.diffusion_file = set(config["diffusion_file"])
            self.set_get_code_snippet = config["set_get_code_snippet"]
            self.ghidra_func_identify_failed = config["ghidra_func_identify_failed"]
            self.ghidra_project = config["ghidra_project"]
            self.get_set_function_info = config["get_set_function_info"]
            self.source2sink_path = config["source2sink_path"]
            self.get2set_path = config["get2set_path"]
            self.visited_function_list = config["visited_function_list"]
            logger.info(f"Loaded AnalysisBinary config from {file_path}")
        except Exception as e:
            logger.error(f"Failed to load AnalysisBinary config from {file_path}: {e}")
            raise
    
    # 将AnalysisBinary对象的信息写入到文件之中（调试使用）
    def write_to_file(self):
        file_process = self.binary_path.replace("/", "_")  # 替换路径中的斜杠
        file_path = os.path.join(config_sgtaint.BINARY_INFO_DIR, f"{file_process}_analysis_binary_info.txt")
        def write_section(title: str, data: Any, *, empty_msg: str, formatter: Callable[[Any], Iterable[str]]):
            file.write(f"{title}\n")
            if not data:
                file.write(empty_msg + "\n\n")
                return
            for idx, item in enumerate(data, start=1):
                for line in formatter(item, idx):
                    file.write(line + "\n")
            file.write("\n")
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(f"Binary Path: {self.binary_path}\n\n")
            # Binary Function Keywords
            write_section(
                title="========== Binary Function Keywords ==========",
                data=sorted(self.binary_function_keyword),
                empty_msg="No keywords found.",
                formatter=lambda kw, i: [f"[{i}] {kw}"]
            )
            # Set-Get Call Sites Dict
            write_section(
                title="========== Set-Get Call Sites ==========",
                data=self.set_get_call_sites_dict.items(),
                empty_msg="No set-get call sites found.",
                formatter=lambda pair, _: [
                    f"{pair[0]}:"  # func_name
                ] + [
                    f"  [{i}] Call Site Address: {addr:#x}, Caller: {caller:#x}, "
                    f"Block Address: {block:#x}, Key: {key}"
                    for i, (addr, caller, block, key) in enumerate(pair[1], start=1)
                ]
            )
            # Related File Paths
            write_section(
                title="========== Related File Paths ==========",
                data=list(self.relate_file_path),
                empty_msg="No related file paths found.",
                formatter=lambda path, i: [f"[{i}] {path}"]
            )
            # Diffusion File Paths
            write_section(
                title="========== Diffusion File Paths ==========",
                data=list(self.diffusion_file),
                empty_msg="No diffusion file paths found.",
                formatter=lambda path, i: [f"[{i}] {path}"]
            )
            # Set-Get Function Info
            write_section(
                title="========== Set-Get Function Info ==========",
                data=self.get_set_function_info,
                empty_msg="No set-get function info found.",
                formatter=lambda tpl, i: [
                    "[{i}] Set: {s}, Get: {g}, KeySet: {ks}, KeyGet: {kg}, "
                    "ValSet: {vs}, ValGet: {vg}".format(
                        i=i,
                        s=tpl[0], g=tpl[1],
                        ks=tpl[2], kg=tpl[3],
                        vs=tpl[4], vg=tpl[5],
                    )
                ]
            )
            # 通用的“Path Dict List”（Source2Sink、Get2Set、Complete ...）
            def path_dict_formatter(rec: dict, i: int) -> Iterable[str]:
                yield f"*** Path #{i} ***"
                for key, val in rec.items():
                    yield f"{key:20}: {val}"
            for section_title, data_list in [
                ("========== Source2Sink Paths ==========",           self.source2sink_path),
                ("========== Get2Set Paths ==========",               self.get2set_path),
            ]:
                write_section(
                    title=section_title,
                    data=data_list,
                    empty_msg=f"No {section_title.split()[-2].lower()} paths found.",
                    formatter=path_dict_formatter
                )   
            write_section(
                title="========== SOURCE ==========",
                data=config_sgtaint.SOURCES,
                empty_msg="No SOURCE items found.",
                formatter=lambda item, i: [f"[{i}] {item}"]
            )
            write_section(
                title="========== TRANSITIVE SET ==========",
                data=config_sgtaint.transitive_set,
                empty_msg="No transitive_set items found.",
                formatter=lambda item, i: [f"[{i}] {item}"]
            )

    def create_binary_file(self):
        # 获取以二进制文件名命名的子目录路径
        binary_dir = os.path.join(config_sgtaint.VULN_OUT_DIR, os.path.basename(self.binary_path))
        # 检查并自动递增文件夹名直到不存在
        orig_binary_dir = binary_dir
        index = 1
        while os.path.exists(binary_dir):
            binary_dir = f"{orig_binary_dir}_{index}"
            index += 1
        try:
            # 如果子目录不存在则创建
            os.makedirs(binary_dir, exist_ok=True)
            # 生成各类输出文件的完整路径
            visited_file_name = os.path.join(binary_dir, 'visited.txt')
            result_file_name = os.path.join(binary_dir, 'result.txt')
            get2set_file_name = os.path.join(binary_dir, 'get2set.txt')
            error_file_name = os.path.join(binary_dir, 'error.txt')
            # 以追加模式打开文件用于写入
            self.visited_file = open(visited_file_name, 'a+')
            self.result_file = open(result_file_name, 'a+')
            self.get2set_file = open(get2set_file_name, 'a+')
            self.error_file = open(error_file_name, 'a+')
            logger.info(f"Created/Opened result files for binary at {binary_dir}")
        except Exception as e:
            logger.error(f"Failed to create/open result files for binary '{self.binary_path}': {e}")
            raise
        
    # 创建二进制的定制handle
    def create_binary_handle(self):
        self.handler = MyHandler()
        self.handler.set_cfg(self.cfg)
        self.handler.set_result_file(self.result_file)
        self.handler.set_get2set_file(self.get2set_file)
        self.handler.set_visited_file(self.visited_file)
        self.handler.set_call_graph(self.cfg.functions.callgraph)
        self.handler.set_call_sites_dict(self.set_get_call_sites_dict.copy()) # 不改变原始结构
        self.handler.set_source2sink_path(self.source2sink_path) # 改变原始结构
        self.handler.set_get2set_path(self.get2set_path)
        # 动态设置对应的方法
        for set_func_name, get_func_name, index_key_set, index_key_get, index_value_set, index_value_get in self.get_set_function_info:
            # 针对进程池中内容
            if set_func_name not in config_sgtaint.transitive_set:
                config_sgtaint.transitive_set.append(set_func_name)
            if get_func_name not in config_sgtaint.SOURCES:
                config_sgtaint.SOURCES.append(get_func_name)
            if get_func_name not in config_sgtaint.transitive_get:
                config_sgtaint.transitive_get.append(get_func_name)
            if (set_func_name, get_func_name) not in config_sgtaint.SET_GET_INFO: # 更新初始的列表名称
                config_sgtaint.SET_GET_INFO[(set_func_name, get_func_name)] = [set_func_name, get_func_name, index_key_set, index_key_get, index_value_set, index_value_get]
            self.handler.setter_handle_dynamic(set_func_name, index_key_set, index_value_set)
            self.handler.getter_handle_dynamic(get_func_name, index_key_get, index_value_get)
        logger.info(f"Created and configured handler for binary '{self.binary_path}'")
            
    # 进行对应的RDA分析
    def rda_analyze(self):
        start_time = datetime.datetime.now()
        logger.info(f"Starting RDA analysis for {self.binary_path}")
        self.create_binary_handle() # 创建定制的handle类
        target_func = config_sgtaint.SOURCES + config_sgtaint.SINKS + config_sgtaint.transitive_set # 确定分析函数的范围
        function_callers_map = get_functions_to_analyse(target_func, self.project, self.cfg)
        visited_function_counter = 0
        for caller_str_addr, call_sites in function_callers_map.items():
            visited_function_counter += 1
            caller_str_addr = int(caller_str_addr)
            caller_func = self.cfg.functions.get_by_addr(caller_str_addr)
            print("***********************************")
            logger.info(f"Analyzing predecessor function {caller_func.name} at {hex(caller_str_addr)} | XRefs: {call_sites}")
            if caller_func.name in self.visited_function_list:
                continue
            self.visited_function_list.append(caller_func.name)
            self.handler.set_current_function(caller_func)
            progress_str = f"[{visited_function_counter}/{len(function_callers_map)}] {caller_func.name}"
            self.visited_file.write("\n" + progress_str)
            self.visited_file.flush()
            config_sgtaint.STACK.clear()
            self.handler.set_start_function(caller_func)
            try:
                result = run_function_with_timeout(self.rda_analyze_core, args=(caller_func,), timeout=config_sgtaint.FUNC_TIMEOUT) # 设置超时时间为1000s
            except TimeoutError:
                logger.error(f"Function call for {caller_func.name} timed out")
                self.error_file.write(f'target_addr: {hex(caller_func.addr)}, target_name: {caller_func.name}, timed out\n')
                self.error_file.flush()
                continue
            except Exception as e:
                logger.exception(f"Error analyzing function {caller_func.name} (addr={hex(caller_func.addr)}): {e}")
                self.error_file.write(f'target_addr: {hex(caller_func.addr)}, target_name: {caller_func.name}, errorMessage: {e} \n')
                self.error_file.flush()
                continue
        # 额外处理New_input_getters
        if visited_function_counter == len(function_callers_map):
            logger.info(f"New_input_getters functions: {', '.join(config_sgtaint.New_input_getters)}")
            self.visited_file.write("\n" + f"New_input_getters functions: {', '.join(config_sgtaint.New_input_getters)}")
            self.visited_file.flush()
            function_callers_map = get_functions_to_analyse(config_sgtaint.New_input_getters, self.project, self.cfg)
            new_index = 0
            for caller_str_addr, call_sites in function_callers_map.items():
                new_index += 1
                caller_str_addr = int(caller_str_addr)
                caller_func = self.cfg.functions.get_by_addr(caller_str_addr)
                print("***********************************")
                logger.info(f"Analyzing new input getter function {caller_func.name} at {hex(caller_str_addr)} | XRefs: {call_sites}")
                if caller_func.name in self.visited_function_list:
                    continue
                self.visited_function_list.append(caller_func.name)
                self.handler.set_current_function(caller_func)
                progress_str = f"[{new_index}/{len(function_callers_map)}] {caller_func.name}"
                self.visited_file.write("\n" + progress_str)
                self.visited_file.flush()
                config_sgtaint.STACK.clear()
                self.handler.set_start_function(caller_func)
                try:
                    result = run_function_with_timeout(self.rda_analyze_core, args=(caller_func,), timeout=config_sgtaint.FUNC_TIMEOUT) # 设置超时时间为1000s
                except TimeoutError:
                    logger.error(f"Function call for {caller_func.name} timed out")
                    self.error_file.write(f'target_addr: {hex(caller_func.addr)}, target_name: {caller_func.name}, timed out\n')
                    self.error_file.flush()
                    continue
                except Exception as e:
                    logger.exception(f"Error analyzing function {caller_func.name} (addr={hex(caller_func.addr)}): {e}")
                    self.error_file.write(f'target_addr: {hex(caller_func.addr)}, target_name: {caller_func.name}, errorMessage: {e} \n')
                    self.error_file.flush()
                    continue
        self.visited_file.write("\n Done"+" \n")
        # 解析结果文件到path路径之中
        self.source2sink_path = parse_result_file_auto(self.result_file.name)[:]
        self.get2set_path = parse_result_file_auto(self.get2set_file.name)[:]
        if config_sgtaint.GHIDRA_ASSIST:
            self.get_decompile_code_by_ghidra() # 通过ghidra获取反编译片段
        else:
            self.get_decompile_code_by_angr()
        self.save_path2json()
        end_time = datetime.datetime.now()
        elapsed = (end_time - start_time).seconds
        self.visited_file.write(f"Total time: {elapsed}s \n")
        self.visited_file.flush()
        logger.info(f"Finished RDA analysis for {self.binary_path} in {elapsed}s")
            
    # 启动rda分析
    def rda_analyze_core(self, caller_func):
        start_time = datetime.datetime.now()
        logger.info(f"Starting RDA core analysis for function {caller_func.name} at {hex(caller_func.addr)}")
        try:
            dec = self.project.analyses.Decompiler(caller_func, cfg=self.cfg)
            clinic = dec.clinic
            self.handler.set_clinic(clinic)
            self.handler.set_dec(dec)
        except Exception as e:
            self.handler.set_clinic(None)
            self.handler.set_dec(None)
            logger.warning(f"Decompiler failed for function {caller_func.name}: {e}")
        # 启动rda分析
        rd = self.project.analyses.ReachingDefinitions(
            subject = caller_func,
            func_graph = caller_func.graph,
            cc = caller_func.calling_convention,
            dep_graph = dep_graph.DepGraph(),
            function_handler = self.handler,
            observe_all = True
        )
        end_time = datetime.datetime.now()
        elapsed = (end_time - start_time).seconds
        logger.info(f"RDA core analysis for {caller_func.name} finished in {elapsed}s")
        self.handler.get_visited_file().write(f", {elapsed}s")
        self.handler.get_visited_file().flush()
        
    # 通过Angr获取反编译片段
    def get_decompile_code_by_angr(self):
        start_time = datetime.datetime.now()
        # 处理source2sink片段
        for idx, source2sink_single_path in enumerate(self.source2sink_path, start=1):
            function_angr_format = transfer_path_to_ghidra(source2sink_single_path["path"], self.project, self.cfg)
            try:
                for i, function_format in enumerate(function_angr_format):
                    if function_format[0] in self.angr_dec_cache:
                        dec = self.angr_dec_cache[function_format[0]]
                        dec_source = "cache"
                    else: # 缓存中不存在
                        dec = self.project.analyses.Decompiler(self.project.kb.functions.get(function_format[0]), cfg=self.cfg)
                        self.angr_dec_cache[function_format[0]] = dec
                        dec_source = "create"
                    function_angr_format[i] = [dec] + function_format
            except Exception as e:
                logger.error(f"[{idx}/{len(self.source2sink_path)}] Decompiler generation failed: {e}!")
                source2sink_single_path["decompile_list"] = ["Fail to Decompile by Angr"]
                continue
            taint_source = source2sink_single_path["taint_source"]
            taint_sink = source2sink_single_path["taint_sink"]
            try:
                source2sink_single_path["decompile_list"] = get_function_decompile_list_by_path(self.project, self.cfg, function_angr_format, taint_source, taint_sink)
            except Exception as e:
                logger.error(f"[{idx}/{len(self.source2sink_path)}] Decompiler generation failed: {e}!")
                source2sink_single_path["decompile_list"] = ["Fail to Decompile by Angr"]
                continue
            logger.info(f"[{idx}/{len(self.source2sink_path)}] Analysis Finished for source2sink path in {self.binary_path} from {dec_source}!")
        # 处理get2set片段
        for idx, get2set_single_path in enumerate(self.get2set_path, start=1):
            function_angr_format = transfer_path_to_ghidra(get2set_single_path["path"], self.project, self.cfg)
            try:
                for i, function_format in enumerate(function_angr_format):
                    if function_format[0] in self.angr_dec_cache:
                        dec = self.angr_dec_cache[function_format[0]]
                        dec_source = "cache"
                    else: # 缓存中不存在
                        dec = self.project.analyses.Decompiler(self.project.kb.functions.get(function_format[0]), cfg=self.cfg)
                        self.angr_dec_cache[function_format[0]] = dec
                        dec_source = "create"
                    function_angr_format[i] = [dec] + function_format
            except Exception as e:
                logger.error(f"[{idx}/{len(self.get2set_path)}] Decompiler generation failed: {e}!")
                get2set_single_path["decompile_list"] = ["Fail to Decompile by Angr"]
                continue
            taint_source = get2set_single_path["taint_source"]
            taint_sink = get2set_single_path["taint_sink"]
            try:
                get2set_single_path["decompile_list"] = get_function_decompile_list_by_path(self.project, self.cfg, function_angr_format, taint_source, taint_sink)
            except Exception as e:
                logger.error(f"[{idx}/{len(self.get2set_path)}] Decompiler generation failed: {e}!")
                get2set_single_path["decompile_list"] = ["Fail to Decompile by Angr"]
                continue
            logger.info(f"[{idx}/{len(self.get2set_path)}] Analysis Finished for get2set path in {self.binary_path} from {dec_source}!")
        end_time = datetime.datetime.now()
        elapsed = (end_time - start_time).seconds
        logger.info(f"Decompile by angr for {self.binary_path} finished in {elapsed}s")
        
    # 通过Ghidra获取反编译片段
    def get_decompile_code_by_ghidra(self):
        source2sink_ghidra_list = []
        get2set_ghidra_list = []
        for source2sink_single_path in self.source2sink_path:
            source2sink_single_path["ghidra_path"] = transfer_path_to_ghidra(source2sink_single_path["path"], self.project, self.cfg)
            source2sink_single_path["taint_source_addr"] = self.cfg.kb.functions.function(name=source2sink_single_path["taint_source"]).addr
            source2sink_single_path["taint_sink_addr"] = self.cfg.kb.functions.function(name=source2sink_single_path["taint_sink"]).addr
            source2sink_ghidra_list.append(source2sink_single_path)
        for get2set_single_path in self.get2set_path:
            get2set_single_path["ghidra_path"] = transfer_path_to_ghidra(get2set_single_path["path"], self.project, self.cfg)
            get2set_single_path["taint_source_addr"] = self.cfg.kb.functions.function(name=get2set_single_path["taint_source"]).addr
            get2set_single_path["taint_sink_addr"] = self.cfg.kb.functions.function(name=get2set_single_path["taint_sink"]).addr
            get2set_ghidra_list.append(get2set_single_path)
        # 生成对应的json文件传递给Ghidra程序
        file_path_process = self.binary_path.replace("/", "_")
        source2sink_file_name = f"{file_path_process}_source2sink_path.json"
        source2sink_file_path = os.path.join(config_sgtaint.BINARY_TMP, source2sink_file_name)
        with open(source2sink_file_path, "w") as file:
            json.dump(source2sink_ghidra_list, file, indent=4)
        get2set_file_name = f"{file_path_process}_get2set_path.json"
        get2set_file_path = os.path.join(config_sgtaint.BINARY_TMP, get2set_file_name)
        with open(get2set_file_path, "w") as file:
            json.dump(get2set_ghidra_list, file, indent=4)
        # 执行Ghidra辅助程序
        try:
            angr_base_addr = hex(self.get_angr_base_addr())
            binary_mark = os.path.basename(self.binary_path)
            self.load_ghidra() # 加载ghidra程序
            ghidra_python_path = config_sgtaint.DECOMPILE_ASSIST_PATH
            ghidra_command = f'{config_sgtaint.ANALYZEHEADLESS} {config_sgtaint.GHIDRA_DIR} {binary_mark} -process {binary_mark} -noanalysis -postScript {ghidra_python_path} "{angr_base_addr}"'
            execute(ghidra_command)
            logger.info(f"Executed Ghidra command for decompilation: {ghidra_command}")
        except Exception as e:
            logger.error(f"Failed to execute Ghidra decompilation: {e}")
            self.get_decompile_code_by_angr() # 使用回退机制
            return
        try:
            # 读取source2sink的结果文件
            source2sink_result_file_name = f"{file_path_process}_source2sink_path_result.json"
            source2sink_result_file_path = os.path.join(config_sgtaint.BINARY_TMP, source2sink_result_file_name)
            with open(source2sink_result_file_path, "r") as file:
                source2sink_ghidra_list_result = json.load(file)
            self.source2sink_path = source2sink_ghidra_list_result[:] # 获取反编译函数列表
            # 删除中间文件
            command = f"rm {source2sink_result_file_path}"
            execute(command)
            # 读取get2set的结果文件
            get2set_result_file_name = f"{file_path_process}_get2set_path_result.json"
            get2set_result_file_path = os.path.join(config_sgtaint.BINARY_TMP, get2set_result_file_name)
            with open(get2set_result_file_path, "r") as file:
                get2set_ghidra_list_result = json.load(file)
            self.get2set_path = get2set_ghidra_list_result[:] # 获取反编译函数列表
            # 删除中间文件
            command = f"rm {get2set_result_file_path}"
            execute(command)
        except Exception as e:
            logger.error(f"Failed to read Ghidra decompilation result files: {e}")
            self.get_decompile_code_by_angr() # 使用回退机制
            return
        # 补充Ghidra不可反编译的片段
        for source2sink_single_path in self.source2sink_path:
            if "Fail to Decompile by Ghidra" in source2sink_single_path["decompile_list"]: # 表示Ghidra反编译失败
                function_angr_format = [sublist[:] for sublist in source2sink_single_path["ghidra_path"]]
                try:
                    for i, function_format in enumerate(function_angr_format):
                        if function_format[0] in self.angr_dec_cache:
                            dec = self.angr_dec_cache[function_format[0]]
                        else: # 缓存中不存在
                            dec = self.project.analyses.Decompiler(self.project.kb.functions.get(function_format[0]), cfg=self.cfg)
                            self.angr_dec_cache[function_format[0]] = dec
                        function_angr_format[i] = [dec] + function_format
                except Exception as e:
                    logger.error(f"Decompiler generation failed: {e}!")
                    source2sink_single_path["decompile_list"] = ["Fail to Decompile by Angr and Ghidra"]
                    continue
                taint_source = source2sink_single_path["taint_source"]
                taint_sink = source2sink_single_path["taint_sink"]
                try:
                    source2sink_single_path["decompile_list"] = get_function_decompile_list_by_path(self.project, self.cfg, function_angr_format, taint_source, taint_sink)
                except Exception as e:
                    logger.error(f"Decompiler generation failed: {e}!")
                    source2sink_single_path["decompile_list"] = ["Fail to Decompile by Angr and Ghidra"]
                    continue
        for get2set_single_path in self.get2set_path:
            if "Fail to Decompile by Ghidra" in get2set_single_path["decompile_list"]: # 表示Ghidra反编译失败
                function_angr_format = [sublist[:] for sublist in get2set_single_path["ghidra_path"]]
                try:
                    for i, function_format in enumerate(function_angr_format):
                        if function_format[0] in self.angr_dec_cache:
                            dec = self.angr_dec_cache[function_format[0]]
                        else: # 缓存中不存在
                            dec = self.project.analyses.Decompiler(self.project.kb.functions.get(function_format[0]), cfg=self.cfg)
                            self.angr_dec_cache[function_format[0]] = dec
                        function_angr_format[i] = [dec] + function_format
                except Exception as e:
                    logger.error(f"Decompiler generation failed: {e}!")
                    get2set_single_path["decompile_list"] = ["Fail to Decompile by Angr and Ghidra"]
                    continue
                taint_source = get2set_single_path["taint_source"]
                taint_sink = get2set_single_path["taint_sink"]
                try:
                    get2set_single_path["decompile_list"] = get_function_decompile_list_by_path(self.project, self.cfg, function_angr_format, taint_source, taint_sink)
                except Exception as e:
                    logger.error(f"Decompiler generation failed: {e}!")
                    get2set_single_path["decompile_list"] = ["Fail to Decompile by Angr and Ghidra"]
                    continue
        
    # 将二进制文件加载到Ghidra中
    def load_ghidra(self):
        if not self.ghidra_project:
            file_mark = os.path.basename(self.binary_path)
            ghidra_python_path = config_sgtaint.AGGRESSIVE_GHIDRA_PATH
            ghidra_command = f"{config_sgtaint.ANALYZEHEADLESS} {config_sgtaint.GHIDRA_DIR} {file_mark} -import {self.binary_path} -preScript {ghidra_python_path}"
            try:
                logger.info(f"Importing {self.binary_path} into Ghidra project with command: {ghidra_command}")
                execute(ghidra_command)
                self.ghidra_project = True
                logger.info(f"Successfully imported {self.binary_path} into Ghidra project.")
            except Exception as e:
                logger.error(f"Failed to import {self.binary_path} into Ghidra project: {e}")
                self.ghidra_project = False
        else:
            logger.info(f"Ghidra project already exists for {self.binary_path}, skipping import.")
            
    # 将路径信息存储在json文件之中
    def save_path2json(self):
        file_process = f'{os.path.basename(self.binary_path)}{os.path.dirname(self.binary_path).replace("/", "_")}'
        source2sink_json_name = f"{file_process}_source2sink_path.json"
        source2sink_json_path = os.path.join(config_sgtaint.BINARY_TMP, source2sink_json_name)
        with open(source2sink_json_path, "w") as file:
            json.dump(self.source2sink_path, file, indent=4)
        get2set_json_name = f"{file_process}_get2set_path.json"
        get2set_json_path = os.path.join(config_sgtaint.BINARY_TMP, get2set_json_name)
        with open(get2set_json_path, "w") as file:
            json.dump(self.get2set_path, file, indent=4)
    
    # 判断其是否存在对应的函数调用
    def has_call_site(self, func_name):
        if not self.has_func(func_name): # 首先判断函数是否存在
            return False
        # 若函数存在判断是否存在对应的函数调用
        call_sites = get_call_site_func_name(self.project, self.cfg, func_name)
        return call_sites if call_sites else False
    
    # 判断二进制文件是否应该作为set对象
    def should_set_role_binary(self):
        if '.so' in self.get_path() or 'lib' in self.get_path(): # 将库函数全部省略
            return False # 库函数不再向下延展
        return True

    # 获取二进制文件的visited_file
    def get_visited_file(self):
        return self.visited_file
    
    # 获取二进制文件的result_file
    def get_result_file(self):
        return self.result_file
    
    # 获取二进制文件的get2set_file
    def get_get2set_file(self):
        return self.get2set_file
    
    # 获取二进制文件的error_file
    def get_error_file(self):
        return self.get_error_file

    # 判断是否存在函数
    def has_func(self, func_name):
        return True if self.project.kb.functions.get(func_name) else False
    
    # 获取angr加载此二进制文件的基地址
    def get_angr_base_addr(self):
        return self.project.loader.main_object.min_addr
    
    # 设定二进制文件为边界二进制文件
    def set_board_binary(self):
        self.is_board_binary = True
    
    # 添加相关文件
    def add_relate_file(self, file_path):
        self.relate_file_path.add(file_path)
        
    # 判断二进制文件是否已经作为set对象
    def has_set_role_binary(self):
        return self.is_set_role
    
    # 获取二进制文件的Angr对象
    def get_angr_project(self):
        return self.project
    
    # 获取二进制文件的CFG对象
    def get_angr_cfg(self):
        return self.cfg
    
    # 获取二进制文件的path路径
    def get_path(self):
        return self.binary_path


# 需要分析的二进制文件字典类
class AnalysisBinaryDict():
    def __init__(self):
        self.analysis_binary_dict = {} # 将二进制文件组织成字典，键值为二进制文件路径
        self.set_dict = {} # 存储需要当作set的二进制文件对象，其中键为不同的set函数
        self.get_set_func_name = [] # 存储对应的set-get函数的信息
        
    # 添加二进制文件
    def add_analysis_binary(self, analysis_binary: AnalysisBinary):
        if isinstance(analysis_binary, AnalysisBinary):
            self.analysis_binary_dict[analysis_binary.get_path()] = analysis_binary
    
    # 获取二进制文件列表
    def get_analysis_binary_dict(self):
        return self.analysis_binary_dict
    
    # 根据二进制文件地址获取对应的AnalysisBinary对象
    def get_analysis_binary_by_path(self, binary_path):
        if binary_path in self.analysis_binary_dict:
            return self.analysis_binary_dict[binary_path]
        return None
    
    # 更新指定地址的二进制文件内容
    def update_analysis_binary_by_path(self, binary_path, analysis_binary: AnalysisBinary):
        if binary_path in self.analysis_binary_dict:
            self.analysis_binary_dict[binary_path] = analysis_binary
        else:
            # 检查是否存在重复的相同二进制文件
            if not any(filecmp.cmp(binary_path, seen, shallow=False) for seen in self.analysis_binary_dict):
                self.add_analysis_binary(analysis_binary)
            
    # 返回边界二进制文件路径列表
    def get_border_binary_path_list(self):
        binary_path_list = []
        for binary_path in self.analysis_binary_dict:
            if self.analysis_binary_dict[binary_path].is_board_binary:
                binary_path_list.append(binary_path)
        return binary_path_list
    
    
# 创建Set-Get图节点类，其基本单位为Call-Site
class SetGetGraphNode(): # 可以使用(call_site, file_path)进行唯一标识
    def __init__(self, call_site, func_name, caller, file_path, role, key, block_addr):
        self.call_site = call_site
        self.func_name = func_name
        self.caller = caller
        self.file_path = file_path # 可以判断是否为跨文件的信息传递
        self.role = role # 仅仅存在两种role -- set，get
        self.key = key
        self.relate = set() # 其中的元素为二元组（对应的Node标识以及类型：0-文件内，1-文件间）
        self.block_addr = block_addr # 对应的块地址
        
    # 添加节点对应的关系节点
    def add_relate(self, relate_node):
        self.relate.add(relate_node)
        
    # 返回该节点的调用点地址
    def get_call_site(self):
        return self.call_site
    
    # 返回该节点的调用函数名称
    def get_caller_name(self):
        return self.caller
    
    # 返回该节点对应的键值
    def get_key(self):
        return self.key
    
    # 获取对应的函数名称
    def get_func_name(self):
        return self.func_name
    
    # 获取对应的节点集合
    def get_related_node(self):
        return self.relate
    
    # 获取所在文件的路径
    def get_file_path(self):
        return self.file_path
    
    # 获取对应的块地址
    def get_block_addr(self):
        return self.block_addr
    
    # 打印出节点的信息
    def __str__(self):
        return f"SGGNode(call-site= {hex(self.call_site)}, caller= {self.caller}, key= {self.key}, func-name= {self.func_name})"
    
    
# 创建Set-Get图类
class SetGetGraph():
    def __init__(self):
        self.node_dict = {} # 其中键值为(call_site, file_path)
        self.node_dict_path = {} # 存储节点信息的路径，键值为(block_addr, file_path)
        self.extra_relate = set() # 存储跨文件的数据流关系((set_file_path, set_call_site), (get_file_path, get_call_site), key)
        
    # 创建node_dict_path字典
    def create_node_dict_path(self):
        for (call_site, file_path), node in self.node_dict.items():
            key = (node.get_block_addr(), file_path)
            if key not in self.node_dict_path:
                self.node_dict_path[key] = node
        
    # 根据调用地址获取SetGetGraphNode
    def get_node_by_call_site(self, call_site, file_path):
        key = (call_site, file_path)
        if key in self.node_dict:
            return self.node_dict[key]
        else:
            logger.warning(f"No SetGetGraphNode found with call-site '{hex(call_site)}' in {file_path}")
            return None
    
    # 根据调用地址获取指定节点的对应节点信息
    def get_related_node(self, call_site, file_path):
        node: SetGetGraphNode = self.get_node_by_call_site(call_site, file_path)
        return node.get_related_node()
    
    # 输出跨文件数据流关系
    def print_extra_relate(self):
        number = 0
        for relate in self.extra_relate:
            number += 1
            print(f"[{number}] Set file:[{relate[0][0]}--{hex(relate[0][1])}] **** {relate[2]} **** Get file:[{relate[1][0]}--{hex(relate[1][1])}]")
            
    # 打印指定节点的对应节点信息
    def print_related_node(self, call_site, file_path):
        node: SetGetGraphNode = self.get_node_by_call_site(call_site, file_path)
        print(f"Call site: {hex(node.get_call_site())}; Identifier: {node.get_func_name()}; Key: {node.get_key()}; File: {node.get_file_path()}; Block Addr: {hex(node.get_block_addr())}")
        node_related = self.get_related_node(call_site, file_path)
        for call_site_tmp, file_path_tmp, relate_kind in node_related:
            node_tmp: SetGetGraphNode = self.get_node_by_call_site(call_site_tmp, file_path_tmp)
            print(f"  [{relate_kind}] Call site: {hex(node_tmp.get_call_site())}; Identifier: {node_tmp.get_func_name()}; Key: {node_tmp.get_key()}; File: {node_tmp.get_file_path()}; Block Addr: {hex(node_tmp.get_block_addr())}")
            
    # 打印出所有节点的对应节点信息
    def print_all_node_relates(self):
        for call_site, file_path in self.node_dict:
            self.print_related_node(call_site, file_path)
            
    # 将Set-Get图信息写入文件
    def set_get_graph_file(self):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")  # 格式化当前时间
        filename = f"{timestamp}_set_get_graph.txt"
        filepath = os.path.join(config_sgtaint.OUTPUT_DIR, filename)
        with open(filepath, "w", encoding="utf-8") as file:
            for call_site, file_path in self.node_dict:
                node: SetGetGraphNode = self.get_node_by_call_site(call_site, file_path)
                file.writelines(f"Call site: {hex(node.get_call_site())}; Identifier: {node.get_func_name()}; Key: {node.get_key()}; File: {node.get_file_path()}; Block Addr: {hex(node.get_block_addr())}\n")
                node_related = self.get_related_node(call_site, file_path)
                for call_site_tmp, file_path_tmp, relate_kind in node_related:
                    node_tmp: SetGetGraphNode = self.get_node_by_call_site(call_site_tmp, file_path_tmp)
                    file.writelines(f"  [{relate_kind}] Call site: {hex(node_tmp.get_call_site())}; Identifier: {node_tmp.get_func_name()}; Key: {node_tmp.get_key()}; File: {node_tmp.get_file_path()}; Block Addr: {hex(node_tmp.get_block_addr())}\n")