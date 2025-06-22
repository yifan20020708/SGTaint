# -*- coding: utf-8 -*-
import os
import json
import time
from collections import defaultdict
import logging
import tool.Config.config as config_sgtaint
from tool.SGGraph.utils import (
    parameter_parsing_by_index, get_args_string_call_sites,
    get_decompiled_code_by_call_site, get_parameters_by_code, is_const,
    parse_set_get_string, get_extern_func_name, parse_function_call,
    get_prompt_for_phase_two, coarse_grained_binary_filter, execute,
    get_call_site_func_name,
)
from tool.SGGraph.border_binary import get_border_binaries_by_cluster_max_mean_gap
from tool.SGGraph.base import (
    AnalysisBinaryDict, AnalysisBinary, SetGetGraph, SetGetGraphNode
)
from tool.LLM.LLM_chat import LLM
from tool.LLM.prompt_template import (
    SYSTEM_SET_GET, DOUBLE_CHECK,
    SYSTEM_SET_GET_OUTPUT_PHASE_ONE, SYSTEM_SET_GET_OUTPUT_PHASE_TWO,
    get_user_set_get_en_prompt_phase_one, get_user_set_get_en_prompt_phase_two,
    double_check_phase_two,
)

logger = logging.getLogger("sgtaint.sggraph")

# （快速获取）针对指定的函数名称获取直接进行参数赋值的key，同样需要对第二个参数进行过滤
def get_set_func_args_fast(project, cfg, func_name, index_key, index_value = None):
    call_sites = get_call_site_func_name(project, cfg, func_name)
    call_sites_parser = []
    number = 0
    number_vsa = 0
    for call_site_address, caller, block_addr in call_sites:
        # 首先进行第二个参数的过滤
        if index_value and parameter_parsing_by_index(project, block_addr, index_value, value_tag=True):
            continue
        key = parameter_parsing_by_index(project, block_addr, index_key)
        number += 1
        if not key:
            number_vsa += 1
            call_sites_parser.append([call_site_address, caller, block_addr, -1])
        else: # 将不为空字符串的key进行存储
            call_sites_parser.append([call_site_address, caller, block_addr, key])
    success_rate = (number - number_vsa) / number if number != 0 else 0
    return call_sites_parser, success_rate


# （辅助Ghidra获取）使用Ghidra的反编译工具进行对应的关键字提取
def get_keyword_by_decompiled_func_ghidra(project, cfg, func_name, file_path, analysis_binary_dict: AnalysisBinaryDict, index_key, index_value = None):
    call_sites = get_call_site_func_name(project, cfg, func_name)
    # 直接从分析二进制对象的set_get_code_snippet进行获取
    analysis_binary: AnalysisBinary = analysis_binary_dict.get_analysis_binary_by_path(file_path)
    if analysis_binary and func_name in analysis_binary.set_get_code_snippet:
        func_decompile_code_snippet = analysis_binary.set_get_code_snippet[func_name]
        ghidra_func_identify_failed = analysis_binary.ghidra_func_identify_failed[func_name]
    else: # 若不存在调用新的Ghidra脚本进行获取
        # 首先对call_sites进行遍历获取所有的函数地址
        unique_callers = {caller for _, caller, _ in call_sites}
        func_addr_list = [{"caller": hex(caller)} for caller in unique_callers]
        # 保存为json文件传递给Ghidra程序
        caller_file_name = f"{func_name}_caller_addr.json"
        caller_file_path = os.path.join(config_sgtaint.TMP_DIR, caller_file_name)
        with open(caller_file_path, "w") as file:
            json.dump(func_addr_list, file, indent=4)
        # 构造执行Ghidra脚本的命令
        angr_base_addr = hex(project.loader.main_object.min_addr)
        binary_mark = os.path.basename(file_path)
        if not os.path.exists(os.path.join(config_sgtaint.GHIDRA_DIR, f"{binary_mark}.gpr")):
            ghidra_load_command = f"{config_sgtaint.ANALYZEHEADLESS} {config_sgtaint.GHIDRA_DIR} {binary_mark} -import {file_path}"
            execute(ghidra_load_command)
        ghidra_python_path = '/home/SGTaint/tool/Ghidra/ghidra_assist.py'   
        ghidra_command = f'{config_sgtaint.ANALYZEHEADLESS} {config_sgtaint.GHIDRA_DIR} {binary_mark} -process {binary_mark} -postScript {ghidra_python_path} "{angr_base_addr}" "{func_name}"'
        execute(ghidra_command)
        # 读取对应的结果文件
        caller_file_result_name =  f"{func_name}_caller_parse_result.json"
        caller_file_result_path = os.path.join(config_sgtaint.TMP_DIR, caller_file_result_name)
        with open(caller_file_result_path, "r") as file:
            caller_parse_result = json.load(file)
        # 删除对应的中间文件
        rm_command = f"rm {caller_file_result_path}"
        execute(rm_command)
        func_decompile_code_snippet = caller_parse_result[0].get("code_dict")
        ghidra_func_identify_failed = caller_parse_result[0].get("func_fail")
    # 若存在Ghidra不可识别的函数，使用angr进行处理
    if ghidra_func_identify_failed:
        for func_addr in ghidra_func_identify_failed:
            call_site_dict = get_args_string_call_sites(project, cfg, func_addr, func_name)
            if call_site_dict:
                func_decompile_code_snippet.update(call_site_dict)
    if analysis_binary:
        analysis_binary.set_get_code_snippet[func_name] = func_decompile_code_snippet
        analysis_binary.ghidra_func_identify_failed[func_name] = [] # 清空对应的函数
        analysis_binary_dict.update_analysis_binary_by_path(file_path, analysis_binary)
    # 进行函数调用参数的解析
    call_sites_parser = []
    number = 0
    number_vsa = 0
    for call_site_address, caller, block_addr in call_sites:
        decompiled_code = get_decompiled_code_by_call_site(project, call_site_address, block_addr, func_decompile_code_snippet)
        if not decompiled_code: # 若没有解析出对应的反汇编代码
            call_sites_parser.append([call_site_address, caller, block_addr, 0])
            continue
        args_call_site = get_parameters_by_code(decompiled_code[1])
        # 若存储的内容为常量则直接跳过
        if index_value and args_call_site and len(args_call_site) > index_value and is_const(project, args_call_site[index_value], file_path):
            continue
        number += 1
        if args_call_site and len(args_call_site) > index_key:
            # 提取对应的关键字
            parameter = is_const(project, args_call_site[index_key], file_path)
            if parameter:
                call_sites_parser.append([call_site_address, caller, block_addr, parameter])
            else:
                number_vsa += 1
                call_sites_parser.append([call_site_address, caller, block_addr, -1])
        else: # 若没有对应的参数则直接跳过
            call_sites_parser.append([call_site_address, caller, block_addr, -1])
    success_rate = (number - number_vsa) / number if number != 0 else 0
    return call_sites_parser, success_rate


# 综合快速获取和Ghidra辅助获取
def get_set_func_args(project, cfg, func_name, file_path, analysis_binary_dict: AnalysisBinaryDict, index_key, index_value = None):
    start_time = time.time()
    # 首先进行参数解析的快速获取
    call_sites_parser, success_rate = get_set_func_args_fast(project, cfg, func_name, index_key, index_value)
    if success_rate >= config_sgtaint.MIN_SUCCESS_RATE:
        logger.info(f"[Fast] Extraction success rate for '{func_name}' = {success_rate:.2%}")
        number = 0
        for call_site_address, caller, block_addr, parameter in call_sites_parser:
            number += 1
            logger.debug(f"[{number}] call_site: {hex(call_site_address)}, caller: {hex(caller)}, block_addr: {hex(block_addr)}, key: {parameter}")
        end_time = time.time()
        elapsed_time = end_time - start_time
        logger.info(f"[+] Analysis for call sites of {func_name} completed in {elapsed_time:.2f} seconds.")
        return call_sites_parser
    else: # 进行进行不精确获取
        logger.warning(f"[Fast] Success rate too low ({success_rate:.2%}); switching to Ghidra for '{func_name}'")
        call_sites_parser_ghidra, success_rate_ghidra = get_keyword_by_decompiled_func_ghidra(project, cfg, func_name, file_path, analysis_binary_dict, index_key, index_value)
        if success_rate_ghidra > success_rate:
            logger.info(f"[Ghidra] Extraction success rate for '{func_name}' = {success_rate_ghidra:.2%}")
            number = 0
            for call_site_address, caller, block_addr, parameter in call_sites_parser_ghidra:
                number += 1
                logger.debug(f"[{number}] call_site: {hex(call_site_address)}, caller: {hex(caller)}, block_addr: {hex(block_addr)}, key: {parameter}")
            end_time = time.time()
            elapsed_time = end_time - start_time
            logger.info(f"[+] Analysis for call sites of {func_name} completed in {elapsed_time:.2f} seconds.")
            return call_sites_parser_ghidra
        else:
            logger.info(f"[Fallback] Using fast method despite low success rate ({success_rate:.2%} >= {success_rate_ghidra:.2%})")
            number = 0
            for call_site_address, caller, block_addr, parameter in call_sites_parser:
                number += 1
                logger.debug(f"[{number}] call_site: {hex(call_site_address)}, caller: {hex(caller)}, block_addr: {hex(block_addr)}, key: {parameter}")
            end_time = time.time()
            elapsed_time = end_time - start_time
            logger.info(f"[+] Analysis for call sites of {func_name} completed in {elapsed_time:.2f} seconds.")
            return call_sites_parser
        
        
# 使用大语言模型获取func_name
def get_func_name_from_llm(analysis_binary_dict: AnalysisBinaryDict, timeout=60):
    start_time = time.time()
    # func_name可以在配置文件中进行配置，若配置，则不使用LLM进行分析 
    if config_sgtaint.SG_FUNCTION_INFO and config_sgtaint.SG_FUNCTION_INFO.startswith("[("):
        logger.info("Set and Get function information received successfully!")
        func_name = parse_set_get_string(config_sgtaint.SG_FUNCTION_INFO)
        for set_func_name, get_func_name, index_key_set, index_key_get, index_value_set, index_value_get in func_name:
            # 更新对应的函数集
            if set_func_name not in config_sgtaint.transitive_set:
                config_sgtaint.transitive_set.append(set_func_name)
            if get_func_name not in config_sgtaint.SOURCES:
                config_sgtaint.SOURCES.append(get_func_name)
            if get_func_name not in config_sgtaint.transitive_get:
                config_sgtaint.transitive_get.append(get_func_name)
            if (set_func_name, get_func_name) not in config_sgtaint.SET_GET_INFO: # 更新初始的列表名称
                config_sgtaint.SET_GET_INFO[(set_func_name, get_func_name)] = [set_func_name, get_func_name, index_key_set, index_key_get, index_value_set, index_value_get]
        logger.info(f"Function names from configuration: {func_name}")
        analysis_binary_dict.get_set_func_name = func_name[:] # 更新分析二进制字典中的函数名称
        return func_name
    # 获取边界二进制文件列表
    binary_path_list = analysis_binary_dict.get_border_binary_path_list()
    func_name_list = []
    for binary_path in binary_path_list:
        analysis_binary: AnalysisBinary = analysis_binary_dict.get_analysis_binary_by_path(binary_path)
        for func_name, _ in get_extern_func_name(analysis_binary.get_angr_project()):
            if func_name not in func_name_list:
                func_name_list.append(func_name)
    # 进行LLM的第一步分析
    func_name_list_str = "[" + ", ".join(func_name_list) + "]"
    LLM_chat = LLM(config_sgtaint.SG_TEMPERATURE)
    LLM_chat.system_role(SYSTEM_SET_GET)
    response = LLM_chat.chat(get_user_set_get_en_prompt_phase_one(func_name_list_str), timeout=timeout)
    error_count = 0
    while not response.startswith("[("): # 其中可能存在[ERROR]超时情况
        if response.startswith("[ERROR]"):
            error_count += 1
            if error_count >= config_sgtaint.MAX_ERROR_COUNT:
                logger.warning("Exceeded maximum consecutive errors during LLM chat")
                return []
        else:
            error_count = 0
        response = LLM_chat.chat(SYSTEM_SET_GET_OUTPUT_PHASE_ONE, timeout=timeout)
    # 进行第二次检查
    response_twice = LLM_chat.chat(DOUBLE_CHECK, timeout=timeout)
    error_count = 0
    while not response_twice.startswith("[("):
        if response_twice.startswith("[ERROR]"):
            error_count += 1
            if error_count >= config_sgtaint.MAX_ERROR_COUNT:
                logger.warning("Exceeded maximum consecutive errors during LLM chat")
                return []
        else:
            error_count = 0
        response_twice = LLM_chat.chat(SYSTEM_SET_GET_OUTPUT_PHASE_ONE, timeout=timeout)
    # 增强LLM回答的健壮性（需要增加次数防止无限循环）
    cycle_number = 0
    while cycle_number < config_sgtaint.MAX_REPEATED_TIMES and response_twice != response:
        response = response_twice
        response_twice = LLM_chat.chat(DOUBLE_CHECK, timeout=timeout)
        error_count = 0
        while not response_twice.startswith("[("):
            if response_twice.startswith("[ERROR]"):
                error_count += 1
                if error_count >= config_sgtaint.MAX_ERROR_COUNT:
                    logger.warning("Exceeded maximum consecutive errors during LLM chat")
                    return []
            else:
                error_count = 0
            response_twice = LLM_chat.chat(SYSTEM_SET_GET_OUTPUT_PHASE_ONE, timeout=timeout)
        cycle_number += 1
    func_name_phase_one = parse_set_get_string(response_twice)
    # 进行LLM的第二步分析，首先需要获取对应到的调用语句
    func_name_phase_list = []
    func_name_previous_known = [] # 存放从SET_GET_INFO中获取的函数信息
    for set_func_name, get_func_name in func_name_phase_one:
        # 找到包含set_func_name和get_func_name的边界二进制文件
        is_correct_pair = False
        for binary_path in binary_path_list:
            analysis_binary: AnalysisBinary = analysis_binary_dict.get_analysis_binary_by_path(binary_path)
            if analysis_binary.has_func(set_func_name) and analysis_binary.has_func(get_func_name):
                set_func_call_sites = analysis_binary.has_call_site(set_func_name)
                get_func_call_sites = analysis_binary.has_call_site(get_func_name)
                if set_func_call_sites and get_func_call_sites:
                    is_correct_pair = True
                    break
        if not is_correct_pair: # 跳过不合法的函数对
            print(f"[-] The function pair ({set_func_name}, {get_func_name}) is not valid!")
            continue
        # 处理已知信息的合法对
        if (set_func_name, get_func_name) in config_sgtaint.SET_GET_INFO:
            func_name_previous_known.append(config_sgtaint.SET_GET_INFO[(set_func_name, get_func_name)])
            continue
        set_func_list = list(set([func_addr for _, func_addr, _ in set_func_call_sites]))
        get_func_list = list(set([func_addr for _, func_addr, _ in get_func_call_sites]))
        func_name_phase_list.append({
            "set_func_name": set_func_name,
            "set_func_addr": set_func_list,
            "get_func_name": get_func_name,
            "get_func_addr": get_func_list,
            "file_path": analysis_binary.get_path()
        })
    # 将输出写成文件传递给Ghidra进行分析
    grouped_by_file = defaultdict(list)
    for item in func_name_phase_list:
        file_path = item["file_path"]
        grouped_by_file[file_path].append(item)
    grouped_by_file = dict(grouped_by_file) # 按照file_path进行分组 
    # 对分组后的文件进行处理
    func_name_eventually = []
    for file_path, items in grouped_by_file.items():
        analysis_binary: AnalysisBinary = analysis_binary_dict.get_analysis_binary_by_path(file_path)
        file_path_process = file_path.replace("/", "_")
        func_name_phase_file_name = f"{file_path_process}_func_name_phase.json"
        func_name_phase_file_path = os.path.join(config_sgtaint.TMP_DIR, func_name_phase_file_name)
        with open(func_name_phase_file_path, "w") as file:
            json.dump(items, file, indent=4)
        # 执行Ghidra脚本进行分析
        analysis_binary.load_ghidra()
        angr_base_addr = hex(analysis_binary.get_angr_base_addr())
        binary_mark = os.path.basename(file_path)
        ghidra_python_path = '/home/SGTaint/tool/Ghidra/ghidra_assist.py'
        ghidra_command = f'{config_sgtaint.ANALYZEHEADLESS} {config_sgtaint.GHIDRA_DIR} {binary_mark} -process {binary_mark} -postScript {ghidra_python_path} "{angr_base_addr}" "*"'
        execute(ghidra_command)
        # 读取对应的结果文件
        func_name_phase_result_file_name = f"{file_path_process}_func_name_phase_result.json"
        func_name_phase_result_file_path = os.path.join(config_sgtaint.TMP_DIR, func_name_phase_result_file_name)
        with open(func_name_phase_result_file_path, "r") as file:
            func_name_phase_result = json.load(file)
        # 删除对应的中间文件
        rm_command = f"rm {func_name_phase_result_file_path}"
        execute(rm_command)
        for func_name_result in func_name_phase_result:
            set_func_name = func_name_result["set_func_name"]
            set_code_dict = func_name_result["set_code_dict"]
            set_func_fail = func_name_result["set_func_fail"]
            analysis_binary.set_get_code_snippet[set_func_name] = set_code_dict
            analysis_binary.ghidra_func_identify_failed[set_func_name] = set_func_fail
            set_code_list = list(set(tuple(v) for v in set_code_dict.values()))
            set_code_filter_list = []
            set_parameter_list = []
            for complete_line, set_code in set_code_list:
                # 对函数调用进行解析，找到符合标准的函数调用
                parameter_list = parse_function_call(analysis_binary.get_angr_project(), set_code, complete_line ,file_path)
                if parameter_list:
                    set_parameter_list += parameter_list
                    set_code_filter_list.append(complete_line)
            get_func_name = func_name_result["get_func_name"]
            get_code_dict = func_name_result["get_code_dict"]
            get_func_fail = func_name_result["get_func_fail"]
            analysis_binary.set_get_code_snippet[get_func_name] = get_code_dict
            analysis_binary.ghidra_func_identify_failed[get_func_name] = get_func_fail
            get_code_list = list(set(tuple(v) for v in get_code_dict.values())) 
            get_code_filter_list = []
            get_parameter_list = []
            for complete_line, get_code in get_code_list:
                # 对函数调用进行解析，找到符合标准的函数调用
                parameter_list = parse_function_call(analysis_binary.get_angr_project(), get_code, complete_line ,file_path)
                if parameter_list:
                    get_parameter_list += parameter_list
                    get_code_filter_list.append(complete_line)
            if not set(set_parameter_list) & set(get_parameter_list):
                print(f"[-] The function pair ({set_func_name}, {get_func_name}) is not valid!")
                continue
            else: # 生成对应的func_name
                func_name_eventually.append({
                    "set_func_name": set_func_name,
                    "set_code_list": set_code_filter_list,
                    "get_func_name": get_func_name,
                    "get_code_list": get_code_filter_list,
                })
    # 开启第二阶段的LLM分析
    prompt_phase_two = get_prompt_for_phase_two(func_name_eventually)
    response = LLM_chat.chat(get_user_set_get_en_prompt_phase_two(prompt_phase_two))
    error_count = 0
    if not response.startswith("[("):
        if response.startswith("[ERROR]"):
            error_count += 1
            if error_count >= config_sgtaint.MAX_ERROR_COUNT:
                logger.warning("Exceeded maximum consecutive errors during LLM chat")
                return []
        else:
            error_count = 0
        response = LLM_chat.chat(SYSTEM_SET_GET_OUTPUT_PHASE_TWO)
    # 进行第二次检查
    response_twice = LLM_chat.chat(double_check_phase_two(get_prompt_for_phase_two(func_name_eventually)))
    error_count = 0
    while not response_twice.startswith("[("):
        if response_twice.startswith("[ERROR]"):
            error_count += 1
            if error_count >= config_sgtaint.MAX_ERROR_COUNT:
                logger.warning("Exceeded maximum consecutive errors during LLM chat")
                return []
        else:
            error_count = 0
        response_twice = LLM_chat.chat(SYSTEM_SET_GET_OUTPUT_PHASE_TWO)
    # 增强LLM回答的健壮性（需要增加次数防止无限循环）
    cycle_number = 0
    while cycle_number < config_sgtaint.MAX_REPEATED_TIMES and response_twice != response:
        response = response_twice
        response_twice = LLM_chat.chat(double_check_phase_two(get_prompt_for_phase_two(func_name_eventually)))
        error_count = 0
        while not response_twice.startswith("[("):
            if response_twice.startswith("[ERROR]"):
                error_count += 1
                if error_count >= config_sgtaint.MAX_ERROR_COUNT:
                    logger.warning("Exceeded maximum consecutive errors during LLM chat")
                    return []
            else:
                error_count = 0
            response_twice = LLM_chat.chat(SYSTEM_SET_GET_OUTPUT_PHASE_TWO)
        cycle_number += 1
    func_name = parse_set_get_string(response_twice) + func_name_previous_known
    for set_func_name, get_func_name, index_key_set, index_key_get, index_value_set, index_value_get in func_name:
        # 更新对应的函数集
        if set_func_name not in config_sgtaint.transitive_set:
            config_sgtaint.transitive_set.append(set_func_name)
        if get_func_name not in config_sgtaint.SOURCES:
            config_sgtaint.SOURCES.append(get_func_name)
        if get_func_name not in config_sgtaint.transitive_get:
            config_sgtaint.transitive_get.append(get_func_name)
        if (set_func_name, get_func_name) not in config_sgtaint.SET_GET_INFO: # 更新初始的列表名称
            config_sgtaint.SET_GET_INFO[(set_func_name, get_func_name)] = [set_func_name, get_func_name, index_key_set, index_key_get, index_value_set, index_value_get]
    analysis_binary_dict.get_set_func_name = func_name[:] # 更新分析二进制字典中的函数名称
    end_time = time.time()
    elapsed_time = end_time - start_time
    logger.info(f"LLM analysis completed in {elapsed_time:.2f} seconds.")
    logger.info(f"Identified functions: {func_name}")
    return func_name


# Set-get图构建的单程步骤，其中func_name为set和get函数名称的列表，其中file_path为边界二进制文件的路径（处理单个set-get对以及单个二进制文件）
def set_get_graph_create_single(analysis_binary_initial: AnalysisBinary, func_name, directory, analysis_binary_dict: AnalysisBinaryDict, set_get_graph: SetGetGraph, index_key, get_index_key ,index_value = None, get_index_value = None, single_tag = False):
    start_time = time.time()
    analysis_binary_initial.construct_intra_graph_tag = True # 不需要重复进行构建
    set_func_name = func_name[0]
    get_func_name = func_name[1]
    # 读取处理二进制文件的处理信息
    project = analysis_binary_initial.get_angr_project()
    cfg = analysis_binary_initial.get_angr_cfg()
    file_path = analysis_binary_initial.get_path()
    # 防止重复调用算法进行call_site的创建
    if set_func_name not in analysis_binary_initial.set_get_call_sites_dict:
        call_sites_parser = get_set_func_args(project, cfg, set_func_name, file_path, analysis_binary_dict, index_key, index_value)
        analysis_binary_initial.set_get_call_sites_dict[set_func_name] = call_sites_parser
    else:
        call_sites_parser = analysis_binary_initial.set_get_call_sites_dict[set_func_name]
    # 若call_sites_parser为空则直接返回（均存储为常数）
    if not call_sites_parser:
        logger.warning(f"No exploitable call sites found for {set_func_name} in {file_path}")
        return
    key_set = {key for (_, _, _, key) in call_sites_parser if key != -1} # 读取相关set函数对应的参数集合
    # 若key_set为空则直接返回（key为动态可变）
    if not key_set:
        logger.warning(f"No exploitable key found for {set_func_name} in {file_path}")
        return
    filtered_files = coarse_grained_binary_filter(get_func_name, key_set, directory) if not single_tag else [file_path]
    for filtered_file_path in filtered_files:
        # 处理完成之后需要进行更新或者加入
        if filtered_file_path not in analysis_binary_dict.analysis_binary_dict:
            # 创建新的二进制文件类
            try: # 加载二进制文件，捕获CFG创建的异常
                analysis_binary = AnalysisBinary(filtered_file_path) # 目前先不加入分析列表之中
            except RuntimeError as e:
                logger.error(f"Error loading binary {filtered_file_path}: {e}")
                continue
        else:
            analysis_binary = analysis_binary_dict.get_analysis_binary_by_path(filtered_file_path)
        # 首先判断是否真正存在get函数
        if not analysis_binary.has_call_site(get_func_name):
            continue
        # 获取对应get函数对应的键值
        filter_project = analysis_binary.get_angr_project()
        filter_cfg = analysis_binary.get_angr_cfg()
        if get_func_name not in analysis_binary.set_get_call_sites_dict: # 加快分析速度
            get_func_call_sites_parser = get_set_func_args(filter_project, filter_cfg, get_func_name, filtered_file_path, analysis_binary_dict, get_index_key, get_index_value)
            analysis_binary.set_get_call_sites_dict[get_func_name] = get_func_call_sites_parser
        else:
            get_func_call_sites_parser = analysis_binary.set_get_call_sites_dict[get_func_name]
        get_key_set = {key for (_, _, _, key) in get_func_call_sites_parser if key != -1} # 读取相关get函数对应的参数集合
        keyword_set = key_set & get_key_set
        if keyword_set: # 存在真正的数据流关系，需要更新分析二进制文件的字典
            # 判断是否需要进行迭代分析
            if analysis_binary.should_set_role_binary() and analysis_binary.has_call_site(set_func_name) and filtered_file_path not in analysis_binary_dict.set_dict[set_func_name] and not analysis_binary.has_set_role_binary():
                analysis_binary_dict.set_dict[set_func_name].append(filtered_file_path)
            # 更新相关文件（防止逆向回溯）
            if filtered_file_path not in analysis_binary_initial.relate_file_path:
                if filtered_file_path != file_path:
                    analysis_binary_initial.add_relate_file(filtered_file_path)
            else:
                continue
            # get类型文件更新相关文件（防止逆向回溯）
            if file_path not in analysis_binary.relate_file_path:
                if file_path != filtered_file_path:
                    analysis_binary.add_relate_file(file_path)
            else:
                continue
            # 直接进行set_get_graph的补充
            for keyword in keyword_set:
                call_site_keyword_set_func = [call_site_info for call_site_info in call_sites_parser if call_site_info[3] == keyword]
                call_site_keyword_get_func = [call_site_info for call_site_info in get_func_call_sites_parser if call_site_info[3] == keyword]
                for call_site_set in call_site_keyword_set_func:
                    if (call_site_set[0], file_path) not in set_get_graph.node_dict:
                        set_graph_node = SetGetGraphNode(call_site_set[0], set_func_name, call_site_set[1], file_path, 'set', keyword, call_site_set[2])
                        set_get_graph.node_dict[(call_site_set[0], file_path)] = set_graph_node
                    else:
                        set_graph_node = set_get_graph.node_dict[(call_site_set[0], file_path)]
                    # 添加相关关系
                    for call_site_get in call_site_keyword_get_func:
                        if (call_site_get[0], filtered_file_path) not in set_get_graph.node_dict:
                            get_graph_node = SetGetGraphNode(call_site_get[0], get_func_name, call_site_get[1], filtered_file_path, 'get', keyword, call_site_get[2])
                            set_get_graph.node_dict[(call_site_get[0], filtered_file_path)] = get_graph_node
                        else:
                            get_graph_node = set_get_graph.node_dict[(call_site_get[0], filtered_file_path)]
                        # 添加双方的对应关系
                        relate_kind = 0 if filtered_file_path == file_path else 1 # 可以进行内部的构建
                        set_graph_node.add_relate((call_site_get[0], filtered_file_path, relate_kind)) # 表示文件间的关系（其中添加的仅仅为标识）
                        get_graph_node.add_relate((call_site_set[0], file_path, relate_kind))
                        # 更新图对应的字典
                        set_get_graph.node_dict[(call_site_get[0], filtered_file_path)] = get_graph_node
                        # 更新对应的相关关系
                        if filtered_file_path != file_path:
                            set_get_graph.extra_relate.add(((file_path, call_site_set[0]), (filtered_file_path, call_site_get[0]), keyword))
                    # 更新图对应的字典
                    set_get_graph.node_dict[(call_site_set[0], file_path)] = set_graph_node
            # 更新对应的二进制文件字典
            analysis_binary_dict.update_analysis_binary_by_path(filtered_file_path, analysis_binary)
            if filtered_file_path != file_path: # 若是不同的文件则需要更新初始二进制文件
                analysis_binary_initial.diffusion_file.add(filtered_file_path) # 构建对应的分析图结构
    # 更新分析字典中的原始二进制文件
    analysis_binary_dict.update_analysis_binary_by_path(file_path, analysis_binary_initial)     
    end_time = time.time()
    elapsed_time = end_time - start_time
    logger.info(f"Creation of single set-get-graph for {set_func_name} and {get_func_name} completed in {elapsed_time:.2f} seconds.")  
    
    
# Set-get图构建，func_name从边界二进制文件中获取，每一轮处理一对func_name:[(set_func_name, get_func_name, index_key_set, index_value_set, index_key_get)....]
def set_get_graph_create(directory, analysis_binary_dict: AnalysisBinaryDict, set_get_graph: SetGetGraph):
    start_time = time.time()
    # 首先进行边界二进制文件的获取
    boundary_files = get_border_binaries_by_cluster_max_mean_gap(directory) # 获取一组边界二进制文件
    for boundary_file in boundary_files:
        try: # 加载边界二进制文件，捕获CFG创建的异常
            analysis_boundary_binary = AnalysisBinary(boundary_file)
        except RuntimeError as e:
            logger.error(f"Error loading binary {boundary_file}: {e}")
            continue
        analysis_boundary_binary.set_board_binary() # 将其设定为边界二进制文件
        analysis_binary_dict.add_analysis_binary(analysis_boundary_binary) # 将所有的边界二进制文件加入到分析列表之中
    # 处理边界二进制文件angr创建失败的情况
    if not analysis_binary_dict.analysis_binary_dict:
        logger.error(f"The creation of the boundary binary in angr failed.")
        return
    # 使用LLM获取边界二进制文件的func_name
    try:
        func_name = get_func_name_from_llm(analysis_binary_dict)
    except Exception as e:
        logger.error(f"Error retrieving function names from LLM: {e}")
        func_name = []  # 将其设置为[]
    exceed_flag = False
    for set_func_name, get_func_name, index_key_set, index_key_get, index_value_set, index_value_get in func_name:
        analysis_binary_dict.set_dict[set_func_name] = [] # 字典元素为对应的列表
        func_name_list = [set_func_name, get_func_name]
        # 判断边界二进制文件中是否存在对应的set_get函数
        for boundary_file in boundary_files:
            analysis_boundary_binary: AnalysisBinary = analysis_binary_dict.get_analysis_binary_by_path(boundary_file)
            if analysis_boundary_binary.has_call_site(set_func_name) and analysis_boundary_binary.has_call_site(get_func_name):
                analysis_binary_dict.set_dict[set_func_name].append(boundary_file) # 仅仅存储二进制文件路径即可
        # 此处扩展二进制分析列表，因此需要加入限制
        while analysis_binary_dict.set_dict[set_func_name]: # 当不可向下迭代时，停止分析
            # 判断分析列表是否超过限制
            if len(analysis_binary_dict.analysis_binary_dict) >= config_sgtaint.MAX_BINARY_LIMIT:
                exceed_flag = True
                logger.info("Number of analyzed binary files exceeds the maximum limit.")
                break
            tmp_set_dict = analysis_binary_dict.set_dict[set_func_name][:]
            for file_path in tmp_set_dict:
                analysis_binary_initial: AnalysisBinary = analysis_binary_dict.get_analysis_binary_by_path(file_path)
                analysis_binary_initial.is_set_role = True
                try: # 捕捉对应的错误
                    set_get_graph_create_single(analysis_binary_initial, func_name_list, directory, analysis_binary_dict, set_get_graph, index_key_set, index_key_get, index_value_set, index_value_get)
                except Exception as e:
                    logger.error(f"Error in set_get_graph_create_single: {e}")
                    continue
                analysis_binary_dict.set_dict[set_func_name].remove(file_path)
        if exceed_flag: # 跳出大循环
            logger.warning("Set-get graph construction terminated early due to binary count overflow.")
            break
        # 进行文件内函数的构造
        for file_path in analysis_binary_dict.analysis_binary_dict:
            if not analysis_binary_dict.analysis_binary_dict[file_path].construct_intra_graph_tag and analysis_binary_dict.analysis_binary_dict[file_path].has_call_site(set_func_name):
                analysis_binary_dict.analysis_binary_dict[file_path].construct_intra_graph_tag = True
                analysis_binary_initial = analysis_binary_dict.get_analysis_binary_by_path(file_path)
                try:
                    set_get_graph_create_single(analysis_binary_initial, func_name_list, directory, analysis_binary_dict, set_get_graph, index_key_set, index_key_get, index_value_set, index_value_get, True)
                except Exception as e:
                    logger.error(f"Error in set_get_graph_create_single: {e}")
                    continue
    # 更新二进制文件的set_get函数信息
    for file_path in analysis_binary_dict.analysis_binary_dict:
        analysis_binary: AnalysisBinary = analysis_binary_dict.get_analysis_binary_by_path(file_path)
        analysis_binary.get_set_function_info = analysis_binary_dict.get_set_func_name[:] # 更新之后进行Myhandle的构建
        # 若存在对应的keyword文件，设置对应的keywordset以及functionset
        file_name = "{}_keyword_function.json".format(file_path.replace("/", "_"))
        keyword_file_path = os.path.join(config_sgtaint.TMP_KEYWORD, file_name)
        if os.path.exists(keyword_file_path):
            with open(keyword_file_path, "r") as file:
                keyword_function_list = json.load(file)
            for keyword_function in keyword_function_list:
                analysis_binary.binary_function_keyword.add(keyword_function["string"])
    set_get_graph.create_node_dict_path() # 创建新索引
    set_get_graph.set_get_graph_file()
    end_time = time.time()
    elapsed_time = end_time - start_time
    logger.info("Final analyzed binary files:\n" + "\n".join(list(analysis_binary_dict.analysis_binary_dict.keys())))
    logger.info(f"Creation of set-get-graph completed in {elapsed_time:.2f} seconds.")