# -*- coding: utf-8 -*-
import re
import os
import json
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
import tool.Config.config as config_sgtaint
from ghidra.app.decompiler import DecompInterface, DecompileOptions # type: ignore
from ghidra.app.decompiler.component import DecompilerUtils # type: ignore
from ghidra.util.task import ConsoleTaskMonitor # type: ignore


# 全局缓存
decompile_cache = {} # 其中键值为函数地址，值为反编译结果


# 执行任意命令
def execute(command):
    from subprocess import check_output, STDOUT
    command = "{}; exit 0".format(command)
    return check_output(command, stderr=STDOUT, shell=True).decode("utf-8")


# 基础地址换算（从ghidra到angr）
def base_addr_transform_ghidra2angr(program, angr_base_addr, ghidra_addr):
    image_base = program.getImageBase()
    ghidra_base_addr = image_base.getOffset()
    angr_addr = ghidra_addr + angr_base_addr - ghidra_base_addr
    return angr_addr


# 通过函数名称或函数地址获取函数对象   
def get_function(program, identifier):
    identifier = str(identifier)
    function_manager = program.getFunctionManager()
    addr_factory = program.getAddressFactory().getDefaultAddressSpace() 
    try:
        if isinstance(identifier, str) and identifier.lower().startswith("0x"):
            addr_val = int(identifier, 16)
        else:
            addr_val = int(identifier)
        addr = addr_factory.getAddress(hex(addr_val))
        func = function_manager.getFunctionAt(addr)
        if func is None:
            print("[-] No function found at address %s" % hex(addr_val))
        return func
    except Exception:
        functions = function_manager.getFunctions(True)
        for func in functions:
            if func.getName() == identifier:
                return func
        print("[-] No function found with name '%s'" % identifier)
        return None
    

# 获取反编译结果
def get_function_decompile(program, identifier):
    if identifier not in decompile_cache:
        try:
            func = get_function(program, identifier)
            if func is None:
                return None
            # 初始化反编译接口
            decomp_iface = DecompInterface()
            decomp_iface.openProgram(program)
            # 设置反编译选项（例如调用约定等）
            decompileOptions = DecompileOptions()
            decompileOptions.setProtoEvalModel("__stdcall")
            decomp_iface.setOptions(decompileOptions)
            # 反编译函数，设置超时时间为60秒
            monitor = ConsoleTaskMonitor()
            decomp_res = decomp_iface.decompileFunction(func, 60, monitor)
            if decomp_res is None or not decomp_res.decompileCompleted():
                return None
            # 利用DecompilerUtils将token组转换为ClangLine列表
            lines = DecompilerUtils.toLines(decomp_res.getCCodeMarkup())
            decompile_cache[identifier] = lines
        except Exception as e:
            print("[-] An exception occurred during decompilation: ", e)
            return None
        finally:
            if 'decomp_iface' in locals():
                decomp_iface.dispose()
    else:
        lines = decompile_cache[identifier]
    # 返回反编译结果
    return lines
        

# 给定反汇编后的代码行提取对应的函数调用内容
def get_call_site_func_name_from_line(idx, lines, call_site_name):
    stack_line = [] # 用于处理嵌套的括号问题
    offset_start = 0
    line = re.sub(r'^\s*\d+:\s*', '', lines[idx].toString())
    call_site_code = ""
    clean_line = ""
    # 找到起始的偏移位置
    tmp_line = line[offset_start:]
    while offset_start < len(line):
        if not tmp_line.startswith(call_site_name):
            offset_start += 1
            tmp_line = line[offset_start:]
            continue
        else:
            break
    offset_finish = offset_start + len(call_site_name)
    # 获取最靠近函数调用的‘（’
    while offset_finish < len(line) and line[offset_finish] != '(':
        offset_finish += 1
    offset_finish += 1
    stack_line.append('(') # 一定出现在函数调用的起始位置，并且不会截断表示
    while offset_finish < len(line):
        if line[offset_finish] == '(':
            stack_line.append('(')
        elif line[offset_finish] == ')':
            stack_line.pop()
            if not stack_line:
                offset_finish += 1
                break
        offset_finish += 1
    call_site_code += line[offset_start:offset_finish]
    clean_line += line
    while idx < len(lines) - 1 and stack_line: # 出现表示截断
        idx += 1 # 处理下一行内容
        line = re.sub(r'^\s*\d+:\s*', '', lines[idx].toString())
        offset_finish = 0
        while offset_finish < len(line):
            if line[offset_finish] == '(':
                stack_line.append('(')
            elif line[offset_finish] == ')':
                stack_line.pop()
                if not stack_line:
                    offset_finish += 1
                    break
            offset_finish += 1
        call_site_code += line[:offset_finish]
        clean_line += line
    return call_site_code, clean_line   

    
# 根据反编译代码获取函数调用参数信息辅助函数
def get_args_string_call_sites(program, identifier, call_site_name, angr_base_addr):
    lines = get_function_decompile(program, identifier)
    if not lines:
        return None
    call_site_dict = {} # 将调用站点存储在字典中，键值为函数调用的地址
    for idx, clang_line in enumerate(lines):
        line_text = clang_line.toString()
        if call_site_name in line_text:
            try:
                call_site_code, clean_line = get_call_site_func_name_from_line(idx, lines, call_site_name)
                for clang_token in clang_line.getAllTokens(): # 获取函数调用的地址
                    if clang_token.getText() == call_site_name:
                        # 仅仅使用call_site点的地址
                        min_addr = base_addr_transform_ghidra2angr(program, angr_base_addr, clang_token.getMinAddress().getOffset())
                        call_site_dict[hex(min_addr)[:-1]] = [clean_line, call_site_code]  
            except Exception as e:
                print("Failed to parse call site in line {}: {}".format(idx, e))
                continue
    return call_site_dict


# 获取指定函数的所有系统调用
def get_call_site_by_identifier(program, identifier, angr_base_addr):
    target_func = get_function(program, identifier)
    if target_func is None:
        return None
    call_site_dict = {}
    callers = target_func.getCallingFunctions(monitor) # type: ignore
    callers_ghidra = [] # 保存Ghidra成功识别的函数
    for caller in callers:
        try:
            caller_identifier = caller.getEntryPoint().getOffset()
            callers_ghidra.append(base_addr_transform_ghidra2angr(program, angr_base_addr, caller_identifier))
            call_site_dict_func = get_args_string_call_sites(program, caller_identifier, identifier, angr_base_addr)
            if call_site_dict_func is not None:
                call_site_dict.update(call_site_dict_func)
        except Exception as e:
            print("Failed during call site decompilation {}".format(e))
            continue
    return call_site_dict, callers_ghidra


# 指定函数的调用站点的反编译获取
def get_decompile_code_by_func_name(program, call_site_name, angr_base_addr):
    # 获取对应的函数地址列表
    caller_file_name = "{}_caller_addr.json".format(call_site_name)
    caller_file_path = os.path.join(config_sgtaint.TMP_DIR, caller_file_name)
    with open(caller_file_path, "r") as file:
        caller_func_list = json.load(file) # angr中识别出的所有调用函数
    try:
        call_site_dict, callers_ghidra = get_call_site_by_identifier(program, call_site_name, angr_base_addr)
    except Exception as e:
        print("Failed during call site decompilation {}".format(e))
        call_site_dict = {}
        callers_ghidra = []
    angr_assist_callers = [addr for addr in caller_func_list if addr not in callers_ghidra]
    caller_parse_result = {
        "code_dict": call_site_dict,
        "angr_assist": angr_assist_callers
    }
    # 存储结果
    caller_file_result_name = "{}_caller_parse_result.json".format(call_site_name)
    caller_file_result_path = os.path.join(config_sgtaint.TMP_DIR, caller_file_result_name)
    with open(caller_file_result_path, "w") as file:
        json.dump(caller_parse_result, file, indent=4)
    # 删除第一个存储的中间文件
    command = "rm {}".format(caller_file_path)
    execute(command)
    

# SG函数信息精确识别
def get_all_decompile_code_precise(program, angr_base_addr):
    # 获取对应的函数列表信息
    file_path = program.getExecutablePath()
    file_path_process = file_path.replace("/", "_")
    func_name_phase_file_name = "{}_func_name_phase.json".format(file_path_process)
    func_name_phase_file_path = os.path.join(config_sgtaint.TMP_DIR, func_name_phase_file_name)
    with open(func_name_phase_file_path, "r") as file:
        func_name_phase_result_json = json.load(file)
    # 存储解析结果
    func_name_phase_result = []
    for func_name, func_addr in func_name_phase_result_json:
        try:
            call_site_dict, callers_ghidra = get_call_site_by_identifier(program, func_name, angr_base_addr)
        except Exception as e:
            print("Failed during call site decompilation {}".format(e))
            call_site_dict = {}
            callers_ghidra = []
        angr_assist_callers = [addr for addr in func_addr if addr not in callers_ghidra]
        func_name_phase_result.append({
            "func_name": func_name,
            "code_dict": call_site_dict,
            "angr_assist": angr_assist_callers
        })
    # 存储对应的文件名称
    func_name_phase_file_result_name = "{}_func_name_phase_result.json".format(file_path_process)
    func_name_phase_file_result_path = os.path.join(config_sgtaint.TMP_DIR, func_name_phase_file_result_name)
    with open(func_name_phase_file_result_path, "w") as file:
        json.dump(func_name_phase_result, file, indent=4)
    # 删除第一个存储的中间文件
    command = "rm {}".format(func_name_phase_file_path)
    execute(command)
    
    
# SG函数信息识别
def get_all_decompile_code(program, angr_base_addr):
    # 获取对应的函数列表信息
    file_path = program.getExecutablePath()
    file_path_process = file_path.replace("/", "_")
    func_name_phase_file_name = "{}_func_name_phase.json".format(file_path_process)
    func_name_phase_file_path = os.path.join(config_sgtaint.TMP_DIR, func_name_phase_file_name)
    with open(func_name_phase_file_path, "r") as file:
        func_name_phase_result_json = json.load(file)
    # 存储解析结果
    func_name_phase_result = []
    for set_get_func_info in func_name_phase_result_json:
        # 进行set函数的反编译代码行获取
        set_func_name = set_get_func_info.get("set_func_name")
        set_func_addr = set_get_func_info.get("set_func_addr")
        try:
            set_code_dict, set_callers_ghidra = get_call_site_by_identifier(program, set_func_name, angr_base_addr) # 键值为函数调用点
        except Exception as e: # 解析过程中存在错误
            print("Failed during call site decompilation {}".format(e))
            set_code_dict = {}
            set_callers_ghidra = []
        set_angr_assist_callers = [addr for addr in set_func_addr if addr not in set_callers_ghidra]
        get_func_name = set_get_func_info.get("get_func_name")
        get_func_addr = set_get_func_info.get("get_func_addr")
        try:
            get_code_dict, get_callers_ghidra = get_call_site_by_identifier(program, get_func_name, angr_base_addr) # 键值为函数调用点
        except Exception as e: # 解析过程中存在错误
            print("Failed during call site decompilation {}".format(e))
            set_code_dict = {}
            get_callers_ghidra = []
        get_angr_assist_callers = [addr for addr in get_func_addr if addr not in get_callers_ghidra]
        func_name_phase_result.append({
            "set_func_name": set_func_name,
            "set_code_dict": set_code_dict,
            "set_func_fail": set_angr_assist_callers,
            "get_func_name": get_func_name,
            "get_code_dict": get_code_dict,
            "get_func_fail": get_angr_assist_callers
        })
    # 存储对应的文件名称
    func_name_phase_file_result_name = "{}_func_name_phase_result.json".format(file_path_process)
    func_name_phase_file_result_path = os.path.join(config_sgtaint.TMP_DIR, func_name_phase_file_result_name)
    with open(func_name_phase_file_result_path, "w") as file:
        json.dump(func_name_phase_result, file, indent=4)
    # 删除第一个存储的中间文件
    command = "rm {}".format(func_name_phase_file_path)
    execute(command)
    

if __name__ == "__main__":
    # 获取传递的参数
    args = list(getScriptArgs()) # type: ignore
    angr_base_addr = int(args[0], 16)
    call_site_name = args[1]
    # 进行Angr以及Ghidra的地址对应
    program = getCurrentProgram() # type: ignore
    if call_site_name == "*": # 进行SG函数信息的识别
        get_all_decompile_code(program, angr_base_addr)
    elif call_site_name == "*-precise": # 进行SG函数信息的精确识别
        get_all_decompile_code_precise(program, angr_base_addr)
    else: # 进行函数调用的解析
        get_decompile_code_by_func_name(program, call_site_name, angr_base_addr)