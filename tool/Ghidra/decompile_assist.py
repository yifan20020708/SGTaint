# -*- coding: utf-8 -*-
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


# 基础地址换算（从angr到ghidra）
def base_addr_transform_angr2ghidra(program, angr_base_addr, angr_addr):
    image_base = program.getImageBase()
    ghidra_base_addr = image_base.getOffset()
    ghidra_addr = angr_addr - angr_base_addr + ghidra_base_addr
    return ghidra_addr


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
    
    
# 获取反编译代码行的地址范围
def get_line_address_range(clang_line):
    min_val = None
    max_val = None
    for clang_token in clang_line.getAllTokens():
        token_min = clang_token.getMinAddress()
        token_max = clang_token.getMaxAddress()
        if token_min is not None:
            offset = token_min.getOffset()
            if min_val is None or offset < min_val:
                min_val = offset
        if token_max is not None:
            offset = token_max.getOffset()
            if max_val is None or offset > max_val:
                max_val = offset
    # 若代码行并不对应Token，直接返回(0, 0)
    if min_val is None or max_val is None:
        return (0, 0)
    return (min_val, max_val)
            
            
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
            # 利用DecompilerUtils将token组转换为ClangLine列表
            lines = DecompilerUtils.toLines(decomp_res.getCCodeMarkup())
            pseudo_code = decomp_res.getDecompiledFunction().getC()
            decompile_cache[identifier] = [pseudo_code, lines]
        except Exception as e:
            print("[-] An exception occurred during decompilation: ", e)
            return None
        finally:
            if 'decomp_iface' in locals():
                decomp_iface.dispose()
    else:
        pseudo_code, lines = decompile_cache[identifier]
    # 返回反编译结果
    return pseudo_code, lines
            

def get_function_decompile_block2block_cached(program, identifier, start_block_start, start_block_end, end_block_start, end_block_end):
    # 获取反编译结果
    decompile_result = get_function_decompile(program, identifier)
    if not decompile_result:
        return None
    pseudo_code, lines = decompile_result
    pseudo_code_lines = pseudo_code.splitlines()
    start_index_list = []
    finish_index_list = []
    # 处理从函数调用的情况
    if identifier == start_block_start:
        for index, line in enumerate(pseudo_code_lines):
            if line.strip():
                start_index_list.append(index)
    for i in range(len(lines)):
        clang_line = lines[i]
        min_addr, max_addr = get_line_address_range(clang_line)
        if max(start_block_start, min_addr) <= min(start_block_end, max_addr) and min_addr >= start_block_start:
            start_index_list.append(i)
        if max(end_block_start, min_addr) <= min(end_block_end, max_addr) and min_addr >= end_block_start:
            finish_index_list.append(i)
    return pseudo_code_lines, start_index_list, finish_index_list
            

def get_function_decompile_list_by_path(program, function_ghidra_format, angr_base_addr, taint_source, taint_sink):
    function_decompile_list = []
    for index in range(len(function_ghidra_format)):
        func_addr = base_addr_transform_angr2ghidra(program, angr_base_addr, function_ghidra_format[index][0])
        start_block_start = base_addr_transform_angr2ghidra(program, angr_base_addr, function_ghidra_format[index][1])
        start_block_end = base_addr_transform_angr2ghidra(program, angr_base_addr, function_ghidra_format[index][2])
        end_block_start = base_addr_transform_angr2ghidra(program, angr_base_addr, function_ghidra_format[index][3])
        end_block_end = base_addr_transform_angr2ghidra(program, angr_base_addr, function_ghidra_format[index][4])
        result = get_function_decompile_block2block_cached(program, func_addr, start_block_start, start_block_end, end_block_start, end_block_end)
        if not result:
            return "Fail to Decompile by Ghidra"
        pseudo_code_lines, start_index_list, finish_index_list = result
        complete_decompile_code = "\n".join(pseudo_code_lines)
        if start_index_list: # 一般情况存在
            # 获取start_index
            if index == 0: # 第一个代码片段
                start_index = next((i for i in start_index_list if taint_source in pseudo_code_lines[i]), None)
                if start_index is None: # 向后进行寻找
                    found = False
                    for offset in range(1, 4): # 截断表示
                        candidate = min(start_index_list) - offset
                        if candidate >= 0 and taint_source in pseudo_code_lines[candidate]:
                            start_index = min(start_index_list)
                            found = True
                            break
                    if not found: # 非截断表示
                        if taint_source in complete_decompile_code: # 确保Ghidra可以识别出taint_source
                            start_index = min(max(start_index_list) + 1, len(pseudo_code_lines) - 1)
                            while start_index < len(pseudo_code_lines) and taint_source not in pseudo_code_lines[start_index]:
                                start_index += 1
                        else: # Ghidra不可以识别出taint_source
                            start_index = 0
            else: # 其余片段的start_index均为0
                start_index = 0
        else:
            start_index = 0
        if finish_index_list: # 一般情况存在
            # 获取end_index
            if index == len(function_ghidra_format) - 1: # 最后一个代码片段
                end_index = next((i for i in finish_index_list if taint_sink in pseudo_code_lines[i]), None) 
                if end_index is None: # 向后进行寻找
                    # 首先判断前面的三行内是否存在对应的函数
                    found = False
                    for offset in range(1, 4): # 截断表示
                        candidate = min(finish_index_list) - offset
                        if candidate >= 0 and taint_sink in pseudo_code_lines[candidate]:
                            end_index = min(finish_index_list)
                            found = True
                            break
                    if not found: # 非截断表示
                        if taint_sink in complete_decompile_code: # 确保Ghidra可以识别出taint_sink
                            end_index = min(max(finish_index_list) + 1, len(pseudo_code_lines) - 1)
                            while end_index < len(pseudo_code_lines) and taint_sink not in pseudo_code_lines[end_index]:
                                end_index += 1
                        else:
                            end_index = len(pseudo_code_lines) - 1
            else: # 与第二个片段的函数名称相关
                next_func_addr = base_addr_transform_angr2ghidra(program, angr_base_addr, function_ghidra_format[index + 1][0])
                next_func = get_function(program, next_func_addr)
                if next_func:
                    next_func_name = next_func.getName() # 需要包含函数名称
                    end_index = next((i for i in finish_index_list if next_func_name in pseudo_code_lines[i]), None) 
                    if end_index is None: # 向后进行寻找（对于长调用函数而言，可能截断表示）
                        # 首先判断前面的三行内是否存在对应的函数
                        found = False
                        for offset in range(1, 4): # 截断表示
                            candidate = min(finish_index_list) - offset
                            if candidate >= 0 and next_func_name in pseudo_code_lines[candidate]:
                                end_index = min(finish_index_list)
                                found = True
                                break
                        if not found: # 非截断表示
                            end_index = min(max(finish_index_list) + 1, len(pseudo_code_lines) - 1)
                            while end_index < len(pseudo_code_lines) and next_func_name not in pseudo_code_lines[end_index]:
                                end_index += 1
                else:
                    end_index = len(pseudo_code_lines) - 1
        else:
            end_index = len(pseudo_code_lines) - 1
        code_snippet_list = pseudo_code_lines[start_index:end_index + 1]
        code_snippet = "\n".join(code_snippet_list)
        function_decompile_list.append(code_snippet)
    return function_decompile_list


# 反汇编二进制文件获取的source2sink路径以及get2set路径
def get_decompile_result_binary(program, angr_base_addr):
    # 读取对应的json文件，针对source2sink路径
    file_path_process = program.getExecutablePath().replace("/", "_")
    source2sink_file_name = "{}_source2sink_path.json".format(file_path_process)
    source2sink_file_path = os.path.join(config_sgtaint.TMP_DIR, source2sink_file_name)
    with open(source2sink_file_path, "r") as file:
        source2sink_ghidra_list = json.load(file)
    source2sink_result = []
    for source2sink_single_path in source2sink_ghidra_list:
        function_ghidra_format = source2sink_single_path["ghidra_path"]
        taint_source = source2sink_single_path["taint_source"]
        taint_sink = source2sink_single_path["taint_sink"]
        try:
            source2sink_single_path["decompile_list"] = get_function_decompile_list_by_path(program, function_ghidra_format, angr_base_addr, taint_source, taint_sink)
        except Exception as e:
            source2sink_single_path["decompile_list"] = "Fail to Decompile by Ghidra"
        source2sink_result.append(source2sink_single_path)
    # 写回文件
    source2sink_result_file_name = "{}_source2sink_path_result.json".format(file_path_process)
    source2sink_result_file_path = os.path.join(config_sgtaint.TMP_DIR, source2sink_result_file_name)
    with open(source2sink_result_file_path, "w") as file:
        json.dump(source2sink_result, file, indent=4)
    # 删除中间文件
    command = "rm {}".format(source2sink_file_path)
    execute(command)
    # 针对get2set路径
    get2set_file_name = "{}_get2set_path.json".format(file_path_process)
    get2set_file_path = os.path.join(config_sgtaint.TMP_DIR, get2set_file_name)
    with open(get2set_file_path, "r") as file:
        get2set_ghidra_list = json.load(file)
    get2set_result = []
    for get2set_single_path in get2set_ghidra_list:
        function_ghidra_format = get2set_single_path["ghidra_path"]
        taint_source = get2set_single_path["taint_source"]
        taint_sink = get2set_single_path["taint_sink"]
        try:
            get2set_single_path["decompile_list"] = get_function_decompile_list_by_path(program, function_ghidra_format, angr_base_addr, taint_source, taint_sink)
        except Exception as e:
            get2set_single_path["decompile_list"] = "Fail to Decompile by Ghidra"
        get2set_result.append(get2set_single_path)
    # 写回文件
    get2set_result_file_name = "{}_get2set_path_result.json".format(file_path_process)
    get2set_result_file_path = os.path.join(config_sgtaint.TMP_DIR, get2set_result_file_name)
    with open(get2set_result_file_path, "w") as file:
        json.dump(get2set_result, file, indent=4)
    # 删除中间文件
    command = "rm {}".format(get2set_file_path)
    execute(command)
    

if __name__ == "__main__":
    program = getCurrentProgram() # type: ignore
    # 获取传递的参数
    args = list(getScriptArgs()) # type: ignore
    angr_base_addr = int(args[0], 16)
    get_decompile_result_binary(program, angr_base_addr)