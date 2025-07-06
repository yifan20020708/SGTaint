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


# 判断是否为完整的调用语句
def is_complete_call_site(call_site_code):
    if call_site_code[-1] not in (";", ")", "{"):
        return False
    if call_site_code.count("(") != call_site_code.count(")"):
        return False
    return True


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


# 根据函数调用名称获取函数调用点地址
def get_call_site_addr_by_func_name(lines, call_site_name):
    call_site_dict = {} # 键值为函数调用的地址
    for idx, clang_line in enumerate(lines):
        line_text = clang_line.toString()
        if call_site_name in line_text:
            for clang_token in clang_line.getAllTokens():
                if clang_token.getText() == call_site_name:
                    min_addr = clang_token.getMinAddress().getOffset() # 获取对应call_site的地址
                    call_site_dict[min_addr] = idx
                    break
    return call_site_dict       


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
            

# 根据行号提取地址进行匹配
def get_function_decompile_block2block_cached(program, identifier, start_block_start, start_block_end, end_block_start, end_block_end):
    # 获取反编译结果
    decompile_result = get_function_decompile(program, identifier)
    if not decompile_result:
        return None
    pseudo_code, lines = decompile_result
    pseudo_code_lines = pseudo_code.splitlines()
    start_index_list = []
    finish_index_list = []
    for i in range(len(lines)):
        clang_line = lines[i]
        min_addr, max_addr = get_line_address_range(clang_line)
        if start_block_start <= max_addr <= start_block_end or start_block_start <= min_addr <= start_block_end:
            start_index_list.append(i)
        if end_block_start <= max_addr <= end_block_end or end_block_start <= min_addr <= end_block_end:
            finish_index_list.append(i)
    print("[+] Decompilation result for function {}:".format(identifier))
    return pseudo_code_lines, lines, start_index_list, finish_index_list
            

def get_function_decompile_list_by_path(program, function_ghidra_format, angr_base_addr, taint_source, taint_sink):
    function_decompile_list = []
    for idx, function_format in enumerate(function_ghidra_format):
        func_addr, start_block_start, start_block_end, end_block_start, end_block_end = function_format
        if end_block_start < start_block_start: # 无效的代码片段
            return ["Invaild code snippet"]
        # 进行angr到ghidra的地址转换
        func_addr = base_addr_transform_angr2ghidra(program, angr_base_addr, func_addr)
        start_block_start = base_addr_transform_angr2ghidra(program, angr_base_addr, start_block_start)
        start_block_end = base_addr_transform_angr2ghidra(program, angr_base_addr, start_block_end)
        end_block_start = base_addr_transform_angr2ghidra(program, angr_base_addr, end_block_start)
        end_block_end = base_addr_transform_angr2ghidra(program, angr_base_addr, end_block_end)
        # 首先根据行号进行地址匹配
        result = get_function_decompile_block2block_cached(program, func_addr, start_block_start, start_block_end, end_block_start, end_block_end)
        if not result: # ghidra反编译失败或函数识别失败
            return ["Fail to Decompile by Ghidra"]
        pseudo_code_lines, lines, start_index_list, finish_index_list = result
        # 获取start_index
        if idx == 0: # 处理第一个含有source的片段
            start_index = next((i for i in start_index_list if taint_source in pseudo_code_lines[i]), None) # start_index并不向上补充
            if start_index is None: # 使用函数名称包含处理异常情况
                call_site_dict = get_call_site_addr_by_func_name(lines, taint_source)
                if not call_site_dict: # 反编译函数中不包含taint_source
                    return ["Fail to Decompile by Ghidra"]
                start_index = find_nearest_call_site(call_site_dict, start_block_start, start_block_end)
        else: # 其他片段均从函数开始处理
            for i, line in enumerate(pseudo_code_lines):
                if line.strip(): # 找到第一个非空的行
                    start_index = i
                    break
        # 获取end_index
        if idx == len(function_ghidra_format) - 1: # 最后一个代码片段
            target_func_name = taint_sink
        else: # 其他代码片段的结尾为调用函数的函数名称
            next_func_addr = base_addr_transform_angr2ghidra(program, angr_base_addr, function_ghidra_format[idx + 1][0])
            next_func = get_function(program, next_func_addr)
            if not next_func: # 不能识别此函数
                return ["Fail to Decompile by Ghidra"]
            target_func_name = next_func.getName()
        end_index = next((i for i in finish_index_list if target_func_name in pseudo_code_lines[i]), None) # end_index需要向下补充完整
        if end_index is None: # 使用函数名称包含处理异常情况
            call_site_dict_unfilter = get_call_site_addr_by_func_name(lines, target_func_name)
            call_site_dict = {addr: idx for addr, idx in call_site_dict_unfilter.items() if idx >= start_index}
            if not call_site_dict:
                return ["Fail to Decompile by Ghidra"]
            end_index = find_nearest_call_site(call_site_dict, end_block_start, end_block_end)
        # end_index向下补充完整
        if not is_complete_call_site(pseudo_code_lines[end_index]):
            while end_index < len(pseudo_code_lines) and pseudo_code_lines[end_index][-1] not in (";", ")", "{"):
                end_index += 1
        # 使用start_index以及end_index截取片段
        code_snippet_list = pseudo_code_lines[start_index:end_index + 1]
        code_snippet = "\n".join(code_snippet_list)
        function_decompile_list.append(code_snippet)
    return function_decompile_list


# 反汇编二进制文件获取的source2sink路径以及get2set路径
def get_decompile_result_binary(program, angr_base_addr):
    # 读取对应的json文件，针对source2sink路径
    file_path_process = program.getExecutablePath().replace("/", "_")
    source2sink_file_name = "{}_source2sink_path.json".format(file_path_process)
    source2sink_file_path = os.path.join(config_sgtaint.BINARY_TMP, source2sink_file_name)
    with open(source2sink_file_path, "r") as file:
        source2sink_ghidra_list = json.load(file)
    source2sink_result = []
    for source2sink_single_path in source2sink_ghidra_list:
        function_ghidra_format = source2sink_single_path["ghidra_path"]
        taint_source = source2sink_single_path["taint_source"]
        if taint_source.startswith("sub_"):
            taint_source_addr = base_addr_transform_angr2ghidra(program, angr_base_addr, source2sink_single_path["taint_source_addr"])
            taint_source_func = get_function(program, taint_source_addr)
            taint_source = taint_source_func.getName() if taint_source_func else None
        taint_sink = source2sink_single_path["taint_sink"]   
        if taint_sink.startswith("sub_"):
            taint_sink_addr = base_addr_transform_angr2ghidra(program, angr_base_addr, source2sink_single_path["taint_sink_addr"])
            taint_sink_func = get_function(program, taint_sink_addr)
            taint_source = taint_sink_func.getName() if taint_sink_func else None
        if taint_source and taint_sink:
            source2sink_single_path["decompile_list"] = get_function_decompile_list_by_path(program, function_ghidra_format, angr_base_addr, taint_source, taint_sink)
        else:
            source2sink_single_path["decompile_list"] = ["Fail to Decompile by Ghidra"]
        source2sink_result.append(source2sink_single_path)
    # 写回文件
    source2sink_result_file_name = "{}_source2sink_path_result.json".format(file_path_process)
    source2sink_result_file_path = os.path.join(config_sgtaint.BINARY_TMP, source2sink_result_file_name)
    with open(source2sink_result_file_path, "w") as file:
        json.dump(source2sink_result, file, indent=4)
    # 删除中间文件
    command = "rm {}".format(source2sink_file_path)
    execute(command)
    # 针对get2set路径
    get2set_file_name = "{}_get2set_path.json".format(file_path_process)
    get2set_file_path = os.path.join(config_sgtaint.BINARY_TMP, get2set_file_name)
    with open(get2set_file_path, "r") as file:
        get2set_ghidra_list = json.load(file)
    get2set_result = []
    for get2set_single_path in get2set_ghidra_list:
        function_ghidra_format = get2set_single_path["ghidra_path"]
        taint_source = get2set_single_path["taint_source"]
        if taint_source.startswith("sub_"):
            taint_source_addr = base_addr_transform_angr2ghidra(program, angr_base_addr, get2set_single_path["taint_source_addr"])
            taint_source_func = get_function(program, taint_source_addr)
            taint_source = taint_source_func.getName() if taint_source_func else None
        taint_sink = get2set_single_path["taint_sink"]   
        if taint_sink.startswith("sub_"):
            taint_sink_addr = base_addr_transform_angr2ghidra(program, angr_base_addr, get2set_single_path["taint_sink_addr"])
            taint_sink_func = get_function(program, taint_sink_addr)
            taint_source = taint_sink_func.getName() if taint_sink_func else None
        if taint_source and taint_sink:
            get2set_single_path["decompile_list"] = get_function_decompile_list_by_path(program, function_ghidra_format, angr_base_addr, taint_source, taint_sink)
        else:
            get2set_single_path["decompile_list"] = ["Fail to Decompile by Ghidra"]
        get2set_result.append(get2set_single_path)
    # 写回文件
    get2set_result_file_name = "{}_get2set_path_result.json".format(file_path_process)
    get2set_result_file_path = os.path.join(config_sgtaint.BINARY_TMP, get2set_result_file_name)
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