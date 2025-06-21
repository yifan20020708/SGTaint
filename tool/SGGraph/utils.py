# -*- coding: utf-8 -*-
import shlex
import ast  
import json
import random
import re
import logging
import tool.Config.config as config_sgtaint
from collections import defaultdict, deque
from archinfo import Endness
from angr.project import Project
from angr.analyses.cfg.cfg_fast import CFGFast

logger = logging.getLogger("sgtaint.sggraph")

# 参数传递寄存器列表
_ordered_argument_regs_names = {
    'ARMEL': ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12'],
    'AARCH64': ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7'],
    'MIPS32': ['a0', 'a1', 'a2', 'a3']
}

# 通过寄存器index获取寄存器名称
def arg_reg_name(project, idx):
    return _ordered_argument_regs_names[project.arch.name][idx]

# 获取前n个参数寄存器（不提供n参数时，获取所有的参数寄存器名称）
def arg_reg_names(project, n = -1):
    if n < 0:
        return _ordered_argument_regs_names[project.arch.name]
    return _ordered_argument_regs_names[project.arch.name][:n]

# 执行任意命令
def execute(command):
    from subprocess import check_output, STDOUT
    command = "{}; exit 0".format(command)
    return check_output(command, stderr=STDOUT, shell=True).decode("utf-8")

# 找到文件系统中所有的二进制文件
def find_binary_path(directory):
    command = 'find ' + directory + ' -type f -exec file {} \; | grep -Ei "ELF|executable" | cut -d: -f1'
    res = execute(command)
    binary_path = list(set(res.split("\n")))
    return binary_path

# 在console中打印绿色文本
def print_green(msg):
    print(f"\033[32m{msg}\033[0m")
    
# 字典列表的去重
def dedupe_paths(path_list):
    seen = set()
    unique = []
    for entry in path_list:
        # 将 dict 转为 JSON 字符串；sort_keys=True 确保 key 顺序一致
        key = json.dumps(entry, sort_keys=True)
        if key not in seen:
            seen.add(key)
            unique.append(entry)
    return unique

# 直接从给定内存读取字符串
def get_mem_string(mem_bytes, extended=False):
    tmp = ''
    chars = config_sgtaint.EXTENDED_ALLOWED_CHARS if extended else config_sgtaint.ALLOWED_CHARS
    for c in mem_bytes:
        c_ascii = chr(c)
        if c_ascii not in chars:
            break
        tmp += c_ascii
    return tmp

# 判断一个文件是否为二进制文件
def is_binary_file(filepath):
    command = f"file {filepath}"
    result = execute(command)
    if "ELF" in result or "binary" in result:
        return True
    return False


# 获取指定函数名称的调用信息
def get_call_site_func_name(project: Project, cfg: CFGFast, func_name):
    target_func = [func for func in project.kb.functions.values() if func.name == func_name]
    if not target_func:
        print(f"[-] Function {func_name} not found.")
        return None
    target_func = target_func[0]
    call_sites = set() # 其中的元素为三元组，（调用点地址，调用函数名称，所在block初始地址）
    # 根据项目架构设置调用指令过滤集合
    arch = project.arch.name.lower()
    if "arm" in arch:
        call_mnemonics = {"bl", "blx"}
    elif "mips" in arch:
        call_mnemonics = {"call", "jal", "jalr"}
    else:
        call_mnemonics = {"call"}
    for src, dst, data in cfg.graph.edges(data = True):
        jk = data.get("jumpkind", "")
        if dst.addr == target_func.addr and jk in {"Ijk_Call", "Ijk_Jal"}: # 找到对应的函数跳转
            block = project.factory.block(src.addr)
            for insn in block.capstone.insns:
                mnemonic = insn.insn.mnemonic.lower() # 需要考虑到jalr命令
                if mnemonic == "jalr": # 若其为寄存器跳转
                    caller_func = cfg.kb.functions.floor_func(src.addr)
                    call_sites.add((insn.address, caller_func.addr, src.addr))
                elif mnemonic in call_mnemonics:
                    # 检查该指令是否带有立即数操作数，并且该立即数等于目标函数地址
                    if insn.insn.operands and hasattr(insn.insn.operands[0], "imm"):
                        if insn.insn.operands[0].imm == target_func.addr:
                            caller_func = cfg.kb.functions.floor_func(src.addr)
                            call_sites.add((insn.address, caller_func.addr, src.addr))
    call_sites = sorted(call_sites, key=lambda x: x[0]) # 按照调用点地址排序
    return call_sites # 返回为列表形式


# 将VEX指令中的常量BVV解析成字符串或立即数
def constant_parameter_parsing(project: Project, mem_addr, min_length=True, const_int=True, extended=True):
    # 判断是否为立即数
    bin_bounds = (project.loader.main_object.min_addr, project.loader.main_object.max_addr)
    if const_int:
        if mem_addr < bin_bounds[0]:
            return mem_addr
    try:
        cnt = project.loader.memory.load(mem_addr, config_sgtaint.STR_LEN)
    except KeyError:
        cnt = ''
    # string_1 对应直接指向的字符串地址
    string_1 = get_mem_string(cnt, extended=extended)
    string_2 = ''
    string_3 = ''
    string_4 = ''
    try:
        endianness = 'little' if project.arch.memory_endness == Endness.LE else 'big'
        ind_addr = int.from_bytes(project.loader.memory.load(mem_addr, project.arch.bytes), endianness)
        if bin_bounds[0] <= ind_addr <= bin_bounds[1]:
            cnt = project.loader.memory.load(ind_addr, config_sgtaint.STR_LEN)
            # String_2 对应mem_addr中对应地址中的字符串
            string_2 = get_mem_string(cnt)
        # 若其中存储的是一个偏移量
        tmp_addr = (ind_addr + project.loader.main_object.sections_map['.got'].min_addr) & (2 ** project.arch.bits - 1)
        cnt = project.loader.memory.load(tmp_addr, config_sgtaint.STR_LEN)
        string_3 = get_mem_string(cnt)
        # mem_addr直接为偏移量
        tmp_addr = (mem_addr + project.loader.main_object.sections_map['.got'].min_addr) & (2 ** project.arch.bits - 1)
        cnt = project.loader.memory.load(tmp_addr, config_sgtaint.STR_LEN)
        string_4 = get_mem_string(cnt)

    except KeyError:
        pass
    # 选择出其中最长的字符串
    candidate = string_1 if len(string_1) > len(string_2) else string_2
    candidate2 = string_3 if len(string_3) > len(string_4) else string_4
    candidate = candidate if len(candidate) > len(candidate2) else candidate2
    if not min_length:
        return candidate
    if len(candidate) >= config_sgtaint.MIN_STR_LEN:
        return candidate
    else:
        print(f"[-] The given memory address {mem_addr} cannot be correctly resolved to a constant!")
        return None
    
    
# 获取基本块中函数调用寄存器的操作指令
def find_site_args_insn(project: Project, block_addr):
    insn_set = []
    block = project.factory.block(block_addr)
    for reg_name in arg_reg_names(project):
        put_stmts = [s for s in block.vex.statements if s.tag == 'Ist_Put' and project.arch.register_names[s.offset] == reg_name]
        if not put_stmts:
            break
        put_stmt = put_stmts[-1]
        stmt_idx = block.vex.statements.index(put_stmt)
        inst_addr = [x.addr for x in block.vex.statements[:stmt_idx] if hasattr(x, 'addr')][-1]
        insn_set.append((inst_addr, put_stmt))
    return insn_set


# 使用index解析基本块中过函数调用中参数的值
def parameter_parsing_by_index(project, block_addr, index, value_tag = False):
    try:
        insn_set = find_site_args_insn(project, block_addr)
        if index > len(insn_set) - 1:
            logger.warning(f"Call site at 0x{block_addr:x} has only {len(insn_set)} arguments; requested index {index} is out of range.")
            return False if value_tag else None
        instruction = insn_set[index]
        if instruction[1].data.tag == "Iex_Const":
            return True if value_tag else constant_parameter_parsing(project, instruction[1].data.con.value)
        else:
            return False if value_tag else None
    except Exception as e:
        logger.exception(f"Failed to parse parameter at block 0x{block_addr:x}, index={index}: {e}")
        return False if value_tag else None
    

# 给定反汇编后的代码行提取对应的函数调用内容
def get_call_site_func_name_from_line(line, call_site_name):
    stack_line = [] # 用于处理嵌套的括号问题
    offset_start = 0
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
    stack_line.append('(')
    while offset_finish < len(line):
        if line[offset_finish] == '(':
            stack_line.append('(')
        elif line[offset_finish] == ')':
            stack_line.pop()
            if not stack_line:
                offset_finish += 1
                break
        offset_finish += 1
    return offset_start, offset_finish

    
# 根据反编译代码获取函数调用参数信息辅助函数
def get_args_string_call_sites(project, cfg, func_addr, call_site_name):
     # 获取目标函数
    target = project.kb.functions.get(func_addr)
    if not target:
        print(f"[-] Function at address {func_addr:#x} not found.")
        return []
    # 反编译
    dec = project.analyses.Decompiler(target, cfg=cfg)
    text = dec.codegen.text
    pos2addr = dec.codegen.map_pos_to_addr
    # 按行拆分并保留换行符，用于统一行偏移和输出
    lines = text.splitlines(keepends=True)
    # 计算每行的起始偏移
    line_starts = []
    offset = 0
    call_site_offset = []
    for ln in lines:
        line_starts.append(offset)
        if call_site_name in ln:
            offset_start, offset_finish = get_call_site_func_name_from_line(ln, call_site_name)
            if offset_start is not None and offset_finish is not None:
                call_site_offset.append((offset + offset_start, offset + offset_finish, ln))
        offset += len(ln)
    call_site_dict = {}
    for start_off, end_off, ln in call_site_offset:
        # 对该行内所有字符逐个扫描
        pos_set = set()
        for pos in range(start_off, end_off):
            elem = pos2addr.get_element(pos)
            if not elem:
                continue
            ins_addr = elem.obj.tags.get("ins_addr")
            if ins_addr is not None:
                pos_set.add(ins_addr)
        for pos_single in pos_set: # 存在不精确的识别情况
            call_site_dict[hex(pos_single)] = [ln, text[start_off:end_off]]
    return call_site_dict # 返回提取结果


# 根据函数调用信息获取对应的反汇编代码
def get_decompiled_code_by_call_site(project: Project, call_site_address, block_addr, func_decompile_code_snippet):
    if hex(call_site_address) in func_decompile_code_snippet: 
        return func_decompile_code_snippet[hex(call_site_address)]
    block = project.factory.block(block_addr)
    ins_addrs = set(block.instruction_addrs)
    for ins_addr in ins_addrs:
        if hex(ins_addr) in func_decompile_code_snippet:
            return func_decompile_code_snippet[hex(ins_addr)]
    return None


# 根据反编译结果提取函数调用的参数
def get_parameters_by_code(call_site_code):
    argument_list = []
    start_point = 0
    while call_site_code[start_point] != '(':
        start_point += 1
    start_point += 1
    while start_point < len(call_site_code) - 1:
        parameter = "" # 提取的对应参数内容
        # 首先跳过提取内容之前的空格
        while start_point < len(call_site_code) and call_site_code[start_point] == " ":
            start_point += 1
        # 若提取内容为字符串，以"或'开头
        if call_site_code[start_point] == '"':
            parameter += call_site_code[start_point]
            start_point += 1
            while start_point < len(call_site_code) - 1 and call_site_code[start_point] != '"':
                parameter += call_site_code[start_point]
                start_point += 1
            parameter += call_site_code[start_point]
            argument_list.append(parameter)
            start_point += 1
            while start_point < len(call_site_code) - 1 and call_site_code[start_point] != ',':
                start_point += 1
            start_point += 1
        elif call_site_code[start_point] == "'":
            parameter += call_site_code[start_point]
            start_point += 1
            while start_point < len(call_site_code) - 1 and call_site_code[start_point] != "'":
                parameter += call_site_code[start_point]
                start_point += 1
            parameter += call_site_code[start_point]
            argument_list.append(parameter)
            start_point += 1
            while start_point < len(call_site_code) - 1 and call_site_code[start_point] != ',':
                start_point += 1
            start_point += 1
        # 提取非字符串的内容
        else: # 非字符串的格式
            stack_argument = [] # 防止函数调用为参数
            while start_point < len(call_site_code) - 1:
                if call_site_code[start_point] == '(':
                    stack_argument.append('(')
                    parameter += call_site_code[start_point]
                elif call_site_code[start_point] == ',':
                    if not stack_argument:
                        start_point += 1
                        break
                    else:
                        parameter += call_site_code[start_point]
                elif call_site_code[start_point] == ')':
                    stack_argument.pop()
                    parameter += call_site_code[start_point]
                else:
                    parameter += call_site_code[start_point]
                start_point += 1
            argument_list.append(parameter)
    return argument_list


# 判断是否为字符串或常量内容
def is_const(project, parameter, file_path):
    if parameter.startswith('"') or parameter.startswith("'"):
        # 判断其是否出现在strings之中
        parameter = parameter[1:-1]
        safe_param = shlex.quote(parameter)
        command = f"strings {file_path} | grep -x {safe_param}"
        result = execute(command)
        unique_lines = list(set(line.strip() for line in result.splitlines() if line.strip()))
        return unique_lines[0] if unique_lines else False
    elif parameter.isdigit(): # 其为对应数字型的key
        return parameter
    elif parameter.startswith("0x") or parameter.startswith("0X"):  # 显式处理十六进制
        try:
            hex_addr = int(parameter, 16)
            return hex(hex_addr)
        except ValueError:
            return False
    else:
        m = config_sgtaint.pattern.match(parameter)
        if not m:
            return False
        hex_str = m.group(1)
        hex_addr = int(hex_str, 16)
        parse_const = constant_parameter_parsing(project, hex_addr, False)
        return parse_const

    
# 二进制文件的粗粒度筛选
def coarse_grained_binary_filter(get_function_name, key_set, directory):
    # 使用grep -rl命令获取包含get函数名称的二进制文件
    command = f"grep -rl {get_function_name} {directory}"
    candidate_files = execute(command).splitlines()
    if not candidate_files:
        return None
    pattern = "|".join(re.escape(k) for k in key_set) # 将关键字列表转换为正则表达式
    filtered_files = []
    for filepath in candidate_files:
        command = f"grep -E '{pattern}' {filepath}"
        if execute(command) and is_binary_file(filepath): # 过滤掉非二进制文件
            filtered_files.append(filepath)
            print(filepath)
    return filtered_files


# 将类表格式的字符串转化为对应的列表
def parse_set_get_string(set_get_string):
    set_get_string = re.sub(r'(?<!["\'])\b([a-zA-Z_][a-zA-Z0-9_]*)\b(?!["\'])', r"'\1'", set_get_string)
    raw_list = ast.literal_eval(set_get_string)
    parsed_list = []
    for item in raw_list:
        if len(item) == 2:
            parsed_list.append(item)
        elif len(item) == 6:
            parsed_item = [
                item[0],  # set_name
                item[1],  # get_name
                int(item[2]) if item[2] != "None" else None,
                int(item[3]) if item[3] != "None" else None,
                int(item[4]) if item[4] != "None" else None,
                int(item[5]) if item[5] != "None" else None,
            ]
            parsed_list.append(parsed_item)
    return parsed_list


# 给定边界二进制文件的地址，获取外部函数的名称列表
def get_extern_func_name(project: Project):
    extern = project.loader.extern_object
    extern_func = set() # 以集合的形式存储外部函数信息
    if extern: # 若extern段存在，使用其限制函数的地址范围
        start = extern.min_addr
        end = extern.max_addr
        for func in project.kb.functions.values():
            if func.addr >= start and func.addr <= end:
                extern_func.add((func.name, func.addr))
    else:
        for func in project.kb.functions.values():
            if not func.name.startswith("sub_"): # 过滤掉以sub_开头的函数
                extern_func.add((func.name, func.addr))
    return extern_func


# 解析函数调用内容
def parse_function_call(project, call_site_code, complete_line, file_path):
    has_const = False
    has_variable = False
    has_return = False
    parameter_list = []
    if '=' in complete_line:
        has_return = True
    args_call_site = get_parameters_by_code(call_site_code)
    for arg_call_site in args_call_site:
        parameter = is_const(project, arg_call_site, file_path)
        if parameter:
            parameter_list.append(parameter)
            has_const = True
        else:
            has_variable = True
    if has_const and has_variable:
        return parameter_list
    elif has_const and has_return:
        return parameter_list
    else:
        return False
    
    
# 为LLM分析的第二阶段生成提示词
def get_prompt_for_phase_two(func_name_eventually):
    prompt_eventually = ""
    for func_name in func_name_eventually:
        # 生成set函数调用的提示词
        set_func_name = func_name["set_func_name"]
        set_string = f"{set_func_name}: "
        index = 0
        for set_code in random.sample(func_name["set_code_list"], min(config_sgtaint.CODE_NUMBER, len(func_name["set_code_list"]))):
            index += 1
            set_string += f"({index}) {set_code} "
        # 生成get函数调用的提示词
        get_func_name = func_name["get_func_name"]
        get_string = f"{get_func_name}: "
        index = 0
        for get_code in random.sample(func_name["get_code_list"], min(config_sgtaint.CODE_NUMBER, len(func_name["get_code_list"]))):
            index += 1
            get_string += f"({index}) {get_code} "
        set_get_string = "{" + set_string + ", " + get_string + "}"
        prompt_eventually += set_get_string + ", "
    return f"[{prompt_eventually[:-2]}]"


# 依靠依赖关系生成二进制文件处理顺序
def generate_binary_processing_order_robust(analysis_binary_dict):
    # 生成依赖关系
    binary_path_list = list(analysis_binary_dict.analysis_binary_dict.keys())
    dependency_graph = defaultdict(set)
    reverse_graph = defaultdict(set)
    # 构建双向的依赖关系
    for binary_path in binary_path_list:
        analysis_binary = analysis_binary_dict.analysis_binary_dict[binary_path]
        for dep in analysis_binary.diffusion_file:
            if dep in binary_path_list:
                dependency_graph[binary_path].add(dep)
                reverse_graph[dep].add(binary_path)
    processing_order = []
    visited_binary_path = set()
    # 初始化0-依赖序列
    zero_dep_queue = deque([b for b in binary_path_list if not dependency_graph[b]])
    while len(visited_binary_path) < len(binary_path_list):
        while zero_dep_queue:
            current = zero_dep_queue.popleft()
            if current in visited_binary_path:
                continue
            processing_order.append(current)
            visited_binary_path.add(current)
            # 移除所有的依赖关系
            for dependent in reverse_graph[current]:
                dependency_graph[dependent].discard(current)
                if not dependency_graph[dependent]:
                    zero_dep_queue.append(dependent)
        # 若存在循环依赖关系（一般不会存在）
        if len(visited_binary_path) < len(binary_path_list):
            # 找到最少依赖的节点
            remaining_nodes = [b for b in binary_path_list if b not in visited_binary_path]
            min_dep_node = min(remaining_nodes, key=lambda b: len(dependency_graph[b]))
            processing_order.append(min_dep_node)
            visited_binary_path.add(min_dep_node)
            # 移除所有的依赖关系
            for dependent in reverse_graph[min_dep_node]:
                dependency_graph[dependent].discard(min_dep_node)
                if not dependency_graph[dependent]:
                    zero_dep_queue.append(dependent)
    logger.info(f"Binary processing order generated. Total binaries: {len(processing_order)}")
    for idx, binary_path in enumerate(processing_order):
        logger.debug(f"[{idx}] {binary_path}")
    return processing_order