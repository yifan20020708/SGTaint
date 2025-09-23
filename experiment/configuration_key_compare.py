# -*- coding: utf-8 -*-
import os
import re
import csv
import json
import time
import math
import angr
import shlex
import string
import pickle
import numpy as np
import pandas as pd
import multiprocessing
import concurrent.futures
import matplotlib.pyplot as plt
from archinfo import Endness
from angr.project import Project
from angr.analyses.cfg.cfg_fast import CFGFast
from matplotlib.ticker import FuncFormatter
from matplotlib.lines import Line2D
import matplotlib.patheffects as pe

MIN_STR_LEN = 3
CODE_NUMBER = 3
STR_LEN = 255
ALLOWED_CHARS = string.digits + string.ascii_letters + "-/_"
EXTENDED_CHARS = "%,.:;+=)(*&^%$#@!~`|<>{}[] "
EXTENDED_ALLOWED_CHARS = ALLOWED_CHARS + EXTENDED_CHARS
# angr中常见的前缀
PREFIXES = [
    "g", "dword", "word", "byte", "qword",
    "float", "double", "unk", "off",
    "sub", "loc", "FUN", "LAB", "DATA", "ptr", "DAT"
]
# 构造正则：^(?:前缀1|前缀2|...?)_([0-9A-Fa-f]+)$
pattern = re.compile(
    r'^&?(?:' + '|'.join(map(re.escape, PREFIXES)) + r')_([0-9A-Fa-f]+)$'
)

# 参数传递寄存器列表
_ordered_argument_regs_names = {
    'ARMEL': ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12'],
    'AARCH64': ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7'],
    'MIPS32': ['a0', 'a1', 'a2', 'a3']
}

# 执行任意命令
def execute(command):
    from subprocess import check_output, STDOUT
    command = "{}; exit 0".format(command)
    return check_output(command, stderr=STDOUT, shell=True).decode("utf-8")

# 获取前n个参数寄存器（不提供n参数时，获取所有的参数寄存器名称）
def arg_reg_names(project, n = -1):
    if n < 0:
        return _ordered_argument_regs_names[project.arch.name]
    return _ordered_argument_regs_names[project.arch.name][:n]

# 直接从给定内存读取字符串
def get_mem_string(mem_bytes, extended=False):
    tmp = ''
    chars = EXTENDED_ALLOWED_CHARS if extended else ALLOWED_CHARS
    for c in mem_bytes:
        c_ascii = chr(c)
        if c_ascii not in chars:
            break
        tmp += c_ascii
    return tmp

# 将VEX指令中的常量BVV解析成字符串或立即数
def constant_parameter_parsing(project: Project, mem_addr, min_length=True, const_int=True, extended=True):
    # 判断是否为立即数
    bin_bounds = (project.loader.main_object.min_addr, project.loader.main_object.max_addr)
    if const_int:
        if mem_addr < bin_bounds[0]:
            return mem_addr
    try:
        cnt = project.loader.memory.load(mem_addr, STR_LEN)
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
            cnt = project.loader.memory.load(ind_addr, STR_LEN)
            # String_2 对应mem_addr中对应地址中的字符串
            string_2 = get_mem_string(cnt)
        # 若其中存储的是一个偏移量
        tmp_addr = (ind_addr + project.loader.main_object.sections_map['.got'].min_addr) & (2 ** project.arch.bits - 1)
        cnt = project.loader.memory.load(tmp_addr, STR_LEN)
        string_3 = get_mem_string(cnt)
        # mem_addr直接为偏移量
        tmp_addr = (mem_addr + project.loader.main_object.sections_map['.got'].min_addr) & (2 ** project.arch.bits - 1)
        cnt = project.loader.memory.load(tmp_addr, STR_LEN)
        string_4 = get_mem_string(cnt)
    except KeyError:
        pass
    # 选择出其中最长的字符串
    candidate = string_1 if len(string_1) > len(string_2) else string_2
    candidate2 = string_3 if len(string_3) > len(string_4) else string_4
    candidate = candidate if len(candidate) > len(candidate2) else candidate2
    if not min_length:
        return candidate
    if len(candidate) >= MIN_STR_LEN:
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
            print(f"Call site at 0x{block_addr:x} has only {len(insn_set)} arguments; requested index {index} is out of range.")
            return False if value_tag else None
        instruction = insn_set[index]
        if instruction[1].data.tag == "Iex_Const":
            return True if value_tag else constant_parameter_parsing(project, instruction[1].data.con.value)
        else:
            return False if value_tag else None
    except Exception as e:
        print(f"Failed to parse parameter at block 0x{block_addr:x}, index={index}: {e}")
        return False if value_tag else None

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
    try:
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
    except Exception as e:
        return offset_start, offset_start + len(call_site_name)
    
# 遍历调用语句
def get_ins_addr_from_range(pos_range, pos2addr):
    for pos in pos_range:
        elem = pos2addr.get_element(pos)
        if elem:
            ins_addr = elem.obj.tags.get("ins_addr")
            if ins_addr is not None:
                return ins_addr
    return None

# 根据反编译代码获取函数调用参数信息辅助函数
def get_args_string_call_sites(project: Project, cfg: CFGFast, func_addr, call_site_name):
     # 获取目标函数
    target = project.kb.functions.get(func_addr)
    if not target:
        print(f"[-] Function at address {func_addr:#x} not found.")
        return []
    # 反编译
    try:
        dec = project.analyses.Decompiler(target, cfg=cfg)
        text = dec.codegen.text
        pos2addr = dec.codegen.map_pos_to_addr
    except Exception as e:
        print(f"Decompile failed on {func_addr:#x}: {e}")
        return {}
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
                call_site_offset.append((offset, offset + offset_start, offset + offset_finish, offset + len(ln), ln))
        offset += len(ln)
    call_site_info = []
    call_site_dict = {}
    for line_start, call_site_start, call_site_end, line_end, ln in call_site_offset:
        # 优先在call_site内部查找
        pos_range = range(call_site_start, call_site_end)
        ins_addr = get_ins_addr_from_range(pos_range, pos2addr)
        # 若其中没有找到，向后查找
        if ins_addr is None:
            pos_range = range(call_site_end, line_end)
            ins_addr = get_ins_addr_from_range(pos_range, pos2addr)
        # 若没有找到，逆向向前查找
        if ins_addr is None:
            pos_range = range(call_site_start - 1, line_start - 1, -1)
            ins_addr = get_ins_addr_from_range(pos_range, pos2addr)
        if ins_addr is not None: # 仅当识别成功的情况下直接加入到集合中
            call_site_info.append((ins_addr, ln, text[call_site_start:call_site_end])) # 按照识别出的指令地址进行排序，利用相对位置的一致性
    call_site_info = sorted(call_site_info, key=lambda x: x[0])
    # 修正函数调用地址
    call_sites = get_call_site_func_name(project, cfg, call_site_name)
    call_sites_function = [call_site_addr for call_site_addr, caller_addr, _ in call_sites if caller_addr == func_addr] # 按照call_site_addr进行排序
    if len(call_site_info) != len(call_sites_function): # 若不匹配直接返回
        for ins_addr, ln, call_site_code in call_site_info:
            call_site_dict[hex(ins_addr)] = [ln, call_site_code]
    else: # 一般情况均满足
        for idx, call_site_addr in enumerate(call_sites_function): # 使用相对关系进行对应
            _, ln, call_site_code = call_site_info[idx]
            ins_addr = call_site_addr
            call_site_dict[hex(ins_addr)] = [ln, call_site_code]
    return call_site_dict # 返回提取结果

def worker_wrapper(q, target_func, project, cfg, func_name, func_addr):
    try:
        result = target_func(project, cfg, func_name, func_addr)
        q.put(('success', result))
    except Exception as e:
        q.put(('error', e))

# 手动管理进程，超时直接清除
def run_with_timeout(target_func, project, cfg, func_name, func_addr, timeout):
    q = multiprocessing.Queue()
    p = multiprocessing.Process(
        target=worker_wrapper,
        args=(q, target_func, project, cfg, func_name, func_addr)
    )
    p.start()
    p.join(timeout)
    if p.is_alive():
        p.terminate()
        p.join()
        raise TimeoutError(f"Task for {hex(func_addr)} timed out.")
    if not q.empty():
        status, data = q.get()
        if status == 'success':
            return data
        else:
            raise data
    raise TimeoutError(f"No result returned for {hex(func_addr)}.")

# 针对单个函数的angr反汇编
def decompile_single_func(project, cfg, func_name, func_addr):
    call_site_dict = get_args_string_call_sites(project, cfg, func_addr, func_name)
    if call_site_dict:
        return call_site_dict    
    return None

# 使用angr并行反编译函数
def parallel_decompile_funcs(ghidra_func_identify_failed, project, cfg, func_name, timeout_seconds=120):
    func_decompile_code_snippet = {}
    total = len(ghidra_func_identify_failed)
    start_time = time.time()
    def task_wrapper(func_addr):
        try:
            call_site_dict = run_with_timeout(decompile_single_func, project, cfg, func_name, func_addr, timeout=timeout_seconds)
            return (func_addr, 'success', call_site_dict)
        except TimeoutError:
            return (func_addr, 'timeout', None)
        except Exception as e:
            return (func_addr, 'error', str(e))
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {
            executor.submit(task_wrapper, func_addr): func_addr
            for func_addr in ghidra_func_identify_failed
        }
        for idx, future in enumerate(concurrent.futures.as_completed(futures), 1):
            try:
                addr, status, call_site_dict = future.result()
                if status == 'success':
                    print(f"[{idx}/{total}] Decompilation of {hex(addr)} from angr success.")
                    if call_site_dict:
                        func_decompile_code_snippet.update(call_site_dict)
                elif status == 'timeout':
                    print(f"[{idx}/{total}] Timeout during decompilation of {hex(addr)}")
                else:
                    print(f"[{idx}/{total}] Decompilation of {hex(addr)} error: {call_site_dict}")
            except Exception as e:
                print(f"[{idx}/{total}] Exception during decompilation of {hex(addr)}: {e}")
    duration = time.time() - start_time
    print(f"Completed parallel decompilation of {total} functions in {duration:.2f} seconds")
    return func_decompile_code_snippet

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
    # 处理特殊情况
    if not call_site_code or '(' not in call_site_code:
        # 加日志说明传入非法代码字符串
        print(f"Invalid call_site_code: '{call_site_code}'")
        return []
    # 加入异常处理
    try:
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
    except IndexError as e:
        print(f"IndexError while parsing call site: {repr(call_site_code)} - {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
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
        m = pattern.match(parameter)
        if not m:
            return False
        hex_str = m.group(1)
        hex_addr = int(hex_str, 16)
        parse_const = constant_parameter_parsing(project, hex_addr, False)
        return parse_const

# （快速获取）针对指定的函数名称获取直接进行参数赋值的key，同样需要对第二个参数进行过滤
def get_set_func_args_fast(project, cfg, func_name, index_key, index_value = None):
    start_time = time.time()
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
            call_sites_parser.append([call_site_address, caller, block_addr, str(key)])
    success_rate = (number - number_vsa) / number if number != 0 else 0
    end_time = time.time()
    elapsed_time = end_time - start_time
    return call_sites_parser, success_rate, elapsed_time, number, number - number_vsa

# （辅助Ghidra获取）使用Ghidra的反编译工具进行对应的关键字提取
def get_keyword_by_decompiled_func_ghidra(project, cfg, func_name, file_path, index_key, index_value = None):
    start_time = time.time()
    call_sites = get_call_site_func_name(project, cfg, func_name)
    unique_callers = list({caller for _, caller, _ in call_sites})
    # 保存为json文件传递给Ghidra程序
    caller_file_name = f"{func_name}_caller_addr.json"
    caller_file_path = os.path.join("/home/SGTaint/tmp", caller_file_name)
    with open(caller_file_path, "w") as file:
        json.dump(unique_callers, file, indent=4)
    # 构造执行Ghidra脚本的命令
    angr_base_addr = hex(project.loader.main_object.min_addr)
    binary_path_split = file_path.split("/")
    ghidra_path = os.path.join("/home/Experiment/tmp/ghidra", binary_path_split[5])
    if not os.path.exists(ghidra_path):
        os.makedirs(ghidra_path)
    binary_mark = os.path.basename(file_path)
    if not os.path.exists(os.path.join(ghidra_path, f"{binary_mark}.gpr")):
        ghidra_python_path = "/home/SGTaint/tool/Ghidra/enable_aggressive_all.py"
        ghidra_load_command = f"/home/SGTaint/ghidra_tool/support/analyzeHeadless {ghidra_path} {binary_mark} -import {file_path} -preScript {ghidra_python_path}"
        execute(ghidra_load_command) # 执行Ghidra脚本进行分析
    ghidra_python_path = "/home/SGTaint/tool/Ghidra/ghidra_assist.py"
    ghidra_command = f'/home/SGTaint/ghidra_tool/support/analyzeHeadless {ghidra_path} {binary_mark} -process {binary_mark} -noanalysis -postScript {ghidra_python_path} "{angr_base_addr}" "{func_name}"'
    print(f"Executing Ghidra command: {ghidra_command}")
    execute(ghidra_command)
    # 读取对应的结果文件
    caller_file_result_name = f"{func_name}_caller_parse_result.json"
    caller_file_result_path = os.path.join("/home/SGTaint/tmp", caller_file_result_name)
    try:
        with open(caller_file_result_path, "r") as file:
            caller_parse_result = json.load(file) # 反编译字典
            func_decompile_code_snippet = caller_parse_result.get("code_dict")
            ghidra_func_identify_failed = caller_parse_result.get("angr_assist")
    except Exception as e: # 识别失败，全部由Ghidra进行识别
        print(f"Unexpected error: {e}")
        func_decompile_code_snippet = {}
        ghidra_func_identify_failed = unique_callers[:]
    if os.path.exists(caller_file_result_path): # 删除对应的中间文件
        rm_command = f"rm {caller_file_result_path}"
        execute(rm_command)
    # 若存在Ghidra不可识别的函数，使用angr进行处理
    print(f"A total of {len(ghidra_func_identify_failed)} functions necessitate supplementary decompilation support through the use of angr.")
    # 并行执行angr的反编译操作
    func_decompile_code_snippet_from_angr = parallel_decompile_funcs(ghidra_func_identify_failed, project, cfg, func_name, timeout_seconds=120)
    func_decompile_code_snippet.update(func_decompile_code_snippet_from_angr)
    # 进行函数调用参数的解析
    call_sites_parser = []
    number = len(call_sites)
    number_success = 0
    for call_site_address, caller, block_addr in call_sites: # 需要使用其block信息
        decompiled_code = get_decompiled_code_by_call_site(project, call_site_address, block_addr, func_decompile_code_snippet)
        if decompiled_code is None:
            call_sites_parser.append([call_site_address, caller, block_addr, 0])
            continue
        args_call_site = get_parameters_by_code(decompiled_code[1])
        # 若存储的内容为常量则直接跳过
        if index_value and args_call_site and len(args_call_site) > index_value and is_const(project, args_call_site[index_value], file_path):
            number -= 1
            continue
        if args_call_site and len(args_call_site) > index_key:
            # 提取对应的关键字
            parameter = is_const(project, args_call_site[index_key], file_path)
            if parameter:
                number_success += 1
                call_sites_parser.append([call_site_address, caller, block_addr, parameter])
            else:
                call_sites_parser.append([call_site_address, caller, block_addr, -1])
        else: # 若没有对应的参数则直接跳过
            call_sites_parser.append([call_site_address, caller, block_addr, -1])
    success_rate = number_success / number if number != 0 else 0
    end_time = time.time()
    elapsed_time = end_time - start_time
    return call_sites_parser, success_rate, elapsed_time, number, number_success

# 增强型配置键获取方法
def get_set_func_args(project, cfg, func_name, file_path, index_key, index_value = None, fast_info = None, ghidra_info = None):
    # 快速获取配置键
    if fast_info is None:
        call_sites_parser, success_rate, elapsed_time_fast, number, number_success = get_set_func_args_fast(
            project, cfg, func_name, file_path, index_key, index_value)
    else:
        call_sites_parser, success_rate, elapsed_time_fast, number, number_success = fast_info
    # 成功率不足，使用Ghidra辅助获取
    if success_rate < 0.5:
        if ghidra_info is None:
            call_sites_parser, success_rate, elapsed_time_ghidra, number, number_success = get_keyword_by_decompiled_func_ghidra(project, cfg, func_name, file_path, index_key, index_value)
        else:
            call_sites_parser, success_rate, elapsed_time_ghidra, number, number_success = ghidra_info
        elapsed_time = elapsed_time_fast + elapsed_time_ghidra
    else:
        elapsed_time = elapsed_time_fast
    return call_sites_parser, success_rate, elapsed_time, number, number_success

# 三种配置键获取方法的对比
def compare_configuation_key_get_methods(binary_path, func_name, index_key, index_value = None):
    # 检查是否存在pickle文件
    binary_mark = binary_path.replace("/", "_")
    project_pickle_path = os.path.join("/home/Experiment/tmp/pickle", f"{binary_mark}_project.pickle")
    cfg_pickle_path = os.path.join("/home/Experiment/tmp/pickle", f"{binary_mark}_cfg.pickle")
    if os.path.exists(project_pickle_path) and os.path.exists(cfg_pickle_path):
        print(f"Loading existing project and CFG from {binary_mark} pickle files.")
        with open(project_pickle_path, 'rb') as f:
            project = pickle.load(f)
        with open(cfg_pickle_path, 'rb') as f:
            cfg = pickle.load(f)
    else:
        print(f"Creating new project and CFG for {binary_mark}.")
        project = angr.Project(binary_path, auto_load_libs=False,  use_sim_procedures=True, default_analysis_mode='symbolic', load_options={'auto_load_libs': False})
        project.analyses.CompleteCallingConventions(recover_variables=True, analyze_callsites=True)
        cfg = project.analyses.CFG(resolve_indirect_jumps=True, cross_references=True,
                                    force_complete_scan=False,
                                    normalize=True, symbols=True, data_references=True)
        # 保存项目和CFG到pickle文件
        with open(project_pickle_path, 'wb') as f:
            pickle.dump(project, f)
        with open(cfg_pickle_path, 'wb') as f:
            pickle.dump(cfg, f)
    # 快速获取配置键
    call_sites_parser_fast, success_rate_fast, elapsed_time_fast, number_fast, number_success_fast = get_set_func_args_fast(project, cfg, func_name, index_key, index_value)
    print(f"  Fast method: {len(call_sites_parser_fast)} call sites parsed, success rate: {success_rate_fast:.2f}, elapsed time: {elapsed_time_fast:.2f} seconds, number of calls: {number_fast}, successful calls: {number_success_fast}")
    write_result_to_csv(binary_path, func_name, "Fast", number_fast, number_success_fast, success_rate_fast, elapsed_time_fast)
    # Ghidra辅助获取配置键
    call_sites_parser_ghidra, success_rate_ghidra, elapsed_time_ghidra, number_ghidra, number_success_ghidra = get_keyword_by_decompiled_func_ghidra(project, cfg, func_name, binary_path, index_key, index_value)
    print(f"  Ghidra-assisted method: {len(call_sites_parser_ghidra)} call sites parsed, success rate: {success_rate_ghidra:.2f}, elapsed time: {elapsed_time_ghidra:.2f} seconds, number of calls: {number_ghidra}, successful calls: {number_success_ghidra}")
    write_result_to_csv(binary_path, func_name, "Ghidra", number_ghidra, number_success_ghidra, success_rate_ghidra, elapsed_time_ghidra)
    # 增强型配置键获取
    fast_info = (call_sites_parser_fast, success_rate_fast, elapsed_time_fast, number_fast, number_success_fast)
    ghidra_info = (call_sites_parser_ghidra, success_rate_ghidra, elapsed_time_ghidra, number_ghidra, number_success_ghidra)
    call_sites_parser_enhanced, success_rate_enhanced, elapsed_time_enhanced, number_enhanced, number_success_enhanced = get_set_func_args(project, cfg, func_name, binary_path, index_key, index_value, fast_info, ghidra_info)
    print(f"  Enhanced method: {len(call_sites_parser_enhanced)} call sites parsed, success rate: {success_rate_enhanced:.2f}, elapsed time: {elapsed_time_enhanced:.2f} seconds, number of calls: {number_enhanced}, successful calls: {number_success_enhanced}\n")
    write_result_to_csv(binary_path, func_name, "Enhanced", number_enhanced, number_success_enhanced, success_rate_enhanced, elapsed_time_enhanced)
    
BINARY_INFO = {
    "/home/firmware/New_dataset/D-Link/DIR-878/cpio-root/bin/prog.cgi": ['nvram_safe_set', 'nvram_safe_get', 0, 0, 1, None],
    "/home/firmware/New_dataset/D-Link/DIR-878/cpio-root/bin/rc": ['nvram_safe_set', 'nvram_safe_get', 0, 0, 1, None],
    "/home/firmware/New_dataset/D-Link/DIR-878/cpio-root/lib/librcm.so": ['nvram_safe_set', 'nvram_safe_get', 0, 0, 1, None],
    "/home/firmware/New_dataset/D-Link/DIR-823G/squashfs-root/bin/boa": ['apmib_set', 'apmib_get', 0, 0, 1, 1],
    "/home/firmware/New_dataset/D-Link/DIR-816/squashfs-root/bin/goahead": ['nvram_bufset', 'nvram_bufget', 1, 1, 2, None],
    "/home/firmware/New_dataset/Netgear/BE9300/squashfs-root/usr/sbin/net-cgi": ['config_set', 'config_get', 0, 0, 1, None],
    "/home/firmware/New_dataset/Netgear/EX6100/squashfs-root/usr/sbin/httpd": ['acosNvramConfig_set', 'acosNvramConfig_get', 0, 0, 1, None],
    "/home/firmware/New_dataset/Netgear/EX6120/squashfs-root/usr/sbin/httpd": ['acosNvramConfig_set', 'acosNvramConfig_get', 0, 0, 1, None],
    "/home/firmware/New_dataset/Netgear/R6200/squashfs-root/usr/sbin/httpd": ['acosNvramConfig_set', 'acosNvramConfig_get', 0, 0, 1, None],
    "/home/firmware/New_dataset/Netgear/R6300/squashfs-root/usr/sbin/httpd": ['acosNvramConfig_set', 'acosNvramConfig_get', 0, 0, 1, None],
    "/home/firmware/New_dataset/Netgear/R6350/squashfs-root/usr/sbin/setup.cgi": ['nvram_set', 'nvram_get', 0, 0, 1, None],
    "/home/firmware/New_dataset/Netgear/R7000P/squashfs-root/usr/sbin/httpd": ['acosNvramConfig_set', 'acosNvramConfig_get', 0, 0, 1, None],
    "/home/firmware/New_dataset/Netgear/WNR2000/squashfs-root/sbin/rcS": ['nvram_set', 'nvram_get', 0, 0, 1, None],
    "/home/firmware/New_dataset/Netgear/WNR2000/squashfs-root/bin/boa": ['nvram_set', 'nvram_get', 0, 0, 1, None],
    "/home/firmware/New_dataset/Linksys/E1200/router/httpd/httpd": ['nvram_set', 'nvram_get', 0, 0, 1, None],
    "/home/firmware/New_dataset/Linksys/E1200/router/httpd/httpd": ['nvram_set', 'nvram_get', 0, 0, 1, None]
}

CSV_PATH = "/home/Experiment/output/config_key_extraction_results.csv"
OUT_FIG = "/home/Experiment/output/Enhanced_Unified_Efficiency"
PLOT_DPI = 300
METHODS = ["Fast", "Ghidra", "Enhanced"]

# 将单条提取结果记录写入CSV。
def write_result_to_csv(binary_path, func_name, method_name, num_calls, num_success, success_rate, elapsed_time):
    CSV_SAVE_PATH = "/home/Experiment/output/config_key_extraction_results.csv"
    file_exists = os.path.exists(CSV_SAVE_PATH)
    with open(CSV_SAVE_PATH, mode="a", newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["Binary", "FuncName", "Method", "#Calls", "#Success", "SuccessRate", "Time(s)"])
        writer.writerow([binary_path, func_name, method_name, num_calls, num_success, f"{success_rate:.4f}", f"{elapsed_time:.4f}"])
        
def _t_multiplier(n):
    table = {5:2.776, 6:2.571, 7:2.447, 8:2.365, 9:2.306, 10:2.262,
             12:2.179, 15:2.131, 20:2.093, 25:2.060, 30:2.042, 40:2.021, 60:2.000}
    if n in table: return table[n]
    if n < 60:
        ks = sorted(table.keys())
        lo = max([k for k in ks if k <= n], default=10)
        hi = min([k for k in ks if k >= n], default=60)
        if lo == hi: return table[lo]
        return table[lo] + (table[hi] - table[lo]) * (n - lo) / (hi - lo)
    return 1.96

def _ci95(x: pd.Series):
    x = x.dropna().astype(float)
    n = len(x)
    if n <= 1:
        return np.nan
    sem = x.std(ddof=1) / math.sqrt(n)
    return _t_multiplier(n) * sem

def _to_numeric(df, cols):
    for c in cols:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    return df

def load_csv(csv_path):
    df = pd.read_csv(csv_path)
    req = {"Binary", "FuncName", "Method", "#Calls", "#Success", "SuccessRate", "Time(s)"}
    miss = req - set(df.columns)
    if miss:
        raise ValueError(f"CSV 缺少字段: {miss}")
    df = _to_numeric(df, ["#Calls", "#Success", "SuccessRate", "Time(s)"])
    # 丢弃非法/非正时间
    df = df[df["Time(s)"] > 0].copy()
    df["SampleKey"] = df["Binary"].astype(str) + " :: " + df["FuncName"].astype(str)
    df["SuccessPerSec"] = df["#Success"] / df["Time(s)"]
    return df

def build_pivot(df):
    piv_sr = df.pivot_table(index="SampleKey", columns="Method", values="SuccessRate", aggfunc="mean")
    piv_t  = df.pivot_table(index="SampleKey", columns="Method", values="Time(s)",     aggfunc="mean")
    valid = piv_sr[METHODS].notna().all(axis=1) & piv_t[METHODS].notna().all(axis=1)
    piv_sr = piv_sr.loc[valid, METHODS]
    piv_t  = piv_t.loc[valid, METHODS]
    return piv_sr, piv_t

def method_summary(df):
    g = df.groupby("Method")
    summary = pd.DataFrame({
        "Mean_SR": g["SuccessRate"].mean(),
        "CI_SR":   g["SuccessRate"].apply(_ci95),
        "Mean_T":  g["Time(s)"].mean(),
        "CI_T":    g["Time(s)"].apply(_ci95),
        "N":       g.size()
    }).reindex(METHODS)
    return summary

def plot_config_key_extraction_efficiency(use_log_x_auto=True, log_ratio_threshold=25.0, max_points_alpha=0.25):
    df = load_csv(CSV_PATH)
    piv_sr, piv_t = build_pivot(df)
    summary = method_summary(df)
    # 决策分组
    no_fallback_mask = (piv_sr["Fast"] >= 0.5)
    fallback_mask = (piv_sr["Fast"] <  0.5)
    fig, ax = plt.subplots(figsize=(7.6, 5.0))
    # 背景点（所有样本）
    bg_kwargs = dict(s=18, alpha=max_points_alpha, zorder=1, linewidths=0.3, edgecolors="none", rasterized=True)
    sc_fast_bg = ax.scatter(piv_t["Fast"],   piv_sr["Fast"],   label="Fast (all samples)",   **bg_kwargs)
    sc_ghidra_bg = ax.scatter(piv_t["Ghidra"], piv_sr["Ghidra"], label="Ghidra (all samples)", **bg_kwargs)
    # Enhanced 两类点：no-fallback=绿色x，fallback=红色x
    en_kwargs = dict(s=32, alpha=0.95, zorder=3, linewidths=0.9)
    sc_en_nofb = ax.scatter(
        piv_t.loc[no_fallback_mask, "Enhanced"], piv_sr.loc[no_fallback_mask, "Enhanced"], marker="x", c="#2e7d32",
        label=f"Enhanced (no fallback: Fast≥0.5, n={int(no_fallback_mask.sum())})", **en_kwargs
    )
    sc_en_fb = ax.scatter(
        piv_t.loc[fallback_mask, "Enhanced"],    piv_sr.loc[fallback_mask, "Enhanced"], marker="x", c="#c62828", 
        label=f"Enhanced (fallback: Fast<0.5, n={int(fallback_mask.sum())})", **en_kwargs
    )
    # 方法均值 ±95%CI（置顶显示）
    mean_marker = {"Fast":"s", "Ghidra":"^", "Enhanced":"D"}
    eb_handles = {}
    for m in METHODS:
        xm, xerr = summary.loc[m, "Mean_T"],  summary.loc[m, "CI_T"]
        ym, yerr = summary.loc[m, "Mean_SR"], summary.loc[m, "CI_SR"]
        eb = ax.errorbar([xm], [ym], xerr=[xerr], yerr=[yerr],
                         fmt=mean_marker[m], ms=9, capsize=5,
                         zorder=5, elinewidth=1.5)
        # 给均值点加白描边，避免与点云混杂
        eb[0].set_path_effects([pe.withStroke(linewidth=2.5, foreground="white")])
        for bar in eb[2]:
            bar.set_zorder(5)
        eb_handles[m] = eb  # 保存以便取颜色做图例代理
    # 阈值线
    ax.axhline(0.5, linestyle="--", linewidth=1, alpha=0.5, zorder=0)
    # 自动 log-x（解决长尾）
    if use_log_x_auto:
        x_min = float(np.nanmin(piv_t.values))
        x_max = float(np.nanmax(piv_t.values))
        if x_min > 0 and (x_max / x_min) >= log_ratio_threshold:
            ax.set_xscale("log")
    ax.set_xlabel("Mean Time (s)   (Left is Better)")
    ax.set_ylabel("Success Rate   (Up is Better)")
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, pos: f"{v*100:.0f}%"))
    ax.set_ylim(0, 1.02)
    ax.grid(linestyle="--", alpha=0.35)
    ax.set_title("Configuration-key extraction: Effectiveness vs. Cost (All Binaries)")
    # 右下角统计文本
    n_total = len(piv_sr)
    n_no_fb = int(no_fallback_mask.sum())
    n_fb = int(fallback_mask.sum())
    gh_t_no = piv_t.loc[no_fallback_mask, "Ghidra"]
    en_t_no = piv_t.loc[no_fallback_mask, "Enhanced"]
    time_save_vs_ghidra = (gh_t_no - en_t_no) / gh_t_no
    fa_sr_f = piv_sr.loc[fallback_mask, "Fast"]
    en_sr_f = piv_sr.loc[fallback_mask, "Enhanced"]
    sr_gain_vs_fast = (en_sr_f - fa_sr_f)

    def _mean_ci_text(series, scale=1.0):
        s = series.dropna().astype(float)
        if len(s) == 0:
            return "NA"
        mean = s.mean() * scale
        ci   = _ci95(s) * scale
        return f"{mean:.2f}±{ci:.2f}"
    stats_txt = (
        f"No-fallback (Fast≥0.5): {n_no_fb} ({n_no_fb/n_total*100:.0f}%)\n"
        f"  Time saving vs Ghidra (mean±95%CI): { _mean_ci_text(time_save_vs_ghidra, 100) }%\n"
        f"Fallback (Fast<0.5): {n_fb} ({n_fb/n_total*100:.0f}%)\n"
        f"  Success gain vs Fast (mean±95%CI): { _mean_ci_text(sr_gain_vs_fast, 100) }%"
    )
    ax.text(0.975, 0.04, stats_txt, transform=ax.transAxes, ha="right", va="bottom",
            fontsize=10, bbox=dict(boxstyle="round", facecolor="white", alpha=0.88, lw=0.6, pad=0.35), zorder=6)
    # 方法总体均值摘要
    method_box_txt = (
        f"Fast     : SR={summary.loc['Fast','Mean_SR']*100:5.1f}%   T={summary.loc['Fast','Mean_T']:.2f}s\n"
        f"Ghidra   : SR={summary.loc['Ghidra','Mean_SR']*100:5.1f}%   T={summary.loc['Ghidra','Mean_T']:.2f}s\n"
        f"Enhanced : SR={summary.loc['Enhanced','Mean_SR']*100:5.1f}%   T={summary.loc['Enhanced','Mean_T']:.2f}s"
    )
    ax.text(0.975, 0.25, method_box_txt, transform=ax.transAxes, ha="right", va="bottom",
            fontsize=10, bbox=dict(boxstyle="round", facecolor="white", alpha=0.92, lw=0.6, pad=0.35), zorder=6)
    proxy_mean_fast = Line2D([0], [0], marker=mean_marker["Fast"],     linestyle="None",
                                 markersize=9, markerfacecolor=eb_handles["Fast"][0].get_color(),
                                 markeredgecolor=eb_handles["Fast"][0].get_color(), label="Fast mean ±95%CI")
    proxy_mean_ghidra = Line2D([0], [0], marker=mean_marker["Ghidra"],   linestyle="None",
                                 markersize=9, markerfacecolor=eb_handles["Ghidra"][0].get_color(),
                                 markeredgecolor=eb_handles["Ghidra"][0].get_color(), label="Ghidra mean ±95%CI")
    proxy_mean_enhanced = Line2D([0], [0], marker=mean_marker["Enhanced"], linestyle="None",
                                 markersize=9, markerfacecolor=eb_handles["Enhanced"][0].get_color(),
                                 markeredgecolor=eb_handles["Enhanced"][0].get_color(), label="Enhanced mean ±95%CI")
    handles = [
        sc_fast_bg, sc_ghidra_bg, sc_en_nofb, sc_en_fb,
        proxy_mean_fast, proxy_mean_ghidra, proxy_mean_enhanced
    ]
    ax.legend(handles=handles, loc="lower right", bbox_to_anchor=(0.980, 0.63),
              borderaxespad=0.0, fontsize=9, framealpha=0.95, ncol=1)
    fig.tight_layout()
    fig.savefig(OUT_FIG + ".png", dpi=PLOT_DPI, bbox_inches="tight")
    fig.savefig(OUT_FIG + ".pdf", dpi=PLOT_DPI, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved: {OUT_FIG}.png / .pdf")

# 主测试函数
def main():
    # 首先读取CSV文件
    idx = {}
    if os.path.exists(CSV_PATH):
        with open(CSV_PATH, mode="r") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            colmap = {name: i for i, name in enumerate(header)} if header else {}
            for row in reader:
                b = row[colmap.get("Binary", 0)]
                fn = row[colmap.get("FuncName", 1)]
                if (b, fn) not in idx:
                    idx[(b, fn)] = True
    # 生成csv数据
    for binary_path, (set_func_name, get_func_name, set_index_key, get_index_key, set_value_key, get_value_key) in BINARY_INFO.items():
        # 首先获取set_func_name的配置键
        print(f"Processing binary: {binary_path}")
        if (binary_path, set_func_name) in idx:
            print(f"  {set_func_name} already processed, skipping.")
        else:
            compare_configuation_key_get_methods(binary_path, set_func_name, set_index_key, set_value_key)
            idx[(binary_path, set_func_name)] = True
        # 然后获取get_func_name的配置键
        if (binary_path, get_func_name) in idx:
            print(f"  {get_func_name} already processed, skipping.")
        else:
            compare_configuation_key_get_methods(binary_path, get_func_name, get_index_key, get_value_key)
            idx[(binary_path, get_func_name)] = True
    # 生成图表
    plot_config_key_extraction_efficiency(use_log_x_auto=False, log_ratio_threshold=25.0, max_points_alpha=0.25)
    
if __name__ == "__main__":
    main()