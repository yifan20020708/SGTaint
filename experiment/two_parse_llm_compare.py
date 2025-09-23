# -*- coding: utf-8 -*-
import os
import re
import ast
import time
import json
import httpx
import string
import random
import pickle
import shlex
from archinfo import Endness
from angr.project import Project
from angr.analyses.cfg.cfg_fast import CFGFast
from openai import OpenAI, RateLimitError, APIConnectionError, APIError

LLM_MODEL = ""
LLM_URL_DEEPSEEK = "https://api.deepseek.com"
DEEPSEEK_API_KEY = "sk-7f3abcde356349189aaeaa9d29250a07"
LLM_MODEL_DEEPSEEK = "deepseek-chat"
SG_TEMPERATURE = 0.3
MAX_ERROR_COUNT = 3
MAX_REPEATED_TIMES = 3
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
pattern_llm_two_parse = re.compile(r'^\s*\[\s*(\(\s*([^,()]+?\s*,\s*){5}[^,()]+?\s*\)\s*,?\s*)+\]$')
pattern_llm_one_parse = re.compile(r'^\s*\[\s*(\(\s*[^,()]+?\s*,\s*[^,()]+?\s*\)\s*,?\s*)+\]$')
SET_GET_INFO = [
    ("config_set", "config_get"), ("SetValue", "GetValue"), ("setenv", "getenv"), ("nvram_safe_set", "nvram_safe_get"), ("nvram_pf_set", "nvram_pf_get"),
    ("acosNvramConfig_set", "acosNvramConfig_get"), ("acosNvramConfig_set", "acosNvramConfig_read"), ("uciSet", "uciGet"), ("wpa_config_set", "wpa_config_get"),
    ("device_set_string_value", "device_get_string_value"), ("OM_ValSet", "OM_ValGet"), ("acosUciConfig_set", "acosUciConfig_get"), ("CAL_abstract_set", "CAL_abstract_get"),
    ("nvram_bufset", "nvram_bufget"), ("apmib_set", "apmib_get"), ("apcli_nvram_set", "apcli_nvram_get"), ("nvram_set_value", "nvram_safe_get")
]

# 实现开启LLM对话的类，方便进行调用，每一个类对象可表示一轮对话
class LLM():
    # 其中model指LLM模型，目前支持deepseek以及gpt
    def __init__(self, temperature = 1.0, model = LLM_MODEL_DEEPSEEK): # 温度默认为1.0
        # 配置灵活获取
        self.model = model or LLM_MODEL # 通过用户参数进行配置
        self.api_key = DEEPSEEK_API_KEY
        self.base_url = LLM_URL_DEEPSEEK
        self.temperature = temperature
        # 参数检查
        if not self.api_key or not self.base_url:
            raise ValueError("API key and base URL must be provided for LLM initialization.")
        try:
            self.client = OpenAI(api_key=self.api_key, base_url=self.base_url)
        except Exception as e:
            print(f"Failed to initialize OpenAI client: {e}")
            raise
        self.messages = []
        self.chat_record = []
        
    # 设置系统角色
    def system_role(self, content):
        if not content:
            print("Empty system role content provided.")
            return
        message = {"role": "system", "content": content}
        self.messages.append(message)
        
    # 开启对话模式（加入了超时对话特性）
    def chat(self, content, timeout=60):
        if not content:
            print("Empty user content for chat; skipping.")
            return ""
        message = {"role": "user", "content": content}
        self.messages.append(message)
        try:
            response = self.client.chat.completions.create(
                model = self.model, 
                messages = self.messages,
                temperature = self.temperature,
                timeout=timeout
            )
        except (TimeoutError, httpx.TimeoutException) as e:
            print(f"Network timeout during LLM chat: {e}")
            return "[ERROR] Network timeout, please try again later."
        except (APIConnectionError, APIError, RateLimitError) as e:
            print(f"OpenAI API error during LLM chat: {e}")
            return f"[ERROR] LLM API error: {e}"
        except Exception as e:
            print(f"Unexpected error during LLM chat: {e}")
            return f"[ERROR] Unexpected error: {e}"
        # 加入此轮对话的回复，方便开启多轮对话
        if self.model == LLM_MODEL:
            self.messages.append(response.choices[0].message)
        else:
            self.messages.append({'role': 'assistant', 'content': response.choices[0].message.content})
        self.chat_record.append((content, response.choices[0].message.content))
        return response.choices[0].message.content
    
# 两阶段获取提示词
SYSTEM_SET_GET_TWOSHOT = ( # 将其分为两阶段，第一阶段获取函数对信息，第二阶段获取函数对的参数信息
    "You are a firmware reverse engineering specialist tasked with analyzing firmware binaries to identify functions "
    "that utilize key-value pair mechanisms for persistent configuration storage or retrieval "
    "(e.g., apmib_set/apmib_get, nvram_safe_set/nvram_safe_get, acosNvramConfig_set/acosNvramConfig_get, acosNvramConfig_set/acosNvramConfig_read). "
    "Your task is divided into two distinct phases:\n"
    "1. Function Pair Identification Based on Naming Semantics:"
    "Given a list of function names, infer all potential key-value related function pairs purely based on naming conventions "
    "and common patterns observed in firmware development. These typically follow set/get pairings for storing and retrieving values.\n"
    "Output the identified function pairs strictly in the format: "
    "[(set_1, get_1), (set_2, get_2), ...], "
    "for example: [(nvram_safe_set, nvram_safe_get), (apmib_set, apmib_get)]."
    "If no relevant pairs are found, return None.\n"
    "Note: You must output only the final answer in the specified format, with no additional explanation or commentary.\n"
    "2. Argument Role Inference from Decompiled Usage Patterns:"
    "Given the outputs derived from the first phase, which are systematically augmented and refined through filtering to obtain the corresponding usage examples in decompiled binary code, identify the argument positions—indexed in a zero-based manner—that correspond to:\n"
    "- the key in the set function "
    "- the value in the set function "
    "- the key in the get function "
    "- the value in the get function "
    "If any of these positions are not applicable or cannot be determined, use None for that field.\n"
    "Output the results strictly in the format: "
    "[(set_1, get_1, set_key_pos, get_key_pos, set_value_pos, get_value_pos), ...].\n"
    "Note: Again, you must output only the answer in the specified format with no extraneous information."
)
    
SYSTEM_SET_GET_OUTPUT_PHASE_ONE = "Please strictly output in the format [(set_1, get_1), (set_2, get_2), ...] or None in the first phase."

SYSTEM_SET_GET_OUTPUT_PHASE_TWO = "Please strictly output in the format [(set_1, get_1, set_key_pos, get_key_pos, set_value_pos, get_value_pos), ...] or None in the second phase."

DOUBLE_CHECK = "Please double check and answer again."

def get_user_set_get_en_prompt_phase_one(name_list):
    return f"Input for the first phase: {name_list}, please strictly output in the format [(set_1, get_1), (set_2, get_2), ...] or None in the phase."

def get_user_set_get_en_prompt_phase_two(code_list):
    return f"Input for the second phase: {code_list}, please strictly output in the format [(set_1, get_1, set_key_pos, get_key_pos, set_value_pos, get_value_pos), ...] or None in the phase."

def double_check_phase_two(code_list):
    return f"Please double check and answer again with new input: {code_list}."

# 一阶段提示词
SYSTEM_SET_GET_ONESHOT = ( # 直接使用LLM获取函数对信息
    "You are a firmware reverse engineering expert analyzing binary firmware code. "
    "Your task is to directly identify all function pairs that operate using key-value mechanisms for persistent configuration "
    "(e.g., nvram_safe_set/nvram_safe_get, apmib_set/apmib_get, acosNvramConfig_set/acosNvramConfig_get, acosNvramConfig_set/acosNvramConfig_read), and simultaneously determine the semantic roles of their arguments. "
    "Each valid function pair consists of one 'set' function (writing a value with a key) and one 'get' function (reading a value using a key). "
    "From the provided list of function names and corresponding decompiled code snippets, infer and output all valid function pairs, "
    "and for each pair, determine the following (using zero-based indexing): "
    "- key argument position in the set function "
    "- value argument position in the set function "
    "- key argument position in the get function "
    "- value argument position in the get function "
    "If a position is not applicable or cannot be determined, use None. "
    "Output your results strictly in the format: "
    "[(set_func_1, get_func_1, set_key_pos, get_key_pos, set_value_pos, get_value_pos), "
    "(set_func_2, get_func_2, set_key_pos, get_key_pos, set_value_pos, get_value_pos), ...] "
    "If no relevant function pairs are found, return None. "
    "Note: You must output only the final answer in the specified format without any explanations or extra text."
)

SYSTEM_SET_GET_OUTPUT = "Please strictly output in the format [(set_func_1, get_func_1, set_key_pos, get_key_pos, set_value_pos, get_value_pos), (set_func_2, get_func_2, set_key_pos, get_key_pos, set_value_pos, get_value_pos), ...] or None in the second phase."

def get_user_set_get_en_prompt(name_list):
    return f"Input for task: {name_list}, please strictly output in the format [(set_func_1, get_func_1, set_key_pos, get_key_pos, set_value_pos, get_value_pos), (set_func_2, get_func_2, set_key_pos, get_key_pos, set_value_pos, get_value_pos), ...] or None in the task."

# 将类表格式的字符串转化为对应的列表
def parse_set_get_string(set_get_string):
    set_get_string = re.sub(r'(?<!["\'])\b([a-zA-Z_][a-zA-Z0-9_]*)\b(?!["\'])', r"'\1'", set_get_string)
    raw_list = ast.literal_eval(set_get_string)
    parsed_list = []
    for item in raw_list:
        if len(item) == 2:
            parsed_list.append(list(item))
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

# 获取完整函数的名称列表
def get_complete_func_name(project: Project):
    complete_func = set()
    for func in project.kb.functions.values():
        if not func.name.startswith("sub_"): # 过滤掉以sub_开头的函数
            complete_func.add((func.name, func.addr))
    return complete_func

# 执行任意命令
def execute(command, timeout=None):
    from subprocess import check_output, STDOUT, TimeoutExpired
    command = "{}; exit 0".format(command)
    output = check_output(command, stderr=STDOUT, shell=True, timeout=timeout).decode("utf-8")
    return output

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

# 判断是否存在对应的函数调用
def has_func_call(project: Project, cfg: CFGFast, func_name):
    call_sites = get_call_site_func_name(project, cfg, func_name)
    return call_sites if call_sites else False

# 为LLM分析的第二阶段生成提示词
def get_prompt_for_phase_two(func_name_eventually):
    prompt_eventually = ""
    for func_name in func_name_eventually:
        # 生成set函数调用的提示词
        set_func_name = func_name["set_func_name"]
        set_string = f"{set_func_name}: "
        index = 0
        for set_code in random.sample(func_name["set_code_list"], min(CODE_NUMBER, len(func_name["set_code_list"]))):
            index += 1
            set_string += f"({index}) {set_code} "
        # 生成get函数调用的提示词
        get_func_name = func_name["get_func_name"]
        get_string = f"{get_func_name}: "
        index = 0
        for get_code in random.sample(func_name["get_code_list"], min(CODE_NUMBER, len(func_name["get_code_list"]))):
            index += 1
            get_string += f"({index}) {get_code} "
        set_get_string = "{" + set_string + ", " + get_string + "}"
        prompt_eventually += set_get_string + ", "
    return f"[{prompt_eventually[:-2]}]"

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

# 给定二进制文件地址获取angr对象
def get_angr_project(binary_path):
    binary_mark = binary_path.replace("/", "_")
    project_pickle_path = os.path.join("/home/Experiment/tmp/pickle", f"{binary_mark}_project.pickle")
    cfg_pickle_path = os.path.join("/home/Experiment/tmp/pickle", f"{binary_mark}_cfg.pickle")
    with open(project_pickle_path, 'rb') as f:
        project = pickle.load(f)
    with open(cfg_pickle_path, 'rb') as f:
        cfg = pickle.load(f)
    return project, cfg

# 获取二进制文件列表
def get_binary_path_list(directory):
    binary_path_list = []
    directory_path = directory.replace("/", "_")
    json_file_path = os.path.join("/home/Experiment/tmp", f"boundary_binaries_{directory_path}.json")
    if not os.path.exists(json_file_path):
        print(f"[-] The specified JSON file {json_file_path} does not exist.")
        return []
    with open(json_file_path, 'r') as f:
        boundary_binaries_list = json.load(f)
    # 确保其存在angr对象以及Ghidra项目
    for binary_path in boundary_binaries_list:
        binary_path_split = binary_path.split("/")
        ghidra_path = os.path.join("/home/Experiment/tmp/ghidra", binary_path_split[5])
        binary_mark = os.path.basename(binary_path)
        binary_mark_angr = binary_path.replace("/", "_")
        project_pickle_path = os.path.join("/home/Experiment/tmp/pickle", f"{binary_mark_angr}_project.pickle")
        cfg_pickle_path = os.path.join("/home/Experiment/tmp/pickle", f"{binary_mark_angr}_cfg.pickle")
        if os.path.exists(os.path.join(ghidra_path, f"{binary_mark}.gpr")) and os.path.exists(project_pickle_path) and os.path.exists(cfg_pickle_path):
            binary_path_list.append(binary_path)
    return binary_path_list  
    
# 两阶段获取转移函数对信息
def get_func_name_from_llm_two_parse(binary_path_list, timeout=60):
    start_time = time.time()
    func_name_list_complete = [] # 存放完整的函数名称列表
    for binary_path in binary_path_list:
        project, _ = get_angr_project(binary_path)
        for func_name, _ in get_complete_func_name(project):
            if func_name not in func_name_list_complete:
                func_name_list_complete.append(func_name)
    # 进行LLM的第一步分析
    func_name_list_str = "[" + ", ".join(func_name_list_complete) + "]"
    LLM_chat = LLM(SG_TEMPERATURE)
    LLM_chat.system_role(SYSTEM_SET_GET_TWOSHOT)
    print("Initiating the first phase of the LLM-based analysis.")
    llm_phase_one_start = time.time()
    response = LLM_chat.chat(get_user_set_get_en_prompt_phase_one(func_name_list_str), timeout=timeout)
    error_count = 0
    while not pattern_llm_one_parse.match(response) and response != "None": # 其中可能存在[ERROR]超时情况
        if response.startswith("[ERROR]"):
            error_count += 1
            if error_count >= MAX_ERROR_COUNT:
                print("Exceeded maximum consecutive errors during LLM chat")
                return [], -1
        else:
            error_count = 0
        response = LLM_chat.chat(SYSTEM_SET_GET_OUTPUT_PHASE_ONE, timeout=timeout)
    # 进行第二次检查
    response_twice = LLM_chat.chat(DOUBLE_CHECK, timeout=timeout)
    error_count = 0
    while not pattern_llm_one_parse.match(response_twice) and response_twice != "None":
        if response_twice.startswith("[ERROR]"):
            error_count += 1
            if error_count >= MAX_ERROR_COUNT:
                print("Exceeded maximum consecutive errors during LLM chat")
                return [], -1
        else:
            error_count = 0
        response_twice = LLM_chat.chat(SYSTEM_SET_GET_OUTPUT_PHASE_ONE, timeout=timeout)
    # 增强LLM回答的健壮性（需要增加次数防止无限循环）
    cycle_number = 0
    while cycle_number < MAX_REPEATED_TIMES and response_twice != response:
        response = response_twice
        response_twice = LLM_chat.chat(DOUBLE_CHECK, timeout=timeout)
        error_count = 0
        while not pattern_llm_one_parse.match(response_twice) and response_twice != "None":
            if response_twice.startswith("[ERROR]"):
                error_count += 1
                if error_count >= MAX_ERROR_COUNT:
                    print("Exceeded maximum consecutive errors during LLM chat")
                    return [], -1
            else:
                error_count = 0
            response_twice = LLM_chat.chat(SYSTEM_SET_GET_OUTPUT_PHASE_ONE, timeout=timeout)
        cycle_number += 1
    # 判断是否存在LLM分析出的内容
    func_name_phase_one = [] if response_twice == "None" else parse_set_get_string(response_twice)
    # 从配置中补充转移函数对名称
    for set_get_pair in SET_GET_INFO:
        if set_get_pair[0] in func_name_list_complete and set_get_pair[1] in func_name_list_complete and [set_get_pair[0], set_get_pair[1]] not in func_name_phase_one:
            func_name_phase_one.append([set_get_pair[0], set_get_pair[1]])
    llm_phase_one_end = time.time()
    print(f"The output of the first phase of the LLM analysis is {func_name_phase_one}, with a duration of {(llm_phase_one_end - llm_phase_one_start):.2f} seconds.")
    if not func_name_phase_one: # 若没有获取到函数对，则直接返回
        return [], -1
    # 进行LLM的第二步分析，首先需要获取对应到的调用语句
    print("Extracting call information from the first phase to facilitate the second phase of LLM-based analysis.")
    # 进行文件组的分类
    func_name_phase_list = []
    call_site_code = {} # 以转移函数对名称为键值
    for set_func_name, get_func_name in func_name_phase_one:
        # 确保边界二进制文件之中，存在set_func_name以及get_func_name的引用，但是不需要同时存在于一个边界二进制文件
        is_find_set_call = False
        is_find_get_call = False
        pair_bucket = []
        for binary_path in binary_path_list:
            project, cfg = get_angr_project(binary_path)
            # 首先判断是否存在set函数
            if project.kb.functions.get(set_func_name):
                set_func_call_sites = has_func_call(project, cfg, set_func_name)
                if set_func_call_sites:
                    is_find_set_call = True
                    set_func_list = list(set([func_addr for _, func_addr, _ in set_func_call_sites]))
                    pair_bucket.append({
                        "func_name": set_func_name,
                        "func_addr": set_func_list,
                        "file_path": binary_path,
                    })
            # 然后判断是否存在get函数
            if project.kb.functions.get(get_func_name):
                get_func_call_sites = has_func_call(project, cfg, get_func_name)
                if get_func_call_sites:
                    is_find_get_call = True
                    get_func_list = list(set([func_addr for _, func_addr, _ in get_func_call_sites]))
                    pair_bucket.append({
                        "func_name": get_func_name,
                        "func_addr": get_func_list,
                        "file_path": binary_path,
                    })
        # 过滤没有有效函数调用的转移函数对
        if is_find_set_call and is_find_get_call: # 进行成对的筛选
            for pair_bucket_single in pair_bucket: # 防止重复加入
                if pair_bucket_single not in func_name_phase_list:
                    func_name_phase_list.append(pair_bucket_single)
            call_site_code[(set_func_name, get_func_name)] = {
                "set_func_name": set_func_name,
                "set_code_filter_list" : [],
                "set_parameter_list": [],
                "get_func_name": get_func_name,
                "get_code_filter_list": [],
                "get_parameter_list": [],
            }
        else:
            print(f"[-] The function pair ({set_func_name}, {get_func_name}) is not valid!")
    # 按照file_path进行分组
    binary_ghidra_process = {}
    for item in func_name_phase_list:
        file_path = item["file_path"]
        if file_path not in binary_ghidra_process:
            binary_ghidra_process[file_path] = []
        binary_ghidra_process[file_path].append([item["func_name"], item["func_addr"]])
    # 按照file_path进行Ghidra脚本执行
    for file_path, items in binary_ghidra_process.items(): # items是一个列表，包含了函数名称和函数地址
        project, cfg = get_angr_project(file_path)
        file_path_process = file_path.replace("/", "_")
        func_name_phase_file_name = f"{file_path_process}_func_name_phase.json"
        func_name_phase_file_path = os.path.join("/home/SGTaint/tmp", func_name_phase_file_name)
        with open(func_name_phase_file_path, "w") as file:
            json.dump(items, file, indent=4)
        # 全部存在对应的 Ghidra 脚本
        binary_path_split = file_path.split("/")
        ghidra_path = os.path.join("/home/Experiment/tmp/ghidra", binary_path_split[5])
        angr_base_addr = project.loader.main_object.min_addr
        binary_mark = os.path.basename(file_path)
        ghidra_python_path = "/home/SGTaint/tool/Ghidra/ghidra_assist.py"
        ghidra_command = f'/home/SGTaint/ghidra_tool/support/analyzeHeadless {ghidra_path} {binary_mark} -process {binary_mark} -noanalysis -postScript {ghidra_python_path} "{angr_base_addr}" "*-precise"'
        print(f"Executing Ghidra command: {ghidra_command}.")
        ghidra_start = time.time()
        execute(ghidra_command)
        ghidra_end = time.time()
        print(f"The execution time of the Ghidra command is {(ghidra_end - ghidra_start):.2f} seconds.")
        # 读取对应的结果文件
        func_name_phase_result_file_name = f"{file_path_process}_func_name_phase_result.json"
        func_name_phase_result_file_path = os.path.join("/home/SGTaint/tmp", func_name_phase_result_file_name)
        try:
            with open(func_name_phase_result_file_path, "r") as file:
                func_name_phase_result = json.load(file)
        except FileNotFoundError:
            print(f"Error: File not found — {func_name_phase_result_file_path}")
            return [], -1
        except Exception as e:
            print(f"Unexpected error: {e}")
            return [], -1
        # 删除对应的中间文件
        rm_command = f"rm {func_name_phase_result_file_path}"
        execute(rm_command)
        for func_name_result in func_name_phase_result:
            func_name = func_name_result["func_name"]
            code_dict = func_name_result["code_dict"]
            code_dict = list(set(tuple(v) for v in code_dict.values())) # 去重
            code_filter_list = [] # 需要进行不同文件的合并
            parameter_list = []
            for complete_line, code in code_dict:
                # 对函数调用进行解析，找到符合标准的函数调用
                parameters = parse_function_call(project, code, complete_line, file_path)
                if parameters:
                    parameter_list.extend(parameters)
                    if complete_line not in code_filter_list: # 避免重复添加
                        code_filter_list.append(complete_line)
            for set_func_name, get_func_name in call_site_code:
                if func_name == set_func_name: # 可能存在多次的匹配
                    call_site_code[(set_func_name, get_func_name)]["set_code_filter_list"].extend(code_filter_list)
                    call_site_code[(set_func_name, get_func_name)]["set_parameter_list"].extend(parameter_list)
                if func_name == get_func_name:
                    call_site_code[(set_func_name, get_func_name)]["get_code_filter_list"].extend(code_filter_list)
                    call_site_code[(set_func_name, get_func_name)]["get_parameter_list"].extend(parameter_list)
    # 进行有效性过滤
    func_name_eventually = []
    for set_func_name, get_func_name in call_site_code:
        set_code_filter_list = call_site_code[(set_func_name, get_func_name)]["set_code_filter_list"]
        get_code_filter_list = call_site_code[(set_func_name, get_func_name)]["get_code_filter_list"]
        set_parameter_list = call_site_code[(set_func_name, get_func_name)]["set_parameter_list"]
        get_parameter_list = call_site_code[(set_func_name, get_func_name)]["get_parameter_list"]
        if not set_code_filter_list or not get_code_filter_list:
            print(f"[-] The function pair ({set_func_name}, {get_func_name}) is not valid!")
            continue
        if not set(set_parameter_list) & set(get_parameter_list):
            print(f"[-] The function pair ({set_func_name}, {get_func_name}) is not valid!")
            continue
        func_name_eventually.append({
            "set_func_name": set_func_name,
            "set_code_list": set_code_filter_list,
            "get_func_name": get_func_name,
            "get_code_list": get_code_filter_list,
        })
    # 开启第二阶段的LLM分析
    if func_name_eventually:
        print("Initiating the second phase of the LLM-based analysis.")
        llm_phase_two_start = time.time()
        prompt_phase_two = get_prompt_for_phase_two(func_name_eventually)
        print(f"Prompt for phase two: {prompt_phase_two}")
        response = LLM_chat.chat(get_user_set_get_en_prompt_phase_two(prompt_phase_two))
        error_count = 0
        while not pattern_llm_two_parse.match(response) and response != "None":
            if response.startswith("[ERROR]"):
                error_count += 1
                if error_count >= MAX_ERROR_COUNT:
                    print("Exceeded maximum consecutive errors during LLM chat")
                    return [], -1
            else:
                error_count = 0
            response = LLM_chat.chat(SYSTEM_SET_GET_OUTPUT_PHASE_TWO)
        # 进行第二次检查
        response_twice = LLM_chat.chat(double_check_phase_two(get_prompt_for_phase_two(func_name_eventually)))
        error_count = 0
        while not pattern_llm_two_parse.match(response_twice) and response_twice != "None":
            if response_twice.startswith("[ERROR]"):
                error_count += 1
                if error_count >= MAX_ERROR_COUNT:
                    print("Exceeded maximum consecutive errors during LLM chat")
                    return [], -1
            else:
                error_count = 0
            response_twice = LLM_chat.chat(SYSTEM_SET_GET_OUTPUT_PHASE_TWO)
        # 增强LLM回答的健壮性（需要增加次数防止无限循环）
        cycle_number = 0
        while cycle_number < MAX_REPEATED_TIMES and response_twice != response:
            response = response_twice
            response_twice = LLM_chat.chat(double_check_phase_two(get_prompt_for_phase_two(func_name_eventually)))
            error_count = 0
            while not pattern_llm_two_parse.match(response_twice) and response_twice != "None":
                if response_twice.startswith("[ERROR]"):
                    error_count += 1
                    if error_count >= MAX_ERROR_COUNT:
                        print("Exceeded maximum consecutive errors during LLM chat")
                        return [], -1
                else:
                    error_count = 0
                response_twice = LLM_chat.chat(SYSTEM_SET_GET_OUTPUT_PHASE_TWO)
            cycle_number += 1
        response_twice_list = parse_set_get_string(response_twice) if response_twice != "None" else []
        llm_phase_two_end = time.time()
        print(f"The output of the second phase of the LLM analysis is {response_twice}, with a duration of {(llm_phase_two_end - llm_phase_two_start):.2f} seconds.")
    else:
        response_twice_list = []
    func_name = response_twice_list
    end_time = time.time()
    elapsed_time = end_time - start_time
    return func_name, elapsed_time

# 两阶段获取转移函数对信息
def get_func_name_from_llm_one_parse(binary_path_list, timeout=60):
    start_time = time.time()
    func_name_list_complete = [] # 存放完整的函数名称列表
    for binary_path in binary_path_list:
        project, _ = get_angr_project(binary_path)
        for func_name, _ in get_complete_func_name(project):
            if func_name not in func_name_list_complete:
                func_name_list_complete.append(func_name)
    # 进行LLM的分析
    func_name_list_str = "[" + ", ".join(func_name_list_complete) + "]"
    LLM_chat = LLM(temperature=SG_TEMPERATURE)
    LLM_chat.system_role(SYSTEM_SET_GET_ONESHOT)
    response = LLM_chat.chat(get_user_set_get_en_prompt(func_name_list_str), timeout=timeout)
    error_count = 0
    while not pattern_llm_two_parse.match(response) and response != "None": # 其中可能存在[ERROR]超时情况
        if response.startswith("[ERROR]"):
            error_count += 1
            if error_count >= MAX_ERROR_COUNT:
                print("Exceeded maximum consecutive errors during LLM chat")
                return [], -1
        else:
            error_count = 0
        response = LLM_chat.chat(SYSTEM_SET_GET_OUTPUT, timeout=timeout)
    # 进行第二次检查
    response_twice = LLM_chat.chat(DOUBLE_CHECK, timeout=timeout)
    error_count = 0
    while not pattern_llm_two_parse.match(response_twice) and response_twice != "None":
        if response_twice.startswith("[ERROR]"):
            error_count += 1
            if error_count >= MAX_ERROR_COUNT:
                print("Exceeded maximum consecutive errors during LLM chat")
                return [], -1
        else:
            error_count = 0
        response_twice = LLM_chat.chat(SYSTEM_SET_GET_OUTPUT, timeout=timeout)
    # 增强LLM回答的健壮性（需要增加次数防止无限循环）
    cycle_number = 0
    while cycle_number < MAX_REPEATED_TIMES and response_twice != response:
        response = response_twice
        response_twice = LLM_chat.chat(DOUBLE_CHECK, timeout=timeout)
        error_count = 0
        while not pattern_llm_two_parse.match(response_twice) and response_twice != "None":
            if response_twice.startswith("[ERROR]"):
                error_count += 1
                if error_count >= MAX_ERROR_COUNT:
                    print("Exceeded maximum consecutive errors during LLM chat")
                    return [], -1
            else:
                error_count = 0
            response_twice = LLM_chat.chat(SYSTEM_SET_GET_OUTPUT, timeout=timeout)
        cycle_number += 1
    response_twice_list = parse_set_get_string(response_twice) if response_twice != "None" else []
    # 进行第一阶段过滤
    func_name = []
    for set_func_name, get_func_name, set_key_pos, get_key_pos, set_value_pos, get_value_pos in response_twice_list:
        # 找到包含set_func_name和get_func_name的边界二进制文件
        is_correct_pair = False
        for binary_path in binary_path_list:
            project, cfg = get_angr_project(binary_path)
            if project.kb.functions.get(set_func_name) and project.kb.functions.get(get_func_name): # 二进制文件中均存在转移函数对
                set_func_call_sites = has_func_call(project, cfg, set_func_name)
                get_func_call_sites = has_func_call(project, cfg, get_func_name)
                if set_func_call_sites and get_func_call_sites: # 均存在调用
                    is_correct_pair = True
                    break
        if not is_correct_pair: # 若不存在对应的函数对，则跳过
            print(f"[-] Function pair ({set_func_name}, {get_func_name}) not found in any boundary binary.")
            continue
        func_name.append([set_func_name, get_func_name, set_key_pos, get_key_pos, set_value_pos, get_value_pos])
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"LLM one-parse analysis completed in {elapsed_time:.2f} seconds.")
    return func_name, elapsed_time

# 对比两种LLM方法的结果
def compare_llm_methods(directory, timeout=60):
    binary_path_list = get_binary_path_list(directory)
    # 获取两阶段LLM结果
    transfer_function_info_two_parse, elapsed_time_two_parse = get_func_name_from_llm_two_parse(binary_path_list, timeout=timeout)
    # 获取一阶段LLM结果
    transfer_function_info_one_parse, elapsed_time_one_parse = get_func_name_from_llm_one_parse(binary_path_list, timeout=timeout)
    return transfer_function_info_two_parse, elapsed_time_two_parse, transfer_function_info_one_parse, elapsed_time_one_parse

FIRMWARE_PATH = [
    "/home/firmware/0-day_dataset/D-Link/DIR-878/cpio-root",
    "/home/firmware/N-day_dataset/D-Link/DIR-882/cpio-root",
    "/home/firmware/0-day_dataset/Linksys/E1200/router",
    "/home/firmware/N-day_dataset/Netgear/R6200/squashfs-root",
    "/home/firmware/N-day_dataset/Netgear/R6300/squashfs-root",
    "/home/firmware/N-day_dataset/Netgear/R7000P/squashfs-root",
    "/home/firmware/0-day_dataset/ToToLink/A720R/squashfs-root",
    "/home/firmware/0-day_dataset/ToToLink/LR1200GB/squashfs-root",
    "/home/firmware/0-day_dataset/ToToLink/NR1800X/squashfs-root",
    "/home/firmware/0-day_dataset/ASUS/4G-AC53U/squashfs-root",
    "/home/firmware/0-day_dataset/ASUS/4G-AX56/squashfs-root",
    "/home/firmware/0-day_dataset/Netgear/BE9300/squashfs-root",
    "/home/firmware/0-day_dataset/Netgear/EX6100/squashfs-root",
    "/home/firmware/0-day_dataset/Netgear/EX6120/squashfs-root",
    "/home/firmware/0-day_dataset/TP-Link/AX90/rootfs_ubifs",
    "/home/firmware/0-day_dataset/TP-Link/C20/squashfs-root",
    "/home/firmware/0-day_dataset/TP-Link/WR902AC/squashfs-root",
    "/home/firmware/N-day_dataset/D-Link/DIR-823G/squashfs-root",
    "/home/firmware/N-day_dataset/Netgear/R6350/squashfs-root",
    "/home/firmware/N-day_dataset/Tenda/AC12/squashfs-root",
    "/home/firmware/N-day_dataset/Tenda/AC15/squashfs-root",
    "/home/firmware/N-day_dataset/Tenda/AC18/squashfs-root",
    "/home/firmware/N-day_dataset/Tenda/G0/squashfs-root",
    "/home/firmware/N-day_dataset/Tenda/G3/squashfs-root",
    "/home/firmware/N-day_dataset/Tenda/W20E/squashfs-root",
    "/home/firmware/N-day_dataset/ToToLink/T10/squashfs-root",
    "/home/firmware/0-day_dataset/D-Link/DIR-816/squashfs-root",
]

# 一阶段的补充确认
def double_check_phase_two():
    CHECK_LIST = [
        "/home/firmware/0-day_dataset/TP-Link/AX90/rootfs_ubifs",
        "/home/firmware/0-day_dataset/TP-Link/C20/squashfs-root",
        "/home/firmware/0-day_dataset/TP-Link/WR902AC/squashfs-root",
        "/home/firmware/N-day_dataset/Tenda/AC12/squashfs-root",
        "/home/firmware/N-day_dataset/Tenda/AC15/squashfs-root",
        "/home/firmware/N-day_dataset/Tenda/AC18/squashfs-root",
        "/home/firmware/N-day_dataset/Tenda/W20E/squashfs-root"
    ]
    for directory in CHECK_LIST:
        firmware_name = directory.split("/")[-2]
        binary_path_list = get_binary_path_list(directory)
        transfer_function_info_one_parse, elapsed_time_one_parse = get_func_name_from_llm_one_parse(binary_path_list, timeout=60)
        # 输出结果
        print(f"Results for {firmware_name}:")
        print(f"  One-parse LLM: {transfer_function_info_one_parse}")
        print(f"  Elapsed time for one-parse LLM: {elapsed_time_one_parse:.2f} seconds\n")
        
# 读取生成结果
def read_llm_result():
    result = {}
    current_bin = None
    buffer = []
    transfer_function_info_compared_file_path = os.path.join("/home/Experiment/output", "transfer_function_info_compared.txt")
    with open(transfer_function_info_compared_file_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("Binary:"):
                if current_bin and buffer:  # 把上一个 binary 保存
                    result[current_bin] = buffer
                current_bin = line.split(":", 1)[1].strip()
                buffer = []
                continue
            if line.startswith("Two-parse LLM:") or line.startswith("One-parse LLM:"):
                list_str = line.split(":", 1)[1].strip()
                try:
                    parsed_list = ast.literal_eval(list_str)
                except Exception:
                    parsed_list = []
                buffer.append(parsed_list)
                continue
            if line.startswith("Elapsed time for"):
                time_str = line.split(":")[1].strip()
                try:
                    elapsed = round(float(time_str), 2)
                except ValueError:
                    elapsed = None
                buffer.append(elapsed)
                continue
        if current_bin and buffer:
            result[current_bin] = buffer
        return result

# 用于统计准确性
CORRECT_RESULT = {
    "DIR-878": [['nvram_safe_set', 'nvram_safe_get', 0, 0, 1, None], ['nvram_set', 'nvram_get', 1, 1, 2, None], ['nvram_set_int', 'nvram_get_int', 0, 0, 1, None], ['nvram_bufset', 'nvram_bufget', 1, 1, 2, None]],
    "DIR-882": [['nvram_safe_set', 'nvram_safe_get', 0, 0, 1, None], ['nvram_set', 'nvram_get', 1, 1, 2, None], ['nvram_set_int', 'nvram_get_int', 0, 0, 1, None], ['nvram_bufset', 'nvram_bufget', 1, 1, 2, None]],
    "E1200": [['nvram_set', 'nvram_get', 0, 0, 1, None]],
    "R6200": [['acosNvramConfig_set', 'acosNvramConfig_get', 0, 0, 1, None], ['acosNvramConfig_set', 'acosNvramConfig_read', 0, 0, 1, 1]],
    "R6300": [['acosNvramConfig_set', 'acosNvramConfig_get', 0, 0, 1, None], ['acosNvramConfig_set', 'acosNvramConfig_read', 0, 0, 1, 1]],
    "R7000P": [['acosNvramConfig_set', 'acosNvramConfig_get', 0, 0, 1, None], ['setenv', 'getenv', 0, 0, 1, None], ['acosNvramConfig_set', 'acosNvramConfig_read', 0, 0, 1, 1]],
    "A720R": [['apmib_set', 'apmib_get', 0, 0, 1, 1], ['inifile_set_int', 'inifile_get_int', 2, 2, 3, None], ['inifile_set', 'inifile_get_string', 2, 2, 3, 3]],
    "LR1200GB": [['nvram_set', 'nvram_get', 0, 0, 1, None], ['nvram_set_int', 'nvram_get_int', 0, 0, 1, None], ['nvram_wlan_set', 'nvram_wlan_get', 1, 1, 2, None], ['nvram_wlan_set_int', 'nvram_wlan_get_int', 1, 1, 2, None], ['set_wan_unit_value', 'get_wan_unit_value', 1, 1, 2, None], ['set_wan_unit_value_int', 'get_wan_unit_value_int', 1, 1, 2, None]],
    "NR1800X": [['nvram_set', 'nvram_get', 0, 0, 1, None], ['nvram_set_int', 'nvram_get_int', 0, 0, 1, None], ['nvram_wlan_set', 'nvram_wlan_get', 1, 1, 2, None], ['nvram_wlan_set_int', 'nvram_wlan_get_int', 1, 1, 2, None], ['set_wan_unit_value', 'get_wan_unit_value', 1, 1, 2, None], ['set_wan_unit_value_int', 'get_wan_unit_value_int', 1, 1, 2, None]],
    "4G-AC53U": [['nvram_set', 'nvram_get', 0, 0, 1, None], ['nvram_pf_set', 'nvram_pf_get', 1, 1, 2, None], ['nvram_set_int', 'nvram_get_int', 0, 0, 1, None], ['setenv', 'getenv', 0, 0, 1, None]],
    "4G-AX56": [['nvram_set', 'nvram_get', 0, 0, 1, None], ['nvram_set_int', 'nvram_get_int', 0, 0, 1, None], ['nvram_set_file', 'nvram_get_file', 0, 0, 1, 1], ['nvram_pf_set', 'nvram_pf_get_int', 1, 1, 2, None]],
    "BE9300": [['config_set', 'config_get', 0, 0, 1, None]],
    "EX6100": [['acosNvramConfig_set', 'acosNvramConfig_get', 0, 0, 1, None], ['acosNvramConfig_set', 'acosNvramConfig_read', 0, 0, 1, 1], ['acosNvramConfig_set_bak', 'acosNvramConfig_get_bak', 0, 0, 1, None]],
    "EX6120": [['acosNvramConfig_set', 'acosNvramConfig_get', 0, 0, 1, None], ['acosNvramConfig_save', 'acosNvramConfig_read', 0, 0, 1, 1]],
    "AX90": [['dhd_set', 'dhd_get', 1, 1, 2, 2], ['wlu_iovar_set', 'wlu_iovar_get', 1, 1, 2, 2], ['wlu_var_setbuf', 'wlu_var_getbuf', 1, 1, 2, 3], ['setenv', 'getenv', 0, 0, 1, None]],
    "C20": [['rdp_setObj', 'rdp_getObj', 1, 1, 2, 2], ['rdp_setObjStruct', 'rdp_getObjStruct', 0, 0, 1, 1]],
    "WR902AC": [['rdp_setObj', 'rdp_getObj', 1, 1, 2, 2], ['rdp_setObjStruct', 'rdp_getObjStruct', 0, 0, 1, 1], ['setenv', 'getenv', 0, 0, 1, None]],
    "DIR-823G": [['apmib_set', 'apmib_get', 0, 0, 1, 1]],
    "R6350": [['nvram_set', 'nvram_get', 0, 0, 1, None], ['apcli_nvram_set', 'apcli_nvram_get', 1, 1, 2, None], ['nvram_set_idx_n', 'nvram_get_idx_n', 0, 0, 3, None], ['nv_set', 'nv_get', 1, 1, 2, None], ['nv_set_int', 'nv_get_int', 1, 1, 2, None], ['setenv', 'getenv', 0, 0, 1, None]],
    "AC12": [['SetValue', 'GetValue', 0, 0, 1, 1], ['SetUrlValue', 'GetUrlValue', 0, 0, 1, 1]],
    "AC15": [['SetValue', 'GetValue', 0, 0, 1, 1], ['SetUrlValue', 'GetUrlValue', 0, 0, 1, 1], ['setenv', 'getenv', 0, 0, 1, None]],
    "AC18": [['bcm_nvram_set', 'bcm_nvram_get', 0, 0, 1, None], ['SetValue', 'GetValue', 0, 0, 1, 1], ['SetUrlValue', 'GetUrlValue', 0, 0, 1, 1]],
    "G0": [['prod_cfm_set_val', 'prod_cfm_get_val', 0, 0, 1, 1], ['prod_cfm_set_int_val', 'prod_cfm_get_int_val', 0, 0, 1, None], ['SetValue', 'GetValue', 0, 0, 1, 1], ['SetIntValue', 'GetIntValue', 0, 0, 1, None]],
    "G3": [['bcm_nvram_set', 'bcm_nvram_get', 0, 0, 1, None], ['SetValue', 'GetValue', 0, 0, 1, 1]],
    "W20E": [['SetValue', 'GetValue', 0, 0, 1, 1], ['bcm_nvram_set', 'bcm_nvram_get', 0, 0, 1, None]],
    "T10": [['apmib_set', 'apmib_get', 0, 0, 1, 1]],
    "DIR-816": [['nvram_set', 'nvram_get', 1, 1, 2, None], ['nvram_bufset', 'nvram_bufget', 1, 1, 2, None], ['dbWriteStr', 'dbReadStr', 2, 2, 4, 4], ['dbWriteInt', 'dbReadInt', 2, 2, 4, 4]]
}

def evaluate_func_pairs(gt_pairs, pred_pairs):
    gt_pairs = set(gt_pairs)
    pred_pairs = set(pred_pairs)
    tp = len(gt_pairs & pred_pairs)
    fp = len(pred_pairs - gt_pairs)
    fn = len(gt_pairs - pred_pairs)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tp": tp,
        "fp": fp,
        "fn": fn
    }
    
def calculate_param_accuracy(standardized_correct_result, standardized_llm_results):
    results = {}
    for firmware in standardized_correct_result.keys():
        gt_pairs_info = {item["func_pair"]: item for item in standardized_correct_result[firmware]}
        pred_pairs_info = {item["func_pair"]: item for item in standardized_llm_results.get(firmware, [])}
        # 找出成功识别的 func_pair
        success_pairs = set(gt_pairs_info.keys()) & set(pred_pairs_info.keys())
        success_count = len(success_pairs)
        # 初始化 key_pos 和 value_pos 正确计数
        correct_key_pos = 0
        correct_value_pos = 0
        total_key_pos = 0
        total_value_pos = 0
        for pair in success_pairs:
            gt = gt_pairs_info[pair]
            pred = pred_pairs_info[pair]
            # key_pos: set_key_pos 和 get_key_pos
            for key in ["set_key_pos", "get_key_pos"]:
                total_key_pos += 1
                if gt[key] == pred[key]:
                    correct_key_pos += 1
            # value_pos: set_value_pos 和 get_value_pos
            for key in ["set_value_pos", "get_value_pos"]:
                total_value_pos += 1
                if gt[key] == pred[key]:
                    correct_value_pos += 1
        key_pos_acc = correct_key_pos / total_key_pos if total_key_pos > 0 else 0.0
        value_pos_acc = correct_value_pos / total_value_pos if total_value_pos > 0 else 0.0
        results[firmware] = {
            "success_func_pair_count": success_count,
            "key_pos_acc": key_pos_acc,
            "value_pos_acc": value_pos_acc
        }
    return results

def calculate_overall_param_accuracy(param_results):
    total_success_func_pair = 0
    total_correct_key = 0
    total_key_count = 0
    total_correct_value = 0
    total_value_count = 0
    for metrics in param_results.values():
        success_count = metrics["success_func_pair_count"]
        total_success_func_pair += success_count
        key_count = 2 * success_count
        total_key_count += key_count
        total_correct_key += metrics["key_pos_acc"] * key_count
        value_count = 2 * success_count
        total_value_count += value_count
        total_correct_value += metrics["value_pos_acc"] * value_count
    overall_key_pos_acc = total_correct_key / total_key_count if total_key_count > 0 else 0.0
    overall_value_pos_acc = total_correct_value / total_value_count if total_value_count > 0 else 0.0
    return {
        "total_success_func_pair": total_success_func_pair,
        "overall_key_pos_acc": overall_key_pos_acc,
        "overall_value_pos_acc": overall_value_pos_acc
    }
    
def count_total_func_pairs(standardized_correct_result):
    total_count = 0
    for _, func_list in standardized_correct_result.items():
        total_count += len(func_list)
    return total_count

# 统计最终结果，其中分为两部分（函数对识别和参数值识别）
def statistic_final_result():
    # 首先将CORRETCT_RESULT的键值进行标准化
    standardized_correct_result = {}
    for firmware, correct_result in CORRECT_RESULT.items():
        standardized_correct_result[firmware] = []
        for set_func_name, get_func_name, set_key_pos, get_key_pos, set_value_pos, get_value_pos in correct_result:
            standardized_correct_result[firmware].append({
                "func_pair": (set_func_name, get_func_name),
                "set_key_pos": set_key_pos,
                "get_key_pos": get_key_pos,
                "set_value_pos": set_value_pos,
                "get_value_pos": get_value_pos
            })
    # 将运行结果进行标准化
    llm_results = read_llm_result()
    standardized_llm_results_two_shot = {}
    standardized_llm_results_one_shot = {}
    llm_time_two_shot = {}
    llm_time_one_shot = {}
    for firmware, (two_shot_result, two_shot_time, one_shot_result, one_shot_time) in llm_results.items():
        standardized_llm_results_two_shot[firmware] = []
        llm_time_two_shot[firmware] = two_shot_time
        for func_set, func_get, set_key_pos, get_key_pos, set_value_pos, get_value_pos in two_shot_result:
            standardized_llm_results_two_shot[firmware].append({
                "func_pair": (func_set, func_get),
                "set_key_pos": set_key_pos,
                "get_key_pos": get_key_pos,
                "set_value_pos": set_value_pos,
                "get_value_pos": get_value_pos
            })
        standardized_llm_results_one_shot[firmware] = []
        llm_time_one_shot[firmware] = one_shot_time
        for func_set, func_get, set_key_pos, get_key_pos, set_value_pos, get_value_pos in one_shot_result:
            standardized_llm_results_one_shot[firmware].append({
                "func_pair": (func_set, func_get),
                "set_key_pos": set_key_pos,
                "get_key_pos": get_key_pos,
                "set_value_pos": set_value_pos,
                "get_value_pos": get_value_pos
            })
    # 获取平均时间
    avg_time_two_shot = sum(llm_time_two_shot.values()) / len(llm_time_two_shot) if llm_time_two_shot else 0.0
    avg_time_one_shot = sum(llm_time_one_shot.values()) / len(llm_time_one_shot) if llm_time_one_shot else 0.0
    # 统计func_pair的识别情况，其中测量Precision，Recall，F1-Score
    func_pair_single_results = {}
    # 同时累积全局TP/FP/FN用于micro平均
    total_tp_two, total_fp_two, total_fn_two = 0, 0, 0
    total_tp_one, total_fp_one, total_fn_one = 0, 0, 0
    precisions_two, recalls_two, f1s_two = [], [], []
    precisions_one, recalls_one, f1s_one = [], [], []
    for firmware in standardized_correct_result.keys():
        gt_pairs = [item["func_pair"] for item in standardized_correct_result[firmware]]
        two_shot_pairs = [item["func_pair"] for item in standardized_llm_results_two_shot.get(firmware, [])]
        one_shot_pairs = [item["func_pair"] for item in standardized_llm_results_one_shot.get(firmware, [])]
        two_shot_metrics = evaluate_func_pairs(gt_pairs, two_shot_pairs)
        one_shot_metrics = evaluate_func_pairs(gt_pairs, one_shot_pairs)
        func_pair_single_results[firmware] = {
            "two_shot": two_shot_metrics,
            "one_shot": one_shot_metrics
        }
        # 累加micro统计
        total_tp_two += two_shot_metrics["tp"]
        total_fp_two += two_shot_metrics["fp"]
        total_fn_two += two_shot_metrics["fn"]
        total_tp_one += one_shot_metrics["tp"]
        total_fp_one += one_shot_metrics["fp"]
        total_fn_one += one_shot_metrics["fn"]

        # 保存macro统计
        precisions_two.append(two_shot_metrics["precision"])
        recalls_two.append(two_shot_metrics["recall"])
        f1s_two.append(two_shot_metrics["f1"])
        precisions_one.append(one_shot_metrics["precision"])
        recalls_one.append(one_shot_metrics["recall"])
        f1s_one.append(one_shot_metrics["f1"])
        
    # Micro平均
    precision_two_micro = total_tp_two / (total_tp_two + total_fp_two) if (total_tp_two + total_fp_two) > 0 else 0.0
    recall_two_micro = total_tp_two / (total_tp_two + total_fn_two) if (total_tp_two + total_fn_two) > 0 else 0.0
    f1_two_micro = (2 * precision_two_micro * recall_two_micro / (precision_two_micro + recall_two_micro)) if (precision_two_micro + recall_two_micro) > 0 else 0.0
    precision_one_micro = total_tp_one / (total_tp_one + total_fp_one) if (total_tp_one + total_fp_one) > 0 else 0.0
    recall_one_micro = total_tp_one / (total_tp_one + total_fn_one) if (total_tp_one + total_fn_one) > 0 else 0.0
    f1_one_micro = (2 * precision_one_micro * recall_one_micro / (precision_one_micro + recall_one_micro)) if (precision_one_micro + recall_one_micro) > 0 else 0.0
    # Macro平均 
    precision_two_macro = sum(precisions_two) / len(precisions_two) if precisions_two else 0.0
    recall_two_macro = sum(recalls_two) / len(recalls_two) if recalls_two else 0.0
    f1_two_macro = sum(f1s_two) / len(f1s_two) if f1s_two else 0.0
    precision_one_macro = sum(precisions_one) / len(precisions_one) if precisions_one else 0.0
    recall_one_macro = sum(recalls_one) / len(recalls_one) if recalls_one else 0.0
    f1_one_macro = sum(f1s_one) / len(f1s_one) if f1s_one else 0.0
    overall_results = {
        "micro": {
            "two_shot": {"precision": precision_two_micro, "recall": recall_two_micro, "f1": f1_two_micro},
            "one_shot": {"precision": precision_one_micro, "recall": recall_one_micro, "f1": f1_one_micro},
        },
        "macro": {
            "two_shot": {"precision": precision_two_macro, "recall": recall_two_macro, "f1": f1_two_macro},
            "one_shot": {"precision": precision_one_macro, "recall": recall_one_macro, "f1": f1_one_macro},
        }
    }
    # 每个固件的结果
    for firmware, metrics_dict in func_pair_single_results.items():
        print(f"\nfirmware: {firmware}")
        for mode, metrics in metrics_dict.items():
            precision = metrics["precision"]
            recall = metrics["recall"]
            f1 = metrics["f1"]
            print(f"  {mode:<10} | Precision: {precision:.3f}  Recall: {recall:.3f}  F1: {f1:.3f}")

    print("\n" + "-" * 60)
    # 整体结果
    print("Aggregated across all firmware:\n")
    for avg_type, metrics_dict in overall_results.items():
        print(f"{avg_type.capitalize()} Average:")
        for mode, metrics in metrics_dict.items():
            precision = metrics["precision"]
            recall = metrics["recall"]
            f1 = metrics["f1"]
            print(f"  {mode:<10} | Precision: {precision:.3f}  Recall: {recall:.3f}  F1: {f1:.3f}")
        print("-" * 60)

    # 统计参数识别信息
    two_shot_param_results = calculate_param_accuracy(standardized_correct_result, standardized_llm_results_two_shot)
    one_shot_param_results = calculate_param_accuracy(standardized_correct_result, standardized_llm_results_one_shot)
    two_shot_overall = calculate_overall_param_accuracy(two_shot_param_results)
    one_shot_overall = calculate_overall_param_accuracy(one_shot_param_results)
    for firmware in two_shot_param_results.keys():
        print(f"\nfirmware: {firmware}")
        for mode, metrics in [("two_shot", two_shot_param_results[firmware]), ("one_shot", one_shot_param_results[firmware])]:
            success_count = metrics["success_func_pair_count"]
            key_pos_acc = metrics["key_pos_acc"]
            value_pos_acc = metrics["value_pos_acc"]
            print(f"  {mode:<10} | success_func_pair_count: {success_count}  key_pos_acc: {key_pos_acc:.3f}  value_pos_acc: {value_pos_acc:.3f}")
    # 总体统计结果
    print("Two-shot overall:")
    print(f"  total_success_func_pair: {two_shot_overall['total_success_func_pair']}")
    print(f"  overall_key_pos_acc: {two_shot_overall['overall_key_pos_acc']:.3f}")
    print(f"  overall_value_pos_acc: {two_shot_overall['overall_value_pos_acc']:.3f}")

    print("One-shot overall:")
    print(f"  total_success_func_pair: {one_shot_overall['total_success_func_pair']}")
    print(f"  overall_key_pos_acc: {one_shot_overall['overall_key_pos_acc']:.3f}")
    print(f"  overall_value_pos_acc: {one_shot_overall['overall_value_pos_acc']:.3f}")
    
    # 将其统计到文件之中
    transfer_function_info_compared_file_path = os.path.join("/home/Experiment/output", "transfer_function_info_compared_statistics.txt")
    with open(transfer_function_info_compared_file_path, "w") as f:
        f.write("Function Pair information Recognition Results:\n")
        for firmware, metrics_dict in func_pair_single_results.items():
            f.write(f"\nfirmware: {firmware}\n")
            for mode, metrics in metrics_dict.items():
                precision = metrics["precision"]
                recall = metrics["recall"]
                f1 = metrics["f1"]
                success_count = two_shot_param_results[firmware]["success_func_pair_count"] if mode == "two_shot" else one_shot_param_results[firmware]["success_func_pair_count"]
                key_pos_acc = two_shot_param_results[firmware]["key_pos_acc"] if mode == "two_shot" else one_shot_param_results[firmware]["key_pos_acc"]
                value_pos_acc = two_shot_param_results[firmware]["value_pos_acc"] if mode == "two_shot" else one_shot_param_results[firmware]["value_pos_acc"]
                time = llm_time_two_shot[firmware] if mode == "two_shot" else llm_time_one_shot[firmware]
                f.write(f"  {mode:<10} | Precision: {precision:.3f}  Recall: {recall:.3f}  F1: {f1:.3f} | success_func_pair_count: {success_count}  key_pos_acc: {key_pos_acc:.3f}  value_pos_acc: {value_pos_acc:.3f} | time: {time}\n")
        f.write("\n" + "-" * 60 + "\n")
        f.write("Aggregated across all firmware:\n\n")
        metrics_dict = overall_results["micro"]
        for mode, metrics in metrics_dict.items():
            precision = metrics["precision"]
            recall = metrics["recall"]
            f1 = metrics["f1"]
            success_count = two_shot_overall["total_success_func_pair"] if mode == "two_shot" else one_shot_overall["total_success_func_pair"]
            key_pos_acc = two_shot_overall["overall_key_pos_acc"] if mode == "two_shot" else one_shot_overall["overall_key_pos_acc"]
            value_pos_acc = two_shot_overall["overall_value_pos_acc"] if mode == "two_shot" else one_shot_overall["overall_value_pos_acc"]
            avg_time = avg_time_two_shot if mode == "two_shot" else avg_time_one_shot
            f.write(f"  {mode:<10} | Correct_func_pair: {count_total_func_pairs(standardized_correct_result)}  Precision: {precision:.3f}  Recall: {recall:.3f}  F1: {f1:.3f} | total_success_func_pair: {success_count}  overall_key_pos_acc: {key_pos_acc:.3f}  overall_value_pos_acc: {value_pos_acc:.3f} | average time: {avg_time}\n")
    print(f"\nStatistics written to {transfer_function_info_compared_file_path}")

# 主测试函数
def main():
    # 设置输出文件
    transfer_function_info_compared_file_path = os.path.join("/home/Experiment/output", "transfer_function_info_compared.txt")
    global LLM_MODEL
    model_list = [LLM_MODEL_DEEPSEEK]
    # 读取已有条目，避免重复
    analyzed_set = set()
    analyzed_model = set()
    if os.path.exists(transfer_function_info_compared_file_path):
        with open(transfer_function_info_compared_file_path, "r") as file:
            content = file.readlines()
        current_model = None
        for line in content:
            if line.startswith("Using LLM model:"):
                current_model = line.strip().split("Using LLM model:")[1].strip()
                analyzed_model.add(current_model)
            if line.startswith("Firmware:") and current_model:
                firmware_name = line.strip().split("Firmware:")[1].strip()
                analyzed_set.add((current_model, firmware_name))
    for model in model_list:
        if model not in analyzed_model:
            with open(transfer_function_info_compared_file_path, "a") as file:
                file.write(f"Using LLM model: {model}\n")
        LLM_MODEL = model
        timeout = 60  
        for directory in FIRMWARE_PATH:
            firmware_name = directory.split("/")[-2]
            if (model, firmware_name) in analyzed_set:
                print(f"[Skip] {model} - {firmware_name}")
                continue
            transfer_function_info_two_parse, elapsed_time_two_parse, transfer_function_info_one_parse, elapsed_time_one_parse = compare_llm_methods(directory, timeout)
            # 输出结果
            print(f"Results for {model} - {firmware_name}:")
            print(f"  Two-parse LLM: {transfer_function_info_two_parse}")
            print(f"  Elapsed time for two-parse LLM: {elapsed_time_two_parse:.2f} seconds")
            print(f"  One-parse LLM: {transfer_function_info_one_parse}")
            print(f"  Elapsed time for one-parse LLM: {elapsed_time_one_parse:.2f} seconds\n")
            # 写入文件
            with open(transfer_function_info_compared_file_path, "a") as file:
                file.write(f"Binary: {firmware_name}\n")
                file.write(f"  Two-parse LLM: {transfer_function_info_two_parse}\n")
                file.write(f"  Elapsed time for two-parse LLM: {elapsed_time_two_parse}\n")
                file.write(f"  One-parse LLM: {transfer_function_info_one_parse}\n")
                file.write(f"  Elapsed time for one-parse LLM: {elapsed_time_one_parse}\n\n")
            # 更新analyzed_set以支持断点续跑
            analyzed_set.add((model, firmware_name))
            
if __name__ == "__main__":
    statistic_final_result()