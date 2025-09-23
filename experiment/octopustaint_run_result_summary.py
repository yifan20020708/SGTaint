# -*- coding: utf-8 -*-
import os
import re
import json
import time
import angr

SOURCES = [
    "sub_1d170", "config_get", "NK_query_entry_get", "webGetVarString", "bcm_nvram_get", "GetValue",
    "acosNvramConfig_read", "sub_42af24", "sub_42a978", "get_cgi", "websGetVar", "nvram_get",
    "nvram_safe_get", "nvram_default_get", "getenv", "nvram_pf_get", "acosNvramConfig_get", "config_get",
    "uciGet", "entry", "wpa_config_get", "httpGenListDataGet", "cJSON_GetArrayItem", "wpa_config_set",
    "vici_find_str", "DoHardwareComponent", "device_get_string_value", "cJSON_Parse", "uciSet", "OM_ValGet",
    "acosUciConfig_get", "CAL_abstract_get", "json_object_object_get", "json_object_object_get_ex",
    "json_tokener_parse", "OM_ValFind", "get_parameter", "get_wlan_setting", "av_dict_get", "cgi_value",
    "stringOut", "cJSON_GetObjectItem", "sw_getValueByName", "querystr", "find_val", "log_query",
    "value_parser_by_index_D7000", "getoption", "WEB_GetVar", "av_opt_get", "paramValueFromObjGet",
    "help_getObjPtr", "NCONF_get_string", "av_metadata_get", "httpGetEnv", "gets", "fgets", "recvfrom",
    "recvmsg", "recvmsg",
]

transitive_set = [
    "config_set", "SetValue", "setenv", "nvram_set", "nvram_safe_set", "nvram_pf_set",
    "artblock_set", "acos_nvram_set", "acosNvramConfig_set", "acosNvramConfig_write", "envz_add", "config_set",
    "uciSet", "device_set_string_value", "wpa_config_set", "scfgmgr_set_by_index_D7000",
    "acosUciConfig_set", "OM_ValSet", "CAL_abstract_set",
]

SINKS = [
    "strcpy", "strcat", "sprintf", "system", "___system", "_system",
    "bstar_system", "popen", "doSystemCmd", "doShell", "twsystem", "CsteSystem",
    "cgi_deal_popen", "ExecShell", "exec_shell_popen", "exec_shell_popen_str", "wl_exec_cmd", "execve",
    "execl", "_eval", "eval", "sh", "send", "execlp",
    "doSystem", "sprintf",
]

satc_time_dict = {
    "DIR-816": 159.71,
    "RE7000": 207.03,
    "E1200": 434.21,
    "DIR-878": 559.12,
    "LR1200GB": 170.74,
    "NR1800X": 213.29,
    "R6200": 333.55,
    "R6300": 328.65,
    "DIR-882": 1252.29,
    "A950RG": 237.95,
    "R7000P": 1936.30,
    "E7350": 6718.27,
    "A720R": 6351.53
}

# 获取文件夹下的二进制文件的名称列表
def find_binaries(result_path):
    binary_names = []
    for root, _, files in os.walk(result_path):
        if "ghidra_project" in root:
            continue
        for file in files:
            if not file.endswith(".result"):
                binary_names.append(file)
    return binary_names

# 读取mangoDFA中的分析列表
def get_analysis_binary_list_mangoDFA():
    analysis_file_path = "/home/firmware/mangoDFA_dataset/mango-Result/analysis_binary.json"
    mangoDFA_analysis_dict = {}
    with open(analysis_file_path, "r", encoding="utf-8") as f:
        analysis_binary_dict = json.load(f)
    for firmware_path, binary_list in analysis_binary_dict.items():
        firmware_mark = os.path.basename(firmware_path)
        mangoDFA_analysis_dict[firmware_mark] = []
        for binary in binary_list:
            mangoDFA_analysis_dict[firmware_mark].append(os.path.basename(binary))
    return mangoDFA_analysis_dict

# 获取OctopusTaint二进制文件集合
def get_analysis_binary_list_octopuTaint():
    octopuTaint_white_list = {
        "A720R" : ["tcpdump", "miniigd"],
        "A950RG" : ["tcpdump"],
        "E7350": ["tcpdump"],
        "DIR-878": ["pluto"]
    }
    directory_path = "/home/firmware"
    octopuTaint_result_dict = {}
    for root, dirs, _ in os.walk(directory_path):
        if "ghidra_extract_result" in dirs:
            firmware_mark = os.path.basename(os.path.dirname(root))
            mangoDFA_analysis_dict = get_analysis_binary_list_mangoDFA()
            if firmware_mark not in mangoDFA_analysis_dict: # 仅仅处理共同的元素
                continue
            result_path = os.path.join(root, "ghidra_extract_result")
            octopuTaint_result_dict[firmware_mark] = {}
            # 获取其分析的二进制文件列表
            octopuTaint_result_dict[firmware_mark]["binaries"] = []
            if firmware_mark in octopuTaint_white_list:
                for binary in find_binaries(result_path):
                    if binary not in octopuTaint_white_list[firmware_mark]:
                        octopuTaint_result_dict[firmware_mark]["binaries"].append(binary)
            else:
                octopuTaint_result_dict[firmware_mark]["binaries"] = find_binaries(result_path)
            # 获取对应的SGTaint的结果文件，其结果可以从中读取
            SGTaint_result_path = os.path.join(os.path.dirname(root), f"SGResult-{firmware_mark}", "log", f"{firmware_mark}_INFO.md")
            octopuTaint_result_dict[firmware_mark]["SGTaint_result_path"] = SGTaint_result_path
    return octopuTaint_result_dict

# 提取单个二进制文件的OctopusTaint结果
def extract_single_binary_octopuTaint_result(binaries, SGTaint_result_path):
    with open(SGTaint_result_path, "r") as f:
        lines = f.readlines()
    cross_sanitization_number = 0
    complete_path_number = 0
    sanitization_path_number = 0
    index = 0
    while index < len(lines):
        if "Analyzing binary file list" in lines[index]:
            binary_file_list = []
            index += 1
            while index < len(lines) and lines[index].strip().startswith("- "):
                pattern = r'- `(?P<path>[^`]+)` \[analysis_time:\s*(?P<time>[\d.]+),\s*function_number:\s*(?P<func>\d+)\];'
                match = re.match(pattern, lines[index].strip())
                if match:
                    path = match.group('path')
                    analysis_time = float(match.group('time'))
                    function_number = int(match.group('func'))
                    if any(os.path.basename(path) == binary for binary in binaries):
                        binary_file_list.append([path, analysis_time, function_number])
                    index += 1
        index += 1
    # 读取对应的路径结果
    get2sink_path_complete_file_path = SGTaint_result_path.replace("_INFO.md", "_get2sink_path_complete.json")
    get2sink_path_sanitization_file_path = SGTaint_result_path.replace("_INFO.md", "_get2sink_path_sanitization.json")
    potential_path_complete_file_path = SGTaint_result_path.replace("_INFO.md", "_potential_path_complete.json")
    potential_path_sanitization_file_path = SGTaint_result_path.replace("_INFO.md", "_potential_path_sanitization.json")
    with open(get2sink_path_complete_file_path, "r") as f:
        get2sink_path_complete = json.load(f)
    with open(get2sink_path_sanitization_file_path, "r") as f:
        get2sink_path_sanitization = json.load(f)
    with open(potential_path_complete_file_path, "r") as f:
        potential_path_complete = json.load(f)
    with open(potential_path_sanitization_file_path, "r") as f:
        potential_path_sanitization = json.load(f)
    # 统计结果
    complete_path = get2sink_path_complete + potential_path_complete
    sanitization_path = get2sink_path_sanitization + potential_path_sanitization
    for complete_single_path in complete_path:
        complete_single_path_binary = complete_single_path["binary"]
        if not set(complete_single_path_binary).issubset(set([item[0] for item in binary_file_list])):
            continue
        if complete_single_path["kind"] == "intra-single":
            if complete_single_path["taint_source"] in SOURCES and complete_single_path["taint_sink"] in SINKS:
                complete_path_number += 1
        else: # 其类型为cross
            if complete_single_path["taint_source"] in SOURCES and complete_single_path["taint_sink"] in SINKS and any(func in complete_single_path["merge"] for func in transitive_set):
                complete_path_number += 1
    for sanitization_single_path in sanitization_path:
        sanitization_single_path_binary = sanitization_single_path["binary"]
        if not set(sanitization_single_path_binary).issubset(set([item[0] for item in binary_file_list])):
            continue
        if sanitization_single_path["kind"] == "intra-single":
            if sanitization_single_path["taint_source"] in SOURCES and sanitization_single_path["taint_sink"] in SINKS:
                sanitization_path_number += 1
        else:
            if sanitization_single_path["taint_source"] in SOURCES and sanitization_single_path["taint_sink"] in SINKS and any(func in sanitization_single_path["merge"] for func in transitive_set):
                sanitization_path_number += 1
                cross_sanitization_number += 1
    # 输出结果
    for item in binary_file_list:
        print(f"  Binary: {item[0]}, Analysis Time: {item[1]}, Function Number: {item[2]}")
    print(f"  Complete Path Number: {complete_path_number}")
    print(f"  Sanitization Path Number: {sanitization_path_number}")
    print(f"  Cross Sanitization Path Number: {cross_sanitization_number}")
    return complete_path_number, sanitization_path_number, cross_sanitization_number, binary_file_list
                
# 提取OctopusTaint的结果
def extract_octopuTaint_results(octopuTaint_result_dict):
    octopuTaint_result = {}
    for firmware_mark, info in octopuTaint_result_dict.items():
        octopuTaint_result[firmware_mark] = {}
        binaries = info["binaries"]
        SGTaint_result_path = info["SGTaint_result_path"]
        print(f"Firmware: {firmware_mark}, Binaries: {len(binaries)}")
        complete_path_number, sanitization_path_number, cross_sanitization_number, binary_file_list = extract_single_binary_octopuTaint_result(binaries, SGTaint_result_path)
        octopuTaint_result[firmware_mark]["complete_path_number"] = complete_path_number
        octopuTaint_result[firmware_mark]["sanitization_path_number"] = sanitization_path_number
        octopuTaint_result[firmware_mark]["cross_sanitization_number"] = cross_sanitization_number
        octopuTaint_result[firmware_mark]["binary_number"] = len(binary_file_list)
        octopuTaint_result[firmware_mark]["function_number"] = sum([item[2] for item in binary_file_list])
        # 现在计算所有的时间信息
        octopuTaint_result[firmware_mark]["rda_analysis_time"] = sum([item[1] for item in binary_file_list])
        start_time = time.time()
        for binary_path, _, _ in binary_file_list:
            project = angr.Project(binary_path, auto_load_libs=False,  use_sim_procedures=True, default_analysis_mode='symbolic', load_options={'auto_load_libs': False})
            project.analyses.CompleteCallingConventions(recover_variables=True, analyze_callsites=True) # 针对RDA分析是必要的
            _ = project.analyses.CFG(resolve_indirect_jumps=True, cross_references=True,
                        force_complete_scan=False,
                        normalize=True, symbols=True, data_references=True)
        end_time = time.time()
        angr_time = end_time - start_time
        octopuTaint_result[firmware_mark]["angr_analysis_time"] = angr_time
        # 同样存在SaTC识别边界二进制文件的时间
        octopuTaint_result[firmware_mark]["satc_analysis_time"] = satc_time_dict.get(firmware_mark, 0)
        octopuTaint_result[firmware_mark]["total_analysis_time"] = octopuTaint_result[firmware_mark]["rda_analysis_time"] + octopuTaint_result[firmware_mark]["angr_analysis_time"] + octopuTaint_result[firmware_mark]["satc_analysis_time"]
    # 生成对应的json文件
    with open("/home/Experiment/output/octopustaint_analysis_result.json", "w", encoding="utf-8") as json_file:
        json.dump(octopuTaint_result, json_file, ensure_ascii=False, indent=4)
    # 将重要信息返回到文件之中（文本表格）
    output_txt_path = "/home/Experiment/output/octopustaint_summary.txt"
    with open(output_txt_path, "w", encoding="utf-8") as txt_file:
        # 写表头
        header = f"{'File Mark':<30} | {'Binary Files':<12} | {'Total Time(s)':<14} | {'Sanit Cross':<12} | {'Path Complete':<14} | {'Path Sanitization':<16}\n"
        txt_file.write(header)
        txt_file.write("-" * len(header) + "\n")
        # 写每一行数据
        for file_mark, info in octopuTaint_result.items():
            line = f"{file_mark:<30} | {info['binary_number']:<12} | {info['total_analysis_time']:<14.2f} | {info['cross_sanitization_number']:<12} | {info['complete_path_number']:<14} | {info['sanitization_path_number']:<16}\n"
            txt_file.write(line)

if __name__ == "__main__":
    octopuTaint_result_dict = get_analysis_binary_list_octopuTaint()
    extract_octopuTaint_results(octopuTaint_result_dict)