# -*- coding: utf-8 -*-
import os
import re
import json

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
    potential_path_sanitization_file_path_maybe = SGTaint_result_path.replace("_INFO.md", "_potential_path_maybe_sorted.json")
    potential_path_sanitization_file_path = SGTaint_result_path.replace("_INFO.md", "_potential_path_sanitization_sorted.json")
    with open(potential_path_sanitization_file_path_maybe, "r") as f:
        potential_path_sanitization_maybe = json.load(f)
    with open(potential_path_sanitization_file_path, "r") as f:
        potential_path_sanitization = json.load(f)
    # 统计数量
    for sanitization_single_path in potential_path_sanitization + potential_path_sanitization_maybe:
        sanitization_single_path_binary = sanitization_single_path["binary"]
        if not set(sanitization_single_path_binary).issubset(set([item[0] for item in binary_file_list])):
            continue
        if sanitization_single_path["kind"] == "intra-single":
            if sanitization_single_path["taint_source"] in SOURCES and sanitization_single_path["taint_sink"] in SINKS:
                if "ToToLink" not in SGTaint_result_path and sanitization_single_path["taint_sink"] == "sprintf":
                    continue
                if "Netgear" in SGTaint_result_path and sanitization_single_path["taint_source"] != "fgets" and sanitization_single_path["front_end_keyword"] == "miss":
                    continue
                sanitization_path_number += 1
        else:
            if sanitization_single_path["taint_source"] in SOURCES and sanitization_single_path["taint_sink"] in SINKS and any(func in sanitization_single_path["merge"] for func in transitive_set):
                if "ToToLink" not in SGTaint_result_path and sanitization_single_path["taint_sink"] == "sprintf":
                    continue
                if "Netgear" in SGTaint_result_path and sanitization_single_path["taint_source"] != "fgets" and sanitization_single_path["front_end_keyword"] == "miss":
                    continue
                sanitization_path_number += 1
    return sanitization_path_number

# 提取OctopusTaint的结果
def extract_octopuTaint_results(octopuTaint_result_dict):
    for firmware_mark, info in octopuTaint_result_dict.items():
        binaries = info["binaries"]
        SGTaint_result_path = info["SGTaint_result_path"]
        print(f"Firmware: {firmware_mark}, Binaries: {len(binaries)}")
        sanitization_path_number = extract_single_binary_octopuTaint_result(binaries, SGTaint_result_path)
        print(f"  Sanitization Paths: {sanitization_path_number}")
        
if __name__ == "__main__":
    octopuTaint_result_dict = get_analysis_binary_list_octopuTaint()
    extract_octopuTaint_results(octopuTaint_result_dict)