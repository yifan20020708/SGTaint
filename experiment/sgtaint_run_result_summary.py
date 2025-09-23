# -*- coding: utf-8 -*-
import os
import re
import ast
import json

# 获取SGTaint运行结果文件路径信息
def get_sgtaint_run_result_file():
    directory_path = "/home/firmware"
    sgtaint_analysis_result = {} 
    for root, _, files in os.walk(directory_path):
        if "SGResult" not in root:
            continue
        for file in files:
            if file.lower().endswith(".md"):
                file_path = os.path.join(root, file)    
                file_mark = f"{file_path.split('/')[4]}-{file_path.split('/')[5]}"
                sgtaint_analysis_result[file_mark] = {} # 存放全部的结果信息
                sgtaint_analysis_result[file_mark]["result_file_path"] = file_path # 存放文件路径
    return sgtaint_analysis_result

# 解析结果文件
def parse_result_file(file_path):
    result_data = {}
    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()
    index = 0 # 进行文件解析
    while index < len(lines):
        if "Set-get graph generation time" in lines[index]:
            result_data["Set-get-graph-time"] = float(lines[index].split(":")[1].strip()[:-2]) # 包含大语言模型识别时间
        if "Transfer function information" in lines[index]:
            result_data["transer-function-information"] = False if lines[index].split(":")[1].strip()[1:-2] == "[]" else ast.literal_eval(lines[index].split(":")[1].strip()[1:-2])
        if "Analyzing binary file list" in lines[index]:
            # 进行分析二进制文件的提取
            binary_file_list = []
            index += 1
            while index < len(lines) and lines[index].strip().startswith("- "):
                pattern = r'- `(?P<path>[^`]+)` \[analysis_time:\s*(?P<time>[\d.]+),\s*function_number:\s*(?P<func>\d+)\];'
                match = re.match(pattern, lines[index].strip())
                if match:
                    path = match.group('path')
                    analysis_time = float(match.group('time'))
                    function_number = int(match.group('func'))
                    binary_file_list.append([path, analysis_time, function_number])
                    index += 1
            result_data["binary-file-list"] = binary_file_list
            result_data["binary-file-number"] = len(binary_file_list)
            result_data["total-function-number"] = sum(item[2] for item in binary_file_list)
            result_data["rda_average_function_time"] = round(sum(item[1] for item in binary_file_list) / result_data["total-function-number"], 2) if binary_file_list and result_data.get("total-function-number", 0) > 0 else 0
        if "Analysis time" in lines[index]:
            result_data["total-time"] = float(lines[index].split(":")[1].strip()[:-2])
        if "Length of get2sink_path_sanitization" in lines[index]:
            result_data["get2sink_path_sanitization-length"] = int(lines[index].split(":")[1].strip())
        if "Length of potential_path_sanitization" in lines[index]:
            result_data["potential_path_sanitization-length"] = int(lines[index].split(":")[1].strip())
        if "Length of get2sink_path_complete" in lines[index]:
            result_data["get2sink_path_complete-length"] = int(lines[index].split(":")[1].strip())
        if "Length of potential_path_complete" in lines[index]:
            result_data["potential_path_complete-length"] = int(lines[index].split(":")[1].strip())
        if "Length of sorted_potential_verify_path" in lines[index]:
            result_data["sorted_potential_verify_path-length"] = int(lines[index].split(":")[1].strip())
        if "Length of sorted_potential_maybe_path" in lines[index]:
            result_data["sorted_potential_maybe_path-length"] = int(lines[index].split(":")[1].strip())
        index += 1
    result_data["path_complete"] = result_data.get("get2sink_path_complete-length", 0) + result_data.get("potential_path_complete-length", 0)
    result_data["path_sanitization"] = result_data.get("get2sink_path_sanitization-length", 0) + result_data.get("potential_path_sanitization-length", 0)
    result_data["average_time_binary"] = round(result_data.get("total-time", 0) / result_data.get("binary-file-number", 1), 2) if result_data.get("binary-file-number", 0) > 0 else 0
    result_data["path_sanitization_cross"] = 0
    potential_path_sanitization = os.path.join(os.path.dirname(file_path), f"{os.path.basename(file_path)[:-8]}_potential_path_sanitization.json")
    if os.path.exists(potential_path_sanitization):
        with open(potential_path_sanitization, 'r', encoding='utf-8') as pp_file:
            potential_data = json.load(pp_file)
        for potential_item in potential_data:
            if potential_item["kind"] == "cross":
                result_data["path_sanitization_cross"] += 1
    get2set_sink_path_sanitization = os.path.join(os.path.dirname(file_path), f"{os.path.basename(file_path)[:-8]}_get2sink_path_sanitization.json")
    if os.path.exists(get2set_sink_path_sanitization):
        with open(get2set_sink_path_sanitization, 'r', encoding='utf-8') as gs_file:
            get2set_data = json.load(gs_file)
        for get2set_item in get2set_data:
            if get2set_item["kind"] == "cross":
                result_data["path_sanitization_cross"] += 1
    result_data["path_sanitization_cross_rate"] = round(result_data["path_sanitization_cross"] / result_data.get("path_sanitization", 1), 4) if result_data.get("path_sanitization", 0) > 0 else 0
    return result_data

# 形成所有数据的表格
def format_data_as_table():
    with open("/home/Experiment/output/sgtaint_analysis_result.json", "r", encoding="utf-8") as json_file:
        sgtaint_analysis_result = json.load(json_file)
    output_txt_path = "/home/Experiment/output/sgtaint_summary.txt"
    with open(output_txt_path, "w", encoding="utf-8") as txt_file:
        # 表头
        header = f"{'Firmware':<30} | {'BinFiles':<9} | {'Time(s)':<9} | {'SGTime(s)':<10} | {'ARTime(s)':<10} | {'Funcs':<6} | {'PathC':<6} | {'PathS':<6} | {'PathSC':<7} | {'PathL':<6}\n"
        txt_file.write(header)
        txt_file.write("-" * len(header) + "\n")
        # 累积统计
        total_bin = total_time = total_sg = total_ar = total_funcs = 0
        total_pathc = total_paths = total_pathsc = total_pathl = 0
        n = len(sgtaint_analysis_result)
        for file_mark, info in sgtaint_analysis_result.items():
            data = info["parsed_data"]
            binfiles = data.get("binary-file-number", 0)
            t_time = data.get("total-time", 0.0)
            sg_time = data.get("Set-get-graph-time", 0.0)
            ar_time = data.get("rda_average_function_time", 0.0)
            funcs = data.get("total-function-number", 0)
            pathc = data.get("path_complete", 0)
            paths = data.get("path_sanitization", 0)
            pathsc = data.get("path_sanitization_cross", 0)
            pathl = data.get("sorted_potential_verify_path-length", 0)
            # 写一行
            line = f"{file_mark:<30} | {binfiles:<9} | {t_time:<9.2f} | {sg_time:<10.2f} | {ar_time:<10.2f} | {funcs:<6} | {pathc:<6} | {paths:<6} | {pathsc:<7} | {pathl:<6}\n"
            txt_file.write(line)
            # 累加
            total_bin += binfiles
            total_time += t_time
            total_sg += sg_time
            total_ar += ar_time
            total_funcs += funcs
            total_pathc += pathc
            total_paths += paths
            total_pathsc += pathsc
            total_pathl += pathl
        # total
        total_line = f"{'Total':<30} | {total_bin:<9} | {total_time:<9.2f} | {total_sg:<10.2f} | {total_ar:<10.2f} | {total_funcs:<6} | {total_pathc:<6} | {total_paths:<6} | {total_pathsc:<7} | {total_pathl:<6}\n"
        txt_file.write("-" * len(header) + "\n")
        txt_file.write(total_line)
        # average
        avg_line = f"{'Average':<30} | {total_bin/n:<9.2f} | {total_time/n:<9.2f} | {total_sg/n:<10.2f} | {total_ar/n:<10.2f} | {total_funcs/n:<6.2f} | {total_pathc/n:<6.2f} | {total_paths/n:<6.2f} | {total_pathsc/n:<7.2f} | {total_pathl/n:<6.2f}\n"
        txt_file.write(avg_line)
            
# 获取所有的数据信息
def get_all_sgtaint_data():
    sgtaint_analysis_result = get_sgtaint_run_result_file()
    for file_mark, info in sgtaint_analysis_result.items():
        file_path = info["result_file_path"]
        parsed_data = parse_result_file(file_path)
        sgtaint_analysis_result[file_mark]["parsed_data"] = parsed_data
    # 存放在json文件之中
    with open("/home/Experiment/output/sgtaint_analysis_result.json", "w", encoding="utf-8") as json_file:
        json.dump(sgtaint_analysis_result, json_file, ensure_ascii=False, indent=4)
    # 将重要信息返回到文件之中（文本表格）
    output_txt_path = "/home/Experiment/output/sgtaint_summary.txt"
    with open(output_txt_path, "w", encoding="utf-8") as txt_file:
        # 写表头
        header = f"{'File Mark':<30} | {'Binary Files':<12} | {'Total Time(s)':<14} | {'Sanit Cross':<12} | {'Path Complete':<14} | {'Path Sanitization':<16}\n"
        txt_file.write(header)
        txt_file.write("-" * len(header) + "\n")
        # 写每一行数据
        for file_mark, info in sgtaint_analysis_result.items():
            data = info["parsed_data"]
            line = f"{file_mark:<30} | {data.get('binary-file-number', 0):<12} | {data.get('total-time', 0):<14.2f} | {data.get('path_sanitization_cross', 0):<12} | {data.get('path_complete', 0):<14} | {data.get('path_sanitization', 0):<16}\n"
            txt_file.write(line)
    output_sg_path = "/home/Experiment/output/sgtaint_set_get_info.txt"
    with open(output_sg_path, "w", encoding="utf-8") as sg_file:
        # 写表头
        header = f"{'File Mark':<30} | {'Binary Files':<12} | {'Set-Get Graph Time(s)':<22} | {'Path Sanitization':<16} | {'Sanit Cross':<12}\n"
        sg_file.write(header)
        sg_file.write("-" * len(header) + "\n")
        # 统计用列表
        binary_files_list = []
        set_get_time_list = []
        path_sanit_list = []
        sanit_cross_list = []
        # 写每一行数据
        for file_mark, info in sgtaint_analysis_result.items():
            data = info["parsed_data"]
            if data.get("path_sanitization_cross", 0) > 0:
                value = data.get('path_sanitization_cross_rate', 0)
                percentage = round(value * 100, 4)
                binary_files = data.get('binary-file-number', 0)
                set_get_time = data.get('Set-get-graph-time', 0)
                path_sanit = data.get('path_sanitization', 0)
                sanit_cross = data.get('path_sanitization_cross', 0)
                line = f"{file_mark:<30} | {binary_files:<12} | {set_get_time:<22.2f} | {path_sanit:<16} | {sanit_cross}/{percentage}%\n"
                sg_file.write(line)
                # 收集统计数据
                binary_files_list.append(binary_files)
                set_get_time_list.append(set_get_time)
                path_sanit_list.append(path_sanit)
                sanit_cross_list.append(sanit_cross)
        # 写统计信息（平均值）
        if binary_files_list:  # 避免除零
            avg_binary_files = sum(binary_files_list) / len(binary_files_list)
            avg_set_get_time = sum(set_get_time_list) / len(set_get_time_list)
            avg_path_sanit = sum(path_sanit_list) / len(path_sanit_list)
            avg_sanit_cross = sum(sanit_cross_list) / len(sanit_cross_list)
            percentage = round(avg_sanit_cross / avg_path_sanit * 100, 4)
            sg_file.write("-" * len(header) + "\n")
            average = f"Average ({len(binary_files_list)}/{len(sgtaint_analysis_result)})"
            avg_line = f"{average:<30} | {avg_binary_files:<12.2f} | {avg_set_get_time:<22.2f} | {avg_path_sanit:<16.2f} | {avg_sanit_cross:.2f}/{percentage}%\n"
            sg_file.write(avg_line)
    return sgtaint_analysis_result


# 测试函数
if __name__ == "__main__":
    format_data_as_table()