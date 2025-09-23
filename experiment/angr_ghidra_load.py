# -*- coding: utf-8 -*-
import os
import angr
import pickle
import json

FIRMWARE_PATH = [
    "/home/firmware/0-day_dataset/D-Link/DIR-816/squashfs-root",
    "/home/firmware/0-day_dataset/D-Link/DIR-878/cpio-root",
    "/home/firmware/N-day_dataset/D-Link/DIR-882/cpio-root",
    "/home/firmware/0-day_dataset/Linksys/E1200/router",
    "/home/firmware/N-day_dataset/Netgear/R6200/squashfs-root",
    "/home/firmware/N-day_dataset/Netgear/R6300/squashfs-root",
    "/home/firmware/N-day_dataset/Netgear/R7000P/squashfs-root",
    "/home/firmware/0-day_dataset/ToToLink/A720R/squashfs-root",
    "/home/firmware/N-day_dataset/ToToLink/A950RG/squashfs-root",
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
    "/home/firmware/N-day_dataset/ToToLink/T10/squashfs-root"
]

def print_color(content, color):
    color_codes = {
        "black": "30",
        "red": "31",
        "green": "32",
        "yellow": "33",
        "blue": "34",
        "magenta": "35",
        "cyan": "36",
        "white": "37",
        "reset": "0" 
    }
    color_code = color_codes.get(color.lower(), color_codes["reset"])
    print(f"\033[{color_code}m{content}\033[0m")

# 执行任意命令
def execute(command, timeout=None):
    from subprocess import check_output, STDOUT, TimeoutExpired
    command = "{}; exit 0".format(command)
    output = check_output(command, stderr=STDOUT, shell=True, timeout=timeout).decode("utf-8")
    return output

# 获取所有的边界二进制文件
def get_all_boundary_binaries(directory):
    SGTAINT_KEYWORD_INFO_PATH = "/home/SGTaint/tool/SGGraph/border_binary.py"
    directory_path = directory.replace("/", "_")
    json_file_path = os.path.join("/home/Experiment/tmp", f"boundary_binaries_{directory_path}.json")
    if not os.path.exists(json_file_path):
        # 运行SGTaint的边界二进制识别脚本
        sgtaint_command = f"python -B {SGTAINT_KEYWORD_INFO_PATH} {directory}"
        try:
            execute(sgtaint_command)
            print_color(f"SGTaint command executed successfully for directory: {directory}", "green")
        except Exception as e:
            print(f"Error executing SGTaint command: {e}")
            return []
    else:
        print_color(f"Boundary binaries JSON already exists for directory: {directory}, skipping SGTaint execution.", "yellow")
    # 读取生成的JSON文件
    with open(json_file_path, 'r') as f:
        boundary_binaries_list = json.load(f)
    if not boundary_binaries_list:
        print(f"No boundary binaries found in directory: {directory}")
        return []
    return boundary_binaries_list
    
# 加载Ghidra对象
def load_ghidra_project(binary_path):
    binary_path_split = binary_path.split("/")
    ghidra_path = os.path.join("/home/Experiment/tmp/ghidra", binary_path_split[5])
    if not os.path.exists(ghidra_path):
        os.makedirs(ghidra_path)
    binary_mark = os.path.basename(binary_path)
    if not os.path.exists(os.path.join(ghidra_path, f"{binary_mark}.gpr")):
        ghidra_python_path = "/home/SGTaint/tool/Ghidra/enable_aggressive_all.py"
        ghidra_load_command = f"/home/SGTaint/ghidra_tool/support/analyzeHeadless {ghidra_path} {binary_mark} -import {binary_path} -preScript {ghidra_python_path}"
        execute(ghidra_load_command, timeout=600) # 执行Ghidra脚本进行分析
    else:
        print_color(f"  Ghidra project already exists for {binary_mark}, skipping loading.", "yellow")
        
# 加载angr项目
def load_angr_project(binary_path):
    binary_mark = binary_path.replace("/", "_")
    project_pickle_path = os.path.join("/home/Experiment/tmp/pickle", f"{binary_mark}_project.pickle")
    cfg_pickle_path = os.path.join("/home/Experiment/tmp/pickle", f"{binary_mark}_cfg.pickle")
    if not os.path.exists(project_pickle_path) and not os.path.exists(cfg_pickle_path):
        project = angr.Project(binary_path, auto_load_libs=False, use_sim_procedures=True, default_analysis_mode='symbolic', load_options={'auto_load_libs': False})
        project.analyses.CompleteCallingConventions(recover_variables=True, analyze_callsites=True)
        cfg = project.analyses.CFG(resolve_indirect_jumps=True, cross_references=True,
                                    force_complete_scan=False,
                                    normalize=True, symbols=True, data_references=True)
        # 保存项目和CFG到pickle文件
        with open(project_pickle_path, 'wb') as f:
            pickle.dump(project, f)
        with open(cfg_pickle_path, 'wb') as f:
            pickle.dump(cfg, f)
    else:
        print_color(f"  Project or CFG already exists for {binary_mark}, skipping loading.", "yellow")
        
# 实现所有内容的加载
def load_all():
    for idx, firmware_path in enumerate(FIRMWARE_PATH, start=1):
        print_color(f"Processing firmware directory: [{idx}\{len(FIRMWARE_PATH)}] {firmware_path}", "green")
        boundary_binaries = get_all_boundary_binaries(firmware_path)
        if not boundary_binaries:
            print_color(f"No boundary binaries found in {firmware_path}, skipping to next firmware.", "red")
            continue
        for index, binary in enumerate(boundary_binaries, start=1):
            print_color(f" Processing binary: [{index}\{len(boundary_binaries)}] {binary}", "blue")
            try:
                load_ghidra_project(binary)
                load_angr_project(binary)
            except Exception as e:
                print_color(f"  Error processing binary {binary}: {e}", "red")
                
if __name__ == "__main__":
    load_all()