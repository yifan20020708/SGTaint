# -*- coding: utf-8 -*-
import os
import re
import json
import matplotlib.pyplot as plt
from matplotlib_venn import venn3, venn3_circles

def plot_overall_venn_with_metrics(A, B, C, out_prefix="/home/Experiment/output/overall_venn"):
    A = set(A); B = set(B); C = set(C)
    U = len(A | B | C) if (A or B or C) else 1 
    plt.figure(figsize=(8, 8))
    labels = (f"SGTaint (n={len(A)})",
              f"mangoDFA (n={len(B)})",
              f"octopuTaint (n={len(C)})")
    v = venn3([A, B, C], set_labels=labels)
    venn3_circles([A, B, C], linestyle="solid", linewidth=1.0, color="gray")
    subset_ids = ['100','010','001','110','101','011','111']
    # 适度位移
    offsets = {
        '100':(-0.02,  0.02), '010':( 0.02,  0.02), '001':( 0.00, -0.02),
        '110':(-0.02,  0.00), '101':(-0.02, -0.02), '011':( 0.02,  0.00),
        '111':( 0.00, -0.03),
    }
    for sid in subset_ids:
        t = v.get_label_by_id(sid)
        if t is None:
            continue
        try:
            count = int(float(t.get_text()))
        except (TypeError, ValueError):
            count = 0
        pct = 100.0 * count / U
        t.set_text(f"{count}\n{pct:.1f}%")
        t.set_fontsize(13)
        # 轻微位移
        (dx, dy) = offsets.get(sid, (0.0, 0.0))
        x, y = t.get_position()
        t.set_position((x + dx, y + dy))
    txt = (
        f"Totals (of union N={U})\n"
        f"  SGTaint : {len(A)} ({len(A)/U*100:.1f}%)\n"
        f"  mangoDFA : {len(B)} ({len(B)/U*100:.1f}%)\n"
        f"  octopuTaint : {len(C)} ({len(C)/U*100:.1f}%)"
    )
    ax = plt.gca()
    ax.text(0.40, 0.10, txt, transform=ax.transAxes,
            ha="right", va="bottom", fontsize=11,
            bbox=dict(boxstyle="round", facecolor="white", alpha=0.90, lw=0.6))
    plt.title("Overall Analysis Binary List Comparison", fontsize=16)
    for text in ax.texts:
        text.set_fontsize(13)
    plt.tight_layout()
    plt.savefig(out_prefix + ".png", dpi=600)
    plt.savefig(out_prefix + ".pdf", bbox_inches="tight")
    plt.close()

# 读取SGTaint中的分析列表
def get_analysis_binary_list_sgtaint():
    directory_path = "/home/firmware"
    sgtaint_analysis_dict = {}
    pattern = re.compile(r"`([^`]+)`")  # 匹配反引号中的路径
    for root, _, files in os.walk(directory_path):
        if "SGResult" not in root:
            continue
        for file in files:
            if file.lower().endswith(".md"):
                firmware_mark = file[:-8]  # 去掉 _INFO.md 后缀
                sgtaint_analysis_dict[firmware_mark] = []
                file_path = os.path.join(root, file)
                with open(file_path, "r", encoding="utf-8") as f:
                    text = f.read()
                # 找到 "Analyzing binary file list" 开始的部分
                if "Analyzing binary file list" in text:
                    section = text.split("Analyzing binary file list", 1)[1]
                    paths = pattern.findall(section)
                    for path in paths:
                        sgtaint_analysis_dict[firmware_mark].append(os.path.basename(path))
    return sgtaint_analysis_dict

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

def find_binaries(result_path):
    binary_names = []
    for root, _, files in os.walk(result_path):
        if "ghidra_project" in root:
            continue
        for file in files:
            if not file.endswith(".result"):
                binary_names.append(file)
    return binary_names

# 读取SaTC策略下的OctopusTaint的分析列表
def get_analysis_binary_list_octopuTaint():
    directory_path = "/home/firmware"
    octopuTaint_analysis_dict = {}
    for root, dirs, _ in os.walk(directory_path):
        if "ghidra_extract_result" in dirs:
            firmware_mark = os.path.basename(os.path.dirname(root))
            result_path = os.path.join(root, "ghidra_extract_result")
            octopuTaint_analysis_dict[firmware_mark] = find_binaries(result_path)
    return octopuTaint_analysis_dict

# 对mangoDFA的独占结果进行分析
def get_unique_mangodfa_result():
    mango_result_file_path = "/home/firmware/mangoDFA_dataset/mango-Result"
    unique_binary_file = "/home/Experiment/output/unique_analysis_binary.txt"
    mangoDFA_dict = {}
    mangoDFA_unique_result = []
    with open(unique_binary_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
        for index, line in enumerate(lines):
            if line.strip() == "Unique to mangoDFA:":
                index += 1 # 从下一行开始
                break
        for line in lines[index:]:
            line = line.strip()
            if not line or line.startswith("Unique to"):
                break
            parts = line.split(']')[-1].strip() 
            device, func = parts.split(':', 1)
            if device.strip() not in mangoDFA_dict:
                mangoDFA_dict[device.strip()] = []
            mangoDFA_dict[device.strip()].append(func.strip())
    for device, funcs in mangoDFA_dict.items():
        binary_result = os.path.join(mango_result_file_path, f"{device}_result.json")
        if not os.path.isfile(binary_result):
            print(f"[-] Result file not found for device: {device}")
            continue
        with open(binary_result, "r", encoding="utf-8") as f:
            results = json.load(f)
        for result in results:
            binary_name = os.path.basename(result.get("binary_path", ""))
            if binary_name in funcs:
                mangoDFA_unique_result.append(result)
    output_file = "/home/Experiment/output/unique_mangoDFA_results.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(mangoDFA_unique_result, f, indent=4)
    print(f"[+] Unique mangoDFA results saved to: {output_file}")
        
def main():
    octopuTaint_white_list = ["A720R:tcpdump", "A950RG:tcpdump", "E7350:tcpdump"]
    # 获取三种工具的二进制分析文件
    sgtaint_analysis_dict = get_analysis_binary_list_sgtaint()
    mangoDFA_analysis_dict = get_analysis_binary_list_mangoDFA()
    octopuTaint_analysis_dict = get_analysis_binary_list_octopuTaint()
    # 存储三种工具分析的二进制文件
    sgtaint_analysis_set = set()
    mangoDFA_analysis_set = set()
    octopuTaint_analysis_set = set()
    # 找到三者的共同 key（firmware_mark）
    common_keys = (set(sgtaint_analysis_dict.keys()) & set(mangoDFA_analysis_dict.keys()) & set(octopuTaint_analysis_dict.keys()))
    for key in sorted(common_keys):
        for binary in sgtaint_analysis_dict[key]:
            sgtaint_analysis_set.add(f"{key}:{binary}")
        for binary in mangoDFA_analysis_dict[key]:
            mangoDFA_analysis_set.add(f"{key}:{binary}")
        for binary in octopuTaint_analysis_dict[key]:
            if f"{key}:{binary}" not in octopuTaint_white_list:
                octopuTaint_analysis_set.add(f"{key}:{binary}")
    # 绘制整体 Venn 图
    plot_overall_venn_with_metrics(sgtaint_analysis_set, mangoDFA_analysis_set, octopuTaint_analysis_set, out_prefix="/home/Experiment/output/overall_analysis_binary_venn")
    # 绘制特有文件集合
    unique_sgtaint = sgtaint_analysis_set - mangoDFA_analysis_set - octopuTaint_analysis_set
    unique_mangoDFA = mangoDFA_analysis_set - sgtaint_analysis_set - octopuTaint_analysis_set
    unique_octopuTaint = octopuTaint_analysis_set - sgtaint_analysis_set - mangoDFA_analysis_set
    unique_analysis_binary_file_path = "/home/Experiment/output/unique_analysis_binary.txt"
    with open(unique_analysis_binary_file_path, "w", encoding="utf-8") as f:
        f.write("Unique to SGTaint:\n")
        for index, binary in enumerate(sorted(unique_sgtaint), start=1):
            f.write(f"  [{index}/{len(unique_sgtaint)}] {binary}\n")
        f.write("\nUnique to mangoDFA:\n")
        for index, binary in enumerate(sorted(unique_mangoDFA), start=1):
            f.write(f"  [{index}/{len(unique_mangoDFA)}] {binary}\n")
        f.write("\nUnique to octopuTaint:\n")
        for index, binary in enumerate(sorted(unique_octopuTaint), start=1):
            f.write(f"  [{index}/{len(unique_octopuTaint)}] {binary}\n")
    print(f"[+] Unique analysis binary list saved to: {unique_analysis_binary_file_path}")
        
if __name__ == "__main__":
    get_unique_mangodfa_result()