# -*- coding: utf-8 -*-
import os
import json

key_translation = {
    "DIR-878": "D-Link-DIR-878",
    "DIR-882": "D-Link-DIR-882",
    "DIR-816": "D-Link-DIR-816",
    "A720R": "ToToLink-A720R",
    "LR1200GB": "ToToLink-LR1200GB",
    "NR1800X": "ToToLink-NR1800X",
    "A950RG": "ToToLink-A950RG",
    "E1200": "Linksys-E1200",
    "RE7000": "Linksys-RE7000",
    "E7350": "Linksys-E7350",
    "R6200": "Netgear-R6200",
    "R6300": "Netgear-R6300",
    "R7000P": "Netgear-R7000P",
}

# 读取对应的csv文件
def extract_time_dict(file_path: str):
    time_dict = {}
    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    # 遍历每一行
    for i, line in enumerate(lines):
        parts = line.strip().split("\t")  
        if not parts or parts[0] == "Firmware":
            continue 
        firmware = parts[0]
        try:
            env_time = float(parts[1])
            cfg_time = float(parts[2])
            vra_time = float(parts[3])
            analysis_time = float(parts[4])
        except (IndexError, ValueError):
            continue  
        time_dict[firmware] = {
            "ENV Time": env_time,
            "CFG Time": cfg_time,
            "VRA Time": vra_time,
            "Analysis Time": analysis_time
        }
    return time_dict

def _fmt(val, width, is_time=False, precision=2):
    if val == "N/A":
        return str(val).rjust(width)
    try:
        if is_time:
            return f"{float(val):.{precision}f}".rjust(width)
        else:
            return f"{int(float(val))}".rjust(width)
    except Exception:
        return str(val).rjust(width)

# 读取SGTaint的运行结果
def read_sgtaint_results():
    sgtaint_results_file_path = "/home/Experiment/output/sgtaint_analysis_result.json"
    with open(sgtaint_results_file_path, 'r') as file:
        sgtaint_analysis_result = json.load(file)
    return sgtaint_analysis_result

# 读取OctopusTaint的运行结果
def read_octopustaint_results():
    octopustaint_results_file_path = "/home/Experiment/output/octopustaint_analysis_result.json"
    with open(octopustaint_results_file_path, 'r') as file:
        octopustaint_analysis_result = json.load(file)
    return octopustaint_analysis_result

# 读取mangoDFA的运行结果
def read_mangodfa_results():
    mangodfa_analysis_result = {} # 存储分析时间以及潜在路径数量
    cmdi_results_file_path = "/home/firmware/mangoDFA_dataset/mango-Result/cmdi_results.csv"
    overflow_results_file_path = "/home/firmware/mangoDFA_dataset/mango-Result/overflow-results.csv"
    cmdi_time_dict = extract_time_dict(cmdi_results_file_path)
    overflow_time_dict = extract_time_dict(overflow_results_file_path)
    for file_path in cmdi_time_dict:
        mangodfa_analysis_result[key_translation[file_path]] = {}
        cmdi_overall_time = cmdi_time_dict[file_path]["ENV Time"] + cmdi_time_dict[file_path]["CFG Time"] + cmdi_time_dict[file_path]["VRA Time"] + cmdi_time_dict[file_path]["Analysis Time"]
        overflow_overall_time = overflow_time_dict[file_path]["ENV Time"] + overflow_time_dict[file_path]["CFG Time"] + overflow_time_dict[file_path]["VRA Time"] + overflow_time_dict[file_path]["Analysis Time"]
        mangodfa_analysis_result[key_translation[file_path]]["Analysis Time"] = max(cmdi_overall_time, overflow_overall_time) # 取两者中较大值
        firmware_result_file = os.path.join("/home/firmware/mangoDFA_dataset/mango-Result", f"{file_path}_result.json")
        with open(firmware_result_file, 'r') as f:
            results = json.load(f)
        mangodfa_analysis_result[key_translation[file_path]]["Potential Paths"] = len(results)
    return mangodfa_analysis_result
        
if __name__ == "__main__":
    # 读取各个工具的分析结果
    sgtaint_analysis_result = read_sgtaint_results()
    octopustaint_analysis_result = read_octopustaint_results()
    mangodfa_analysis_result = read_mangodfa_results()

    # 三者共有的固件键，并按首字母排序
    common_keys = sorted(
        set(sgtaint_analysis_result.keys()) &
        set(octopustaint_analysis_result.keys()) &
        set(mangodfa_analysis_result.keys()),
        key=lambda x: x[0]
    )

    # 列定义（标题 & 是否时间列）
    SGT_COLS  = [("BinFiles", False), ("Time(s)", True), ("PathC", False), ("PathS", False), ("PathL", False), ("Vul", False)]
    OCTO_COLS = [("BinFiles", False), ("Time(s)", True), ("PathC", False), ("PathS", False), ("Vul", False)]
    MNG_COLS  = [("Time(s)", True),  ("PathS", False), ("Vul", False)]

    # 数字列统一宽度；固件列宽按最长固件名自适应
    COL_W = 10
    FW_W  = max(len(k) for k in common_keys) + 2

    # 区块真实宽度 = 子列数 * COL_W + (子列数 - 1) * len(" | ")
    def block_width(n_cols: int) -> int:
        return n_cols * COL_W + (n_cols - 1) * 3

    SGT_W  = block_width(len(SGT_COLS))
    OCTO_W = block_width(len(OCTO_COLS))
    MNG_W  = block_width(len(MNG_COLS))

    out = "/home/Experiment/output/bug_finding_comparison.txt"
    with open(out, "w", encoding="utf-8") as f:
        # 一级表头（方法名与二级列严格同宽）
        line1 = (
            f"{'Firmware':<{FW_W}} | "
            f"{'SGTaint':^{SGT_W}} | "
            f"{'OctopusTaint':^{OCTO_W}} | "
            f"{'Mangodfa':^{MNG_W}}"
        )
        f.write(line1 + "\n")

        # 二级表头（逐列标题）
        line2 = (
            f"{'':<{FW_W}} | "
            + " | ".join(f"{name:>{COL_W}}" for name, _ in SGT_COLS) + " | "
            + " | ".join(f"{name:>{COL_W}}" for name, _ in OCTO_COLS) + " | "
            + " | ".join(f"{name:>{COL_W}}" for name, _ in MNG_COLS)
        )
        f.write(line2 + "\n")

        # 分隔线：与第一行长度一致
        f.write("-" * len(line1) + "\n")

        # 平均值累加器（只统计非预留列）
        avg = {
            "sgt_bin": [], "sgt_time": [], "sgt_pc": [], "sgt_ps": [],
            "oct_bin": [], "oct_time": [], "oct_pc": [], "oct_ps": [],
            "mng_time": [], "mng_ps": []
        }

        # 数据行
        for fw in common_keys:
            sgt  = sgtaint_analysis_result.get(fw, {}).get("parsed_data", {})
            octo = octopustaint_analysis_result.get(fw, {})
            mng  = mangodfa_analysis_result.get(fw, {})

            # 取值映射（你的字典字段名）
            sgt_vals  = [
                (sgt.get('binary-file-number', "N/A"), False),
                (sgt.get('total-time',         "N/A"), True),
                (sgt.get('path_complete',      "N/A"), False),
                (sgt.get('path_sanitization',  "N/A"), False),
                ("N/A", False),  # PathL 预留
                ("N/A", False),  # Vul   预留
            ]
            octo_vals = [
                (octo.get('binary_number',          "N/A"), False),
                (octo.get('total_analysis_time',     "N/A"), True),
                (octo.get('complete_path_number',    "N/A"), False),
                (octo.get('sanitization_path_number',"N/A"), False),
                ("N/A", False),  # Vul 预留
            ]
            mng_vals  = [
                (mng.get('Analysis Time',   "N/A"), True),
                (mng.get('Potential Paths', "N/A"), False),
                ("N/A", False),  # Vul 预留
            ]

            # 写一行
            row = (
                f"{fw:<{FW_W}} | "
                + " | ".join(_fmt(v, COL_W, is_time=t) for v, t in sgt_vals) + " | "
                + " | ".join(_fmt(v, COL_W, is_time=t) for v, t in octo_vals) + " | "
                + " | ".join(_fmt(v, COL_W, is_time=t) for v, t in mng_vals)
            )
            f.write(row + "\n")

            # 参与平均（忽略 'N/A' 与预留）
            def _acc(lst, v, is_time=False):
                try:
                    x = float(v)
                    lst.append(x)
                except:
                    pass

            _acc(avg["sgt_bin"],  sgt.get('binary-file-number', None))
            _acc(avg["sgt_time"], sgt.get('total-time', None), True)
            _acc(avg["sgt_pc"],   sgt.get('path_complete', None))
            _acc(avg["sgt_ps"],   sgt.get('path_sanitization', None))

            _acc(avg["oct_bin"],  octo.get('binary_number', None))
            _acc(avg["oct_time"], octo.get('total_analysis_time', None), True)
            _acc(avg["oct_pc"],   octo.get('complete_path_number', None))
            _acc(avg["oct_ps"],   octo.get('sanitization_path_number', None))

            _acc(avg["mng_time"], mng.get('Analysis Time', None), True)
            _acc(avg["mng_ps"],   mng.get('Potential Paths', None))

        # 平均行
        f.write("-" * len(line1) + "\n")
        def _sum(xs):  
            return sum(xs) if xs else "N/A"
        def _mean(xs): 
            return (sum(xs) / len(xs)) if xs else "N/A"
        
        # Total 行
        tot_sgt  = [(_sum(avg["sgt_bin"]), False), (_sum(avg["sgt_time"]), True), (_sum(avg["sgt_pc"]), False), (_sum(avg["sgt_ps"]), False), ("N/A", False), ("N/A", False)]
        tot_octo = [(_sum(avg["oct_bin"]), False), (_sum(avg["oct_time"]), True), (_sum(avg["oct_pc"]), False), (_sum(avg["oct_ps"]), False), ("N/A", False)]
        tot_mng  = [(_sum(avg["mng_time"]), True), (_sum(avg["mng_ps"]), False), ("N/A", False)]
        
        total_row = (
            f"{'Total':<{FW_W}} | "
            + " | ".join(_fmt(v, COL_W, is_time=t) for v, t in tot_sgt) + " | "
            + " | ".join(_fmt(v, COL_W, is_time=t) for v, t in tot_octo) + " | "
            + " | ".join(_fmt(v, COL_W, is_time=t) for v, t in tot_mng)
        )
        f.write(total_row + "\n")

        avg_sgt  = [
            (_mean(avg["sgt_bin"]),  False),
            (_mean(avg["sgt_time"]), True),
            (_mean(avg["sgt_pc"]),   False),
            (_mean(avg["sgt_ps"]),   False),
            ("N/A", False),  # PathL 预留
            ("N/A", False),  # Vul   预留
        ]
        avg_octo = [
            (_mean(avg["oct_bin"]),  False),
            (_mean(avg["oct_time"]), True),
            (_mean(avg["oct_pc"]),   False),
            (_mean(avg["oct_ps"]),   False),
            ("N/A", False),  # Vul 预留
        ]
        avg_mng  = [
            (_mean(avg["mng_time"]), True),
            (_mean(avg["mng_ps"]),   False),
            ("N/A", False),  # Vul 预留
        ]

        avg_row = (
            f"{'Average':<{FW_W}} | "
            + " | ".join(_fmt(v, COL_W, is_time=t) for v, t in avg_sgt) + " | "
            + " | ".join(_fmt(v, COL_W, is_time=t) for v, t in avg_octo) + " | "
            + " | ".join(_fmt(v, COL_W, is_time=t) for v, t in avg_mng)
        )
        f.write(avg_row + "\n")

    print(f"Comparison table written to {out}")