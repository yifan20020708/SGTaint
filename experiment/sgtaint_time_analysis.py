# -*- coding: utf-8 -*-
import json
import matplotlib.pyplot as plt
import numpy as np

# 读取sgtaint的时间信息
def get_sgtaint_time_info():
    sgtaint_time_info = {}
    sgtaint_result_info_path = "/home/Experiment/output/sgtaint_analysis_result.json"
    with open(sgtaint_result_info_path, "r", encoding="utf-8") as f:
        sgtaint_result = json.load(f)
    for firmware_mark, result in sgtaint_result.items():
        run_result = result["parsed_data"]
        sgtaint_time_info[firmware_mark] = {
            "total-time": run_result["total-time"],
            "rda_average_function_time": run_result["rda_average_function_time"],
            "average_time_binary": run_result["average_time_binary"]
        }
    return sgtaint_time_info

def plot_sgtaint_times_publication(sgtaint_time_info, out_prefix="sgtaint_times"):
    # 提取三个维度
    fw_times = [v["total-time"] for v in sgtaint_time_info.values()]
    bin_times = [v["average_time_binary"] for v in sgtaint_time_info.values()]
    fn_times = [v["rda_average_function_time"] for v in sgtaint_time_info.values()]

    data = [fw_times, bin_times, fn_times]
    labels = ["Firmware-level", "Binary-level", "Function-level"]
    positions = [1, 2, 3]
    colors = ["#4C72B0", "#55A868", "#C44E52"]

    EPS = 1e-2
    data = [[max(x, EPS) for x in arr if x is not None] for arr in data]

    fig, ax = plt.subplots(figsize=(7, 5), dpi=150)

    # 箱线图
    box = ax.boxplot(
        data,
        positions=positions,
        widths=0.6,
        showmeans=True,
        patch_artist=True,
        medianprops=dict(color="black", linewidth=1.5),
        meanprops=dict(marker="D", markersize=7, markeredgecolor="black", markerfacecolor="black"),
        boxprops=dict(linewidth=1.2),
        whiskerprops=dict(linewidth=1.2),
        capprops=dict(linewidth=1.2),
        flierprops=dict(marker="o", markersize=3, alpha=0.4, markerfacecolor="gray"),
    )

    # 给箱体上色
    for patch, color in zip(box["boxes"], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.5)

    # 抖动散点
    rng = np.random.default_rng(42)
    for i, arr in enumerate(data):
        x = rng.normal(positions[i], 0.05, size=len(arr))
        ax.scatter(x, arr, s=18, alpha=0.6, color=colors[i], edgecolor="k", linewidth=0.3)

    # 均值数值标注
    for i, arr in enumerate(data):
        mean_val = np.mean(arr)
        ax.text(
            positions[i],
            mean_val * 1.2,  # 稍微往上移
            f"{mean_val:.1f}",
            ha="center",
            va="bottom",
            fontsize=10,
            fontweight="bold",
        )

    # 对数坐标
    ax.set_yscale("log")
    ax.set_ylabel("Analysis Time (s, log scale)", fontsize=12)
    ax.set_xticks(positions)
    ax.set_xticklabels(labels, fontsize=11)
    ax.set_title("SGTaint Analysis Time across Three Granularities", fontsize=13, weight="bold")
    ax.grid(axis="y", linestyle="--", alpha=0.4)

    fig.tight_layout()

    # 输出高质量图
    fig.savefig(f"{out_prefix}.png", dpi=600, bbox_inches="tight")
    fig.savefig(f"{out_prefix}.pdf", bbox_inches="tight")
    print(f"Saved: {out_prefix}.png (600 dpi), {out_prefix}.pdf (vector)")

if __name__ == "__main__":
    sgtaint_time_info = get_sgtaint_time_info()
    plot_sgtaint_times_publication(sgtaint_time_info, out_prefix="/home/Experiment/output/sgtaint_times_logscale")
