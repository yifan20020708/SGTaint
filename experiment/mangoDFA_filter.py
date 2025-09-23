# -*- coding: utf-8 -*-
import re 
import json

filter_list = ["LR1200GB", "NR1800X", "R6200", "R6300", "R7000P"]

def is_constant_style(s: str) -> bool:
    pattern = r'^[A-Z0-9_]+$'  # 允许大写字母、数字和下划线
    return bool(re.match(pattern, s))

# 进行mangoDFA结果过滤
def mangoDFA_filter():
    filter_path = []
    file_path = "/home/Experiment/output/unique_mangoDFA_results.json"
    with open(file_path, "r", encoding="utf-8") as f:
        mangoDFA_results = json.load(f)
    for path in mangoDFA_results:
        binary_path = path["binary_path"]
        if any(filter_item in binary_path for filter_item in filter_list):
            input_likely = path["inputs"]["likely"]
            if any(is_constant_style(input_item) for input_item in input_likely):
                continue
            filter_path.append(path)
    print(f"filter: {len(filter_path)}")
    with open("/home/Experiment/output/mangoDFA_filter_results.json", "w", encoding="utf-8") as f:
        json.dump(filter_path, f, indent=4)
        
if __name__ == "__main__":
    mangoDFA_filter()
            

