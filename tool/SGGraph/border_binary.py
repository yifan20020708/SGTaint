# -*- coding: utf-8 -*-
import time
import logging
import warnings
import os
import filecmp
from pathlib import Path
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed, TimeoutError
import numpy as np
from sklearn.mixture import GaussianMixture
from sklearn.exceptions import ConvergenceWarning
import tool.Config.config as config_sgtaint
from tool.SGGraph.utils import find_binary_path, file_contains_function
from tool.Keyword.front_analysis import get_keyword_function_from_front
from tool.Keyword.binary_analysis import AnalysisBinary

logger = logging.getLogger("sgtaint.BorderBinary")

# 获取所有二进制文件的匹配关键字个数
def binary_keyword_function(directory):
    binary_path = find_binary_path(directory)
    start = time.time()
    binary_keyword_function_list = [] # 最终结果
    binary_keyword_function_list_unfilter = []
    universal_string_list = [] # 获取通用字符串
    # 获取前端关键字以及函数集合
    keyword_set, function_set = get_keyword_function_from_front(directory)
    # 进行路径过滤
    valid_paths = []
    for idx, path in enumerate(binary_path, start=1):
        if not Path(path).exists() or not Path(path).is_file():
            logger.warning(f"[{idx}/{len(binary_path)}] Skipping non-existent or non-file path: {path}")
            continue
        valid_paths.append(path)
    logger.info(f"Starting parallel binary analysis: {len(valid_paths)} files")
    for idx, path in enumerate(valid_paths, start=1):
        try:
            binary = AnalysisBinary(path) # 前端关键字匹配相关二进制对象
            # 提取二进制文件中的字符串
            binary.get_string()
            binary.find_keyword(keyword_set)
            binary.find_function(function_set)
            binary_string = binary.binary_only_string
            binary.keyword_function_file() # 将相关信息写入文件之中
            universal_string_list.append(binary_string) # 收集所有的关键字信息
            if os.path.basename(path) in config_sgtaint.BOUNDARY_BINARIES_WHITE_LIST or ".so" in os.path.basename(path): # 初始过滤
                continue
            binary_keyword_function_list_unfilter.append((path, binary_string))
            logger.debug(f"[{idx}/{len(valid_paths)}] Analyze Finished: {path}.")
        except Exception:
            logger.exception(f"[{idx}/{len(valid_paths)}] Failed binary analysis: {path}.")
    # 获取通用字符串
    string_counter = Counter()
    for binary_string_set in universal_string_list:
        string_counter.update(binary_string_set) # 统计每一个字符串出现的文件次数
    universal_string = {string for string, count in string_counter.items() if count > config_sgtaint.THRESHOLD}
    # 进行通用字符串的过滤
    for path, binary_string in binary_keyword_function_list_unfilter:
        unique_string = binary_string - universal_string
        binary_keyword_function_list.append((path, len(unique_string)))
    binary_keyword_function_list.sort(key=lambda x: x[1], reverse=True)
    duration = time.time() - start
    logger.info(f"Completed serial analysis of {len(valid_paths)} binaries in {duration:.2f}s")
    # 记录匹配结果
    for idx, result in enumerate(binary_keyword_function_list, start=1):
        logger.info(f"[{idx}/{len(binary_keyword_function_list)}] {result[0]} -- {result[1]}")
    return binary_keyword_function_list


# 修改为并行模式（高性能模式）
def process_single_binary(path, keyword_set, function_set):
    try:
        binary = AnalysisBinary(path)
        binary.get_string()
        binary.find_keyword(keyword_set)
        binary.find_function(function_set)
        binary_string = binary.binary_only_string
        binary.keyword_function_file() # 将相关信息写入文件之中
        return (path, binary_string)
    except Exception:
        logger.exception(f"Worker failed for binary: {path}")
    return None


# 使用进程池进行速度提升
def binary_keyword_function_parallel(directory):
    binary_path = find_binary_path(directory)
    start = time.time()
    binary_keyword_function_list = [] # 最终结果
    binary_keyword_function_list_unfilter = []
    universal_string_list = [] # 获取通用字符串
    # 获取前端关键字以及函数集合
    keyword_set, function_set = get_keyword_function_from_front(directory)
    # 进行路径过滤
    valid_paths = []
    for idx, path in enumerate(binary_path, start=1):
        if not Path(path).exists() or not Path(path).is_file():
            logger.warning(f"[{idx}/{len(binary_path)}] Skipping non-existent or non-file path: {path}")
            continue
        valid_paths.append(path)
    logger.info(f"Starting parallel binary analysis: {len(valid_paths)} files")
    with ProcessPoolExecutor() as executor:
        # 提交所有任务
        futures = {
            executor.submit(process_single_binary, path, keyword_set, function_set): path
            for path in valid_paths
        }
        for idx, future in enumerate(as_completed(futures), 1):
            try:
                result = future.result(timeout=config_sgtaint.WORKER_TIMEOUT_SECONDS)
                if result:
                    path, binary_string = result
                    universal_string_list.append(binary_string) # 收集所有的关键字信息
                    if os.path.basename(path) not in config_sgtaint.BOUNDARY_BINARIES_WHITE_LIST and ".so" not in os.path.basename(path): # 初始过滤
                        binary_keyword_function_list_unfilter.append((path, binary_string))
                    logger.debug(f"[{idx}/{len(valid_paths)}] Analyze Finished: {futures[future]}.")
            except TimeoutError:
                logger.error(f"[{idx}/{len(valid_paths)}] Timeout analyzing: {futures[future]}.")
            except Exception:
                logger.exception(f"[{idx}/{len(valid_paths)}] Exception analyzing: {futures[future]}.")
    # 获取通用字符串
    string_counter = Counter()
    for binary_string_set in universal_string_list:
        string_counter.update(binary_string_set) # 统计每一个字符串出现的文件次数
    universal_string = {string for string, count in string_counter.items() if count > config_sgtaint.THRESHOLD}
    # 进行通用字符串的过滤
    for path, binary_string in binary_keyword_function_list_unfilter:
        unique_string = binary_string - universal_string
        if unique_string:
            binary_keyword_function_list.append((path, len(unique_string)))
    binary_keyword_function_list.sort(key=lambda x: x[1], reverse=True)
    duration = time.time() - start
    logger.info(f"Completed parallel analysis of {len(binary_path)} binaries in {duration:.2f}s")
    # 记录匹配结果
    for idx, result in enumerate(binary_keyword_function_list, start=1):
        logger.info(f"[{idx}/{len(binary_keyword_function_list)}] {result[0]} -- {result[1]}")
    return binary_keyword_function_list


# 使用聚类算法获取边界二进制文件组，使用最大均值差
def get_border_binaries_by_cluster_max_mean_gap(directory):
    start_time = time.time()
    if config_sgtaint.BOUNDARY_BINARIES: # 直接从配置中读取边界二进制文件
        logger.info("Boundary binaries received successfully!")
        boundary_binary_list = [x.strip() for x in config_sgtaint.BOUNDARY_BINARIES.split(",") if x.strip()]
        for binary_path in boundary_binary_list:
            if not os.path.exists(binary_path):
                raise FileNotFoundError(f"Binary path not found: {binary_path}")
        names = ", ".join(str(f) for f in boundary_binary_list)
        logger.info(f"Boundary binaries identified: {names}")
        return boundary_binary_list
    results = binary_keyword_function_parallel(directory)
    files = [r[0] for r in results]
    counts = np.array([r[1] for r in results]).reshape(-1, 1)
    if counts.size == 0:
        logger.warning(f"No binaries to cluster in {directory}")
        return []
    if counts.size == 1:
        names = ", ".join(str(f) for f in files)
        logger.info(f"Boundary binaries identified: {names}")
        return files
    # 使用BIC选模型组件数
    max_components = min(5, len(counts))
    best_bic, best_n = np.inf, 1
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=ConvergenceWarning)
        for n in range(1, max_components + 1):
            try:
                gm = GaussianMixture(n_components=n, random_state=0).fit(counts)
                bic = gm.bic(counts)
                if bic < best_bic:
                    best_bic, best_n = bic, n
            except Exception:
                continue
    gm = GaussianMixture(n_components=best_n, random_state=0).fit(counts)
    labels = gm.predict(counts)
    means = gm.means_.flatten()
    # 找最大均值差确定边界簇
    sorted_clusters = sorted(enumerate(means), key=lambda x: -x[1])
    gaps = [(sorted_clusters[i][1] - sorted_clusters[i+1][1], i) for i in range(len(sorted_clusters)-1)]
    _, gap_idx = max(gaps, key=lambda x: x[0]) if gaps else (0, 0)
    boundary_cluster_indices = {idx for idx, _ in sorted_clusters[: gap_idx+1]}
    boundary_files = [files[i] for i, lbl in enumerate(labels) if lbl in boundary_cluster_indices]
    # 过滤重复文件
    unique_boundary = []
    for f in boundary_files:
        if not any(filecmp.cmp(str(f), str(seen), shallow=False) for seen in unique_boundary):
            unique_boundary.append(f)
    # 默认项进行匹配
    for file in files:
        for binary_name_re in config_sgtaint.BOUNDARY_BINARY_NAME:
            if binary_name_re in os.path.basename(file) and file not in unique_boundary:
                unique_boundary.append(file)
                break
    # 对unique文件进行功能性过滤      
    filtered_boundary = []
    for path in unique_boundary:
        if any(file_contains_function(path, func) for func in config_sgtaint.SOURCES):
            filtered_boundary.append(path)
    boundary_list = filtered_boundary if filtered_boundary else unique_boundary # 若不存在进行回退
    # 将识别到的边界二进制写入日志中
    if boundary_list:
        names = ", ".join(str(f) for f in boundary_list)
        logger.info(f"Boundary binaries identified: {names}")
    else:
        logger.info("No boundary binaries identified.")
    logger.info(f"Identified {len(boundary_list)} boundary binaries using {best_n} clusters")
    duration = time.time() - start_time
    logger.info(f"Boundary binary identification completed in {duration:.2f}s")
    return boundary_list