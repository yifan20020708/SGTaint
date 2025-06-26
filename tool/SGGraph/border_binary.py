# -*- coding: utf-8 -*-
import time
import logging
import warnings
import os
import filecmp
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed, TimeoutError
import numpy as np
from sklearn.mixture import GaussianMixture
from sklearn.exceptions import ConvergenceWarning
import tool.Config.config as config_sgtaint
from tool.SGGraph.utils import find_binary_path
from tool.Keyword.front_analysis import get_keyword_function_from_front
from tool.Keyword.binary_analysis import AnalysisBinary

logger = logging.getLogger("sgtaint.BorderBinary")

# 获取所有二进制文件的匹配关键字个数
def binary_keyword_function(directory):
    binary_path = find_binary_path(directory)
    start = time.time()
    logger.info(f"Starting serial binary analysis: {len(binary_path)} files")
    binary_keyword_function_list = []
    # 获取前端关键字以及函数集合
    keyword_set, function_set = get_keyword_function_from_front(directory)
    index = 0
    for path in binary_path:
        index += 1
        path = Path(path)
        # 路径校验
        if not path.exists():
            logger.warning(f"[{index}/{len(binary_path)}] Skipping non-existent path: {path}")
            continue
        if not path.is_file():
            logger.warning(f"[{index}/{len(binary_path)}] Skipping non-file path: {path}")
            continue
        try:
            binary = AnalysisBinary(path)
            # 提取二进制文件中的字符串
            binary.get_string()
            binary.find_keyword(keyword_set)
            binary.find_function(function_set)
            keyword_number = binary.get_keyword_number()
            function_number = binary.get_function_number()
            binary.keyword_function_file()
            if keyword_number + function_number >= config_sgtaint.MIN_KEYWORD_NUMBER or os.path.basename(path) in config_sgtaint.BOUNDARY_BINARY_NAME:
                # 需要更新二进制文件内部的关键字信息
                binary_keyword_function_list.append((path, keyword_number + function_number))
            logger.debug(f"[{index}/{len(binary_path)}] Analyze Finished! {path} : {keyword_number + function_number} matches")
        except Exception:
            logger.exception(f"[{index}/{len(binary_path)}] Failed binary analysis: {path}")
    # 按照keyword_number+function_number从高到低排序
    binary_keyword_function_list.sort(key=lambda x: x[1], reverse=True)
    duration = time.time() - start
    logger.info(f"Completed serial analysis of {len(binary_path)} binaries in {duration:.2f}s")
    return binary_keyword_function_list


# 修改为并行模式（高性能模式）
def process_single_binary(path, keyword_set, function_set):
    try:
        binary = AnalysisBinary(path)
        binary.get_string()
        binary.find_keyword(keyword_set)
        binary.find_function(function_set)
        keyword_number = binary.get_keyword_number()
        function_number = binary.get_function_number()
        binary.keyword_function_file()
        if keyword_number + function_number >= config_sgtaint.MIN_KEYWORD_NUMBER or os.path.basename(path) in config_sgtaint.BOUNDARY_BINARY_NAME:
            return (path, keyword_number + function_number)
    except Exception:
        logger.exception(f"Worker failed for binary: {path}")
    return None


# 使用进程池进行速度提升
def binary_keyword_function_parallel(directory):
    binary_path = find_binary_path(directory)
    keyword_set, function_set = get_keyword_function_from_front(directory)
    binary_keyword_function_list = []
    # 进行路径过滤
    valid_paths = []
    for idx, raw in enumerate(binary_path, start=1):
        p = Path(raw)
        if not p.exists():
            logger.warning(f"[{idx}/{len(binary_path)}] Skipping non-existent path: {p}")
        elif not p.is_file():
            logger.warning(f"[{idx}/{len(binary_path)}] Skipping non-file path: {p}")
        else:
            valid_paths.append(p)
    start = time.time()
    logger.info(f"Starting parallel binary analysis: {len(valid_paths)} files")
    with ProcessPoolExecutor() as executor:
        # 提交所有任务
        futures = {
            executor.submit(process_single_binary, str(path), keyword_set, function_set): path
            for path in valid_paths
        }
        total = len(valid_paths)
        for idx, future in enumerate(as_completed(futures), 1):
            try:
                result = future.result(timeout=config_sgtaint.WORKER_TIMEOUT_SECONDS)
                if result:
                    binary_keyword_function_list.append(result)
                logger_info = f"[{idx}/{total}] Analyze Finished! {futures[future]} : {result[1]} matches" if result else f"[{idx}/{total}] Analyze Finished! {futures[future]}"
                logger.debug(logger_info)
            except TimeoutError:
                logger.error(f"[{idx}/{total}] Timeout analyzing: {futures[future]}")
            except Exception:
                logger.exception(f"[{idx}/{total}] Exception analyzing: {futures[future]}")
    binary_keyword_function_list.sort(key=lambda x: x[1], reverse=True)
    duration = time.time() - start
    logger.info(f"Completed parallel analysis of {len(binary_path)} binaries in {duration:.2f}s")
    return binary_keyword_function_list


# 使用聚类算法获取边界二进制文件组（获取边界二进制文件的文件地址）
def get_border_binaries_by_cluster(directory):
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
    binary_file = []
    keyword_number = []
    binary_list = binary_keyword_function_parallel(directory) # 使用并行处理
    for binary in binary_list:
        binary_file.append(binary[0])
        keyword_number.append(binary[1])
    keyword_number = np.array(keyword_number)
    X = keyword_number.reshape(-1, 1)
    if len(X) == 0:
        logger.warning(f"No binaries to cluster in {directory}")
        return []  # 没有文件，直接返回空列表
    if len(X) == 1:
        names = ", ".join(str(f) for f in binary_file)
        logger.info(f"Boundary binaries identified: {names}")
        return binary_file
    max_components = min(5, len(X))  # 最多不能超过样本数
    best_bic, best_n = np.inf, 1
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=ConvergenceWarning)
        for n in range(1, max_components + 1):
            try:
                gm = GaussianMixture(n_components=n, random_state=0).fit(X)
                bic = gm.bic(X)
                if bic < best_bic:
                    best_bic, best_n = bic, n
            except ValueError:
                continue  # 某些 n 无法拟合，跳过
    gm = GaussianMixture(n_components=best_n, random_state=0).fit(X)
    labels = gm.predict(X)
    means = gm.means_.flatten()
    k_max = int(np.argmax(means))
    boundary_idxs = np.where(labels == k_max)[0]
    boundary_files = [binary_file[i] for i in boundary_idxs]
    # 过滤重复文件
    unique_boundary = []
    for f in boundary_files:
        if any(filecmp.cmp(f, seen, shallow=False) for seen in unique_boundary):
            continue
        unique_boundary.append(f)
    # 默认项进行匹配
    for file in binary_file:
        if os.path.basename(file) in config_sgtaint.BOUNDARY_BINARY_NAME and file not in unique_boundary:
            unique_boundary.append(file)
    # 将识别到的边界二进制写入日志中
    if unique_boundary:
        names = ", ".join([f for f in unique_boundary])
        logger.info(f"Boundary binaries identified: {names}")
    else:
        logger.info("No boundary binaries identified.")
    logger.info(f"Identified {len(unique_boundary)} boundary binaries using {best_n} clusters")
    duration = time.time() - start_time
    logger.info(f"Boundary binary identification completed in {duration:.2f}s")
    return unique_boundary


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
        if os.path.basename(file) in config_sgtaint.BOUNDARY_BINARY_NAME and file not in unique_boundary:
            unique_boundary.append(file)
    # 将识别到的边界二进制写入日志中
    if unique_boundary:
        names = ", ".join(str(f) for f in unique_boundary)
        logger.info(f"Boundary binaries identified: {names}")
    else:
        logger.info("No boundary binaries identified.")
    logger.info(f"Identified {len(unique_boundary)} boundary binaries using {best_n} clusters")
    duration = time.time() - start_time
    logger.info(f"Boundary binary identification completed in {duration:.2f}s")
    return unique_boundary