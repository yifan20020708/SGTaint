import os
import sys
import argparse
import logging
import time
import shutil
import json
from collections import defaultdict
import tool.Config.config as config_sgtaint
from pathlib import Path
from logging.handlers import RotatingFileHandler
from concurrent.futures import ProcessPoolExecutor, as_completed, TimeoutError
from tool.SGGraph.base import AnalysisBinaryDict, SetGetGraph, AnalysisBinary
from tool.SGGraph.sg_graph import set_get_graph_create
from tool.SGGraph.utils import dedupe_paths, generate_binary_processing_order_robust
from tool.BugFinder.utils import construct_cross_binary_data_flow_single, get_sorted_potential_path_sanitization
from tool.LLM.LLM_check import llm_assist_parallel, llm_prompt_generate

__version__ = "1.1.0"

# 日志输出颜色
LEVEL_COLORS = {
    logging.DEBUG: "\033[37m",    # 灰
    logging.INFO: "\033[32m",     # 绿
    logging.WARNING: "\033[33m",  # 黄
    logging.ERROR: "\033[31m",    # 红
    logging.CRITICAL: "\033[41m", # 红底
}
RESET_SEQ = "\033[0m"

# 日志格式配置
class MaxLevelFilter(logging.Filter):
    def __init__(self, level: int):
        super().__init__()
        self.max_level = level
    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno <= self.max_level
    
class ColorFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        color = LEVEL_COLORS.get(record.levelno, "")
        if color:
            return f"{color}{msg}{RESET_SEQ}"
        return msg


# SGTaint运行类
class SGTaintRunner:
    def __init__(self, firmware, name, output_dir, sggraph=None, parallel=True, ghidra=True, llm=True, config=True, model="deepseek", boundary_binaries=None):
        self.firmware = firmware
        self.name = name
        self.output_dir = output_dir
        self.sggraph = sggraph
        self.parallel = parallel
        self.llm = llm
        self.ghidra = ghidra
        # 配置全局参数
        config_sgtaint.FILE_SYSTEM = firmware
        config_sgtaint.FIRMWARE_NAME = name
        config_sgtaint.SG_FUNCTION_INFO = sggraph
        config_sgtaint.CONFIG_NEW_GETTER = config
        config_sgtaint.LLM_MODEL = config_sgtaint.MODEL_MAP.get(model, config_sgtaint.LLM_MODEL_QIANWEN)
        config_sgtaint.GHIDRA_ASSIST = ghidra
        config_sgtaint.BOUNDARY_BINARIES = boundary_binaries
        self._setup_logger()
        self.logger.info(f"Initialized SGTaintRunner (v{__version__})")

    # 配置日志记录器
    def _setup_logger(self):
        # 确保日志目录存在
        log_dir = Path(config_sgtaint.OUT_DIR)
        os.makedirs(log_dir, exist_ok=True)
        log_file = log_dir / "sgtaint.log"
        # 先关闭并移除旧 handler
        old_handlers = list(self.logger.handlers) if hasattr(self, "logger") else []
        for h in old_handlers:
            h.close()
        self.logger = logging.getLogger("sgtaint")
        self.logger.handlers.clear()
        self.logger.setLevel(logging.DEBUG)
        # 删除旧日志文件
        if log_file.exists():
            log_file.unlink()
        # 文件滚动日志
        fh = RotatingFileHandler(
            filename=log_file,
            mode="w",
            maxBytes=10 * 1024 * 1024,  # 限定单个文件的大小
            backupCount=5,
            encoding="utf-8"
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        self.logger.addHandler(fh)
        # 控制台：INFO 及以下 -> stdout
        stdout_handler = logging.StreamHandler(sys.stdout)
        stdout_handler.setLevel(logging.DEBUG)
        stdout_handler.addFilter(MaxLevelFilter(logging.INFO))
        stdout_handler.setFormatter(ColorFormatter("%(asctime)s [%(levelname)s] %(message)s"))
        self.logger.addHandler(stdout_handler)
        # 控制台：WARNING 及以上 -> stderr
        stderr_handler = logging.StreamHandler(sys.stderr)
        stderr_handler.setLevel(logging.WARNING)
        stderr_handler.setFormatter(ColorFormatter("%(asctime)s [%(levelname)s] %(message)s"))
        self.logger.addHandler(stderr_handler)

    # 针对每一次任务清空输出目录
    def clear_dir(self, path: str):
        if not os.path.exists(path):
            os.makedirs(path, exist_ok=True)
            self.logger.info(f"Created directory: {path}")
            return
        if not os.path.isdir(path):
            self.logger.warning(f"Skipping non-directory: {path}")
            return

        for entry in os.scandir(path):
            try:
                if entry.is_dir(follow_symlinks=False):
                    shutil.rmtree(entry.path)
                    self.logger.debug(f"Removed directory: {entry.path}")
                else:
                    # 普通文件或符号链接都使用 os.remove
                    os.remove(entry.path)
                    self.logger.debug(f"Removed file/symlink: {entry.path}")
            except Exception as e:
                self.logger.error(f"Failed to remove {entry.path}: {e}")
        
    # 清除历史遗留文件
    def clear_project(self):
        dirs = [
            config_sgtaint.OUTPUT_DIR,
            config_sgtaint.VULN_OUT_DIR,
            config_sgtaint.BINARY_CONFIG_DIR,
            config_sgtaint.BINARY_INFO_DIR,
            config_sgtaint.TMP_KEYWORD,
            config_sgtaint.BINARY_TMP,
            config_sgtaint.GHIDRA_DIR,
            config_sgtaint.NEW_GETTER_DIR
        ]
        for d in dirs:
            self.clear_dir(d)
            self.logger.info(f"Cleared: {d}")
    
    # 将结果转储到用户提供的目录之中
    def copy_results(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)
            self.logger.info(f"Created output dir: {self.output_dir}")
        src_dirs = [config_sgtaint.OUT_DIR, config_sgtaint.TMP_DIR]
        for src in src_dirs:
            for item in os.listdir(src):
                src_path = os.path.join(src, item)
                dst_path = os.path.join(self.output_dir, item)
                try:
                    if os.path.isdir(src_path):
                        if os.path.exists(dst_path):
                            shutil.rmtree(dst_path)
                        shutil.copytree(src_path, dst_path)
                    else:
                        shutil.copy2(src_path, dst_path)
                    self.logger.debug(f"Copied {src_path} to {dst_path}")
                except Exception as e:
                    self.logger.error(f"Failed copying {src_path} -> {dst_path}: {e}")
    
    # 运行SGTaint
    def run(self):
        self.clear_project()
        if not os.path.isdir(self.firmware):
            raise FileNotFoundError(f"Firmware path not found: {self.firmware}")
        # 需要生成对应的固件挖掘md信息
        firmware_info_markdown_file_path = os.path.join(config_sgtaint.OUTPUT_DIR, f"{self.name}_INFO.md") # 统计重要信息
        self.info_file = open(firmware_info_markdown_file_path, 'a+')
        self.info_file.write(f"# Firmware information of {self.name}\n\n")
        self.info_file.write(f"1. File system folder: `{self.firmware}`;\n") # 写入文件系统名称
        self.info_file.flush()
        if self.parallel:
            merged_path, sorted_potential_path_sanitization = start_sgtaint_parallel(self.info_file)
        else:
            merged_path, sorted_potential_path_sanitization = start_sgtaint_serial(self.info_file)
        # 合并路径
        os.makedirs(config_sgtaint.OUTPUT_DIR, exist_ok=True)
        llm_prompt_path = llm_prompt_generate(merged_path)
        llm_prompt_file_path = os.path.join(config_sgtaint.OUTPUT_DIR, f"{self.name}_path_sanitization_llm_prompt.json")
        with open(llm_prompt_file_path, "w") as f:
            json.dump(llm_prompt_path, f, indent=4)
        if self.llm: # 开启llm检查
            llm_check_path = llm_assist_parallel(sorted_potential_path_sanitization)
            llm_check_file_path = os.path.join(config_sgtaint.OUTPUT_DIR, f"{self.name}_path_sanitization_llm_check.json")
            with open(llm_check_file_path, "w") as f: # 写入到文件之中
                json.dump(llm_check_path, f, indent=4)
        self.copy_results()
        

# 使用串行方法启动SGTaint分析
def start_sgtaint_serial(info_file):
    logger = logging.getLogger("sgtaint")
    total_start = time.time()
    logger.info("[STEP 1] Initializing AnalysisBinaryDict and SetGetGraph ...")
    analysis_binary_dict = AnalysisBinaryDict()
    set_get_graph = SetGetGraph()
    step1_end = time.time()
    logger.info(f"[STEP 1] finished in {step1_end - total_start:.2f} seconds\n")

    logger.info("[STEP 2] Building SGGraph and collecting binaries to analyze ...")
    sg_start = time.time()
    set_get_graph_create(config_sgtaint.FILE_SYSTEM, analysis_binary_dict, set_get_graph)
    processing_order_dict = generate_binary_processing_order_robust(analysis_binary_dict)
    sg_end = time.time()
    logger.info(f"[STEP 2] finished in {sg_end - sg_start:.2f} seconds\n")
    
    # 将相关信息写入info_file
    info_file.write("2. Boundary binaries: \n")
    for file_path in analysis_binary_dict.get_border_binary_path_list():
        info_file.write(f"   - `{file_path}`;\n")
    info_file.write(f"3. Transfer function information: `{analysis_binary_dict.get_set_func_name}`;\n")
    info_file.write(f"4. Set-get graph generation time: {sg_end - sg_start:.2f} s\n")
    info_file.write("5. Analyzing binary file list: \n")
    info_file.flush()

    logger.info("[STEP 3] Serial analysis of all binaries ...")
    serial_start = time.time()
    keyword_binary_dict = {}
    binary_index = 0
    for file_path in analysis_binary_dict.analysis_binary_dict:
        analysis_binary: AnalysisBinary = analysis_binary_dict.get_analysis_binary_by_path(file_path)
        keyword_binary_dict[file_path] = analysis_binary.binary_function_keyword # 存储为set集合的形式
        try:
            logger.info(f"[SERIAL] Starting analysis for: {file_path} ({binary_index + 1}/{len(analysis_binary_dict.analysis_binary_dict)})")
            t1 = time.time()
            analysis_binary.create_binary_file() # 加载对应的文件
            analysis_binary.rda_analyze()
            analysis_binary.write_to_file()
            analysis_time = analysis_binary.binary_analysis_info["time"]
            function_number = analysis_binary.binary_analysis_info["function_number"]
            info_file.write(f"   - `{file_path}` [analysis_time: {analysis_time:.2f}, function_number: {function_number}];\n")
            info_file.flush()
            t2 = time.time()
            logger.info(f"[SERIAL] Finished analysis for: {file_path} in {t2-t1:.2f}s")
        except Exception as e:
            logger.exception(f"[SERIAL] Analysis failed for: {file_path}, error: {e}")
        binary_index += 1
    serial_end = time.time()
    logger.info(f"[STEP 3] Serial analysis finished in {serial_end - serial_start:.2f} seconds\n")

    # 合并跨二进制文件数据流
    merge_start = time.time()
    logger.info("[STEP 4] Merging cross-binary data flow ...")
    potential_path_dict = defaultdict(dict) # 去重之后的路径字典
    complete_path_dict = defaultdict(dict) # 完整的路径字典
    for set_func_name, _, _, _, _, _ in analysis_binary_dict.get_set_func_name:
        analysis_binary: AnalysisBinary = analysis_binary_dict.get_analysis_binary_by_path(file_path)
        if analysis_binary_dict.analysis_binary_dict:
            for file_path in analysis_binary_dict.analysis_binary_dict:
                potential_path_dict[set_func_name][file_path] = {
                    "get2set_path": analysis_binary.get2set_path,
                    "source2sink_path": analysis_binary.source2sink_path,
                    "diffusion_file": sorted(list(analysis_binary.diffusion_file[set_func_name])),
                    "complete_source2sink_path": [],
                    "complete_get2sink_path": [],
                    "complete_get2sink_path_dict": {}
                }
                complete_path_dict[set_func_name][file_path] = {
                    "get2set_path": analysis_binary.get2set_complete_path,
                    "source2sink_path": analysis_binary.source2sink_complete_path,
                    "diffusion_file": sorted(list(analysis_binary.diffusion_file[set_func_name])),
                    "complete_source2sink_path": [],
                    "complete_get2sink_path": [],
                    "complete_get2sink_path_dict": {}
                }
        else:
            potential_path_dict["None"][file_path] = {
                "get2set_path": analysis_binary.get2set_path,
                "source2sink_path": analysis_binary.source2sink_path,
                "diffusion_file": [],
                "complete_source2sink_path": [],
                "complete_get2sink_path": [],
                "complete_get2sink_path_dict": {}
            }
            complete_path_dict["None"][file_path] = {
                "get2set_path": analysis_binary.get2set_complete_path,
                "source2sink_path": analysis_binary.source2sink_complete_path,
                "diffusion_file": [],
                "complete_source2sink_path": [],
                "complete_get2sink_path": [],
                "complete_get2sink_path_dict": {}
            }
    # 合并跨二进制文件数据流
    merge_start = time.time()
    for func_name, processing_order in processing_order_dict.items():
        logger.info(f"[MERGE] Processing function: {func_name}")
        for file_path in processing_order:
            logger.info(f"[MERGE] Processing file: {file_path}")
            construct_cross_binary_data_flow_single(file_path, potential_path_dict[func_name])
            construct_cross_binary_data_flow_single(file_path, complete_path_dict[func_name])
    merge_end = time.time()
    logger.info(f"[MERGE] Cross-binary data flow merge finished in {merge_end - merge_start:.2f} seconds\n")

    collect_start = time.time()
    # 合并去重路径
    potential_path = []
    get2sink_path = []
    for func_name in potential_path_dict:
        for file_path in potential_path_dict[func_name]:
            potential_path.extend(potential_path_dict[func_name][file_path]["complete_source2sink_path"])
            get2sink_path.extend(potential_path_dict[func_name][file_path]["complete_get2sink_path"])
    potential_path = dedupe_paths(potential_path)  # 去重
    get2sink_path = dedupe_paths(get2sink_path)
    # 合并完整路径
    potential_complete_path = []
    get2sink_complete_path = []
    for func_name in complete_path_dict:
        for file_path in complete_path_dict[func_name]:
            potential_complete_path.extend(complete_path_dict[func_name][file_path]["complete_source2sink_path"])
            get2sink_complete_path.extend(complete_path_dict[func_name][file_path]["complete_get2sink_path"])
    potential_complete_path = dedupe_paths(potential_complete_path)
    get2sink_complete_path = dedupe_paths(get2sink_complete_path)
    collect_end = time.time()
    logger.info(f"[COLLECT] Path aggregation and dedupe finished in {collect_end - collect_start:.2f} seconds\n")

   # 写入文件
    write_start = time.time()
    os.makedirs(config_sgtaint.OUTPUT_DIR, exist_ok=True)
    file_name = config_sgtaint.FIRMWARE_NAME
    # 过滤之后的路径
    potential_path_file_path = os.path.join(config_sgtaint.OUTPUT_DIR, f"{file_name}_potential_path_sanitization.json")
    with open(potential_path_file_path, "w") as f:
        json.dump(potential_path, f, indent=4)
    get2sink_path_file_path = os.path.join(config_sgtaint.OUTPUT_DIR, f"{file_name}_get2sink_path_sanitization.json")
    with open(get2sink_path_file_path, "w") as f:
        json.dump(get2sink_path, f, indent=4)
    # 完整路径
    potential_complete_path_file_path = os.path.join(config_sgtaint.OUTPUT_DIR, f"{file_name}_potential_path_complete.json")
    with open(potential_complete_path_file_path, "w") as f:
        json.dump(potential_complete_path, f, indent=4)
    get2sink_complete_path_file_path = os.path.join(config_sgtaint.OUTPUT_DIR, f"{file_name}_get2sink_path_complete.json")
    with open(get2sink_complete_path_file_path, "w") as f:
        json.dump(get2sink_complete_path, f, indent=4)
    merged_path = potential_path + get2sink_path
    sorted_potential_verify, sorted_potential_maybe = get_sorted_potential_path_sanitization(keyword_binary_dict, potential_path)
    # 记录排序后的文件
    sorted_potential_path_sanitization_file_path = os.path.join(config_sgtaint.OUTPUT_DIR, f"{file_name}_potential_path_sanitization_sorted.json")
    with open(sorted_potential_path_sanitization_file_path, "w") as f:
        json.dump(sorted_potential_verify, f, indent=4)
    sorted_potential_path_maybe_file_path = os.path.join(config_sgtaint.OUTPUT_DIR, f"{file_name}_potential_path_maybe_sorted.json")
    with open(sorted_potential_path_maybe_file_path, "w") as f:
        json.dump(sorted_potential_maybe, f, indent=4)
    write_end = time.time()
    logger.info(f"[SAVE] Results written to files in {write_end - write_start:.2f} seconds")
    logger.info(f"[MERGE] length of get2sink_path_sanitization: {len(get2sink_path)}")
    logger.info(f"[MERGE] length of potential_path_sanitization: {len(potential_path)}") # 需要进行严重性排序
    logger.info(f"[MERGE] length of get2sink_path_complete: {len(get2sink_complete_path)}")
    logger.info(f"[MERGE] length of potential_path_complete: {len(potential_complete_path)}")
    logger.info(f"[MERGE] length of sorted_potential_verify_path: {len(sorted_potential_verify)}")
    logger.info(f"[MERGE] length of sorted_potential_maybe_path: {len(sorted_potential_maybe)}")
    total_time = time.time() - total_start
    logger.info(f"SGTaint serial pipeline completed in {total_time:.2f} seconds.")
    # 记录总体信息
    info_file.write(f"6. Analysis time: {total_time:.2f} s\n")
    info_file.write(f"7. Length of get2sink_path_sanitization: {len(get2sink_path)}\n")
    info_file.write(f"8. Length of potential_path_sanitization: {len(potential_path)}\n")
    info_file.write(f"9. Length of get2sink_path_complete: {len(get2sink_complete_path)}\n")
    info_file.write(f"10. Length of potential_path_complete: {len(potential_complete_path)}\n")
    info_file.write(f"11. Length of sorted_potential_verify_path: {len(sorted_potential_verify)}\n")
    info_file.write(f"12. Length of sorted_potential_maybe_path: {len(sorted_potential_maybe)}\n")
    info_file.flush()
    return merged_path, sorted_potential_verify
    
    
# 进程池子任务
def run_rda_worker(file_path):
    analysis_binary = AnalysisBinary(file_path)
    analysis_binary.create_binary_file() # 加载对应的文件
    analysis_binary.load_config() # 加载配置文件
    analysis_binary.rda_analyze()
    analysis_binary.write_to_file()
    potential_info_dict = {} # 以set_func_name为键
    complete_info_dict = {}
    if analysis_binary.diffusion_file: # 存在对应的分散
        for func, files in analysis_binary.diffusion_file.items():
            potential_info_dict[func] = {
                "get2set_path": analysis_binary.get2set_path,
                "source2sink_path": analysis_binary.source2sink_path,
                "diffusion_file": sorted(list(files)),
                "complete_source2sink_path": [],
                "complete_get2sink_path": [],
                "complete_get2sink_path_dict": {}
            }
            complete_info_dict[func] = {
                "get2set_path": analysis_binary.get2set_complete_path,
                "source2sink_path": analysis_binary.source2sink_complete_path,
                "diffusion_file": sorted(list(files)),
                "complete_source2sink_path": [],
                "complete_get2sink_path": [],
                "complete_get2sink_path_dict": {}
            }
    else:
        potential_info_dict["None"] = {
            "get2set_path": analysis_binary.get2set_path,
            "source2sink_path": analysis_binary.source2sink_path,
            "diffusion_file": [],
            "complete_source2sink_path": [],
            "complete_get2sink_path": [],
            "complete_get2sink_path_dict": {}
        }
        complete_info_dict["None"] = {
            "get2set_path": analysis_binary.get2set_complete_path,
            "source2sink_path": analysis_binary.source2sink_complete_path,
            "diffusion_file": [],
            "complete_source2sink_path": [],
            "complete_get2sink_path": [],
            "complete_get2sink_path_dict": {}
        }
    return file_path, potential_info_dict, complete_info_dict, analysis_binary.binary_analysis_info
    
    
def start_sgtaint_parallel(info_file):
    logger = logging.getLogger("sgtaint")
    step_start = time.time()
    logger.info("[STEP 1] Initializing AnalysisBinaryDict and SetGetGraph ...")
    analysis_binary_dict = AnalysisBinaryDict()
    set_get_graph = SetGetGraph()
    step1_end = time.time()
    logger.info(f"[STEP 1] finished in {step1_end - step_start:.2f} seconds\n")

    logger.info("[STEP 2] Building SGGraph and collecting binaries to analyze ...")
    sg_start = time.time()
    set_get_graph_create(config_sgtaint.FILE_SYSTEM, analysis_binary_dict, set_get_graph)
    processing_order_dict = generate_binary_processing_order_robust(analysis_binary_dict)
    sg_end = time.time()
    logger.info(f"[STEP 2] finished in {sg_end - sg_start:.2f} seconds\n")
    
    # 将相关信息写入info_file
    info_file.write("2. Boundary binaries: \n")
    for file_path in analysis_binary_dict.get_border_binary_path_list():
        info_file.write(f"   - `{file_path}`;\n")
    info_file.write(f"3. Transfer function information: `{analysis_binary_dict.get_set_func_name}`;\n")
    info_file.write(f"4. Set-get graph generation time: {sg_end - sg_start:.2f} s\n")
    info_file.write("5. Analyzing binary file list: \n")
    info_file.flush()
    
    # 保存每个二进制文件的配置
    config_start = time.time()
    keyword_binary_dict = {}
    for file_path in analysis_binary_dict.analysis_binary_dict:
        analysis_binary: AnalysisBinary = analysis_binary_dict.get_analysis_binary_by_path(file_path)
        keyword_binary_dict[file_path] = analysis_binary.binary_function_keyword # 存储为set集合的形式
        logger.debug(f"Saving config for: {file_path}")
        analysis_binary.save_config()
    config_end = time.time()
    logger.info(f"[STEP 2.5] Saving configs finished in {config_end - config_start:.2f} seconds\n")

    file_path_list = list(analysis_binary_dict.analysis_binary_dict.keys())
    logger.info(f"[STEP 3] Parallel analysis of {len(file_path_list)} binaries ...")
    pool_start = time.time()
    potential_path_dict = defaultdict(dict) # 去重之后的路径字典
    complete_path_dict = defaultdict(dict) # 完整的路径字典
    with ProcessPoolExecutor() as executor:
        futures = {}
        for idx, file_path in enumerate(file_path_list):
            futures[executor.submit(run_rda_worker, file_path)] = (file_path, idx)
        finished = 0
        for future in as_completed(futures):
            file_path, idx = futures[future]
            try:
                binary_path, potential_info_dict, complete_info_dict, binary_analysis_info = future.result(timeout=config_sgtaint.BINARY_TIMEOUT)  # 单个分析最大3小时
                # 统计二进制文件分析信息
                analysis_time = binary_analysis_info["time"]
                function_number = binary_analysis_info["function_number"]
                info_file.write(f"   - `{binary_path}` [analysis_time: {analysis_time:.2f}, function_number: {function_number}];\n")
                info_file.flush()
                # 构建以set_func_name为键的分析列表
                for func_name, potential_info in potential_info_dict.items():
                    potential_path_dict[func_name][binary_path] = potential_info
                for func_name, complete_info in complete_info_dict.items():
                    complete_path_dict[func_name][binary_path] = complete_info
                finished += 1
                logger.info(f"[PARALLEL] Finished analysis for: {file_path} ({finished}/{len(file_path_list)})")
            except TimeoutError:
                logger.error(f"[TIMEOUT] Analysis timeout for: {file_path}")
            except Exception as e:
                logger.exception(f"[ERROR] Analysis failed for: {file_path}, error: {e}")
    pool_end = time.time()
    logger.info(f"[STEP 3] All parallel analysis finished in {pool_end - pool_start:.2f} seconds\n")

    # 合并跨二进制文件数据流
    merge_start = time.time()
    for func_name, processing_order in processing_order_dict.items():
        logger.info(f"[MERGE] Processing function: {func_name}")
        for file_path in processing_order:
            logger.info(f"[MERGE] Processing file: {file_path}")
            construct_cross_binary_data_flow_single(file_path, potential_path_dict[func_name])
            construct_cross_binary_data_flow_single(file_path, complete_path_dict[func_name])
    merge_end = time.time()
    logger.info(f"[MERGE] Cross-binary data flow merge finished in {merge_end - merge_start:.2f} seconds\n")

    collect_start = time.time()
    # 合并去重路径
    potential_path = []
    get2sink_path = []
    for func_name in potential_path_dict:
        for file_path in potential_path_dict[func_name]:
            potential_path.extend(potential_path_dict[func_name][file_path]["complete_source2sink_path"])
            get2sink_path.extend(potential_path_dict[func_name][file_path]["complete_get2sink_path"])
    potential_path = dedupe_paths(potential_path)  # 去重
    get2sink_path = dedupe_paths(get2sink_path)
    # 合并完整路径
    potential_complete_path = []
    get2sink_complete_path = []
    for func_name in complete_path_dict:
        for file_path in complete_path_dict[func_name]:
            potential_complete_path.extend(complete_path_dict[func_name][file_path]["complete_source2sink_path"])
            get2sink_complete_path.extend(complete_path_dict[func_name][file_path]["complete_get2sink_path"])
    potential_complete_path = dedupe_paths(potential_complete_path)
    get2sink_complete_path = dedupe_paths(get2sink_complete_path)
    collect_end = time.time()
    logger.info(f"[COLLECT] Path aggregation and dedupe finished in {collect_end - collect_start:.2f} seconds\n")

    # 写入文件
    write_start = time.time()
    os.makedirs(config_sgtaint.OUTPUT_DIR, exist_ok=True)
    file_name = config_sgtaint.FIRMWARE_NAME
    # 过滤之后的路径
    potential_path_file_path = os.path.join(config_sgtaint.OUTPUT_DIR, f"{file_name}_potential_path_sanitization.json")
    with open(potential_path_file_path, "w") as f:
        json.dump(potential_path, f, indent=4)
    get2sink_path_file_path = os.path.join(config_sgtaint.OUTPUT_DIR, f"{file_name}_get2sink_path_sanitization.json")
    with open(get2sink_path_file_path, "w") as f:
        json.dump(get2sink_path, f, indent=4)
    # 完整路径
    potential_complete_path_file_path = os.path.join(config_sgtaint.OUTPUT_DIR, f"{file_name}_potential_path_complete.json")
    with open(potential_complete_path_file_path, "w") as f:
        json.dump(potential_complete_path, f, indent=4)
    get2sink_complete_path_file_path = os.path.join(config_sgtaint.OUTPUT_DIR, f"{file_name}_get2sink_path_complete.json")
    with open(get2sink_complete_path_file_path, "w") as f:
        json.dump(get2sink_complete_path, f, indent=4)
    merged_path = potential_path + get2sink_path
    sorted_potential_verify, sorted_potential_maybe = get_sorted_potential_path_sanitization(keyword_binary_dict, potential_path)
    # 记录排序后的文件
    sorted_potential_path_sanitization_file_path = os.path.join(config_sgtaint.OUTPUT_DIR, f"{file_name}_potential_path_sanitization_sorted.json")
    with open(sorted_potential_path_sanitization_file_path, "w") as f:
        json.dump(sorted_potential_verify, f, indent=4)
    sorted_potential_path_maybe_file_path = os.path.join(config_sgtaint.OUTPUT_DIR, f"{file_name}_potential_path_maybe_sorted.json")
    with open(sorted_potential_path_maybe_file_path, "w") as f:
        json.dump(sorted_potential_maybe, f, indent=4)
    write_end = time.time()
    logger.info(f"[SAVE] Results written to files in {write_end - write_start:.2f} seconds")
    logger.info(f"[MERGE] length of get2sink_path_sanitization: {len(get2sink_path)}")
    logger.info(f"[MERGE] length of potential_path_sanitization: {len(potential_path)}") # 需要进行严重性排序
    logger.info(f"[MERGE] length of get2sink_path_complete: {len(get2sink_complete_path)}")
    logger.info(f"[MERGE] length of potential_path_complete: {len(potential_complete_path)}")
    logger.info(f"[MERGE] length of sorted_potential_verify_path: {len(sorted_potential_verify)}")
    logger.info(f"[MERGE] length of sorted_potential_maybe_path: {len(sorted_potential_maybe)}")
    total_time = time.time() - step_start
    logger.info(f"SGTaint parallel pipeline completed in {total_time:.2f} seconds.")
    # 记录总体信息
    info_file.write(f"6. Analysis time: {total_time:.2f} s\n")
    info_file.write(f"7. Length of get2sink_path_sanitization: {len(get2sink_path)}\n")
    info_file.write(f"8. Length of potential_path_sanitization: {len(potential_path)}\n")
    info_file.write(f"9. Length of get2sink_path_complete: {len(get2sink_complete_path)}\n")
    info_file.write(f"10. Length of potential_path_complete: {len(potential_complete_path)}\n")
    info_file.write(f"11. Length of sorted_potential_verify_path: {len(sorted_potential_verify)}\n")
    info_file.write(f"12. Length of sorted_potential_maybe_path: {len(sorted_potential_maybe)}\n")
    info_file.flush()
    return merged_path, sorted_potential_verify
        
        
# 参数配置
def parse_args():
    parser = argparse.ArgumentParser(prog="sgtaint", description=__doc__)
    parser.add_argument("-f", "--firmware", required=True, help="Path to firmware filesystem")
    parser.add_argument("-n", "--name", required=True, help="Firmware identifier")
    parser.add_argument("-o", "--output", required=True, help="User output directory")
    parser.add_argument("-p", "--parallel", action="store_true", help="Enable parallel mode")
    parser.add_argument("-g", "--ghidra", action="store_true", help="Enable Ghidra-assisted analysis during the decompilation process")
    parser.add_argument("-l", "--llm", action="store_true", help="Enable final LLM check")
    parser.add_argument("-c", "--config", action="store_true", help="Enable retrieving newly identified data reception functions from the configuration")
    parser.add_argument("-s", "--sggraph", 
                        help=(
                            "Optional SGGraph info path or mode. "
                            "It can be a file path specifying transfer function pair info "
                            "(e.g., a list of tuples like [(set_func, get_func, set_key_pos, get_key_pos, set_value_pos, get_value_pos), ...]), "
                            "or special keywords: "
                            "'config' to load transfer function pairs directly from the configuration, "
                            "'precise' to use a more accurate method for extracting transfer function pairs."
                        ))
    parser.add_argument("-m", "--model", default="deepseek", choices=["gpt", "deepseek", "qwen"], help="Choose LLM model to use (gpt, deepseek or qwen). Default is deepseek.")
    parser.add_argument("-b", "--boundary", type=str, help="Comma-separated list of boundary binary files (absolute paths). Use ',' to separate multiple files.")
    parser.add_argument("--version", action="version", version=__version__)
    return parser.parse_args()


# SGTaint入口函数
def main():
    args = parse_args()
    runner = SGTaintRunner(
        firmware=args.firmware,
        name=args.name,
        output_dir=args.output,
        sggraph=args.sggraph,
        parallel=args.parallel,
        ghidra=args.ghidra,
        llm=args.llm,
        config=args.config,
        model=args.model,
        boundary_binaries=args.boundary
    )
    try:
        runner.run()
    except Exception as e:
        runner.logger.exception("SGTaint execution failed")
        sys.exit(1)


if __name__ == "__main__":
    main()