# -*- coding: utf-8 -*-
import chardet
import logging
import os
import time
import tool.Config.config as config_sgtaint
from concurrent.futures import ProcessPoolExecutor, as_completed
from bs4 import BeautifulSoup
from tool.Keyword.base.Base import KeywordSet, FunctionSet, is_filter
from tool.Keyword.js_keyword import JsParser

logger = logging.getLogger("sgtaint.keyword") # 配置对应的日志文件

# 给定目录遍历获取其中所有html文件的路径
def find_html_files(directory):
    html_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            # 使用 lower() 统一处理大小写问题
            if file.lower().endswith(('.html', '.htm', '.shtml', 'asp', 'aspx')):
                html_files.append(os.path.join(root, file))
    return html_files

# html文件解析类，可以处理一组html文件
class HtmlParser():
    def __init__(self, directory): # 传入需要分析的目录地址
        self.directory = directory
        self.keyword_set = KeywordSet()
        self.html_file_list = find_html_files(directory)
        self.function_set = FunctionSet() # 存储对应action属性的值
        logger.info("HtmlParser initialized: %d HTML files to process", len(self.html_file_list))
    
    # 提取出html文件中的js代码（仅处理单个文件）
    def _get_js_code_snippet(self, file_path): # file_path为对应html文件的路径
        with open(file_path, "rb") as f:
            content = f.read()
        if not content:
            return
        encoding = chardet.detect(content)['encoding']
        html_content = content.decode(encoding, "ignore")
        soup = BeautifulSoup(html_content, 'html.parser')
        # 查找所有<script>标签
        script_tags = soup.find_all('script')
        js_snippet_set = set()
        for tag in script_tags:
            # 只提取内联的js代码（即没有src属性的标签）
            if not tag.has_attr('src'):
                js_code = tag.get_text().strip()
                if js_code:
                    js_snippet_set.add(js_code)
        return js_snippet_set
    
    # 获取html文件中的关键字信息（仅处理单个文件）
    def _get_keyword_function(self, file_path):
        with open(file_path, "rb") as f:
            content = f.read()
        if not content:
            return
        encoding = chardet.detect(content)['encoding']
        html_content = content.decode(encoding, "ignore")
        soup = BeautifulSoup(html_content, 'html.parser')
        # 获取所有name以及id属性的取值
        for tag in soup.find_all(True):
            if tag.has_attr('name'):
                value = tag.get('name')
                if value and not is_filter(value):
                    self.keyword_set.add_keyword(value, file_path)
            if tag.has_attr('id'):
                value = tag.get('id')
                if value and not is_filter(value):
                    self.keyword_set.add_keyword(value, file_path)
            if tag.has_attr('action'):
                value = tag.get('action')
                if value and not is_filter(value):
                    self.function_set.add_function(value, file_path)
        # 处理其中的js代码片段
        for js_snippet in self._get_js_code_snippet(file_path):
            keywords, functions = JsParser._parse_js_code(js_snippet)
            for keyword in keywords:
                self.keyword_set.add_keyword(keyword, file_path)
            for function in functions:
                self.function_set.add_function(function, file_path)
                
    # 进行并行处理
    def _get_keyword_function_single(self, file_path):
        local_keyword_set = KeywordSet()
        local_function_set = FunctionSet()
        try:
            with open(file_path, "rb") as f:
                content = f.read()
            if not content:
                return local_keyword_set, local_function_set
            encoding = chardet.detect(content)['encoding']
            html_content = content.decode(encoding, "ignore")
            soup = BeautifulSoup(html_content, 'html.parser')
            for tag in soup.find_all(True):
                if tag.has_attr('name'):
                    value = tag.get('name')
                    if value and not is_filter(value):
                        local_keyword_set.add_keyword(value, file_path)
                if tag.has_attr('id'):
                    value = tag.get('id')
                    if value and not is_filter(value):
                        local_keyword_set.add_keyword(value, file_path)
                if tag.has_attr('action'):
                    value = tag.get('action')
                    if value and not is_filter(value):
                        local_function_set.add_function(value, file_path)
            for js_snippet in self._get_js_code_snippet(file_path):
                keywords, functions = JsParser._parse_js_code(js_snippet)
                for keyword in keywords:
                    local_keyword_set.add_keyword(keyword, file_path)
                for function in functions:
                    local_function_set.add_function(function, file_path)
        except Exception as e:
            logger.exception("Failed to parse HTML file %s: %s", file_path, e)
        return local_keyword_set, local_function_set
        
    # 打印出html文件中的keyword以及function
    def print_keyword_function(self):
        index = 0
        print("[*] There are a total of {} keywords.".format(self.keyword_set.length()))
        for keyword in self.keyword_set.get_keyword_set():
            index += 1
            keyword.print_information(index)
        index = 0
        print("[*] There are a total of {} functions.".format(self.function_set.length()))
        for function in self.function_set.get_function_set():
            index += 1
            function.print_information(index)
            
    # 将所有的关键字写入到文件中
    def html_keyword_function_file(self):
        file_name = "{}_html_keyword_function.txt".format(config_sgtaint.FIRMWARE_NAME)
        file_path = os.path.join(config_sgtaint.OUTPUT_DIR, file_name)
        with open(file_path, "w", encoding='utf-8') as file:
            index = 0
            file.writelines("All keywords in {}\n".format(config_sgtaint.FIRMWARE_NAME))
            for keyword in self.keyword_set.get_keyword_set():
                index += 1
                value = keyword.get_value()
                paths = keyword.get_file_path()
                file.writelines("[{}] Keyword: {}\n".format(index, value))
                file.writelines(" Front-end file path:\n")
                for path in paths:
                    file.writelines("  {}\n".format(path))
            index = 0
            file.writelines("All functions in {}\n".format(config_sgtaint.FIRMWARE_NAME))
            for function in self.function_set.get_function_set():
                index += 1
                value = function.get_value()
                paths = function.get_file_path()
                file.writelines("[{}] Function: {}\n".format(index, value))
                file.writelines(" Front-end file path:\n")
                for path in paths:
                    file.writelines("  {}\n".format(path))
    
    # 进行所有html文件的关键字提取
    def run(self):
        total_files = len(self.html_file_list)
        # 空目录处理
        if total_files == 0:
            logger.warning(f"No HTML files found under {self.directory}; skipping parallel parse.")
            return self.keyword_set, self.function_set
        start_time = time.time()
        logger.info(f"Starting parsing: {total_files} files")
        for idx, path in enumerate(self.html_file_list, start=1):
            try:
                self._get_keyword_function(path)
                logger.debug(f"[{idx}/{total_files}] Parsed successfully: {path}")
            except Exception:
                # 只记录异常，不中断后续文件处理
                logger.exception(f"Failed to parse HTML [{idx}/{total_files}]: {path}")
        total_time = time.time() - start_time
        logger.info(f"Completed parsing of {total_files} files in {total_time:.2f}s")
        return self.keyword_set, self.function_set
    
    def run_parallel(self):
        total_files = len(self.html_file_list)
        # 空目录处理
        if total_files == 0:
            logger.warning(f"No HTML files found under {self.directory}; skipping parallel parse.")
            return self.keyword_set, self.function_set
        start_time = time.time()
        logger.info(f"Starting parallel parsing: {total_files} files")
        all_keywords = []
        all_functions = []
        # 提交任务
        with ProcessPoolExecutor() as executor:
            futures = {
                executor.submit(self._get_keyword_function_single, path): path
                for path in self.html_file_list
            }
            for idx, future in enumerate(as_completed(futures), start=1):
                path = futures[future]
                try:
                    kw_set, fn_set = future.result()
                    all_keywords.append(kw_set)
                    all_functions.append(fn_set)
                    logger.debug(f"[{idx}/{total_files}] Parsed successfully: {path}")
                except Exception as e:
                    logger.exception(f"Failed to parse HTML [{idx}/{total_files}]: {path}, error: {e}")
        # 归并结果
        merge_start = time.time()
        for kw in all_keywords:
            self.keyword_set.merge(kw)
        for fn in all_functions:
            self.function_set.merge(fn)
        merge_time = time.time() - merge_start
        logger.info(f"Merged {len(all_keywords)} keyword sets and {len(all_functions)} function sets in {merge_time:.2f}s")
        total_time = time.time() - start_time
        logger.info(f"Completed parallel parsing of {total_files} files in {total_time:.2f}s")
        return self.keyword_set, self.function_set