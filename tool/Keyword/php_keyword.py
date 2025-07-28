# -*- coding: utf-8 -*-
import chardet
import logging
import os
import time
import re
import tool.Config.config as config_sgtaint
from tool.Keyword.base.Base import KeywordSet, FunctionSet, is_filter
from tool.Keyword.html_keyword import HtmlParser

logger = logging.getLogger("sgtaint.keyword") # 配置对应的日志文件

# 给定目录遍历获取其中所有php文件的路径
def find_php_files(directory):
    php_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            # 使用 lower() 统一处理大小写问题
            if file.lower().endswith(('.php', '.phtml', '.php5', '.php4', '.inc', '.tpl')):
                php_files.append(os.path.join(root, file))
    return php_files

# php文件解析类，可以处理一组php文件
class PhpParser():
    def __init__(self, directory): # 传入需要分析的目录地址
        self.directory = directory
        self.keyword_set = KeywordSet() # 仅仅存储关键字信息
        self.php_file_list = find_php_files(directory)
        self.function_set = FunctionSet() # 存储对应action属性的值
        logger.info("PhpParser initialized: %d PHP files to process", len(self.php_file_list))
        
    # 获取php文件中的关键字信息（仅处理单个文件）
    def _get_keyword_function(self, file_path):
        html_parser = HtmlParser(self.directory) # 仅仅使用其中的一个方法
        valid_keyword_set, valid_function_set = html_parser._get_keyword_function_single(file_path)
        self.keyword_set.merge(valid_keyword_set)
        self.function_set.merge(valid_function_set)
        with open(file_path, "rb") as f:
            content = f.read()
        if not content:
            return valid_keyword_set
        matches = re.findall(
            """\$_(?:GET|POST|SERVER)\[(?:"|')(.*)(?:"|')\]""", content.decode(chardet.detect(content)['encoding'], "ignore")
        )
        for match_string in set(matches):
            if not is_filter(match_string):
                self.keyword_set.add_keyword(match_string, file_path)
    
    # 打印出php文件中的keyword以及function
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
    def php_keyword_function_file(self):
        file_name = "{}_php_keyword_function.txt".format(config_sgtaint.FIRMWARE_NAME)
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
    
    # 进行所有php文件的关键字提取
    def run(self):
        total_files = len(self.php_file_list)
        # 空目录处理
        if total_files == 0:
            logger.warning(f"No PHP files found under {self.directory}; skipping parallel parse.")
            return self.keyword_set, self.function_set
        start_time = time.time()
        logger.info(f"Starting parsing: {total_files} files")
        for idx, path in enumerate(self.php_file_list, start=1):
            try:
                self._get_keyword_function(path)
                logger.debug(f"[{idx}/{total_files}] Parsed successfully: {path}")
            except Exception as e:
                # 只记录异常，不中断后续文件处理
                logger.exception(f"Failed to parse PHP [{idx}/{total_files}]: {path}")
        total_time = time.time() - start_time
        logger.info(f"Completed parsing of {total_files} files in {total_time:.2f}s")
        return self.keyword_set, self.function_set