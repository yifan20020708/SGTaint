# -*- coding: utf-8 -*-
import os
import json
import logging
import subprocess
import tool.Config.config as config_sgtaint
from tool.Keyword.base.Base import is_filter, KeywordSet, FunctionSet, Keyword, Function

logger = logging.getLogger("sgtaint.binary")

# 定义分析二进制文件的类，其分析单个二进制文件
class AnalysisBinary():
    def __init__(self, binary_path):
        self.binary_path = str(binary_path)
        self.binary_string = set()
        self.binary_keyword = set() # (string, keyword)
        self.binary_function = set() # (string, function)
        self.binary_endian = AnalysisBinary.check_lsb_or_msb(binary_path)
        
    # 获取二进制文件的名称
    def get_name(self):
        return self.binary_path.split("/")[-1]
    
    # 判断程序的端序
    @staticmethod
    def check_lsb_or_msb(binary_path):
        try:
            result = subprocess.check_output(["file", str(binary_path)], text=True, stderr=subprocess.STDOUT)
            if "LSB" in result:
                return "LSB"
            if "MSB" in result:
                return "MSB"
            logger.warning(f"Unknown endianness for {binary_path}: {result.strip()}")
            return "UNKNOWN"
        except subprocess.CalledProcessError:
            logger.exception(f"Error detecting endianness for {binary_path}")
            return "UNKNOWN"
        
    # 获取二进制文件中的字符串
    def get_string(self):
        try:
            output = subprocess.check_output(["strings", str(self.binary_path)], text=True, stderr=subprocess.DEVNULL)
            strings = list(set(output.split("\n")))
            for string in strings:
                # 使用与keyword同样的过滤方法
                if not is_filter(string, "str"):
                    self.binary_string.add(string)
            logger.info(f"Extracted {len(self.binary_string)} strings from {self.binary_path}")
        except Exception:
            logger.exception(f"Failed to extract strings from {self.binary_path}")
        return self.binary_string
    
    # 获取二进制文件中包含字符串的数量
    def get_string_count(self):
        return len(self.binary_string)
    
    # 获取二进制文件中匹配到的关键字（使用精确匹配方法）
    def find_keyword(self, keywords: KeywordSet): # 其中keywords为KeywordSet类
        for string in self.binary_string:
            keyword: Keyword = keywords.find_match(string)
            if keyword:
                keyword.add_binary(self.binary_path)
                self.binary_keyword.add((string, keyword))
        return self.binary_keyword
    
    # 获取二进制文件中匹配到的函数（使用精确匹配方法）
    def find_function(self, functions: FunctionSet): # 其中functions为FunctionSet类
        for string in self.binary_string:
            function: Function = functions.find_match(string)
            if function:
                function.add_binary(self.binary_path)
                self.binary_function.add((string, function))
        return self.binary_keyword
    
    # 获取二进制文件中匹配到的关键字个数
    def get_keyword_number(self):
        return len(self.binary_keyword)
    
    # 获取二进制文件中匹配到的函数个数
    def get_function_number(self):
        return len(self.binary_function)
            
    # 打印出二进制文件中匹配到的keyword
    def print_keyword(self):
        index = 0
        for keyword in self.binary_keyword:
            index += 1
            print("[{}] {}--{}".format(index, keyword[0], keyword[1].get_value()))
    
    # 打印出二进制文件中匹配到的function
    def print_function(self):
        index = 0
        for function in self.binary_function:
            index += 1
            print("[{}] {}--{}".format(index, function[0], function[1].get_value()))
            
    # 将匹配到的关键字写入json文件
    def keyword_function_file(self):
        if len(self.binary_keyword) + len(self.binary_function) > config_sgtaint.MIN_KEYWORD_NUMBER:
            file_name = "{}_keyword_function.json".format(self.binary_path.replace("/", "_"))
            file_path = os.path.join(config_sgtaint.TMP_KEYWORD, file_name)
            keyword_function_list = []
            for keyword in self.binary_keyword:
                keyword_function_list.append({
                    "keyword_function": keyword[1].get_value(), # 匹配到前端的关键字
                    "string": keyword[0], # 二进制文件中匹配到的字符串
                    "path": list(keyword[1].get_file_path())
                })
            for function in self.binary_function:
                keyword_function_list.append({
                    "keyword_function": function[1].get_value(), 
                    "string": function[0],
                    "path": list(function[1].get_file_path())
                })
            with open(file_path, "w") as file:
                json.dump(keyword_function_list, file, indent=4)