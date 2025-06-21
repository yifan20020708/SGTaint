# -*- coding: utf-8 -*-
import re
import tool.Config.config as config_sgtaint


# 计算两个字符串的编辑距离   
def EditDistanceRecursive(str1, str2):
    edit = [[i + j for j in range(len(str2) + 1)] for i in range(len(str1) + 1)]
    for i in range(1, len(str1) + 1):
        for j in range(1, len(str2) + 1):
            if str1[i - 1] == str2[j - 1]:
                d = 0
            else:
                d = 1
            edit[i][j] = min(edit[i - 1][j] + 1, edit[i][j - 1] + 1, edit[i - 1][j - 1] + d)
    return edit[len(str1)][len(str2)]


# 计算两个字符串的相似程度
def SimilarityScore(str1, str2):
    ED = EditDistanceRecursive(str1, str2)
    return round((1 - (ED / max(len(str1), len(str2)))) * 100, 2)


# 定义关键字类
class Keyword():
    def __init__(self, value):
        self.value = value
        self.file_path = set() # 所在前端文件路径的集合
        self.binary_path = set() # 所在后端文件路径的集合
        
    # 添加前端文件路径
    def add_file(self, path):
        self.file_path.add(path)
        
    # 添加二进制文件路径
    def add_binary(self, path):
        self.binary_path.add(path)
        
    # 返回Keyword的取值信息
    def get_value(self):
        return self.value
    
    # 返回Keyword所在前端文件路径的集合
    def get_file_path(self):
        return self.file_path
    
    # 返回Keyword所在后端文件路径的集合
    def get_binary_path(self):
        return self.binary_path
    
    # 打印出keyword信息
    def print_information(self, index):
        print("[{}] Keyword: {}".format(index, self.value))
        print("Front-end file path:")
        for path in self.file_path:
            print("  {}".format(path))
        print("Binary file path:")
        for path in self.binary_path:
            print("  {}".format(path))
            

# 定义关键字集合类
class KeywordSet():
    def __init__(self):
        self.set = set() # 存储关键字类
        
    # 根据关键字取值获取对应的关键字对象
    def get_keyword_by_value(self, value):
        keyword = [keyword for keyword in self.set if keyword.get_value() == value]
        if not keyword:
            return None
        return keyword[0]
    
    # 获取关键字集合的长度
    def length(self):
        return len(self.set)
    
    # 合并另一个 KeywordSet 到当前对象
    def merge(self, other):
        for keyword in other.get_keyword_set():
            existing = self.get_keyword_by_value(keyword.get_value())
            if not existing:
                # 关键字不存在于当前集合，直接添加一个副本
                new_keyword = Keyword(keyword.get_value())
                for file_path in keyword.get_file_path():  # 假设 Keyword 类中有 get_file_list()
                    new_keyword.add_file(file_path)
                self.set.add(new_keyword)
            else:
                # 关键字已存在，合并文件路径
                for file_path in keyword.get_file_path():
                    existing.add_file(file_path)
    
    # 添加关键字元素
    def add_keyword(self, value, path):
        keyword = self.get_keyword_by_value(value)
        if not keyword: # 不存在对应的关键字对象
            keyword_class = Keyword(value)
            keyword_class.add_file(path)
            self.set.add(keyword_class)
        else: # 若原先存在仅仅更新文件信息
            keyword.add_file(path)
            
    # 获取关键字类集合
    def get_keyword_set(self):
        return self.set
    
    # 对字符串进行模糊匹配
    def fuzzy_match(self, string):
        max_similarity = 0
        tmp_keyword = None
        for keyword in self.set:
            similarity = SimilarityScore(keyword.get_value(), string)
            if similarity == 100:
                max_similarity = 100
                tmp_keyword = keyword
                break
            if similarity >= max_similarity:
                max_similarity = similarity
                tmp_keyword = keyword
        if max_similarity > config_sgtaint.MIN_SIMILARITY:
            return tmp_keyword, max_similarity
        else:
            return False
        
    # 对字符串进行精确匹配
    def accurate_match(self, string):
        for keyword in self.set:
            if string == keyword.get_value():
                return keyword
        return False
    
    # 对字符串进行存在匹配
    def find_match(self, string):
        for keyword in self.set:
            if string.find(keyword.get_value()) >= 0 and (len(string) - len(keyword.get_value()) <= config_sgtaint.MAX_DISTANCE):
                return keyword
        return False
            
            
# 定义函数类
class Function():
    def __init__(self, value):
        self.value = value
        self.file_path = set() # 所在前端文件路径的集合
        self.binary_path = set() # 所在后端文件路径的集合
        
    # 添加前端文件路径
    def add_file(self, path):
        self.file_path.add(path)
        
    # 添加二进制文件路径
    def add_binary(self, path):
        self.binary_path.add(path)
        
    # 返回Function的取值信息
    def get_value(self):
        return self.value
    
    # 返回Function所在前端文件路径的集合
    def get_file_path(self):
        return self.file_path
    
    # 返回Function所在后端文件路径的集合
    def get_binary_path(self):
        return self.binary_path
    
    # 打印出Function信息
    def print_information(self, index):
        print("[{}] Function: {}".format(index, self.value))
        print("Front-end file path:")
        for path in self.file_path:
            print("  {}".format(path))
        print("Binary file path:")
        for path in self.binary_path:
            print("  {}".format(path))
            

# 定义关函数集合类
class FunctionSet():
    def __init__(self):
        self.set = set() # 存储函数类
        
    # 根据关键字取值获取对应的函数对象
    def get_function_by_value(self, value):
        function = [function for function in self.set if function.get_value() == value]
        if not function:
            return None
        return function[0]
    
    # 获取函数集合的长度
    def length(self):
        return len(self.set)
    
    # 合并另一个 FunctionSet 到当前对象
    def merge(self, other):
        for function in other.get_function_set():
            existing = self.get_function_by_value(function.get_value())
            if not existing:
                # 当前集合中没有该函数，复制添加
                new_function = Function(function.get_value())
                for file_path in function.get_file_path():  # 假设 Function 类中有 get_file_list()
                    new_function.add_file(file_path)
                self.set.add(new_function)
            else:
                # 当前集合已有该函数，合并文件路径
                for file_path in function.get_file_path():
                    existing.add_file(file_path)
    
    # 添加函数元素
    def add_function(self, value, path):
        function = self.get_function_by_value(value)
        if not function: # 不存在对应的函数对象
            function_class = Function(value)
            function_class.add_file(path)
            self.set.add(function_class)
        else: # 若原先存在仅仅更新文件信息
            function.add_file(path)
        
    # 获取函数集合
    def get_function_set(self):
        return self.set
    
    # 对字符串进行模糊匹配
    def fuzzy_match(self, string):
        max_similarity = 0
        tmp_function = None
        for function in self.set:
            similarity = SimilarityScore(function.get_value(), string)
            if similarity == 100:
                max_similarity = 100
                tmp_function = function
                break
            if similarity >= max_similarity:
                max_similarity = similarity
                tmp_function = function
        if max_similarity > config_sgtaint.MIN_SIMILARITY:
            return tmp_function, max_similarity
        else:
            return False
        
    # 对字符串进行精确匹配
    def accurate_match(self, string):
        for function in self.set:
            if string == function.get_value():
                return function
        return False
    
    # 对字符串进行存在匹配
    def find_match(self, string):
        for function in self.set:
            if string.find(function.get_value()) >= 0 and (len(string) - len(function.get_value()) <= config_sgtaint.MAX_DISTANCE):
                return function
        return False
    

# 检查字符串中是否存在中文字符
def contains_chinese(text):
    # 匹配中文字符范围
    pattern = re.compile(r'[\u4e00-\u9fff]')
    return bool(pattern.search(text))


# 检查字符串是否为数字型字符串
def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        return False


# 检查字符串是否为颜色类型的字符串
def is_color_code(s):
    pattern = r'^#[0-9a-fA-F]{6}$'
    return re.match(pattern, s) is not None


# 检查关键字是否需要进行过滤
def is_filter(string, type = "keyword"):
    if type == "keyword":
        if len(string) < config_sgtaint.MIN_KEYWORD_LEN or len(string) > config_sgtaint.MAX_KEYWORD_LEN:
            return True
    if contains_chinese(string):
        return True
    if any(char in string for char in config_sgtaint.BLOCK_CHARS):
        return True
    if is_number(string):
        return True
    if string in config_sgtaint.WHITE_LIST:
        return True
    if is_color_code(string):
        return True
    return False