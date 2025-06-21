# -*- coding: utf-8 -*-
import json
import chardet
import time
import logging
import requests
import os
import tool.Config.config as config_sgtaint
from concurrent.futures import ThreadPoolExecutor, as_completed
from tool.Keyword.base.Base import KeywordSet, FunctionSet, is_filter

logger = logging.getLogger("sgtaint.keyword") # 配置对应的日志文件

# 给定目录遍历获取其中所有js文件的路径
def find_js_files(directory):
    js_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            # 使用 lower() 统一处理大小写问题
            if file.lower().endswith('.js'):
                js_files.append(os.path.join(root, file))
    return js_files

# js文件解析类，可以处理一组js文件
class JsParser():
    def __init__(self, directory): # 传入需要分析的目录地址
        self.directory = directory
        self.keyword_set = KeywordSet()
        self.js_file_list = find_js_files(directory)
        self.function_set = FunctionSet()
        
    # 给定js文件代码解析js文件
    @staticmethod
    def _parse_js_code(js_code, key_list=[]): # key存储需要提取的属性名称
        tmp_keywords = set()
        tmp_functions = set()
        # 构造js文件代码解析请求
        http_data = {
            "engine": "acorn",
            "code": js_code
        }
        headers = {'Content-Type': 'application/json'}
        # 传递js文件代码解析请求
        try:
            response = requests.post("http://localhost:30000/codeparse", headers=headers, data=json.dumps(http_data))
            data = response.json()
            if data["code"] != 200:
                raise Exception("Error: fail to parse javascript!")
            # 获取js代码的抽象语法树
            parse_data = data["data"]
            if len(key_list) == 0: # 使用默认的属性进行提取
                keywords, functions = JsParser.get_target_value("name", parse_data, [], [], parse_data)
                keywords1, function1 = JsParser.get_target_value("value", parse_data, [], [], parse_data)
                keywords = list(set(keywords + keywords1))
                functions = list(set(functions + function1))
            else:
                keywords, functions = []
                for key in key_list:
                    keywords1, function1 = JsParser.get_target_value(key, parse_data, [], [], parse_data)
                    keywords = list(set(keywords + keywords1))
                    functions = list(set(functions + function1))
            
            # 进行关键字的过滤
            for r in keywords:
                if isinstance(r, str) and not is_filter(r):
                    tmp_keywords.add(r)
            for f in functions:
                if isinstance(f, str) and not is_filter(f):
                    tmp_functions.add(f)

        except requests.exceptions.ConnectionError:
            return "[-] ERROR: Please start the parsing function of the Js_Parser!"
        except Exception as e:
            return "Error: {}".format(e)
        finally:
            return list(tmp_keywords), list(tmp_functions)
        
    # 给定js文件路径解析js文件
    def parse_js_file(self, file_path):
        with open(file_path, "rb") as f:
            content = f.read()
        if not content:
            return
        encoding = chardet.detect(content)['encoding']
        content = content.decode(encoding, "ignore")
        keywords, functions = JsParser._parse_js_code(content)
        for keyword in keywords:
            self.keyword_set.add_keyword(keyword, file_path)
        for function in functions:
            self.function_set.add_function(function, file_path)
    
    # 迭代获取SOAP方法中的关键字    
    @staticmethod
    def get_target_value(key, dic, tmp_list, func_list, ast): # ast为完整的抽象语法树
        if not isinstance(dic, dict) or not isinstance(tmp_list, list):  # 对传入数据进行格式校验
            return 'argv[1] not an dict or argv[-1] not an list '
        # 大部分固件使用sendSOAPAction进行前后端的数据传输
        if dic.get("type", "") == "CallExpression" and len(dic.get("arguments",[])) == 3:
            obj = dic.get("callee", None)
            if obj:
                soapaction = obj.get("property", None)
                if soapaction and soapaction.get("name", "") == "sendSOAPAction":
                    args = dic.get("arguments", [])
                    if args and args[0].get("type", "") == "Literal":
                        func_list.append(args[0].get("value", ""))
                        # 读取对应参数的键值
                        if "Identifier" in (args[1].get("type", ""), args[2].get("type", "")):
                            index = 1 if args[1].get("type", "") == "Identifier" else 2
                            func_para = args[index].get("name", "")
                            property_list = JsParser.get_property(func_para, ast, [])
                            for property in property_list:
                                tmp_list.append(property)
        if key in dic.keys() and dic.get("type", "") == "Literal":
            tmp_list.append(str(dic[key]))  # 传入数据存在则存入tmp_list
        for value in dic.values():  # 传入数据不符合则对其value值进行遍历
            if isinstance(value, dict):
                JsParser.get_target_value(key, value, tmp_list, func_list, ast)  # 传入数据的value值是字典，则直接调用自身
            elif isinstance(value, (list, tuple)):
                if value:
                    JsParser._get_value(key, value, tmp_list, func_list, ast)  # 传入数据的value值是列表或者元组，则调用_get_value
        return list(set(tmp_list)), list((func_list))
    
    # get_target_value的辅助函数
    @staticmethod
    def _get_value(key, val, tmp_list, func_list, ast):
        for val_ in val:
            if isinstance(val_, dict):
                JsParser.get_target_value(key, val_, tmp_list, func_list, ast)  # 传入数据的value值是字典，则调用get_target_value
            elif isinstance(val_, (list, tuple)):
                if val_:
                    JsParser._get_value(key, val_, tmp_list, func_list, ast)  # 传入数据的value值是列表或者元组，则调用自身
                    
    # 迭代获取SOAP方法中的参数的属性
    @staticmethod
    def get_property(name, dic, property_list):
        # 寻找到对应的属性标识
        if dic.get("type", "") == "MemberExpression":
            obj = dic.get("object", None)
            if obj and obj.get("type", "") == "Identifier" and obj.get("name", "") == name:
                prop = dic.get("property", None)
                if prop and prop.get("type", "") == "Identifier":
                    property_list.append(str(prop.get("name", "")))
        # 进行AST的迭代处理
        for value in dic.values():
            if isinstance(value, dict):
                JsParser.get_property(name, value, property_list)
            elif isinstance(value, (list, tuple)):
                if value:
                    JsParser._get_property(name, value, property_list)
        return list(set(property_list))
    
    # get_property的辅助函数
    @staticmethod
    def _get_property(name, val, property_list):
        for val_ in val:
            if isinstance(val_, dict):
                JsParser.get_property(name, val_, property_list)  # 传入数据的value值是字典，则调用get_property
            elif isinstance(val_, (list, tuple)):
                if val_:
                    JsParser._get_property(name, val_, property_list)  # 传入数据的value值是列表或者元组，则调用自身
                    
    # 打印出js文件中的keyword以及function
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
    def js_keyword_function_file(self):
        file_name = "{}_js_keyword_function.txt".format(config_sgtaint.FIRMWARE_NAME)
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
                    
    # 进行所有js文件的解析
    def run(self):
        total = len(self.js_file_list)
        if total == 0:
            logger.warning(f"No JavaScript files found under {self.directory}; skipping parse.")
            return self.keyword_set, self.function_set
        start_time = time.time()
        logger.info(f"Starting serial parsing of {total} JavaScript files")
        for idx, path in enumerate(self.js_files, start=1):
            try:
                self.parse_js_file(path)
                logger.debug(f"[{idx}/{total}] Parsed successfully: {path}")
            except Exception:
                logger.exception(f"Failed to parse JavaScript file [{idx}/{total}]: {path}")
        duration = time.time() - start_time
        kw_count = self.keyword_set.length()
        fn_count = self.function_set.length()
        logger.info(
            f"Completed parsing {total} files in {duration:.2f}s; "
            f"extracted {kw_count} keywords and {fn_count} functions"
        )
        return self.keyword_set, self.function_set

    # 并行处理js文件
    def run_parallel(self):
        total = len(self.js_file_list)
        if total == 0:
            logger.warning(f"No JavaScript files found under {self.directory}; skipping parse.")
            return self.keyword_set, self.function_set
        start_time = time.time()
        logger.info(f"Starting parallel parsing of {total} JavaScript files.")
        all_keywords = []
        all_functions = []
        def parse_single(js_path):
            local_keywords = KeywordSet()
            local_functions = FunctionSet()
            try:
                with open(js_path, "rb") as f:
                    content = f.read()
                if not content:
                    return local_keywords, local_functions
                encoding = chardet.detect(content)['encoding']
                content = content.decode(encoding, "ignore")
                keywords, functions = JsParser._parse_js_code(content)
                for keyword in keywords:
                    local_keywords.add_keyword(keyword, js_path)
                for function in functions:
                    local_functions.add_function(function, js_path)
            except Exception as e:
                logger.exception(f"Error processing {js_path}")
            return local_keywords, local_functions

        with ThreadPoolExecutor() as executor:
            futures = {
                executor.submit(parse_single, js_path): js_path
                for js_path in self.js_file_list
            }
            for idx, future in enumerate(as_completed(futures), 1):
                try:
                    local_keywords, local_functions = future.result()
                    all_keywords.append(local_keywords)
                    all_functions.append(local_functions)
                    logger.debug(f"[{idx}/{len(self.js_file_list)}] Parsed: {futures[future]}")
                except Exception:
                    logger.exception(f"Failed to parse JavaScript file [{idx}/{total}]: {futures[future]}")
        # 批量合并结果，避免逐一 merge 的性能瓶颈
        merge_start = time.time()
        for kw_set in all_keywords:
            self.keyword_set.merge(kw_set)
        for fn_set in all_functions:
            self.function_set.merge(fn_set)
        merge_time = time.time() - merge_start
        total_time = time.time() - start_time
        logger.info(f"Merged {len(all_keywords)} keyword sets and {len(all_functions)} function sets in {merge_time:.2f}s")
        logger.info(f"Completed parallel parsing of {total} JavaScript files in {total_time:.2f}s")
        return self.keyword_set, self.function_set