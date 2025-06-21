# -*- coding: utf-8 -*-
import os
import chardet
import re
import logging
import time
import tool.Config.config as config_sgtaint
import xml.etree.ElementTree as ET
from tool.Keyword.base.Base import KeywordSet, FunctionSet # xml文件解析的关键字并不需要进行过滤

logger = logging.getLogger("sgtaint.keyword")

# 给定目录遍历获取其中所有xml文件的路径
def find_xml_files(directory):
    xml_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            # 使用 lower() 统一处理大小写问题
            if file.lower().endswith('.xml'):
                xml_files.append(os.path.join(root, file))
    return xml_files

# xml文件解析类，可以处理一组xml文件
class XmlParser():
    def __init__(self, directory): # 传入需要分析的目录地址
        self.directory = directory
        self.keyword_set = KeywordSet()
        self.xml_file_list = find_xml_files(directory)
        self.function_set = FunctionSet()
        
    # 处理单个XML文件
    def _xml_parser(self, file_path):
        level = 1  # 节点的深度从1开始
        with open(file_path, "rb") as f:
            content = f.read()
        if not content:
            return
        encoding = chardet.detect(content)['encoding']
        content = content.decode(encoding, "ignore")
        # 规范xml文件内容
        match = re.search(r"<\?xml\s+version=['\"].*?>", content)
        if match:
            xml_content = content
        else:
            # 跳过前面的PHP代码部分
            pattern = re.compile(r'(<soap:Envelope[^>]*>.*)', re.DOTALL)
            match = pattern.search(content)
            # 构成标准的XML文件格式
            if match:
                # 去除其中的PHP代码部分
                content = re.sub(r'<\?.+?\?>', '', match.group(1))
                xml_content = '<?xml version="1.0" encoding="utf-8"?>\n'
                xml_content = xml_content + content
            else:
                xml_content = content        
        try:
            # 获得根节点
            root = ET.fromstring(xml_content)
            self.walkData(root, level, file_path)
        except Exception:  # 捕获除与程序退出sys.exit()相关之外的所有异常
            return "parse {} fail!".format(file_path)

    # 遍历所有的节点，同时记录父级路径（从 level==3 开始）
    def walkData(self, root_node, level, file_path, path_list=None):
        if path_list is None:
            path_list = []
        # 获取当前节点名称，去除命名空间部分
        index = root_node.tag.find("}")
        if index > 0:
            tag_name = root_node.tag[index+1:]
        else:
            tag_name = root_node.tag
        # 当层级为3时，认为是function，并重置路径
        if level == 3:
            self.function_set.add_function(tag_name, file_path)
            current_path = [tag_name]
        # 当层级大于3时，认为是keyword，同时添加单一tag和完整路径
        elif level > 3:
            self.keyword_set.add_keyword(tag_name, file_path)
            full_path = "/" + "/".join(path_list + [tag_name])
            self.keyword_set.add_keyword(full_path, file_path)
            current_path = path_list + [tag_name]
        else:
            # level小于3时不加入任何集合，路径保持不变
            current_path = path_list
        # 遍历每个子节点
        for child in list(root_node):
            self.walkData(child, level+1, file_path, current_path)
        return

    # 打印出xml文件中的keyword以及function
    def print_keyword_function(self):
        index = 0
        print("[*] There are a total of {} keywords.".format(len(self.keyword_set)))
        for keyword in self.keyword_set.get_keyword_set():
            index += 1
            keyword.print_information(index)
        index = 0
        print("[*] There are a total of {} functions.".format(len(self.function_set)))
        for function in self.function_set.get_function_set():
            index += 1
            function.print_information(index)
            
    # 将所有的关键字写入到文件中
    def xml_keyword_function_file(self):
        file_name = "{}_xml_keyword_function.txt".format(config_sgtaint.FIRMWARE_NAME)
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
    
    # 进行所有xml文件的关键字提取
    def run(self):
        total = len(self.xml_file_list)
        if total == 0:
            logger.warning(f"No XML files found under {self.directory}; skipping parse.")
            return self.keyword_set, self.function_set
        start_time = time.time()
        logger.info(f"Starting serial parsing of {total} XML files in {self.directory}")
        for idx, file_path in enumerate(self.xml_file_list, start=1):
            try:
                result = self._xml_parser(file_path)
                # 如果 _xml_parser 返回错误信息字符串，就记录为 error 级别
                if isinstance(result, str):
                    logger.error(f"[{idx}/{total}] Failed to parse {file_path}: {result}")
                else:
                    logger.debug(f"[{idx}/{total}] Parsed successfully: {file_path}")
            except Exception:
                logger.exception(f"[{idx}/{total}] Unexpected exception processing: {file_path}")
        duration = time.time() - start_time
        kw_count = self.keyword_set.length()
        fn_count = self.function_set.length()
        logger.info(
            f"Completed parsing {total} XML files in {duration:.2f}s; "
            f"extracted {kw_count} keywords and {fn_count} functions"
        )
        return self.keyword_set, self.function_set