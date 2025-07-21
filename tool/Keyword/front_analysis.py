# -*- coding: utf-8 -*-
import os
import subprocess
import time
import signal
import logging
import tool.Config.config as config_sgtaint
from tool.Keyword.base.Base import KeywordSet, FunctionSet
from tool.Keyword.html_keyword import HtmlParser
from tool.Keyword.php_keyword import PhpParser
from tool.Keyword.js_keyword import JsParser
from tool.Keyword.xml_keyword import XmlParser

logger = logging.getLogger("sgtaint.front")

# 获取前端文件解析出的关键字，目前支持html，js以及xml
def get_keyword_function_from_front(directory):
    # 开启npm服务
    npm_dir = config_sgtaint.NPM_DIR # npm服务目录
    logger.info(f"Starting npm service in {npm_dir}")
    try:
        npm_proc = subprocess.Popen(
            ['npm', 'run', 'start'],
            cwd=str(npm_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid
        )
    except Exception as e:
        logger.exception(f"Failed to launch npm service: {npm_dir}")
        raise
    # 进行前端文件的解析
    try:
        logger.debug("Waiting 3s for npm service startup")
        time.sleep(3)
        logger.info("npm service should be up now")
        keyword_set = KeywordSet()
        function_set = FunctionSet()
        # 获取html文件关键字信息
        html_parser = HtmlParser(directory)
        html_kw, html_fn = html_parser.run_parallel()
        for kw in html_kw.get_keyword_set():
            for path in kw.get_file_path():
                keyword_set.add_keyword(kw.get_value(), path)
        for fn in html_fn.get_function_set():
            for path in fn.get_file_path():
                function_set.add_function(fn.get_value(), path)
        logger.info("HTML parsing completed: %d keywords, %d functions", html_kw.length(), html_fn.length())
        # 获取php文件关键字信息
        php_parser = PhpParser(directory)
        php_kw, php_fn = php_parser.run()
        for kw in php_kw.get_keyword_set():
            for path in kw.get_file_path():
                keyword_set.add_keyword(kw.get_value(), path)
        for fn in php_fn.get_function_set():
            for path in fn.get_file_path():
                function_set.add_function(fn.get_value(), path)
        logger.info("PHP parsing completed: %d keywords, %d functions", php_kw.length(), php_fn.length())
        # 获取js文件关键字信息
        js_parser = JsParser(directory)
        js_kw, js_fn = js_parser.run_parallel()
        for kw in js_kw.get_keyword_set():
            for path in kw.get_file_path():
                keyword_set.add_keyword(kw.get_value(), path)
        for fn in js_fn.get_function_set():
            for path in fn.get_file_path():
                function_set.add_function(fn.get_value(), path)
        logger.info("JS parsing completed: %d keywords, %d functions", js_kw.length(), js_fn.length())
        # 获取xml文件关键字信息
        xml_parser = XmlParser(directory)
        xml_kw, xml_fn = xml_parser.run()
        for kw in xml_kw.get_keyword_set():
            for path in kw.get_file_path():
                keyword_set.add_keyword(kw.get_value(), path)
        for fn in xml_fn.get_function_set():
            for path in fn.get_file_path():
                function_set.add_function(fn.get_value(), path)
        logger.info("XML parsing completed: %d keywords, %d functions", xml_kw.length(), xml_fn.length())
        return keyword_set, function_set
    finally: # 安全终止 npm 进程及其子进程
        try:
            os.killpg(os.getpgid(npm_proc.pid), signal.SIGTERM)
            logger.info("npm service terminated")
        except Exception:
            logger.exception("Failed to terminate npm service")
            

# 将关键字以及函数信息写入文件
def keyword_function_file(keyword_set, function_set):
    file_name = "{}_keyword_function.txt".format(config_sgtaint.FIRMWARE_NAME)
    file_path = os.path.join(config_sgtaint.OUTPUT_DIR, file_name)
    with open(file_path, "w", encoding='utf-8') as file:
        index = 0
        file.writelines("All keywords in {}\n".format(config_sgtaint.FIRMWARE_NAME))
        for keyword in keyword_set.get_keyword_set():
            index += 1
            value = keyword.get_value()
            paths = keyword.get_file_path()
            file.writelines("[{}] Keyword: {}\n".format(index, value))
            file.writelines(" Front-end file path:\n")
            for path in paths:
                file.writelines("  {}\n".format(path))
        index = 0
        file.writelines("All functions in {}\n".format(config_sgtaint.FIRMWARE_NAME))
        for function in function_set.get_function_set():
            index += 1
            value = function.get_value()
            paths = function.get_file_path()
            file.writelines("[{}] Function: {}\n".format(index, value))
            file.writelines(" Front-end file path:\n")
            for path in paths:
                file.writelines("  {}\n".format(path))