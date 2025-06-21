# -*- coding: utf-8 -*-
import string
import re
import os

# 计算项目根目录
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))

# 输出目录配置
OUT_DIR = os.path.join(BASE_DIR, "output")
OUTPUT_DIR = os.path.join(OUT_DIR, "log")
TMP_DIR = os.path.join(BASE_DIR, "tmp")
GHIDRA_DIR = os.path.join(TMP_DIR, "ghidra")
ANALYZEHEADLESS = os.path.join(BASE_DIR, "ghidra", "support", "analyzeHeadless")
VULN_OUT_DIR = os.path.join(OUT_DIR, "vulnerable")
TMP_KEYWORD = os.path.join(TMP_DIR, "BinaryKeyword")
BINARY_INFO_DIR = os.path.join(TMP_DIR, "BinaryInfo")
BINARY_CONFIG_DIR = os.path.join(TMP_DIR, "BinaryConfig")
BINARY_TMP = os.path.join(TMP_DIR, "BinaryTmp")
NPM_DIR = os.path.join(BASE_DIR, "tool", "Keyword", "JS_Parse")

# LLM配置
LLM_API_KEY_DEEPSEEK = "sk-d6d28208fde8451192b401dbbf963b12"
LLM_URL_DEEPSEEK = "https://api.deepseek.com"
LLM_MODEL = "deepseek-chat"
SG_TEMPERATURE = 0.7
MAX_ERROR_COUNT = 3

# 读取config文件之后进行配置
SG_FUNCTION_INFO = None  # 格式为[(set_1, get_1, set_key_pos, get_key_pos, set_value_pos, get_value_pos), ...]或None
FIRMWARE_NAME = ""
FILE_SYSTEM = ""

# 从内存中提取字符串的相关配置
MIN_STR_LEN = 3
STR_LEN = 255
ALLOWED_CHARS = string.digits + string.ascii_letters + "-/_"
EXTENDED_CHARS = "%,.:;+=)(*&^%$#@!~`|<>{}[] "
EXTENDED_ALLOWED_CHARS = ALLOWED_CHARS + EXTENDED_CHARS

# 进行参数提取的相关配置
MIN_SUCCESS_RATE = 0.5
MAX_BINARY_LIMIT = 20

# 关键字过滤的相关配置
MIN_KEYWORD_LEN = 3
MAX_KEYWORD_LEN = 30
BLOCK_CHARS = [" ", "{", "}", ";", ".", "<", ">", "\'", '\"', "(", ")", "[", "]", ":", "*", "`", "!", "+", "^", "&"]
WHITE_LIST = ["True", "true", "False", "false", "None", "none", "ERROR", "Error"]

# 模糊匹配相关配置
MIN_SIMILARITY = 90
MAX_DISTANCE = 2
MIN_KEYWORD_NUMBER = 30
WORKER_TIMEOUT_SECONDS = 20

# angr中常见的前缀
PREFIXES = [
    "g", "dword", "word", "byte", "qword",
    "float", "double", "unk", "off",
    "sub", "loc", "FUN", "LAB", "DATA", "ptr", "DAT"
]

# 构造正则：^(?:前缀1|前缀2|...?)_([0-9A-Fa-f]+)$
pattern = re.compile(
    r'^&?(?:' + '|'.join(map(re.escape, PREFIXES)) + r')_([0-9A-Fa-f]+)$'
)

# 大模型最大重复次数
MAX_REPEATED_TIMES = 3
CODE_NUMBER = 3

# RDA分析配置
defination_dictionary = []
OVERWRITTEN_STACK_VARIABLES = {}
strcpy_counter = [0]
strchr_counter = [0]
getenv_counter = [0]
init_addr_conter = [0]
# to collect user defined functions
New_input_getters = []
STACK = []
Analyzed_Before = {}  # to store previously analysed function decopiler to save time of regenerate them
global_counter = [0]
# 原始内容
SOURCES = [
    "sub_1d170", "config_get", "NK_query_entry_get", "webGetVarString", "bcm_nvram_get", "GetValue", "acosNvramConfig_read",
    "sub_42af24", "sub_42a978", "get_cgi", "websGetVar", "nvram_get", "nvram_safe_get", "nvram_default_get", "getenv",
    "nvram_pf_get", "acosNvramConfig_get", "uciGet", "entry", "wpa_config_get", "httpGenListDataGet", "cJSON_GetArrayItem",
    "vici_find_str", "DoHardwareComponent", "device_get_string_value", "cJSON_Parse", 
    "OM_ValGet", "acosUciConfig_get", "CAL_abstract_get", "json_object_object_get", "json_object_object_get_ex",
    "json_tokener_parse", "OM_ValFind", "get_parameter", "get_wlan_setting", "av_dict_get", "cgi_value", "stringOut",
    "cJSON_GetObjectItem", "sw_getValueByName", "querystr", "find_val", "log_query", "value_parser_by_index_D7000",
    "getoption", "WEB_GetVar", "av_opt_get", "paramValueFromObjGet", "help_getObjPtr", "NCONF_get_string",
    "av_metadata_get", "httpGetEnv", "gets", "fgets", "recvfrom", "recvmsg"
]
transitive_get = [
    "config_get", "GetValue", "getenv", "nvram_get", "nvram_safe_get", "nvram_pf_get", "acosNvramConfig_get",
    "uciGet", "wpa_config_get", "device_get_string_value", "OM_ValGet", "acosUciConfig_get", "CAL_abstract_get"
]
transitive_set = [
    "config_set", "SetValue", "setenv", "nvram_set", "nvram_safe_set", "nvram_pf_set", "artblock_set",
    "acos_nvram_set", "acosNvramConfig_set", "acosNvramConfig_write", "envz_add", "uciSet",
    "device_set_string_value", "wpa_config_set", "scfgmgr_set_by_index_D7000", "acosUciConfig_set",
    "OM_ValSet", "CAL_abstract_set"
]
SINKS = [
    "strcpy", "strcat", "sprintf", "system", "___system", "_system", "bstar_system", "popen", "doSystemCmd", "doShell",
    "twsystem", "CsteSystem", "cgi_deal_popen", "ExecShell", "exec_shell_popen", "exec_shell_popen_str",
    "wl_exec_cmd", "execve", "execl", "_eval", "eval", "sh", "send", "execlp", "doSystem", "sprintf"
]
# 已知的set-get函数info
SET_GET_INFO = {
    ("config_set", "config_get"): ["config_set", "config_get", 0, 0, 1, None],
    ("SetValue", "GetValue"): ["SetValue", "GetValue", 0, 0, 1, 1],
    ("setenv", "getenv"): ["setenv", "getenv", 0, 0, 1, None],
    ("nvram_set", "nvram_get"): ["nvram_set", "nvram_get", 0, 0, 1, None],
    ("nvram_safe_set", "nvram_safe_get"): ["nvram_safe_set", "nvram_safe_get", 0, 0, 1, None],
    ("nvram_pf_set", "nvram_pf_get"): ["nvram_pf_set", "nvram_pf_get", 0, 0, 1, None],
    ("acosNvramConfig_set", "acosNvramConfig_get"): ["acosNvramConfig_set", "acosNvramConfig_get", 0, 0, 1, None],
    ("uciSet", "uciGet"): ["uciSet", "uciGet", 0, 0, 1, None],
    ("wpa_config_set", "wpa_config_get"): ["wpa_config_set", "wpa_config_get", 0, 0, 1, None],
    ("device_set_string_value", "device_get_string_value"): ["device_set_string_value", "device_get_string_value", 0, 0, 1, None],
    ("OM_ValSet", "OM_ValGet"): ["OM_ValSet", "OM_ValGet", 0, 0, 1, None],
    ("acosUciConfig_set", "acosUciConfig_get"): ["acosUciConfig_set", "acosUciConfig_get", 0, 0, 1, None],
    ("CAL_abstract_set", "CAL_abstract_get"): ["CAL_abstract_set", "CAL_abstract_get", 0, 0, 1, None]
}