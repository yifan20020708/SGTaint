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
ANALYZEHEADLESS = os.path.join(BASE_DIR, "ghidra_tool", "support", "analyzeHeadless")
VULN_OUT_DIR = os.path.join(OUT_DIR, "vulnerable")
TMP_KEYWORD = os.path.join(TMP_DIR, "BinaryKeyword")
BINARY_INFO_DIR = os.path.join(TMP_DIR, "BinaryInfo")
BINARY_CONFIG_DIR = os.path.join(TMP_DIR, "BinaryConfig")
BINARY_TMP = os.path.join(TMP_DIR, "BinaryTmp")
NPM_DIR = os.path.join(BASE_DIR, "tool", "Keyword", "JS_Parse")
GHIDRA_ASSIST_PATH = os.path.join(BASE_DIR, "tool", "Ghidra", "ghidra_assist.py")
DECOMPILE_ASSIST_PATH = os.path.join(BASE_DIR, "tool", "Ghidra", "decompile_assist.py")
AGGRESSIVE_GHIDRA_PATH = os.path.join(BASE_DIR, "tool", "Ghidra", "enable_aggressive_all.py")

# LLM配置
LLM_URL_DEEPSEEK = "https://api.deepseek.com"
LLM_URL_CHATGPT = "https://api.openai.com/v1"
LLM_URL_QIANWEN = "https://dashscope.aliyuncs.com/compatible-mode/v1"
LLM_MODEL_DEEPSEEK = "deepseek-chat"
LLM_MODEL_CHATGPT = "gpt-4.1"
LLM_MODEL_QIANWEN = "qwen3-coder-plus"
LLM_MODEL = ""
SG_TEMPERATURE = 0.3 # 进行代码分析
MAX_ERROR_COUNT = 3
LLM_MODEL_INFO = {
    LLM_MODEL_DEEPSEEK: ["DEEPSEEK_API_KEY", LLM_URL_DEEPSEEK],
    LLM_MODEL_QIANWEN: ["QIANWEN_API_KEY", LLM_URL_QIANWEN],
    LLM_MODEL_CHATGPT: ["OPENAI_API_KEY", LLM_MODEL_CHATGPT]
}
MODEL_MAP = {
    "deepseek": LLM_MODEL_DEEPSEEK,
    "qwen": LLM_MODEL_QIANWEN,
    "gpt": LLM_MODEL_CHATGPT
}

# 读取config文件之后进行配置
SG_FUNCTION_INFO = None  # 格式为[(set_1, get_1, set_key_pos, get_key_pos, set_value_pos, get_value_pos), ...]或None
BOUNDARY_BINARIES = None
FIRMWARE_NAME = ""
FILE_SYSTEM = ""
BOUNDARY_BINARY_NAME = ["cgi", "httpd", "goahead", "boa", "upnp"]
GHIDRA_ASSIST = False

# 从内存中提取字符串的相关配置
MIN_STR_LEN = 3
STR_LEN = 255
ALLOWED_CHARS = string.digits + string.ascii_letters + "-/_"
EXTENDED_CHARS = "%,.:;+=)(*&^%$#@!~`|<>{}[] "
EXTENDED_ALLOWED_CHARS = ALLOWED_CHARS + EXTENDED_CHARS

# 进行参数提取的相关配置
MIN_SUCCESS_RATE = 0.5
MAX_BINARY_LIMIT = 30
THRESHOLD = 5
MAX_BOUNDARY_BINARIES_LIMIT = 5

# 关键字过滤的相关配置
MIN_KEYWORD_LEN = 3
MAX_KEYWORD_LEN = 30
BLOCK_CHARS = [" ", "{", "}", ";", ".", "<", ">", "\'", '\"', "(", ")", "[", "]", ":", "*", "`", "!", "+", "^", "&"]
WHITE_LIST = ["True", "true", "False", "false", "None", "none", "ERROR", "Error"]
BOUNDARY_BINARIES_WHITE_LIST = [
    "busybox", "egrep", "hostname", "iptunnel", "cat", "chmod", "cp", "data", "echo", "false", "fgrep", "grep", "gunzip", "gzip",
    "ip", "ipaddr", "iplink", "iproute", "iprule", "kill", "ln", "ls", "mkdir", "mknod", "mount", "msh", "mv", "netstat", "ping",
    "ping6", "ps", "pwd", "rm", "sed", "sh", "sleep", "tar", "touch", "true", "umount", "uname", "vi", "zcat", "halt", "init", 
    "modprobe", "insmod", "lsmod", "poweroff", "reboot", "rmmod", "route", "ifconfig", "sysctl", "vconfig", "tunctl", "arp",
    "arping", "basename", "bzcat", "bunzip2", "bzip2", "cut", "free", "killall", "killall5", "top", "uptime", "yes", "[[", "awk", 
    "expr", "test", "tr", "wc", "xargs", "brctl", "genuuid", "getbootver", "gethostip", "logger", "logd", "klogd", "syslog_msg", 
    "gpioc", "gpiod", "pidmon", "trigger", "fonts", "ethreg", "vconfig", "seama"
]

# 模糊匹配相关配置
MIN_SIMILARITY = 90
MAX_DISTANCE = 2
MIN_KEYWORD_NUMBER = 30
WORKER_TIMEOUT_SECONDS = 20

# 超时时间设置
DECOMPILE_TIMEOUT = 120
BINARY_TIMEOUT = 3 * 60 * 60
FUNC_TIMEOUT = 1000

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
pattern_llm_two_parse = re.compile(r'^\s*\[\s*(\(\s*([^,()]+?\s*,\s*){5}[^,()]+?\s*\)\s*,?\s*)+\]$')
pattern_llm_one_parse = re.compile(r'^\s*\[\s*(\(\s*[^,()]+?\s*,\s*[^,()]+?\s*\)\s*,?\s*)+\]$')
spec_map = {
    r"%s" : r"(?P<str>[^#\s]+)",
    r"%c" : r"(?P<char>.{1})",
    r"%d" : r"(?P<int>[+-]?\d+)",
    r"%i" : r"(?P<int>[+-]?\d+)",
    r"%u" : r"(?P<uint>\d+)",
    r"%o" : r"(?P<oct>[0-7]+)",
    r"%x" : r"(?P<hex>[0-9a-f]+)",
    r"%X" : r"(?P<HEX>[0-9A-F]+)",
    r"%p" : r"(?P<ptr>0x[0-9a-fA-F]+)",
    r"%f" : r"(?P<float>[+-]?\d+\.\d+)",
    r"%F" : r"(?P<float>[+-]?\d+\.\d+)",
    r"%e" : r"(?P<exp>[+-]?\d+\.\d+[eE][+-]?\d+)",
    r"%E" : r"(?P<EXP>[+-]?\d+\.\d+[eE][+-]?\d+)",
    r"%g" : r"(?P<float>[+-]?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)",
    r"%G" : r"(?P<float>[+-]?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)",
    r"%a" : r"(?P<a>0x[0-9a-f]+\.[0-9a-f]+p[+-]?\d+)",
    r"%A" : r"(?P<A>0x[0-9A-F]+\.[0-9A-F]+P[+-]?\d+)",
    r"%%" : r"%"
}

# 大模型最大重复次数
MAX_REPEATED_TIMES = 3
CODE_NUMBER = 3

# RDA分析配置
STRING_LENGTH_RESTRICTION = 200
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
    "vici_find_str", "DoHardwareComponent", "device_get_string_value", "cJSON_Parse", "websGetVarSafe", "websGetVar_secure",
    "OM_ValGet", "acosUciConfig_get", "CAL_abstract_get", "json_object_object_get", "json_object_object_get_ex",
    "json_tokener_parse", "OM_ValFind", "get_parameter", "get_wlan_setting", "av_dict_get", "cgi_value", "stringOut",
    "cJSON_GetObjectItem", "sw_getValueByName", "querystr", "find_val", "log_query", "value_parser_by_index_D7000",
    "getoption", "WEB_GetVar", "av_opt_get", "paramValueFromObjGet", "help_getObjPtr", "NCONF_get_string", "getString", "web_get"
    "av_metadata_get", "httpGetEnv", "gets", "fgets", "recvfrom", "recvmsg", "nvram_get_ex2", "nvram_bufget", "apmib_get", "apcli_nvram_get"
]
KEYWORD_SOURCES = [
    "webGetVarString", "websGetVar", "websGetVarSafe", "websGetVar_secure", "WEB_GetVar", "httpGetEnv", "cJSON_GetObjectItem",
    "sub_42af24", "sub_42a978", "get_cgi", "web_get"
]
STRCPY_SINKS = [
    "strcpy", "strcat"
]
transitive_get = [
    "config_get", "GetValue", "getenv", "nvram_get", "nvram_safe_get", "nvram_pf_get", "acosNvramConfig_get", "nvram_bufget", "apcli_nvram_get",
    "uciGet", "wpa_config_get", "device_get_string_value", "OM_ValGet", "acosUciConfig_get", "CAL_abstract_get", "nvram_get_ex2", "apmib_get",
    "acosNvramConfig_read", "stringOut"
]
transitive_set = [
    "config_set", "SetValue", "setenv", "nvram_set", "nvram_safe_set", "nvram_pf_set", "artblock_set",
    "acos_nvram_set", "acosNvramConfig_set", "acosNvramConfig_write", "envz_add", "uciSet",
    "device_set_string_value", "wpa_config_set", "scfgmgr_set_by_index_D7000", "acosUciConfig_set",
    "OM_ValSet", "CAL_abstract_set", "nvram_bufset", "apmib_set", "apcli_nvram_set", "nvram_set_value"
]
SINKS = [
    "strcpy", "strcat", "sprintf", "system", "___system", "_system", "bstar_system", "popen", "doSystemCmd", "doShell",
    "twsystem", "CsteSystem", "cgi_deal_popen", "ExecShell", "exec_shell_popen", "exec_shell_popen_str", "doSystem",
    "wl_exec_cmd", "execve", "execl", "_eval", "eval", "sh", "send", "execlp", "doSystem", "sprintf"
]
CI_SINKS = [
    "system", "___system", "_system", "bstar_system", "popen", "doSystemCmd", "doShell",
    "twsystem", "CsteSystem", "cgi_deal_popen", "ExecShell", "exec_shell_popen", "exec_shell_popen_str", "doSystem",
    "wl_exec_cmd", "execve", "execl", "_eval", "eval", "sh", "send", "execlp", "doSystem"
]
# 已知的set-get函数info
SET_GET_INFO = {
    ("config_set", "config_get"): ["config_set", "config_get", 0, 0, 1, None],
    ("SetValue", "GetValue"): ["SetValue", "GetValue", 0, 0, 1, 1],
    ("setenv", "getenv"): ["setenv", "getenv", 0, 0, 1, None],
    ("nvram_safe_set", "nvram_safe_get"): ["nvram_safe_set", "nvram_safe_get", 0, 0, 1, None],
    ("nvram_pf_set", "nvram_pf_get"): ["nvram_pf_set", "nvram_pf_get", 0, 0, 1, None],
    ("acosNvramConfig_set", "acosNvramConfig_get"): ["acosNvramConfig_set", "acosNvramConfig_get", 0, 0, 1, None],
    ("acosNvramConfig_set", "acosNvramConfig_read"): ["acosNvramConfig_set", "acosNvramConfig_read", 0, 0, 1, 1],
    ("uciSet", "uciGet"): ["uciSet", "uciGet", 0, 0, 1, None],
    ("wpa_config_set", "wpa_config_get"): ["wpa_config_set", "wpa_config_get", 0, 0, 1, None],
    ("device_set_string_value", "device_get_string_value"): ["device_set_string_value", "device_get_string_value", 0, 0, 1, None],
    ("OM_ValSet", "OM_ValGet"): ["OM_ValSet", "OM_ValGet", 0, 0, 1, None],
    ("acosUciConfig_set", "acosUciConfig_get"): ["acosUciConfig_set", "acosUciConfig_get", 0, 0, 1, None],
    ("CAL_abstract_set", "CAL_abstract_get"): ["CAL_abstract_set", "CAL_abstract_get", 0, 0, 1, None],
    ("nvram_bufset", "nvram_bufget"): ["nvram_bufset", "nvram_bufget", 1, 1, 2, None],
    ("apmib_set", "apmib_get"): ["apmib_set", "apmib_get", 0, 0, 1, 1],
    ("apcli_nvram_set", "apcli_nvram_get"): ["apcli_nvram_set", "apcli_nvram_get", 1, 1, 2, None],
    ("nvram_set_value", "nvram_safe_get"): ["nvram_set_value", "nvram_safe_get", 0, 0, 1, None]
}
taint_sources_remove = ["strtok", "strchr", "atoi", "strspn", "strtol", "fork", "rand", "malloc", "strlen"]
sanitization_functions = ["atoi", "strcmp", "strncmp", "acosNvramConfig_match"]