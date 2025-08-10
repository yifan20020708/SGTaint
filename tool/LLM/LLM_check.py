# -*- coding: utf-8 -*-
import logging
import tool.Config.config as config_sgtaint
from concurrent.futures import ThreadPoolExecutor, as_completed
from tool.LLM.prompt_template import SYSTEM_LLM_PATH_CHECK, SYSTEM_LLM_PATH_OUTPUT, get_start_prompt, get_middle_prompt, get_end_prompt
from tool.LLM.LLM_chat import LLM

logger = logging.getLogger("sgtaint.llmcheck")

# 给完整的反编译代码加入行号
def number_complete_blocks(complete_list):
    numbered = []
    for block in complete_list:
        lines = block.splitlines()
        width = max(2, len(str(len(lines))))
        out = "\n".join(f"{i:>{width}} {line}" for i, line in enumerate(lines, start=1))
        numbered.append(out)
    return numbered


# 加入超时时间
def llm_worker(path, timeout=90):
    code_snippet_list = path.get("decompile_list")
    keywords = ("Fail to Decompile", "Invalid code snippet")
    if not code_snippet_list or any(any(k in snippet for k in keywords) for snippet in code_snippet_list): # 处理不存在反编译代码的情况
        path["LLM_judge"] = "unsupported"
        path["LLM_response"] = "unsupported"
        return path
    # 构造对应的提示词
    taint_source = path.get("taint_source")
    taint_sink = path.get("taint_sink")
    vulnerability_type = path.get("vulnerability_type") # 提示词的构造与漏洞类型相关
    number_complete_code = number_complete_blocks(path.get("complete_list")) # 完整且存在行号的代码片段集合
    try:
        LLM_chat = LLM(config_sgtaint.SG_TEMPERATURE)
        LLM_chat.system_role(SYSTEM_LLM_PATH_CHECK)
        # 生成起始提示词
        first_snippet = number_complete_code[0] if vulnerability_type == "buffer overflow" else code_snippet_list[0]
        start_index, end_index = path.get("range_list")[0] if vulnerability_type == "buffer overflow" else (None, None)
        resp = LLM_chat.chat(get_start_prompt(taint_source, first_snippet, start_index, end_index), timeout=timeout)
        if resp.startswith("[ERROR]"):
            path["LLM_judge"] = "unsupported"
            path["LLM_response"] = resp
            return path
        # 迭代处理中间代码片段
        for index in range(1, len(code_snippet_list)):
            middle_snippet = number_complete_code[index] if vulnerability_type == "buffer overflow" else code_snippet_list[index]
            start_index, end_index = path.get("range_list")[index] if vulnerability_type == "buffer overflow" else (None, None)
            resp = LLM_chat.chat(get_middle_prompt(middle_snippet, start_index, end_index), timeout=timeout)
            if resp.startswith("[ERROR]"):
                path["LLM_judge"] = "unsupported"
                path["LLM_response"] = resp
                return path
        # 明确最终任务
        start_index, end_index = path.get("range_list")[-1] if vulnerability_type == "buffer overflow" else (None, None)
        response = LLM_chat.chat(get_end_prompt(taint_sink, start_index, end_index), timeout=timeout)
        if response.startswith("[ERROR]"):
            path["LLM_judge"] = "unsupported"
            path["LLM_response"] = response
            return path
        # 规范大语言模型的输入
        while not response.startswith("Yes") and not response.startswith("No"):
            response = LLM_chat.chat(SYSTEM_LLM_PATH_OUTPUT, timeout=timeout)
            if response.startswith("[ERROR]"):
                path["LLM_judge"] = "unsupported"
                path["LLM_response"] = response
                return path
        llm_judge = True if response.startswith("Yes") else False
        path["LLM_judge"] = llm_judge
        path["LLM_response"] = response
        return path
    except Exception as e:
        logger.error(f"llm_worker failed: {e}")
        path["LLM_judge"] = "unsupported"
        path["LLM_response"] = f"[ERROR] llm_worker failed: {e}"
        return path


# 并行进行LLM的检查
def llm_assist_parallel(potential_path):
    llm_process_potential_path = [None] * len(potential_path)
    logger.info(f"Starting LLM-assisted judgment on {len(potential_path)} paths.")
    max_workers = min(16, max(1, len(potential_path)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future2idx = {
            executor.submit(llm_worker, path): idx
            for idx, path in enumerate(potential_path)
        }
        finished = 0
        for future in as_completed(future2idx):
            idx = future2idx[future]
            try:
                result = future.result()
                llm_process_potential_path[idx] = result
            except Exception as e:
                logger.error(f"LLM worker failed at idx={idx}: {e}")
            finished += 1
            logger.info(f"LLM-assisted judgment task completed [{finished}/{len(potential_path)}]")
    logger.info("All LLM-assisted judgment tasks completed.")
    return llm_process_potential_path


# 生成对应的提示词
def llm_prompt_generate(merged_path):
    llm_prompt_path = []
    for path in merged_path:
        code_snippet_list = path.get("decompile_list")
        keywords = ("Fail to Decompile", "Invalid code snippet") # 处理编译失败的情况
        if not code_snippet_list or any(any(k in snippet for k in keywords) for snippet in code_snippet_list): # 处理不存在反编译代码的情况
            path["LLM_prompt"] = "Fail to generate llm prompt"
            path["LLM_judge"] = "unsupported"
            llm_prompt_path.append(path)
            continue
        # 构造对应的提示词
        llm_prompt_list = []
        taint_source = path.get("taint_source")
        taint_sink = path.get("taint_sink")
        vulnerability_type = path.get("vulnerability_type") # 提示词的构造与漏洞类型相关
        number_complete_code = number_complete_blocks(path.get("complete_list")) # 完整且存在行号的代码片段集合
        # 获取起始提示词
        first_snippet = number_complete_code[0] if vulnerability_type == "buffer overflow" else code_snippet_list[0]
        start_index, end_index = path.get("range_list")[0] if vulnerability_type == "buffer overflow" else (None, None)
        llm_prompt_list.append(get_start_prompt(taint_source, first_snippet, start_index, end_index))
        # 迭代处理中间代码片段
        for index in range(1, len(code_snippet_list)):
            middle_snippet = number_complete_code[index] if vulnerability_type == "buffer overflow" else code_snippet_list[index]
            start_index, end_index = path.get("range_list")[index] if vulnerability_type == "buffer overflow" else (None, None)
            llm_prompt_list.append(get_middle_prompt(middle_snippet, start_index, end_index))
        # 明确最终任务
        start_index, end_index = path.get("range_list")[-1] if vulnerability_type == "buffer overflow" else (None, None)
        llm_prompt_list.append(get_end_prompt(taint_sink, start_index, end_index))
        path["LLM_prompt"] = llm_prompt_list
        path["LLM_judge"] = ""
        llm_prompt_path.append(path)
    return llm_prompt_path