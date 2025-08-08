# -*- coding: utf-8 -*-
import logging
import tool.Config.config as config_sgtaint
from concurrent.futures import ProcessPoolExecutor, as_completed
from tool.LLM.prompt_template import SYSTEM_LLM_PATH_CHECK, SYSTEM_LLM_PATH_OUTPUT, get_start_prompt, get_middle_prompt, get_end_prompt
from tool.LLM.LLM_chat import LLM

logger = logging.getLogger("sgtaint.llmcheck")

# 加入超时时间
def llm_worker(path, timeout=60):
    code_snippet_list = path.get("decompile_list")
    keywords = ("Fail to Decompile", "Invalid code snippet")
    if not code_snippet_list or any(any(k in snippet for k in keywords) for snippet in code_snippet_list): # 处理不存在反编译代码的情况
        path["LLM_judge"] = "unsupported"
        path["LLM_response"] = "unsupported"
        return path
    # 构造对应的提示词
    taint_source = path.get("taint_source")
    taint_sink = path.get("taint_sink")
    try:
        LLM_chat = LLM(config_sgtaint.SG_TEMPERATURE)
        LLM_chat.system_role(SYSTEM_LLM_PATH_CHECK)
        first_snippet = code_snippet_list[0]
        resp = LLM_chat.chat(get_start_prompt(taint_source, first_snippet), timeout=timeout)
        if resp.startswith("[ERROR]"):
            path["LLM_judge"] = "unsupported"
            path["LLM_response"] = resp
            return path
        # 迭代处理中间代码片段
        middle_snippet_list = code_snippet_list[1:]
        for middle_snippet in middle_snippet_list:
            resp = LLM_chat.chat(get_middle_prompt(middle_snippet), timeout=timeout)
            if resp.startswith("[ERROR]"):
                path["LLM_judge"] = "unsupported"
                path["LLM_response"] = resp
                return path
        # 明确最终任务
        response = LLM_chat.chat(get_end_prompt(taint_sink), timeout=timeout)
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
    with ProcessPoolExecutor() as executor:
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
        # 获取起始提示词
        first_snippet = code_snippet_list[0]
        llm_prompt_list.append(get_start_prompt(taint_source, first_snippet))
        # 迭代处理中间代码片段
        middle_snippet_list = code_snippet_list[1:]
        for middle_snippet in middle_snippet_list:
            llm_prompt_list.append(get_middle_prompt(middle_snippet))
        # 明确最终任务
        llm_prompt_list.append(get_end_prompt(taint_sink))
        path["LLM_prompt"] = llm_prompt_list
        path["LLM_judge"] = ""
        llm_prompt_path.append(path)
    return llm_prompt_path