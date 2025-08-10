# -*- coding: utf-8 -*-
import os
import datetime
import logging
import httpx
import tool.Config.config as config_sgtaint
from dotenv import load_dotenv
from openai import OpenAI, RateLimitError, APIConnectionError, APIError

logger = logging.getLogger("sgtaint.llm")
load_dotenv()

# 实现开启LLM对话的类，方便进行调用，每一个类对象可表示一轮对话
class LLM():
    # 其中model指LLM模型，目前支持deepseek以及gpt
    def __init__(self, temperature = 1.0, model = None): # 温度默认为1.0
        # 配置灵活获取
        self.model = model or config_sgtaint.LLM_MODEL # 通过用户参数进行配置
        self.api_key = os.getenv(config_sgtaint.LLM_MODEL_INFO[self.model][0])
        self.base_url = config_sgtaint.LLM_MODEL_INFO[self.model][1]
        self.temperature = temperature
        # 参数检查
        if not self.api_key or not self.base_url:
            raise ValueError("API key and base URL must be provided for LLM initialization.")
        try:
            self.client = OpenAI(api_key=self.api_key, base_url=self.base_url)
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI client: {e}")
            raise
        self.messages = []
        self.chat_record = []
        
    # 设置系统角色
    def system_role(self, content):
        if not content:
            logger.warning("Empty system role content provided.")
            return
        message = {"role": "system", "content": content}
        self.messages.append(message)
        
    # 开启对话模式（加入了超时对话特性）
    def chat(self, content, timeout=60):
        if not content:
            logger.warning("Empty user content for chat; skipping.")
            return ""
        message = {"role": "user", "content": content}
        self.messages.append(message)
        try:
            response = self.client.chat.completions.create(
                model = self.model, 
                messages = self.messages,
                temperature = self.temperature,
                timeout=timeout
            )
        except (TimeoutError, httpx.TimeoutException) as e:
            logger.error(f"Network timeout during LLM chat: {e}")
            return "[ERROR] Network timeout, please try again later."
        except (APIConnectionError, APIError, RateLimitError) as e:
            logger.error(f"OpenAI API error during LLM chat: {e}")
            return f"[ERROR] LLM API error: {e}"
        except Exception as e:
            logger.error(f"Unexpected error during LLM chat: {e}")
            return f"[ERROR] Unexpected error: {e}"
        # 加入此轮对话的回复，方便开启多轮对话
        if self.model == config_sgtaint.LLM_MODEL:
            self.messages.append(response.choices[0].message)
        else:
            self.messages.append({'role': 'assistant', 'content': response.choices[0].message.content})
        self.chat_record.append((content, response.choices[0].message.content))
        return response.choices[0].message.content
    
    # 异步调用LLM API
    async def chat_async(self, content, timeout=60):
        if not content:
            logger.warning("Empty user content for chat; skipping.")
            return ""
        message = {"role": "user", "content": content}
        self.messages.append(message)
        try:
            response = await self.client.chat.completions.create(
                model=self.model, 
                messages=self.messages,
                temperature=self.temperature,
                timeout=timeout
            )
        except (TimeoutError, httpx.TimeoutException) as e:
            logger.error(f"Network timeout during LLM chat: {e}")
            return "[ERROR] Network timeout, please try again later."
        except (APIConnectionError, APIError, RateLimitError) as e:
            logger.error(f"OpenAI API error during LLM chat: {e}")
            return f"[ERROR] LLM API error: {e}"
        except Exception as e:
            logger.error(f"Unexpected error during LLM chat: {e}")
            return f"[ERROR] Unexpected error: {e}"
        if self.model == config_sgtaint.LLM_MODEL:
            self.messages.append(response.choices[0].message)
        else:
            self.messages.append({'role': 'assistant', 'content': response.choices[0].message.content})
        self.chat_record.append((content, response.choices[0].message.content))
        return response.choices[0].message.content
    
    # 打印出当前轮所有的对话
    def print_chat(self):
        for chat in self.chat_record:
            print(f"USER: {chat[0]}")
            print(f"  LLM: {chat[1]}")
    
    # 将当前的对话存为文件格式
    def chat_file(self):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"LLM_chat_{timestamp}.txt"
        filepath = os.path.join(config_sgtaint.OUTPUT_DIR, filename)
        with open(filepath, "w", encoding="utf-8") as file:
            for chat in self.chat_record:
                file.writelines(f"USER: {chat[0]}\n")
                file.writelines(f"  LLM: {chat[1]}\n")