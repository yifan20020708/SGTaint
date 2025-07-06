# -*- coding: utf-8 -*-
from ghidra.app.script import GhidraScript  # type: ignore

class EnableAggressiveAll(GhidraScript):
    def run(self):
        if currentProgram is None: # type: ignore
            print("[!] No open program – aborting.")
            return
        opts = {
            "Aggressive Instruction Finder": "true", # 识别更多指令边界
            "Decompiler Parameter ID": "true", # 提升反编译准确率
            "Decompiler Switch Analysis": "true",
            "Function ID": "true", # 启用函数签名识别，用于检测库函数
            "Non-Returning Functions - Discovered": "true",
            "Non-Returning Functions - Known": "true",
        }
        print("[*] Enabling aggressive analysis options...")
        setAnalysisOptions(currentProgram, opts) # type: ignore
        print("[+] Options successfully set:")
        for k, v in opts.items():
            print("    {} = {}".format(k, v))

if __name__ == "__main__":
    script = EnableAggressiveAll()
    script.run()
