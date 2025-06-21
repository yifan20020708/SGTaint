#!/bin/bash

# 定义版本和下载链接
GHIDRA_VERSION="11.3.2"
BUILD_DATE="20250415"
DOWNLOAD_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${BUILD_DATE}.zip"
TARGET_DIR="ghidra_tool"  # 固定解压后的文件夹名称

# 下载 Ghidra
echo "[*] 下载 Ghidra ${GHIDRA_VERSION}..."
wget "$DOWNLOAD_URL" || { echo "[!] 下载失败"; exit 1; }

# 解压到固定名称的文件夹
echo "[*] 解压到文件夹 '$TARGET_DIR'..."
unzip -q "ghidra_${GHIDRA_VERSION}_PUBLIC_${BUILD_DATE}.zip" -d "$TARGET_DIR" \
    || { echo "[!] 解压失败"; exit 1; }

# 重命名解压后的内部文件夹（确保最终路径为 ./ghidra/）
mv "$TARGET_DIR/ghidra_${GHIDRA_VERSION}_PUBLIC"/* "$TARGET_DIR/" \
    && rm -r "$TARGET_DIR/ghidra_${GHIDRA_VERSION}_PUBLIC" \
    || echo "[*] 内部文件夹已合并"

# 清理临时文件
rm "ghidra_${GHIDRA_VERSION}_PUBLIC_${BUILD_DATE}.zip"
echo "[+] Ghidra 已解压到 '$TARGET_DIR/'"