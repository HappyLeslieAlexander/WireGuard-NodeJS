#!/bin/bash

# 设置变量
WIREGUARD_JS="WireGuard.js"
CONFIG_FILE="config.json"
PRIVATE_KEY_FILE="private.key"
NODE_MODULES_DIR="node_modules"

# 检查 Node.js 是否已安装
if ! command -v node &> /dev/null
then
    echo "Node.js 未安装，请先安装 Node.js。"
    exit 1
fi

# 检查是否存在 Node.js 依赖
if [ ! -d "$NODE_MODULES_DIR" ]; then
    echo "正在安装 Node.js 依赖..."
    npm install libsodium-wrappers
fi

# 确保配置文件存在
if [ ! -f "$CONFIG_FILE" ]; then
    echo "配置文件 $CONFIG_FILE 不存在，请创建该文件。"
    exit 1
fi

# 确保密钥文件存在
if [ ! -f "$PRIVATE_KEY_FILE" ]; then
    echo "生成 WireGuard 私钥文件..."
    openssl rand -base64 32 > "$PRIVATE_KEY_FILE"
    echo "私钥文件生成在 $PRIVATE_KEY_FILE"
fi

# 启动 WireGuard 服务
echo "启动 WireGuard 服务..."
nohup node "$WIREGUARD_JS" > wireguard.log 2>&1 &
echo "WireGuard 服务已启动，日志记录在 wireguard.log"

# 配置文件监视
if command -v fswatch &> /dev/null
then
    echo "开始监视配置文件变化..."
    fswatch -o "$CONFIG_FILE" | while read -r; do
        echo "配置文件 $CONFIG_FILE 已更改"
        # 重新加载配置或其他操作
        node "$WIREGUARD_JS" > wireguard.log 2>&1 &
    done
else
    echo "fswatch 工具未安装。请安装 fswatch 工具以启用配置文件监视功能。"
fi
