#!/bin/bash

# 安装必要的软件包
apt-get update
apt-get install -y nodejs npm iproute2 iptables

# 确保 libsodium 库存在
npm install libsodium-wrappers

# 生成 WireGuard.js 配置文件
cat <<EOT > config.json
{
    "server_port": 51820,
    "allowed_ips": ["0.0.0.0/0", "::/0"],
    "client": {
        "public_key": "CLIENT_PUBLIC_KEY",
        "allowed_ips": ["10.0.0.2/32", "fd00::2/128"]
    }
}
EOT

# 启动 WireGuard.js
node WireGuard.js
