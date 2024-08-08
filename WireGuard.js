const sodium = require('libsodium-wrappers');
const dgram = require('dgram');
const net = require('net');
const fs = require('fs');
const path = require('path');
const { Transform } = require('stream');
const winston = require('winston');
const { exec } = require('child_process');
const TUN = require('node-tun');

// 配置文件路径
const configFilePath = path.join(__dirname, 'config.json');

// 初始化密钥和加密工具
async function initializeCrypto() {
    await sodium.ready;

    const keyPairA = sodium.crypto_kx_keypair();
    const keyPairB = sodium.crypto_kx_keypair();

    const sharedA = sodium.crypto_kx_client_session_keys(keyPairA.publicKey, keyPairA.privateKey, keyPairB.publicKey);
    const sharedB = sodium.crypto_kx_server_session_keys(keyPairB.publicKey, keyPairB.privateKey, keyPairA.publicKey);

    return {
        clientKeys: keyPairA,
        serverKeys: keyPairB,
        sharedA,
        sharedB
    };
}

// 密钥管理：保存和轮换密钥
const keyStore = {
    currentKey: null,
    setKey(key) {
        this.currentKey = key;
        // 可以将密钥保存到数据库或文件系统
    },
    getKey() {
        return this.currentKey;
    }
};

// 示例：更新密钥
function rotateKeys(newKey) {
    keyStore.setKey(newKey);
}

// 加密函数
function encryptMessage(message, sharedKey) {
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
    const ciphertext = sodium.crypto_secretbox_easy(message, nonce, sharedKey);
    return { ciphertext, nonce };
}

// 解密函数
function decryptMessage(ciphertext, nonce, sharedKey) {
    const decryptedMessage = sodium.crypto_secretbox_open_easy(ciphertext, nonce, sharedKey);
    return sodium.to_string(decryptedMessage);
}

// 数据包处理函数
let sequenceNumber = 0;

function createPacket(data, destination) {
    const packet = {
        sequenceNumber: sequenceNumber++,
        destination: destination,
        data: data
    };
    return Buffer.from(JSON.stringify(packet));
}

function parsePacket(packet) {
    return JSON.parse(packet.toString());
}

function fragmentPacket(packet, maxSize) {
    const fragments = [];
    let offset = 0;

    while (offset < packet.length) {
        const end = Math.min(offset + maxSize, packet.length);
        const fragment = packet.slice(offset, end);
        fragments.push(fragment);
        offset += maxSize;
    }

    return fragments;
}

function reassembleFragments(fragments) {
    return Buffer.concat(fragments);
}

// 配置管理
function loadConfig() {
    try {
        const config = JSON.parse(fs.readFileSync(configFilePath, 'utf8'));
        return config;
    } catch (err) {
        console.error('Error loading configuration:', err);
        return null;
    }
}

function updateConfig(newConfig) {
    try {
        fs.writeFileSync(configFilePath, JSON.stringify(newConfig, null, 2));
    } catch (err) {
        console.error('Error updating configuration:', err);
    }
}

// 日志记录
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'combined.log' }),
        new winston.transports.Console()
    ]
});

// 错误处理
function handleError(err) {
    logger.error('An error occurred:', err.message);
    console.error('An error occurred:', err.message);
}

// 安全性与隐私
function signMessage(message, key) {
    const signature = sodium.crypto_sign_detached(message, key.privateKey);
    return { message, signature };
}

function verifySignature(message, signature, key) {
    return sodium.crypto_sign_verify_detached(signature, message, key.publicKey);
}

// 性能优化
class PacketTransform extends Transform {
    constructor(options) {
        super(options);
        this.buffer = Buffer.alloc(0);
    }

    _transform(chunk, encoding, callback) {
        this.buffer = Buffer.concat([this.buffer, chunk]);
        if (this.buffer.length >= 1500) {  // 假设最大数据包大小为1500字节
            this.push(this.buffer.slice(0, 1500));
            this.buffer = this.buffer.slice(1500);
        }
        callback();
    }

    _flush(callback) {
        if (this.buffer.length > 0) {
            this.push(this.buffer);
        }
        callback();
    }
}

// 管理工具
function executeCommand(command, callback) {
    exec(command, (error, stdout, stderr) => {
        if (error) {
            logger.error('Command execution error:', error);
            return callback(error);
        }
        callback(null, stdout);
    });
}

// 网络接口管理
function createTUNInterface() {
    return new Promise((resolve, reject) => {
        TUN.create({ name: 'tun0' }, (err, tun) => {
            if (err) {
                return reject(err);
            }
            resolve(tun);
        });
    });
}

function configureNetworkInterface() {
    // 配置网络接口的 IP 和路由
    exec('ip addr add 10.0.0.1/24 dev tun0', (err) => {
        if (err) {
            console.error('Error configuring TUN interface:', err);
        } else {
            console.log('TUN interface configured');
        }
    });
}

async function setupNetwork() {
    try {
        const tun = await createTUNInterface();
        console.log('TUN interface created:', tun);
        configureNetworkInterface();
    } catch (err) {
        console.error('Error setting up network:', err);
    }
}

// UDP 服务器处理
function handleUDPServer(sharedKeys, server) {
    server.on('message', (msg, rinfo) => {
        const nonce = msg.slice(0, sodium.crypto_secretbox_NONCEBYTES);
        const ciphertext = msg.slice(sodium.crypto_secretbox_NONCEBYTES);
        const decryptedMessage = decryptMessage(ciphertext, nonce, sharedKeys.sharedRx);

        const packet = parsePacket(Buffer.from(decryptedMessage));
        const route = routingTable[packet.destination.address];

        if (route && route.destination.protocol === 'udp') {
            console.log(`Forwarding UDP packet to ${route.destination.address}:${route.destination.port}`);
            server.send(encryptMessage(packet.data, route.sharedKeys.sharedTx).ciphertext, route.destination.port, route.destination.address);
        }
    });
}

// TCP 服务器处理
function handleTCPServer(sharedKeys, server) {
    server.on('connection', (socket) => {
        socket.on('data', (data) => {
            const nonce = data.slice(0, sodium.crypto_secretbox_NONCEBYTES);
            const ciphertext = data.slice(sodium.crypto_secretbox_NONCEBYTES);
            const decryptedMessage = decryptMessage(ciphertext, nonce, sharedKeys.sharedRx);

            const packet = parsePacket(Buffer.from(decryptedMessage));
            const route = routingTable[packet.destination.address];

            if (route && route.destination.protocol === 'tcp') {
                console.log(`Forwarding TCP packet to ${route.destination.address}:${route.destination.port}`);
                const client = new net.Socket();
                client.connect(route.destination.port, route.destination.address, () => {
                    client.write(encryptMessage(packet.data, route.sharedKeys.sharedTx).ciphertext);
                });
            }
        });
    });
}

// 启动 UDP 服务器
function startUDPServer(sharedKeys) {
    const server = dgram.createSocket('udp4');
    handleUDPServer(sharedKeys, server);
    server.bind(12345, () => {
        console.log('UDP Server is listening on port 12345.');
    });
}

// 启动 TCP 服务器
function startTCPServer(sharedKeys) {
    const server = net.createServer();
    handleTCPServer(sharedKeys, server);
    server.listen(12346, () => {
        console.log('TCP Server is listening on port 12346.');
    });
}

// UDP 客户端
function startUDPClient(sharedKeys) {
    const client = dgram.createSocket('udp4');
    const message = "Hello from UDP client!";
    const destination = { address: "10.0.0.1", port: 23456, protocol: 'udp' };

    const encapsulatedMessage = createPacket(message, destination);
    const { ciphertext, nonce } = encryptMessage(encapsulatedMessage, sharedKeys.sharedTx);
    const messageToSend = Buffer.concat([nonce, ciphertext]);

    client.send(messageToSend, 12345, 'localhost', () => {
        console.log('UDP Client sent encrypted message.');
    });

    client.on('message', (msg) => {
        const nonce = msg.slice(0, sodium.crypto_secretbox_NONCEBYTES);
        const ciphertext = msg.slice(sodium.crypto_secretbox_NONCEBYTES);
        const decryptedMessage = decryptMessage(ciphertext, nonce, sharedKeys.sharedRx);
        console.log('UDP Client received:', decryptedMessage.toString());
    });
}

// TCP 客户端
function startTCPClient(sharedKeys) {
    const client = new net.Socket();
    const message = "Hello from TCP client!";
    const destination = { address: "10.0.0.1", port: 23457, protocol: 'tcp' };

    const encapsulatedMessage = createPacket(message, destination);
    const { ciphertext, nonce } = encryptMessage(encapsulatedMessage, sharedKeys.sharedTx);
    const messageToSend = Buffer.concat([nonce, ciphertext]);

    client.connect(12346, 'localhost', () => {
        console.log('TCP Client connected to server.');
        client.write(messageToSend);
    });

    client.on('data', (data) => {
        const nonce = data.slice(0, sodium.crypto_secretbox_NONCEBYTES);
        const ciphertext = data.slice(sodium.crypto_secretbox_NONCEBYTES);
        const decryptedMessage = decryptMessage(ciphertext, nonce, sharedKeys.sharedRx);
        console.log('TCP Client received:', decryptedMessage.toString());
        client.destroy();
    });
}

// 主函数
async function main() {
    try {
        const keys = await initializeCrypto();
        keyStore.setKey(keys.clientKeys);

        // 网络设置
        await setupNetwork();

        // 启动服务器
        startUDPServer(keys);
        startTCPServer(keys);

        // 启动客户端
        startUDPClient(keys);
        startTCPClient(keys);
    } catch (err) {
        handleError(err);
    }
}

main();
