const fs = require('fs');
const sodium = require('libsodium-wrappers');
const dgram = require('dgram');
const { execSync } = require('child_process');
const os = require('os');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');

// 初始化libsodium
async function initializeCrypto() {
    await sodium.ready;
    console.log('Crypto initialized');
}

// 生成密钥对（Curve25519）
function generateKeyPair() {
    return sodium.crypto_kx_keypair();
}

// 恒定时间的密钥比较
function secureCompare(a, b) {
    return sodium.memcmp(a, b);
}

// 使用恒定时间的加密函数
function secureEncrypt(message, key) {
    const nonce = sodium.randombytes_buf(sodium.crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
    const ciphertext = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(message, null, null, nonce, key);
    return { ciphertext, nonce };
}

function secureDecrypt(ciphertext, nonce, key) {
    try {
        const message = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(null, ciphertext, null, nonce, key);
        return message;
    } catch (error) {
        console.error('Decryption failed:', error);
        throw new Error('Decryption failed');
    }
}

// 初始化滑动窗口，防止重放攻击
const replayWindow = {};

function initializeReplayWindow(sessionId) {
    replayWindow[sessionId] = {
        maxSeq: 0,
        window: 0
    };
}

function updateReplayWindow(sessionId, sequenceNumber) {
    const { maxSeq, window } = replayWindow[sessionId];
    
    if (sequenceNumber > maxSeq) {
        const shift = sequenceNumber - maxSeq;
        replayWindow[sessionId].window = (window << shift) | 1;
        replayWindow[sessionId].maxSeq = sequenceNumber;
    } else {
        const offset = maxSeq - sequenceNumber;
        replayWindow[sessionId].window |= (1 << offset);
    }
}

function isReplayAttack(sessionId, sequenceNumber) {
    const { maxSeq, window } = replayWindow[sessionId];
    
    if (sequenceNumber <= maxSeq) {
        const offset = maxSeq - sequenceNumber;
        if ((window & (1 << offset)) !== 0) {
            return true; // 检测到重放攻击
        }
    }
    return false;
}

// 处理配置文件
function loadConfig(configPath) {
    return JSON.parse(fs.readFileSync(configPath, 'utf8'));
}

// 解析WireGuard数据包
function parseDataPacket(packet) {
    const type = packet.readUInt8(0);
    const sessionId = packet.slice(1, 9).toString('hex');
    const sequenceNumber = packet.readUInt32BE(9);
    const payload = packet.slice(13);
    return { type, sessionId, sequenceNumber, payload };
}

// 验证数据包
function verifyPacket(packet, key) {
    const { type, sessionId, sequenceNumber, payload } = parseDataPacket(packet);

    if (isReplayAttack(sessionId, sequenceNumber)) {
        throw new Error('Replay attack detected');
    }

    const isValid = sodium.crypto_aead_chacha20poly1305_ietf_verify(payload, key);

    if (!isValid) {
        throw new Error('Packet verification failed');
    }

    updateReplayWindow(sessionId, sequenceNumber);

    return payload;
}

// 创建WireGuard数据包
function createWireGuardPacket(type, sessionId, message, key) {
    const sequenceNumber = sodium.randombytes_buf(4);
    const packet = Buffer.concat([Buffer.from([type]), Buffer.from(sessionId), sequenceNumber, message]);
    
    const { ciphertext, nonce } = secureEncrypt(packet, key);

    return Buffer.concat([nonce, ciphertext]);
}

// 清理密钥
function clearKey(key) {
    sodium.sodium_memzero(key);
}

// 安全存储密钥
function secureStoreKey(key) {
    const secureMemory = sodium.sodium_malloc(key.length);
    sodium.sodium_memcpy(secureMemory, key);
    return secureMemory;
}

// 密钥轮换
function rotateKeys() {
    serverStaticKeyPair = generateKeyPair();
    console.log('Keys rotated');
}

// 更新服务器配置
let serverConfig = loadConfig('config.json');
let serverStaticKeyPair = generateKeyPair();

function updateServerConfig(newConfig) {
    serverConfig = { ...serverConfig, ...newConfig };
    if (newConfig.publicKey || newConfig.privateKey) {
        serverStaticKeyPair = generateKeyPair();
    }
    console.log('Server configuration updated');
}

// 处理TUN接口创建
function createTunInterface(interfaceName) {
    if (os.platform() !== 'linux') {
        throw new Error('This implementation currently supports only Linux platform.');
    }

    try {
        execSync(`ip tuntap add dev ${interfaceName} mode tun`);
        execSync(`ip addr add 10.0.0.1/24 dev ${interfaceName}`);
        execSync(`ip link set dev ${interfaceName} up`);
        console.log(`TUN interface ${interfaceName} created successfully.`);
    } catch (error) {
        console.error(`Failed to create TUN interface: ${error.message}`);
        throw error;
    }
}

// 启动服务线程
if (isMainThread) {
    const server = dgram.createSocket('udp4');

    server.on('message', (msg, rinfo) => {
        const worker = new Worker(__filename, {
            workerData: {
                msg: msg,
                rinfo: rinfo,
                key: serverStaticKeyPair.privateKey
            }
        });

        worker.on('message', (result) => {
            console.log(`Processed message from ${rinfo.address}:${rinfo.port}`);
        });

        worker.on('error', (error) => {
            console.error(`Worker error: ${error.message}`);
        });
    });

    server.on('error', (err) => {
        console.error(`Server error:\n${err.stack}`);
        server.close();
    });

    server.bind(51820, () => {
        console.log('Server is listening on port 51820');
    });

    // 轮换密钥，每24小时
    setInterval(rotateKeys, 24 * 60 * 60 * 1000);

    // 创建TUN接口
    createTunInterface('wg0');

} else {
    // Worker 线程处理加密和解密任务
    const { msg, rinfo, key } = workerData;
    try {
        const decryptedMessage = verifyPacket(msg, key);
        // 处理解密后的消息...
        parentPort.postMessage('done');
    } catch (error) {
        console.error(`Failed to process message: ${error.message}`);
    }
}
