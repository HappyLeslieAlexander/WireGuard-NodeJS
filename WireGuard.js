const fs = require('fs');
const sodium = require('libsodium-wrappers');
const dgram = require('dgram');
const { execSync } = require('child_process');
const os = require('os');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');

// 初始化 libsodium
async function initializeCrypto() {
    await sodium.ready;
    console.log('Crypto initialized');
}

// 密钥对生成
function generateKeyPair() {
    return sodium.crypto_kx_keypair();
}

// 加密与解密函数
function noiseProtocolEncrypt(payload, key, nonce) {
    return sodium.crypto_aead_chacha20poly1305_ietf_encrypt(payload, null, null, nonce, key);
}

function noiseProtocolDecrypt(ciphertext, nonce, key) {
    try {
        return sodium.crypto_aead_chacha20poly1305_ietf_decrypt(null, ciphertext, null, nonce, key);
    } catch (e) {
        console.error('Decryption failed:', e);
        throw new Error('Decryption failed');
    }
}

// 滑动窗口防止重放攻击
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

// 配置文件处理
function loadConfig(configPath) {
    return JSON.parse(fs.readFileSync(configPath, 'utf8'));
}

function applyConfigChanges(newConfig) {
    Object.assign(serverConfig, newConfig);
    // Apply configuration changes dynamically
    console.log('Configuration updated:', serverConfig);
}

// 解析和验证数据包
function parseDataPacket(packet) {
    const type = packet.readUInt8(0);
    const sessionId = packet.slice(1, 9).toString('hex');
    const sequenceNumber = packet.readUInt32BE(9);
    const payload = packet.slice(13);
    return { type, sessionId, sequenceNumber, payload };
}

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

// 数据包创建
function createWireGuardPacket(type, sessionId, message, key) {
    const sequenceNumber = sodium.randombytes_buf(4);
    const packet = Buffer.concat([Buffer.from([type]), Buffer.from(sessionId), sequenceNumber, message]);
    
    const nonce = sodium.randombytes_buf(sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
    const ciphertext = noiseProtocolEncrypt(packet, key, nonce);

    return Buffer.concat([nonce, ciphertext]);
}

// 密钥管理
function clearKey(key) {
    sodium.sodium_memzero(key);
}

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

// TUN接口创建
function createTunInterface(interfaceName) {
    if (os.platform() !== 'linux') {
        throw new Error('This implementation currently supports only Linux platform.');
    }

    try {
        execSync(`ip tuntap add dev ${interfaceName} mode tun`);
        execSync(`ip addr add 10.0.0.1/24 dev ${interfaceName}`);
        execSync(`ip addr add fd00::1/64 dev ${interfaceName}`);
        execSync(`ip link set dev ${interfaceName} up`);
        console.log(`TUN interface ${interfaceName} created successfully.`);
    } catch (error) {
        console.error(`Failed to create TUN interface: ${error.message}`);
        throw error;
    }
}

// 路由配置
function configureRoutes() {
    execSync('sysctl -w net.ipv4.ip_forward=1');
    execSync('sysctl -w net.ipv6.conf.all.forwarding=1');
    execSync('iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE');
    execSync('ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE');
    execSync('iptables -A FORWARD -i wg0 -o eth0 -j ACCEPT');
    execSync('ip6tables -A FORWARD -i wg0 -o eth0 -j ACCEPT');
    execSync('iptables -A FORWARD -i eth0 -o wg0 -j ACCEPT');
    execSync('ip6tables -A FORWARD -i eth0 -o wg0 -j ACCEPT');
    console.log('Network routing configured');
}

// 启动服务
if (isMainThread) {
    initializeCrypto().then(() => {
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

        // 轮换密钥
        setInterval(rotateKeys, 24 * 60 * 60 * 1000);

        // 创建TUN接口
        createTunInterface('wg0');

        // 配置网络路由
        configureRoutes();

        // 配置动态更新
        fs.watchFile('config.json', (curr, prev) => {
            console.log('Configuration file changed');
            const newConfig = loadConfig('config.json');
            applyConfigChanges(newConfig);
        });
    });

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
