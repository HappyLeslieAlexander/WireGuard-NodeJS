const dgram = require('dgram');
const net = require('net');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const sodium = require('libsodium-wrappers');
const noise = require('noise-protocol');
const TUN = require('node-tun');
const winston = require('winston');

// 配置日志
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'server.log' }),
        new winston.transports.Console()
    ]
});

// 加载密钥对
function saveKeyPair(keyPair, filename) {
    const filepath = path.join(os.homedir(), filename);
    fs.writeFileSync(filepath, JSON.stringify(keyPair));
    fs.chmodSync(filepath, 0o600); // 仅允许拥有者访问
}

function loadKeyPair(filename) {
    const filepath = path.join(os.homedir(), filename);
    if (fs.existsSync(filepath)) {
        const keyPairData = fs.readFileSync(filepath, 'utf8');
        return JSON.parse(keyPairData);
    }
    return null;
}

// 初始化密钥交换和加密
async function initializeHandshake() {
    await sodium.ready;

    // 生成服务端静态密钥对
    const serverStaticKeyPair = loadKeyPair('server_keys.json') || noise.generateKeypair(sodium.crypto_box_keypair());
    saveKeyPair(serverStaticKeyPair, 'server_keys.json');

    // 生成临时密钥对（用于Noise协议）
    const ephemeralKeyPair = noise.generateKeypair(sodium.crypto_box_keypair());

    return { serverStaticKeyPair, ephemeralKeyPair };
}

function startHandshake(clientPublicKey, serverStaticKeyPair, ephemeralKeyPair) {
    const noiseState = noise.initialize('Noise_IK_25519_ChaChaPoly_SHA256', true, serverStaticKeyPair, clientPublicKey);
    const handshakeMessage = noise.writeMessage(noiseState, null, ephemeralKeyPair.publicKey);
    return { noiseState, handshakeMessage };
}

function completeHandshake(noiseState, clientMessage) {
    const { payload, noiseState: newState } = noise.readMessage(noiseState, clientMessage);
    const { sharedSecret } = noise.finalize(newState);
    return sharedSecret;
}

// 创建和配置 TUN 接口
async function createTUNInterface() {
    return new Promise((resolve, reject) => {
        TUN.create({ name: 'tun0' }, (err, tun) => {
            if (err) {
                return reject(err);
            }
            resolve(tun);
        });
    });
}

async function configureNetworkInterface() {
    try {
        await executeCommand('ip addr add 10.0.0.1/24 dev tun0');
        await executeCommand('ip link set dev tun0 up');
        logger.info('TUN interface configured');
    } catch (err) {
        logger.error('Error configuring TUN interface:', err);
    }
}

function executeCommand(command) {
    return new Promise((resolve, reject) => {
        exec(command, (error, stdout, stderr) => {
            if (error) {
                logger.error('Command execution error:', error);
                return reject(error);
            }
            resolve(stdout);
        });
    });
}

async function setupNetwork() {
    try {
        const tun = await createTUNInterface();
        logger.info('TUN interface created:', tun);
        await configureNetworkInterface();
    } catch (err) {
        logger.error('Error setting up network:', err);
    }
}

// 加密与解密
function secureEncrypt(message, key) {
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
    const ciphertext = sodium.crypto_aead_chacha20poly1305_encrypt(message, null, nonce, key);
    return { ciphertext, nonce };
}

function secureDecrypt(ciphertext, nonce, key) {
    return sodium.crypto_aead_chacha20poly1305_decrypt(ciphertext, null, nonce, key);
}

// 数据包处理与防重放攻击
const lastReceivedSequence = {};

function createDataPacket(type, sessionId, message, nonce, key) {
    const packet = Buffer.alloc(16 + message.length);
    packet.writeUInt32BE(type, 0);
    packet.writeUInt32BE(sessionId, 4);
    nonce.copy(packet, 8, 0, nonce.length);
    const encryptedMessage = secureEncrypt(message, key);
    encryptedMessage.ciphertext.copy(packet, 16);
    return packet;
}

function parseDataPacket(packet, key) {
    const type = packet.readUInt32BE(0);
    const sessionId = packet.readUInt32BE(4);
    const nonce = packet.slice(8, 16);
    const encryptedMessage = packet.slice(16);

    const message = secureDecrypt(encryptedMessage, nonce, key);

    return { type, sessionId, message };
}

function isReplayAttack(packet, sessionId) {
    const { sequenceNumber } = parseDataPacket(packet, sessionId);
    if (sequenceNumber <= lastReceivedSequence[sessionId]) {
        return true;
    }
    lastReceivedSequence[sessionId] = sequenceNumber;
    return false;
}

function handlePacket(data, key) {
    try {
        const { type, sessionId, message } = parseDataPacket(data, key);

        if (!isReplayAttack(data, sessionId)) {
            logger.info('Received valid packet:', message.toString());
            // 处理消息
        } else {
            logger.warn('Duplicate packet detected');
        }
    } catch (err) {
        logger.error('Error processing packet:', err);
    }
}

// 动态配置更新
let config = {};

function loadConfig(filePath) {
    try {
        const data = fs.readFileSync(filePath, 'utf8');
        config = JSON.parse(data);
        logger.info('Config loaded:', config);
    } catch (error) {
        logger.error('Failed to load config:', error);
    }
}

function updateConfig(newConfig) {
    config = { ...config, ...newConfig };
    logger.info('Config updated:', config);
}

fs.watch('config.json', (eventType, filename) => {
    if (eventType === 'change') {
        loadConfig(filename);
    }
});

// UDP 服务器
function startUDPServer(sharedKey) {
    const server = dgram.createSocket('udp4');
    server.on('message', (msg) => {
        handlePacket(msg, sharedKey);
    });

    server.bind(12345, () => {
        logger.info('UDP Server listening on port 12345');
    });
}

// TCP 服务器
function startTCPServer(sharedKey) {
    const server = net.createServer((socket) => {
        socket.on('data', (data) => {
            handlePacket(data, sharedKey);
        });

        socket.on('error', (err) => {
            logger.error('TCP Server error:', err);
        });
    });

    server.listen(12346, () => {
        logger.info('TCP Server listening on port 12346');
    });
}

// 主函数
async function main() {
    try {
        // 初始化安全握手
        const { serverStaticKeyPair, ephemeralKeyPair } = await initializeHandshake();

        // 设置网络和接口
        await setupNetwork();

        // 加载和更新配置
        loadConfig('config.json');

        // 启动服务器
        const clientPublicKey = config.clientPublicKey; // 假设配置中包含客户端公钥
        const { noiseState, handshakeMessage } = startHandshake(clientPublicKey, serverStaticKeyPair, ephemeralKeyPair);
        const sharedKey = completeHandshake(noiseState, handshakeMessage);

        startUDPServer(sharedKey);
        startTCPServer(sharedKey);

    } catch (err) {
        logger.error('Initialization error:', err);
    }
}

main();
