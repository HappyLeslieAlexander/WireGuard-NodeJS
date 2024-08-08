const dgram = require('dgram');
const net = require('net');
const { exec } = require('child_process');
const TUN = require('node-tun');
const sodium = require('libsodium-wrappers');
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

// 密钥初始化
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

// 加密与解密
function encryptMessage(message, key) {
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
    const ciphertext = sodium.crypto_secretbox_easy(message, nonce, key);
    return { ciphertext, nonce };
}

function decryptMessage(ciphertext, nonce, key) {
    return sodium.crypto_secretbox_open_easy(ciphertext, nonce, key);
}

// 防重放机制
const packetSequence = new Map(); // 防重放机制

function isDuplicatePacket(sequenceNumber, destination) {
    const key = `${sequenceNumber}:${destination}`;
    if (packetSequence.has(key)) {
        return true;
    }
    packetSequence.set(key, Date.now());
    return false;
}

function handlePacket(data, key) {
    try {
        const nonce = data.slice(0, sodium.crypto_secretbox_NONCEBYTES);
        const ciphertext = data.slice(sodium.crypto_secretbox_NONCEBYTES);
        const decryptedMessage = decryptMessage(ciphertext, nonce, key);

        const { sequenceNumber, ...message } = JSON.parse(decryptedMessage.toString());

        if (!isDuplicatePacket(sequenceNumber, message.destination)) {
            logger.info('Received valid packet:', message);
        } else {
            logger.info('Duplicate packet detected');
        }
    } catch (err) {
        logger.error('Error processing packet:', err);
    }
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

// UDP 服务器
function startUDPServer(keys) {
    const server = dgram.createSocket('udp4');
    server.on('message', (msg) => {
        handlePacket(msg, keys.sharedB.sharedRx);
    });

    server.bind(12345, () => {
        logger.info('UDP Server listening on port 12345');
    });
}

// TCP 服务器
function startTCPServer(keys) {
    const server = net.createServer((socket) => {
        socket.on('data', (data) => {
            handlePacket(data, keys.sharedB.sharedRx);
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
        const keys = await initializeCrypto();
        await setupNetwork();

        startUDPServer(keys);
        startTCPServer(keys);
    } catch (err) {
        logger.error('Initialization error:', err);
    }
}

main();
