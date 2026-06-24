/**
 * ECDH 密钥协商最小演示(完整闭环)。
 * 核心思想:双方从不发送共享密钥,却能各自算出同一把,再用它对称加密报文。
 * 运行: node scripts/ecdh-demo.js
 */
'use strict';

const crypto = require('crypto');

const CURVE = 'prime256v1'; // = secp256r1 / NIST P-256;更现代可用 'X25519'

console.log('===== 1. 双方各生成临时 ECDH 密钥对 =====');
const alice = crypto.createECDH(CURVE);
alice.generateKeys();
const alicePub = alice.getPublicKey(); // Alice 公开值,将发给 Bob

const bob = crypto.createECDH(CURVE);
bob.generateKeys();
const bobPub = bob.getPublicKey(); // Bob 公开值,将发给 Alice

console.log('Alice 公钥:', alicePub.toString('hex').slice(0, 24), '...');
console.log('Bob   公钥:', bobPub.toString('hex').slice(0, 24), '...');

console.log('\n===== 2. 各自用「对方公钥 + 自己私钥」算共享密钥 =====');
const sharedAlice = alice.computeSecret(bobPub);
const sharedBob = bob.computeSecret(alicePub);
console.log('双方算出的共享密钥相同?', sharedAlice.equals(sharedBob));
console.log('共享密钥(从未上过网络):', sharedAlice.toString('hex'));

console.log('\n===== 3. HKDF 派生 AES 密钥(原始共享密钥不可直接用)=====');
const aesKey = Buffer.from(
  crypto.hkdfSync('sha256', sharedAlice, 'demo-salt', 'aes-256-key', 32)
);
console.log('派生 AES Key:', aesKey.toString('hex'));

console.log('\n===== 4. 用派生密钥做对称加密(AES-256-GCM 认证加密)=====');
const iv = crypto.randomBytes(12);
const plaintext = Buffer.from('这是机密报文 🔐 —— 前向安全', 'utf8');

const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
const authTag = cipher.getAuthTag();

// 模拟 Bob 用同一把派生密钥解密
const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
decipher.setAuthTag(authTag);
const recovered = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

console.log('密文(base64):', ciphertext.toString('base64').slice(0, 32), '...');
console.log('解密报文:', recovered.toString('utf8'));
console.log('往返一致?', recovered.equals(plaintext));
