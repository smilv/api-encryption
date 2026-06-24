/**
 * 密码学工具(服务端)。
 *
 * 密钥协商采用 ECDHE:每次会话通过 ECDH(P-256)协商共享密钥,
 * HKDF 派生为 AES 会话密钥;RSA 仅用于对握手响应签名(防中间人),不再做密钥传输。
 *
 * ===== 算法约定(前端 client/src/utils/crypto.js 必须逐字节对齐)=====
 *  - 数据加密: AES-256-GCM(AEAD,加密与完整性认证合一,无需独立 HMAC)
 *  - 密钥协商: ECDH(P-256) + HKDF-SHA256
 *  - 身份认证: RSA 签名(PKCS#1 v1.5 + SHA-256,仅用于握手)
 *  - 防篡改:   GCM 认证标签 tag;请求方向把 sessionId/timestamp/nonce 作为 AAD 一并认证
 *
 * ===== 认证数据(AAD)拼接顺序(不可更改,否则 tag 验不过)=====
 *  请求方向:    sessionId \n timestamp \n nonce   —— 作为 GCM 的 AAD
 *  响应方向:    (无 AAD)
 *  握手响应:    sessionId \n serverPub \n clientPub(RSA 签名)
 */
'use strict';

const crypto = require('crypto');
const config = require('../config');

const AES_ALGO = 'aes-256-gcm';
const AES_KEY_LEN = 32;
const IV_LEN = 12; // GCM 标准 nonce(96 位),性能与安全性最佳
const TAG_LEN = 16; // GCM 认证标签(128 位)

const CURVE = 'prime256v1'; // = NIST P-256;浏览器 Web Crypto 用 'P-256' 指同一曲线
const HKDF_SALT = 'api-encryption-demo-salt';
const HKDF_INFO = 'aes-256-session-key';

// ---------- 随机数 ----------
function randomBytes(n) {
  return crypto.randomBytes(n);
}

/** 生成随机 nonce(16 字节 hex,共 32 字符) */
function generateNonce() {
  return randomBytes(16).toString('hex');
}

// ---------- AES-GCM(AEAD)----------
/**
 * 加密:返回 { cipher, tag }。
 * aadBuffer 为额外认证数据(可选):不保密,但被 tag 完整性保护,篡改即解密失败。
 */
function aesEncrypt(plainBuffer, keyBuffer, ivBuffer, aadBuffer) {
  const cipher = crypto.createCipheriv(AES_ALGO, keyBuffer, ivBuffer);
  if (aadBuffer && aadBuffer.length) cipher.setAAD(aadBuffer);
  const cipherBuffer = Buffer.concat([cipher.update(plainBuffer), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { cipher: cipherBuffer, tag };
}

/**
 * 解密:setAuthTag 后 final() 会校验密文 + AAD 完整性,任一字节被篡改即抛错。
 * 因此本函数同时承担"解密 + 防篡改"职责(替代旧的 CBC + 独立 HMAC 方案)。
 */
function aesDecrypt(cipherBuffer, keyBuffer, ivBuffer, tagBuffer, aadBuffer) {
  const decipher = crypto.createDecipheriv(AES_ALGO, keyBuffer, ivBuffer);
  if (aadBuffer && aadBuffer.length) decipher.setAAD(aadBuffer);
  decipher.setAuthTag(tagBuffer);
  return Buffer.concat([decipher.update(cipherBuffer), decipher.final()]);
}

// ---------- ECDH 密钥协商 ----------
/** 生成临时 ECDH 密钥对,返回 { dh, publicKeyB64 }(dh 用于后续 computeSecret) */
function generateEcdhKeyPair() {
  const dh = crypto.createECDH(CURVE);
  dh.generateKeys();
  return { dh, publicKeyB64: dh.getPublicKey().toString('base64') };
}

/** 从 ECDH 共享密钥派生 32B 会话 AES Key(HKDF-SHA256,与前端 Web Crypto HKDF 逐字节对齐) */
function deriveSessionKey(sharedSecretBuffer) {
  return Buffer.from(crypto.hkdfSync('sha256', sharedSecretBuffer, HKDF_SALT, HKDF_INFO, 32));
}

// ---------- RSA 签名(仅用于握手认证)----------
/** RSA 私钥签名(PKCS#1 v1.5 + SHA-256),输出 base64 */
function rsaSign(data) {
  const s = crypto.createSign('sha256');
  s.update(data, 'utf8');
  return s.sign(config.rsaPrivateKey, 'base64');
}

// ---------- AAD / 签名串构造 ----------
/**
 * 请求方向 GCM 的 AAD:把防重放元数据(sessionId/timestamp/nonce)一并认证。
 * 等价于旧方案里 HMAC 对这些字段的绑定 —— 篡改任一字段都会让 tag 校验失败。
 */
function buildRequestAad({ sessionId, timestamp, nonce }) {
  return Buffer.from([sessionId, String(timestamp), nonce].join('\n'), 'utf8');
}

function buildHandshakeSignString({ sessionId, serverPub, clientPub }) {
  return [sessionId, serverPub, clientPub].join('\n');
}
function signHandshake(fields) {
  return rsaSign(buildHandshakeSignString(fields));
}

module.exports = {
  AES_ALGO,
  AES_KEY_LEN,
  IV_LEN,
  TAG_LEN,
  CURVE,
  HKDF_SALT,
  HKDF_INFO,
  randomBytes,
  generateNonce,
  aesEncrypt,
  aesDecrypt,
  generateEcdhKeyPair,
  deriveSessionKey,
  rsaSign,
  buildRequestAad,
  buildHandshakeSignString,
  signHandshake,
};
