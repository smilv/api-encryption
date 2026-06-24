/**
 * 密码学工具(前端)。
 *
 * ⚠️ 算法必须与服务端 server/src/utils/crypto.js 逐字节对齐:
 *   - 数据加密: AES-256-GCM(AEAD,加密与完整性认证合一,forge AES-GCM)
 *   - 密钥协商: ECDH(P-256) + HKDF(在 ecdh.js 用 Web Crypto 完成)
 *   - 身份认证: RSA 验签(握手响应)
 *   - 防篡改:   GCM 认证标签 tag;请求方向把 sessionId/timestamp/nonce 作为 AAD 一并认证
 *
 * 认证数据(AAD)拼接顺序(不可更改):
 *   请求: sessionId \ timestamp \ nonce   —— 作为 GCM 的 AAD
 *   响应: (无 AAD)
 */
import forge from 'node-forge';

// ---------- 随机数 ----------
function randomBytes(n) {
  return forge.random.getBytesSync(n);
}
function generateNonce() {
  return forge.util.bytesToHex(randomBytes(16));
}

// ---------- AES-256-GCM ----------
/**
 * 加密:返回 { encryptedData, tagB64 }。
 * additionalData(aad,forge bytes)被 tag 完整性保护,与后端 Buffer AAD 逐字节一致。
 */
function aesGcmEncryptB64(plainStr, keyBytes, ivBytes, aadBytes) {
  const cipher = forge.cipher.createCipher('AES-GCM', keyBytes);
  cipher.start({ iv: ivBytes, additionalData: aadBytes });
  cipher.update(forge.util.createBuffer(forge.util.encodeUtf8(plainStr)));
  cipher.finish();
  const ciphertext = cipher.output.getBytes();
  const tag = cipher.mode.tag.getBytes(); // 16B 认证标签
  return { encryptedData: forge.util.encode64(ciphertext), tagB64: forge.util.encode64(tag) };
}

/**
 * 解密:tag 通过 start() 传入,finish() 返回 false 即完整性校验失败(数据被篡改)。
 */
function aesGcmDecryptB64(cipherB64, keyBytes, ivBytes, tagBytes, aadBytes) {
  const decipher = forge.cipher.createDecipher('AES-GCM', keyBytes);
  decipher.start({ iv: ivBytes, additionalData: aadBytes, tag: tagBytes });
  decipher.update(forge.util.createBuffer(forge.util.decode64(cipherB64)));
  const ok = decipher.finish();
  if (!ok) throw new Error('GCM 认证失败(数据可能被篡改)');
  return forge.util.decodeUtf8(decipher.output.getBytes());
}

// ---------- 请求方向 AAD ----------
/** 与后端 buildRequestAad 对齐:utf8 编码的 "sessionId\timestamp\nonce" */
function buildRequestAadBytes({ sessionId, timestamp, nonce }) {
  return forge.util.encodeUtf8([sessionId, String(timestamp), nonce].join('\n'));
}

// ---------- 请求加密(GCM:用会话密钥)----------
/**
 * @param {object} plainBody 明文业务数据
 * @param {{sessionId:string, aesKeyBytes:string}} ctx
 * @returns {{sessionId,timestamp,nonce,iv,encryptedData,tag,_keyBytes}}
 */
export function encryptRequestEcdhe(plainBody, ctx) {
  const plain = JSON.stringify(plainBody);
  const ivBytes = randomBytes(12); // GCM nonce = 12B
  const timestamp = String(Date.now());
  const nonce = generateNonce();
  const aad = buildRequestAadBytes({ sessionId: ctx.sessionId, timestamp, nonce });
  const { encryptedData, tagB64 } = aesGcmEncryptB64(plain, ctx.aesKeyBytes, ivBytes, aad);
  const iv = forge.util.encode64(ivBytes);
  return { sessionId: ctx.sessionId, timestamp, nonce, iv, encryptedData, tag: tagB64, _keyBytes: ctx.aesKeyBytes };
}

// ---------- 响应解密 + 完整性校验 ----------
/**
 * @param {{encryptedData:string, iv:string, tag:string}} payload
 * @param {string} keyBytes 会话 AES key(forge binary string)
 * @returns {object} 解密后的明文对象
 */
export function decryptResponse(payload, keyBytes) {
  if (!payload || !payload.encryptedData) {
    throw new Error('响应不是加密格式');
  }
  const ivBytes = forge.util.decode64(payload.iv);
  const tagBytes = forge.util.decode64(payload.tag);
  // 响应方向无 AAD
  return JSON.parse(aesGcmDecryptB64(payload.encryptedData, keyBytes, ivBytes, tagBytes, ''));
}

// ---------- RSA 验签(握手响应,防中间人)----------
/** 与后端 crypto.createSign('sha256') 对齐:先 SHA-256 摘要,再 PKCS#1 v1.5 验证 */
export function rsaVerify(message, signB64, publicKeyPem) {
  const pub = forge.pki.publicKeyFromPem(publicKeyPem);
  const md = forge.md.sha256.create();
  md.update(message, 'utf8');
  return pub.verify(md.digest().getBytes(), forge.util.decode64(signB64));
}

export { forge };
