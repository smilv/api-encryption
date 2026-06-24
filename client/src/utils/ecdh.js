/**
 * ECDHE 握手模块(前端)。
 * 使用浏览器原生 Web Crypto API 做 ECDH(P-256)与 HKDF,node-forge 做 RSA 验签。
 * 算法与后端 server/src/utils/crypto.js 逐字节对齐:
 *   - 曲线 P-256;公钥 raw 格式 = 未压缩点 65 字节(与 Node getPublicKey() 一致)
 *   - HKDF-SHA256,salt/info 与后端常量一致
 *
 * 信任锚:RSA 公钥**内置在前端**(client/src/keys.json,构建期注入),
 * 不从服务端接口获取。握手响应用内置公钥逐一验签,任一通过即可(支持轮换多公钥并存)。
 *
 * 流程:generateKey → 导出 clientPub → POST /api/handshake →
 *       内置公钥逐一 RSA 验签 → deriveBits(ECDH) → HKDF 派生 → { sessionId, aesKeyBytes }
 */
import { rsaVerify } from './crypto';

const HKDF_SALT = 'api-encryption-demo-salt';
const HKDF_INFO = 'aes-256-session-key';
const subtle = globalThis.crypto.subtle;

// ---- ArrayBuffer / base64 / forge-bytes 互转 ----
function bufToB64(buf) {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
function b64ToBytes(b64) {
  const s = atob(b64);
  const arr = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) arr[i] = s.charCodeAt(i);
  return arr;
}
function bytesToForgeBinary(uint8) {
  let s = '';
  for (let i = 0; i < uint8.length; i++) s += String.fromCharCode(uint8[i]);
  return s; // latin1 binary string = forge 内部 bytes 表示
}
function utf8ToBytes(str) {
  return new TextEncoder().encode(str);
}

/**
 * 完成一次 ECDHE 握手。
 * @param {object} http axios 实例
 * @param {string[]} trustedPublicKeys 内置的可信 RSA 公钥 PEM 数组(支持轮换多公钥并存)
 * @returns {Promise<{sessionId:string, aesKeyBytes:string}>} aesKeyBytes 为 forge binary string
 */
export async function performHandshake(http, trustedPublicKeys) {
  // 1. 生成 ECDH 密钥对(P-256)
  const keyPair = await subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );

  // 2. 导出 client 公钥(raw = 未压缩点 65 字节,与 Node getPublicKey() 一致)
  const clientPubBuf = await subtle.exportKey('raw', keyPair.publicKey);
  const clientPubB64 = bufToB64(clientPubBuf);

  // 3. 请求握手
  const res = await http.post('/api/handshake', { clientPub: clientPubB64 });
  const { sessionId, serverPub, sign } = res.data;

  // 4. RSA 验签(防中间人):用内置公钥逐一验,任一通过即可
  const signStr = [sessionId, serverPub, clientPubB64].join('\n');
  const verified = trustedPublicKeys.some((pem) => rsaVerify(signStr, sign, pem));
  if (!verified) {
    throw new Error('握手响应签名验证失败(可能遭遇中间人,或内置公钥已过期/需轮换)');
  }

  // 5. ECDH deriveBits 得到共享密钥
  const serverKey = await subtle.importKey(
    'raw',
    b64ToBytes(serverPub),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );
  const sharedBits = await subtle.deriveBits(
    { name: 'ECDH', public: serverKey },
    keyPair.privateKey,
    256
  );

  // 6. HKDF 派生 32B 会话密钥(与后端 hkdfSync 参数对齐)
  const ikmKey = await subtle.importKey('raw', new Uint8Array(sharedBits), 'HKDF', false, ['deriveBits']);
  const aesBits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: utf8ToBytes(HKDF_SALT), info: utf8ToBytes(HKDF_INFO) },
    ikmKey,
    256
  );

  const aesKeyBytes = bytesToForgeBinary(new Uint8Array(aesBits));
  return { sessionId, aesKeyBytes };
}
