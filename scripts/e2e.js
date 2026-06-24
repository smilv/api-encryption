/**
 * ECDHE 模式端到端验证。
 * 用 Node 内置 Web Crypto(webcrypto,与浏览器 API 完全相同)模拟前端,
 * 对运行中的后端完成:握手(ECDH+HKDF+RSA 验签)→ 加密请求 → 防重放/防篡改/会话校验。
 * 运行: node scripts/e2e.js  (前置:后端已启动)
 *
 * 数据加密采用 AES-256-GCM(AEAD):完整性由 tag 内建校验,
 * 请求方向把 sessionId/timestamp/nonce 作为 AAD,与 client/utils/crypto.js 逐字节对齐。
 */
'use strict';

const https = require('https');
const { webcrypto } = require('crypto');
const forge = require('../client/node_modules/node-forge');

const subtle = webcrypto.subtle;
const HKDF_SALT = 'api-encryption-demo-salt';
const HKDF_INFO = 'aes-256-session-key';

let passed = 0;
let failed = 0;
const check = (n, c, extra) => {
  console.log((c ? '  ✅ ' : '  ❌ ') + n + (extra ? `  (${extra})` : ''));
  c ? passed++ : failed++;
};

function request(opts, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      { hostname: 'localhost', port: 3000, rejectUnauthorized: false, ...opts },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          let j = null;
          try { j = data ? JSON.parse(data) : null; } catch { j = data; }
          resolve({ status: res.statusCode, body: j });
        });
      }
    );
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}
const POST = (p, b) =>
  request({ path: p, method: 'POST', headers: { 'Content-Type': 'application/json' } }, b);

// ---- 字节转换 ----
const bufToB64 = (buf) => Buffer.from(buf).toString('base64');
const b64ToBuf = (b64) => Buffer.from(b64, 'base64');
const bytesToForge = (buf) => Buffer.from(buf).toString('binary');
const utf8 = (s) => Buffer.from(s, 'utf8');

// ---- forge AES-GCM(与 client/utils/crypto 对齐)----
function aesGcmEncryptB64(plainStr, keyForge, ivForge, aadForge) {
  const cipher = forge.cipher.createCipher('AES-GCM', keyForge);
  cipher.start({ iv: ivForge, additionalData: aadForge });
  cipher.update(forge.util.createBuffer(forge.util.encodeUtf8(plainStr)));
  cipher.finish();
  return {
    encryptedData: forge.util.encode64(cipher.output.getBytes()),
    tag: forge.util.encode64(cipher.mode.tag.getBytes()),
  };
}
function aesGcmDecryptB64(cipherB64, keyForge, ivForge, tagForge, aadForge) {
  const d = forge.cipher.createDecipher('AES-GCM', keyForge);
  d.start({ iv: ivForge, additionalData: aadForge, tag: tagForge });
  d.update(forge.util.createBuffer(forge.util.decode64(cipherB64)));
  const ok = d.finish();
  if (!ok) throw new Error('GCM auth fail');
  return forge.util.decodeUtf8(d.output.getBytes());
}

/** 请求方向 AAD:sessionId\ntimestamp\nnonce */
function buildRequestAadForge({ sessionId, timestamp, nonce }) {
  return forge.util.encodeUtf8([sessionId, timestamp, nonce].join('\n'));
}

async function handshake(publicKey) {
  const keyPair = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const clientPubBuf = await subtle.exportKey('raw', keyPair.publicKey);
  const clientPubB64 = bufToB64(clientPubBuf);

  const res = await POST('/api/handshake', { clientPub: clientPubB64 });
  const { sessionId, serverPub, sign } = res.body;

  // RSA 验签(防中间人)
  const signStr = [sessionId, serverPub, clientPubB64].join('\n');
  const pub = forge.pki.publicKeyFromPem(publicKey);
  const md = forge.md.sha256.create();
  md.update(signStr, 'utf8');
  const verifyOk = pub.verify(md.digest().getBytes(), forge.util.decode64(sign));

  // ECDH
  const serverKey = await subtle.importKey('raw', b64ToBuf(serverPub), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const sharedBits = await subtle.deriveBits({ name: 'ECDH', public: serverKey }, keyPair.privateKey, 256);

  // HKDF 派生
  const ikm = await subtle.importKey('raw', new Uint8Array(sharedBits), 'HKDF', false, ['deriveBits']);
  const aesBits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: utf8(HKDF_SALT), info: utf8(HKDF_INFO) },
    ikm,
    256
  );
  const aesKeyForge = bytesToForge(new Uint8Array(aesBits));
  return { sessionId, aesKeyForge, verifyOk, clientPubB64 };
}

function buildRequest(plainBody, { sessionId, aesKeyForge }, opts = {}) {
  const plain = JSON.stringify(plainBody);
  const ivForge = forge.random.getBytesSync(12); // GCM nonce = 12B
  const timestamp = opts.timestampOverride ?? String(Date.now());
  const nonce = opts.nonceOverride ?? forge.util.bytesToHex(forge.random.getBytesSync(16));
  const aad = buildRequestAadForge({ sessionId, timestamp, nonce });
  const { encryptedData, tag } = aesGcmEncryptB64(plain, aesKeyForge, ivForge, aad);
  const iv = forge.util.encode64(ivForge);
  return { payload: { sessionId, timestamp, nonce, iv, encryptedData, tag }, aesKeyForge };
}

const decryptResp = (payload, aesKeyForge) =>
  JSON.parse(
    aesGcmDecryptB64(
      payload.encryptedData,
      aesKeyForge,
      forge.util.decode64(payload.iv),
      forge.util.decode64(payload.tag),
      ''
    )
  );

(async () => {
  // 公钥内置在前端 client/src/keys.json,不再通过 /api/key 获取
  const publicKey = require('../client/src/keys.json').trustedPublicKeys[0];

  console.log('== ECDHE 握手 ==');
  const hs = await handshake(publicKey);
  check('握手响应 RSA 签名验证通过(防中间人)', hs.verifyOk);
  console.log('     sessionId:', hs.sessionId);

  console.log('\n== ECDHE 模式加密请求 ==');
  const a = buildRequest({ username: 'admin', password: '123456' }, hs);
  const r1 = await POST('/api/secure/login', a.payload);
  check('登录响应为加密结构', !!r1.body.encryptedData, `status=${r1.status}`);
  const p1 = decryptResp(r1.body, a.aesKeyForge);
  check('登录成功 (code=0)', p1.code === 0, `user=${p1.data?.user?.username}`);

  const r2 = await POST('/api/secure/login', a.payload);
  check('重放被拒 NONCE_REUSED', r2.status === 403 && r2.body?.code === 'NONCE_REUSED', `status=${r2.status}`);

  // 篡改 GCM tag:换新 nonce 绕过防重放,GCM 完整性校验失败 → AES_DECRYPT_FAIL
  const badTag = (a.payload.tag[0] === '0' ? '1' : '0') + a.payload.tag.slice(1);
  const r3 = await POST('/api/secure/login', {
    ...a.payload,
    tag: badTag,
    nonce: forge.util.bytesToHex(forge.random.getBytesSync(16)),
  });
  check('篡改 tag 被拒 AES_DECRYPT_FAIL', r3.status === 400 && r3.body?.code === 'AES_DECRYPT_FAIL', `status=${r3.status}`);

  const cReq = buildRequest({ username: 'admin', password: '123456' }, hs, {
    timestampOverride: String(Date.now() - 20 * 60 * 1000),
  });
  const r4 = await POST('/api/secure/login', cReq.payload);
  check('过期时间戳被拒 TIMESTAMP_EXPIRED', r4.status === 403 && r4.body?.code === 'TIMESTAMP_EXPIRED', `status=${r4.status}`);

  const fake = buildRequest({ username: 'admin', password: '123456' }, { sessionId: 'deadbeefdeadbeefdeadbeefdeadbeef', aesKeyForge: hs.aesKeyForge });
  const r5 = await POST('/api/secure/login', fake.payload);
  check('非法 sessionId 被拒 SESSION_EXPIRED', r5.status === 403 && r5.body?.code === 'SESSION_EXPIRED', `status=${r5.status}`);

  const d = buildRequest({ username: 'admin' }, hs);
  const r6 = await POST('/api/secure/profile', d.payload);
  const p6 = decryptResp(r6.body, d.aesKeyForge);
  check('档案查询成功 (code=0)', p6.code === 0);

  console.log(`\n结果: ${passed} 通过, ${failed} 失败`);
  process.exit(failed ? 1 : 0);
})().catch((e) => {
  console.error('e2e 出错:', e);
  process.exit(1);
});
