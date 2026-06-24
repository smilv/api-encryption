/**
 * 端到端验证:对【运行中的服务端】做一次 ECDHE 握手,
 * 确认其握手签名能用 client/src/keys.json 里的某把内置公钥验过。
 *
 * 用法:
 *   node scripts/key-verify.js                       # 默认 https://localhost:${PORT||3000}
 *   node scripts/key-verify.js http://localhost:3000
 *
 * 与 key-gen 的区别:
 *   key-gen    —— 把密钥【文件】里的公钥写入 keys.json(铺公钥用)
 *   key-verify —— 对服务端【实际握手】验证签名(确认 keys.json 覆盖服务端当前私钥)
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { webcrypto } = require('crypto');
const { URL } = require('url');
const http = require('http');
const https = require('https');

const subtle = webcrypto.subtle;

function readTrustedKeys() {
  const keysPath = path.join(__dirname, '..', 'client', 'src', 'keys.json');
  if (!fs.existsSync(keysPath)) return [];
  const config = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
  return Array.isArray(config.trustedPublicKeys) ? config.trustedPublicKeys : [];
}

function postJson(url, body) {
  return new Promise((resolve, reject) => {
    const isHttps = url.startsWith('https');
    const tlsOpts = isHttps ? { rejectUnauthorized: false } : {}; // 自签证书放行
    const lib = isHttps ? https : http;
    const u = new URL(url);
    const bodyStr = JSON.stringify(body);
    const req = lib.request(
      {
        hostname: u.hostname,
        port: u.port || (isHttps ? 443 : 80),
        path: u.pathname,
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(bodyStr) },
        ...tlsOpts,
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch (e) {
            reject(new Error('响应不是合法 JSON: ' + data.slice(0, 120)));
          }
        });
      }
    );
    req.on('error', reject);
    req.write(bodyStr);
    req.end();
  });
}

const b64 = (buf) => Buffer.from(buf).toString('base64');

async function main() {
  const trustedKeys = readTrustedKeys();
  if (!trustedKeys.length) {
    console.error('❌ keys.json 无内置公钥,请先 npm run key:gen');
    process.exit(1);
  }

  const baseUrl = process.argv[2] || `https://localhost:${process.env.PORT || 3000}`;
  console.log(`探测服务端: ${baseUrl}/api/handshake`);

  // 生成 ECDH 临时密钥,导出 clientPub
  const keyPair = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const clientPubBuf = await subtle.exportKey('raw', keyPair.publicKey);
  const clientPubB64 = b64(clientPubBuf);

  const res = await postJson(`${baseUrl}/api/handshake`, { clientPub: clientPubB64 });
  const { sessionId, serverPub, sign } = res || {};
  if (!sessionId || !serverPub || !sign) {
    console.error('❌ 握手响应异常:', JSON.stringify(res).slice(0, 200));
    process.exit(1);
  }

  // 用内置公钥逐一验签(与前端 ecdh.js#performHandshake 逻辑一致)
  const signStr = [sessionId, serverPub, clientPubB64].join('\n');
  let matchedPem = null;
  for (const pem of trustedKeys) {
    const v = crypto.createVerify('sha256');
    v.update(signStr, 'utf8');
    if (v.verify(pem, Buffer.from(sign, 'base64'))) {
      matchedPem = pem;
      break;
    }
  }

  if (matchedPem) {
    const derB64 = matchedPem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
    const fp = crypto.createHash('sha256').update(Buffer.from(derB64, 'base64')).digest('base64');
    console.log('✓ 握手签名验证通过 —— 服务端公钥在 keys.json 内(指纹 ' + fp + ')');
  } else {
    console.log('✗ 握手签名验证失败 —— 服务端私钥对应的公钥不在 keys.json!');
    console.log('  修复: npm run key:gen 把服务端当前公钥追加进 client/src/keys.json');
    process.exit(2);
  }
}

main().catch((e) => {
  console.error('❌ 验证失败:', e.message);
  process.exit(1);
});
