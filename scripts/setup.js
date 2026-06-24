/**
 * 一键生成 demo 所需的密钥材料:
 *   1. RSA-2048 密钥对      -> server/keys/{rsa_private,rsa_public}.pem  (仅用于 ECDHE 握手签名/验签,防中间人)
 *   2. HTTPS 自签名证书     -> server/certs/{key,cert}.pem               (本地 HTTPS)
 *
 * 运行: npm run setup   (在项目根目录)
 *
 * 说明:RSA 密钥仅用于本地演示;生产环境的私钥务必从环境/密钥管理服务注入,绝不入库。
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SERVER_DIR = path.join(__dirname, '..', 'server');
const KEYS_DIR = path.join(SERVER_DIR, 'keys');
const CERTS_DIR = path.join(SERVER_DIR, 'certs');

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function genRsaKeys() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  fs.writeFileSync(path.join(KEYS_DIR, 'rsa_private.pem'), privateKey);
  fs.writeFileSync(path.join(KEYS_DIR, 'rsa_public.pem'), publicKey);
  console.log('[keys] RSA-2048 密钥对已生成 -> server/keys/');
}

function genHttpsCert() {
  // selfsigned 是可选依赖,这里动态加载并给出友好提示
  let selfsigned;
  try {
    selfsigned = require('selfsigned');
  } catch (e) {
    console.warn(
      '\n[cert] 缺少 selfsigned 依赖。请先在项目根目录执行:\n' +
        '    npm install\n' +
        '随后重新运行 npm run setup。\n'
    );
    process.exit(1);
  }

  const pems = selfsigned.generate(
    [{ name: 'commonName', value: 'localhost' }],
    {
      keySize: 2048,
      days: 825,
      algorithm: 'sha256',
      extensions: [
        { name: 'basicConstraints', cA: false },
        {
          name: 'keyUsage',
          keyCertSign: false,
          digitalSignature: true,
          keyEncipherment: true,
        },
        {
          name: 'extKeyUsage',
          serverAuth: true,
        },
        {
          name: 'subjectAltName',
          altNames: [
            { type: 2, value: 'localhost' }, // DNS
            { type: 7, ip: '127.0.0.1' }, // IP
          ],
        },
      ],
    }
  );
  fs.writeFileSync(path.join(CERTS_DIR, 'key.pem'), pems.private);
  fs.writeFileSync(path.join(CERTS_DIR, 'cert.pem'), pems.cert);
  console.log('[cert] HTTPS 自签名证书已生成 -> server/certs/');
}

function main() {
  ensureDir(KEYS_DIR);
  ensureDir(CERTS_DIR);
  genRsaKeys();
  genHttpsCert();
  console.log('\n✅ 密钥材料准备完成,可以启动服务:');
  console.log('   cd server && npm run dev');
  console.log('   cd client && npm run dev');
}

main();
