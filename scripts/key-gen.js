/**
 * 把服务端 RSA 公钥【幂等追加】进前端内置信任配置 client/src/keys.json。
 * 前端握手时用这些公钥逐一验签服务端签名,任一通过即可(支持轮换多公钥并存)。
 *
 * 用法:
 *   npm run key:gen                                     # 读 server/keys/rsa_public.pem
 *   npm run key:gen -- server/keys/rsa_public.next.pem  # 指定公钥(轮换时铺新公钥)
 *
 * 轮换:生成 next 密钥 → 本命令追加 next 公钥 → 发布前端 → 切服务端 → key:verify。
 *       过渡期后手动从 keys.json 移除旧公钥。
 *
 * 说明:公钥 PEM 内部换行以 \n 形式存入 JSON,JSON.parse 读取时自动还原;
 *       trim 后比对保证"同一公钥多次追加"幂等去重。
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const rootDir = path.join(__dirname, '..');
const keysPath = path.join(rootDir, 'client', 'src', 'keys.json');
const defaultPub = path.join(rootDir, 'server', 'keys', 'rsa_public.pem');

const pubPath = process.argv[2] ? path.resolve(process.argv[2]) : defaultPub;
if (!fs.existsSync(pubPath)) {
  console.error('❌ 未找到公钥文件: ' + pubPath);
  console.error('   请先 npm run setup,或检查传入的公钥路径。');
  process.exit(1);
}

const pem = fs.readFileSync(pubPath, 'utf8').trim(); // 规范化首尾,保证去重一致

// 指纹仅用于日志展示,便于人眼识别/核对(不参与信任逻辑)
const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
const der = Buffer.from(b64, 'base64');
const pin = crypto.createHash('sha256').update(der).digest('base64');

let config;
if (fs.existsSync(keysPath)) {
  config = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
} else {
  config = { trustedPublicKeys: [] };
}
if (!Array.isArray(config.trustedPublicKeys)) config.trustedPublicKeys = [];

if (config.trustedPublicKeys.includes(pem)) {
  console.log('公钥已在 keys.json 中,无需变更。指纹:');
} else {
  config.trustedPublicKeys.push(pem);
  fs.writeFileSync(keysPath, JSON.stringify(config, null, 2) + '\n');
  console.log('已追加进 client/src/keys.json。指纹:');
}
console.log(pin);
console.log('当前信任公钥数:', config.trustedPublicKeys.length);
