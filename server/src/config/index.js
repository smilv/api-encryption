/**
 * 集中读取配置与密钥。
 * 密钥(RSA 私钥/公钥、HTTPS 证书)由根目录 `npm run setup` 生成。
 */
'use strict';

const fs = require('fs');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '..', '.env') });

const rootDir = path.join(__dirname, '..', '..');
const readPem = (rel) => fs.readFileSync(path.join(rootDir, rel), 'utf8');

function loadOptionalPem(rel) {
  const full = path.join(rootDir, rel);
  if (fs.existsSync(full)) return fs.readFileSync(full, 'utf8');
  return null;
}

const config = {
  port: Number(process.env.PORT) || 3000,
  appId: process.env.APP_ID || 'demo-client',

  timestampToleranceMs: Number(process.env.TIMESTAMP_TOLERANCE_MS) || 5 * 60 * 1000,
  nonceTtlMs: Number(process.env.NONCE_TTL_MS) || 5 * 60 * 1000,

  // RSA 密钥(混合加密中的密钥协商)
  rsaPrivateKey: loadOptionalPem('keys/rsa_private.pem'),
  rsaPublicKey: loadOptionalPem('keys/rsa_public.pem'),

  // HTTPS 自签证书
  httpsKey: loadOptionalPem('certs/key.pem'),
  httpsCert: loadOptionalPem('certs/cert.pem'),
};

module.exports = config;
