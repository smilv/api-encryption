/**
 * HTTPS 服务启动入口。
 * 缺少 RSA 密钥/HTTPS 证书时给出明确提示(请先在根目录执行 npm run setup)。
 */
'use strict';

const https = require('https');
const http = require('http');

const config = require('./config');
const { createApp } = require('./app');

function ensureKeys() {
  if (!config.rsaPrivateKey) {
    console.error('\n❌ 未找到 RSA 密钥(server/keys/rsa_private.pem)。');
    console.error('   请在项目根目录执行: npm run setup\n');
    process.exit(1);
  }
}

function start() {
  ensureKeys();
  const app = createApp();

  if (config.httpsKey && config.httpsCert) {
    https
      .createServer({ key: config.httpsKey, cert: config.httpsCert }, app)
      .listen(config.port, () => {
        console.log(`🔒 HTTPS 服务已启动: https://localhost:${config.port}`);
      });
  } else {
    console.warn('\n⚠️  未找到 HTTPS 证书,回退到 HTTP(仅本地调试,生产务必启用 HTTPS)\n');
    http.createServer(app).listen(config.port, () => {
      console.log(`HTTP 服务已启动: http://localhost:${config.port}`);
    });
  }
}

start();
