/**
 * Express 应用装配。
 *  - POST /api/handshake    ECDHE 握手(明文 JSON,带 RSA 签名防中间人)
 *  - POST /api/secure/*     走 secure 中间件(解密+验签+防重放,出站自动加密+签名)
 *
 * 注:RSA 公钥不再通过接口下发,而是内置在前端 client/src/keys.json(构建期注入)。
 */
'use strict';

const express = require('express');
const cors = require('cors');
const secure = require('./middleware/secure');
const handshakeRoute = require('./routes/handshake');
const apiRoute = require('./routes/api');

function createApp() {
  const app = express();
  app.use(cors());
  app.use(express.json({ limit: '1mb' }));

  app.get('/', (req, res) =>
    res.json({ name: 'api-encryption-server', status: 'ok' })
  );

  // ECDHE 握手(明文 JSON,带 RSA 签名防中间人)
  app.use('/api', handshakeRoute);
  // 加密业务接口(自动兼容 RSA transport 与 ECDHE 两种模式)
  app.use('/api', secure, apiRoute);

  // 统一错误兜底
  app.use((err, req, res, next) => {
    // JSON 解析失败等
    if (err && err.type === 'entity.parse.failed') {
      return res.status(400).json({ code: 'BAD_JSON', message: '请求体不是合法 JSON' });
    }
    console.error('[server] error:', err);
    res.status(500).json({ code: 'INTERNAL', message: '服务器内部错误' });
  });

  return app;
}

module.exports = { createApp };
