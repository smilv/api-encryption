/**
 * ECDHE 握手接口(明文 JSON,传输层由 HTTPS 保护)。
 *
 * 请求: { clientPub }            —— 客户端 ECDH 公钥(base64,未压缩点 65 字节)
 * 响应: { sessionId, serverPub, sign }
 *   serverPub: 服务端 ECDH 公钥(base64)
 *   sign:      RSA 签名(SHA-256),覆盖 "sessionId\nserverPub\nclientPub",
 *              客户端用预先信任的服务端公钥验签 → 防中间人
 *
 * 安全性:clientPub / serverPub 都是公开值,被截获无所谓;
 *   攻击者要冒充服务端必须能伪造 RSA 签名 —— 拿不到私钥就不可能。
 */
'use strict';

const express = require('express');
const {
  generateEcdhKeyPair,
  deriveSessionKey,
  signHandshake,
} = require('../utils/crypto');
const sessions = require('../utils/sessions');

const router = express.Router();

router.post('/handshake', (req, res) => {
  const { clientPub } = req.body || {};
  if (!clientPub || typeof clientPub !== 'string') {
    return res.status(400).json({ code: 'BAD_REQUEST', message: '缺少 clientPub' });
  }
  try {
    const { dh, publicKeyB64: serverPub } = generateEcdhKeyPair();
    const sharedSecret = dh.computeSecret(Buffer.from(clientPub, 'base64'));
    const aesKey = deriveSessionKey(sharedSecret);
    const sessionId = sessions.create(aesKey);
    const sign = signHandshake({ sessionId, serverPub, clientPub });
    return res.json({ sessionId, serverPub, sign });
  } catch (e) {
    console.error('[handshake] error:', e.message);
    return res.status(400).json({
      code: 'HANDSHAKE_FAIL',
      message: '握手失败(clientPub 格式可能非法)',
    });
  }
});

module.exports = router;
