/**
 * 安全中间件:挂在 /api/secure/* 上,统一处理 ECDHE 会话的
 * "防重放 + AES-GCM 解密(AEAD,完整性内建)/ 出站加密"。
 *
 * 入站:字段齐全 → 防重放(timestamp/nonce)→ 按 sessionId 取会话密钥
 *      → AES-GCM 解密(AAD=sessionId/timestamp/nonce,tag 校验完整性)→ 写入 req.body
 * 出站:包装 res.json,业务层照常 res.json(plainObj),中间件自动加密(GCM)返回。
 * 错误响应(4xx)为明文 { code, message },便于定位。
 *
 * 相比旧版 AES-CBC + 独立 HMAC:GCM 把"解密 + 防篡改"合为一步,
 * 不再需要单独的 HMAC 验签;对 sessionId/timestamp/nonce 的绑定改由 GCM 的 AAD 承担。
 */
'use strict';

const {
  randomBytes,
  IV_LEN,
  TAG_LEN,
  aesEncrypt,
  aesDecrypt,
  buildRequestAad,
} = require('../utils/crypto');
const { verifyAndStore } = require('../utils/replay');
const sessions = require('../utils/sessions');

function fail(res, status, code, message) {
  return res.status(status).json({ code, message });
}

function secureMiddleware(req, res, next) {
  const { sessionId, timestamp, nonce, iv, encryptedData, tag } = req.body || {};

  // 0. 字段齐全性
  if (!sessionId || !timestamp || !nonce || !iv || !encryptedData || !tag) {
    return fail(res, 400, 'BAD_REQUEST', '缺少必要的加密字段');
  }

  // 1. 防重放(最快,优先做)
  const replay = verifyAndStore(timestamp, nonce);
  if (!replay.ok) return fail(res, 403, replay.code, replay.message);

  // 2. 取会话密钥
  const sess = sessions.get(sessionId);
  if (!sess) return fail(res, 403, 'SESSION_EXPIRED', '会话已过期,请重新握手');
  const aesKeyBuf = sess.aesKey;

  // 3. AES-GCM 解密 + 完整性校验(tag 内建,无需独立 HMAC)
  //    AAD = sessionId/timestamp/nonce:篡改这些元数据会让 tag 校验失败,等价于原 HMAC 绑定
  let plain;
  try {
    const cipherBuf = Buffer.from(encryptedData, 'base64');
    const ivBuf = Buffer.from(iv, 'base64');
    const tagBuf = Buffer.from(tag, 'base64');
    if (tagBuf.length !== TAG_LEN) throw new Error('tag 长度非法');
    const aadBuf = buildRequestAad({ sessionId, timestamp, nonce });
    plain = JSON.parse(aesDecrypt(cipherBuf, aesKeyBuf, ivBuf, tagBuf, aadBuf).toString('utf8'));
  } catch (e) {
    return fail(res, 400, 'AES_DECRYPT_FAIL', '业务数据解密或完整性校验失败');
  }

  req.body = plain;
  req.cryptoCtx = { sessionId, nonce };

  // 4. 包装 res.json:出站加密(GCM,AAD 为空)
  const originalJson = res.json.bind(res);
  res.json = (data) => {
    const jsonStr = JSON.stringify(data);
    const respIv = randomBytes(IV_LEN);
    const { cipher: encBuf, tag: respTag } = aesEncrypt(
      Buffer.from(jsonStr, 'utf8'),
      aesKeyBuf,
      respIv
    );
    return originalJson({
      encryptedData: encBuf.toString('base64'),
      iv: respIv.toString('base64'),
      tag: respTag.toString('base64'),
    });
  };

  next();
}

module.exports = secureMiddleware;
