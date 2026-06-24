/**
 * ECDHE 会话存储:sessionId -> { aesKey: Buffer, expireAt: number }
 *
 * 与 RSA transport 的"无状态"不同,ECDHE 握手算出的会话密钥必须存住,
 * 绑定 sessionId,后续加密请求靠 sessionId 取回。
 * 生产环境多实例应换 Redis 等共享存储。
 */
'use strict';

const crypto = require('crypto');

const TTL_MS = 30 * 60 * 1000; // 会话有效期 30 分钟

/** @type {Map<string, {aesKey: Buffer, expireAt: number}>} */
const sessions = new Map();

function sweep() {
  const now = Date.now();
  for (const [k, v] of sessions) {
    if (v.expireAt <= now) sessions.delete(k);
  }
}
setInterval(sweep, 5 * 60 * 1000).unref?.();

/** 创建会话,返回 sessionId */
function create(aesKey) {
  const sessionId = crypto.randomBytes(16).toString('hex');
  sessions.set(sessionId, { aesKey, expireAt: Date.now() + TTL_MS });
  return sessionId;
}

/** 取会话;过期或不存在返回 null */
function get(sessionId) {
  const s = sessions.get(sessionId);
  if (!s) return null;
  if (s.expireAt <= Date.now()) {
    sessions.delete(sessionId);
    return null;
  }
  return s;
}

function reset() {
  sessions.clear();
}

module.exports = { create, get, reset, TTL_MS };
