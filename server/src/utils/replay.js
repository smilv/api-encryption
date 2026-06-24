/**
 * 防重放:时间戳偏差校验 + nonce 去重。
 *
 * 设计:
 *  - 时间戳偏差超过 tolerance 即拒绝(防陈旧请求/重放)。
 *  - nonce 在 TTL 内不可重复;过期自动清理。
 *  - 单进程内存实现,生产环境应替换为 Redis 等共享存储。
 */
'use strict';

const config = require('../config');

/** @type {Map<string, number>} nonce -> 过期时间戳(ms) */
const nonceStore = new Map();

// 惰性清理 + 定时清理
function sweep() {
  const now = Date.now();
  for (const [k, expireAt] of nonceStore) {
    if (expireAt <= now) nonceStore.delete(k);
  }
}

// 每 60 秒主动清理一次,防止 Map 无限增长
setInterval(sweep, 60 * 1000).unref?.();

/**
 * @param {string} timestamp 客户端时间戳(ms)
 * @param {string} nonce 客户端随机 nonce
 * @returns {{ ok: true } | { ok: false, code: string, message: string }}
 */
function verifyAndStore(timestamp, nonce) {
  const now = Date.now();
  const ts = Number(timestamp);

  // 1. 时间戳合法性
  if (!Number.isFinite(ts)) {
    return { ok: false, code: 'TIMESTAMP_INVALID', message: '时间戳格式非法' };
  }
  if (Math.abs(now - ts) > config.timestampToleranceMs) {
    return {
      ok: false,
      code: 'TIMESTAMP_EXPIRED',
      message: `请求已过期(允许偏差 ${config.timestampToleranceMs}ms)`,
    };
  }

  // 2. nonce 去重
  if (!nonce || typeof nonce !== 'string') {
    return { ok: false, code: 'NONCE_INVALID', message: 'nonce 缺失' };
  }
  if (nonceStore.has(nonce)) {
    return { ok: false, code: 'NONCE_REUSED', message: '请求不可重放' };
  }
  nonceStore.set(nonce, now + config.nonceTtlMs);

  // 顺便惰性清理一部分,避免仅在定时器触发时才清理
  if (nonceStore.size > 5000) sweep();

  return { ok: true };
}

/** 测试用:清空 nonce 缓存 */
function reset() {
  nonceStore.clear();
}

module.exports = { verifyAndStore, sweep, reset };
