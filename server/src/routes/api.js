/**
 * 业务接口(全部走 secure 中间件,收到的是解密后的明文,返回值会被自动加密)。
 * Demo 用内存模拟用户数据。
 */
'use strict';

const express = require('express');
const crypto = require('crypto');
const router = express.Router();

const USERS = {
  admin: {
    password: '123456',
    profile: { id: 1, username: 'admin', name: '管理员', role: 'admin' },
  },
  guest: {
    password: 'guest',
    profile: { id: 2, username: 'guest', name: '访客', role: 'guest' },
  },
};

// 登录:校验账号密码,签发 demo token
router.post('/secure/login', (req, res) => {
  const { username, password } = req.body || {};
  const u = USERS[username];
  if (!u || u.password !== password) {
    return res.json({ code: 40101, message: '账号或密码错误', data: null });
  }
  // demo token:base64(username:随机),非生产方案
  const token = Buffer.from(`${username}:${crypto.randomBytes(8).toString('hex')}`).toString('base64');
  res.json({
    code: 0,
    message: 'ok',
    data: { token, user: u.profile },
    _meta: { sessionId: req.cryptoCtx?.sessionId, nonce: req.cryptoCtx?.nonce },
  });
});

// 用户档案:演示二次加密请求
router.post('/secure/profile', (req, res) => {
  const { username } = req.body || {};
  const u = USERS[username];
  if (!u) {
    return res.json({ code: 40400, message: '用户不存在', data: null });
  }
  res.json({
    code: 0,
    message: 'ok',
    data: { user: u.profile, visitedAt: new Date().toISOString() },
    _meta: { sessionId: req.cryptoCtx?.sessionId, nonce: req.cryptoCtx?.nonce },
  });
});

module.exports = router;
