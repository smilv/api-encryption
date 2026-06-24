# 流程与信任模型

本文件补充 [README](README.md),详细说明握手数据流、信任模型、以及 RSA 签名密钥的轮换流程。

## 1. 信任模型

| 信任根 | 载体 | 获取方式 |
|---|---|---|
| RSA 公钥(握手验签) | `client/src/keys.json` | **构建期注入**,运行时不从网络获取 |
| 会话对称密钥 | 内存(per-session) | ECDHE 协商,从不传输 |

核心:**RSA 公钥内置在前端**,握手响应用内置公钥逐一验签。中间人即使控制网络、
解了 HTTPS,也无法伪造能通过验签的握手响应 —— 因为他没有服务端 RSA 私钥,
而内置公钥对应的私钥只有服务端持有。

> **为什么不用服务端接口下发公钥?**
> 早期方案用 `GET /api/key` 下发公钥,但"用不可信信道下发的公钥去验证同一信道"
> 等于没验证 —— 中间人替换公钥即可全程代理解密。内置公钥从根上消除这条路径。

---

## 2. 握手流程(ECDHE)

```
前端                                            后端
 │                                               │
 │ ① 生成 ECDH(P-256)临时密钥对                   │
 │   导出 clientPub(base64, 65B 未压缩点)         │
 │                                               │
 │  POST /api/handshake { clientPub }            │
 │ ─────────────────────────────────────────────►│
 │                                               │ ② 生成 ECDH 临时密钥对
 │                                               │   computeSecret(clientPub) → 共享密钥
 │                                               │   HKDF-SHA256 → 32B 会话密钥
 │                                               │   sessions.create(key) → sessionId
 │                                               │   sign = RSA-SHA256("sessionId\nserverPub\nclientPub")
 │   ◄── { sessionId, serverPub, sign } ─────────│
 │                                               │
 │ ③ 用【内置公钥】逐一 RSA 验签 sign              │
 │   任一通过 → serverPub 可信(防中间人)          │
 │                                               │
 │ ④ deriveBits(ECDH, serverPub) → 共享密钥       │
 │   HKDF-SHA256 → 32B 会话密钥(与后端一致)       │
 │                                               │
 │ 持有 { sessionId, 会话密钥 }                    │ 持有 { sessionId → 会话密钥 }
```

握手后,双方各自持有**相同**的会话密钥(从未上过网络),用 sessionId 关联。

---

## 3. 业务请求 / 响应(全密文)

请求(`POST /api/secure/*`):
```
明文 body
   │  AES-256-GCM 加密(key=会话密钥, iv=随机12B, AAD="sessionId\ntimestamp\nnonce")
   ▼
{ sessionId, timestamp, nonce, iv, encryptedData, tag }
```
- `timestamp` + `nonce`:防重放(时间戳偏差 5min;nonce TTL 内不可重复)。
- `AAD`:sessionId/timestamp/nonce 被 GCM tag 一并认证,篡改任一字段 → 解密失败。
- `tag`:GCM 认证标签,保证密文完整性。

响应:
```
{ encryptedData, iv, tag }   ← 复用会话密钥,响应无 AAD
   │  AES-256-GCM 解密 + tag 校验
   ▼
明文 body
```

---

## 4. 密钥轮换(RSA 签名密钥)

> 要轮换的是 `server/keys/` 的 RSA 签名密钥,**不是** ECDHE 会话密钥(那个每次握手自动换)。

核心原则:**先在前端铺新公钥,再切服务端**。因为公钥内置在前端,服务端换私钥后,
旧前端没有新公钥 → 验签失败。所以必须先让前端带上新公钥。

### 流程图

```
时间 ──────────────────────────────────────────────────────────►

[阶段0] 服务端用旧私钥 K0 签      前端 keys.json = [Pub0]
   │
   │  ① 生成 next 密钥对 K1(不覆盖 K0)
   │  ② npm run key:gen -- server/keys/rsa_public.next.pem
   │     → 前端 keys.json = [Pub0, Pub1]   (追加,保留旧)
   │  ③ 重新构建发布前端,等渗透率(>95%)
   ▼
[切换] 服务端换成 K1 签
   │  ④ rsa_private.next.pem → rsa_private.pem,重启
   │  ⑤ npm run key:verify  确认 ✓
   │     新前端:用 Pub1 验签通过
   │     未更新的旧前端:无 Pub1 → 验签失败(故 ③ 要等够)
   ▼
[过渡期 30~90 天]
   │  keys.json 保留 [Pub0, Pub1]:Pub0 是回滚保险
   │  ⚠️ 旧私钥 K0 仍被信任(Pub0 在集合内),必须同等保护
   ▼
[清理]
   ⑥ 新版本前端从 keys.json 删除 Pub0
      → 此后 K0 才退役,可归档/销毁
```

### 命令速查

```bash
# ① 生成 next 密钥(不覆盖现有)
node -e "const c=require('crypto'),fs=require('fs');const k=c.generateKeyPairSync('rsa',{modulusLength:2048,publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});fs.writeFileSync('server/keys/rsa_private.next.pem',k.privateKey);fs.writeFileSync('server/keys/rsa_public.next.pem',k.publicKey);"

# ② 追加 next 公钥到前端(保留旧)
npm run key:gen -- server/keys/rsa_public.next.pem

# ③ 构建发布前端
npm --prefix client run build

# ④ 切换服务端私钥后重启,然后验证
npm run key:verify

# ⑥ 过渡期后,手动从 client/src/keys.json 删除旧公钥那一行
```

### 三个易踩的安全点

1. **保留旧公钥 = 回滚保险**:新私钥出问题可秒切回旧私钥,新前端因 keys.json 还有旧公钥能立即恢复,不用紧急发版。
2. **过渡期内旧私钥同等保护**:旧公钥还在 keys.json → 旧私钥泄露即可对**新前端**做 MITM(用旧私钥签,旧公钥验过)。
3. **过渡期设上限并清理**:只有从 keys.json 移除旧公钥后,旧私钥才退役。无限保留 = 无限暴露面。

---

## 5. 防御边界

| 攻击场景 | 是否防御 |
|---|---|
| 控制网络,伪造握手响应 | ✓ 验签失败(无私钥) |
| 控制网络,替换公钥下发 | ✓ 无 `/api/key` 接口;公钥内置 |
| 解了 HTTPS(抓包证书)+ MITM | ✓ 握手验签挡住(无私钥) |
| 篡改前端 bundle(改 keys.json / 加密逻辑) | ✗ 信任根落在 bundle 完整性 |
| RSA 私钥泄露 + 实时 MITM | ✗ 有私钥可签;须轮换密钥 |
| 服务端 RSA 私钥离线泄露(只录了历史流量) | ✓ 前向保密:ECDHE 临时私钥已销毁,历史流量解不开 |

> 浏览器里任何 JS 加密,信任根最终落在**前端 bundle 完整性**上。
> 本方案把"网络层最廉价的替换攻击"挡掉,是纵深防御的一层,不是银弹。
> 生产应叠加:强制 HTTPS + 可信 CDN + SRI + 私钥 KMS 管理 + 定期轮换。
