# API 加密 Demo

一套**完整可运行**的接口安全方案演示:**HTTPS + ECDHE 密钥协商 + AES-256-GCM 认证加密 + 时间戳/nonce 防重放**。

- 后端:Node.js + Express(密码学全部用内置 `crypto`)
- 前端:Vue 3 + Vite + Axios(`node-forge` 做对称加密/验签,浏览器原生 **Web Crypto** 做 ECDH/HKDF)

> 本方案具有**前向安全性**:即使服务端 RSA 私钥日后泄露,历史流量也无法被解密 —— 因为每次会话的对称密钥由临时 ECDH 协商,从不传输。
> RSA 公钥**内置在前端**(`client/src/keys.json`),不通过服务端接口下发,从根上杜绝"公钥被中间人替换"。

---

## 方案总览

```
┌──────────────┐                        ┌──────────────┐
│   前端 Vue   │                        │  后端 Express │
└──────┬───────┘                        └──────┬───────┘
       │ ① POST /api/handshake  (ECDHE 握手)   │
       │   发 clientPub ──────────────►        │  ECDH 协商共享密钥 → HKDF 派生会话密钥
       │   ◄── { sessionId, serverPub, sign }  │  存 sessionId→密钥;RSA 签名防中间人
       │   客户端用【内置公钥】RSA 验签通过      │
       │                                       │
       │ ② POST /api/secure/*  (全密文)        │
       │   AES-256-GCM 加密 body               │  防重放 → 取会话密钥 → GCM 解密+验完整性
       │   + sessionId + timestamp + nonce     │  → 业务 → 出站加密响应(GCM)
       │ ◄─────────────────────────────────────     │
       │ ③ 解密响应(GCM tag 校验)→ 明文业务数据 │
       └──────┴───────┘                        └──────┴───────┘
```

> **信任锚**:RSA 公钥在构建期注入前端 `client/src/keys.json`,运行时不从网络获取。
> 握手响应用内置公钥逐一验签(支持轮换多公钥并存),任一通过即可。

### 密钥体系
| 用途 | 算法 | 说明 |
|---|---|---|
| 数据加密 + 防篡改 | **AES-256-GCM**(AEAD) | 每个请求随机 12B nonce;tag 内建完整性认证,无需独立 HMAC |
| 密钥协商 | **ECDH P-256 + HKDF-SHA256** | 双方协商共享密钥(从不发送),HKDF 派生 32B 会话密钥 |
| 身份认证 | **RSA-2048 签名(SHA-256)** | 服务端对握手响应签名,客户端用**内置公钥**逐一验签,防中间人 |
| 元数据绑定 | **GCM AAD** | 请求的 sessionId/timestamp/nonce 作为 AAD,被 tag 一并认证 |
| 防重放 | **timestamp + nonce** | 时间戳偏差 5min;nonce TTL 5min 内不可重复 |

### 请求 / 响应格式
握手(`POST /api/handshake`):
```
请求 { clientPub }                       客户端 ECDH 公钥(base64,未压缩点 65B)
响应 { sessionId, serverPub, sign }       sign = RSA-SHA256("sessionId\nserverPub\nclientPub")
```
加密业务(`POST /api/secure/*`):
```
请求 { sessionId, timestamp, nonce, iv, encryptedData, tag }
   encryptedData = AES-256-GCM(明文, 会话密钥, iv, AAD="sid\nts\nnonce")
   tag           = GCM 认证标签(16B, base64)
响应 { encryptedData, iv, tag }           复用本次会话密钥;响应无 AAD
```
错误响应(4xx)为明文 `{ code, message }`,便于定位。

---

## 目录结构
```
api-encryption/
├─ scripts/
│  ├─ setup.js          # 生成 RSA 密钥对(仅用于签名)+ HTTPS 自签证书
│  ├─ key-gen.js        # 把服务端公钥写入前端 client/src/keys.json(内置信任锚)
│  ├─ key-verify.js     # 对运行中的服务端握手验证签名(确认 keys.json 覆盖当前私钥)
│  ├─ e2e.js            # ECDHE 全链路端到端测试(Web Crypto 模拟前端)
│  └─ ecdh-demo.js      # ECDH 协商 + HKDF + AES-GCM 闭环演示
├─ server/src/
│  ├─ config/index.js     # 配置与密钥加载
│  ├─ utils/crypto.js     # ECDH/HKDF/AES-GCM/RSA签名 工具(算法约定在此)
│  ├─ utils/replay.js     # 防重放(timestamp + nonce)
│  ├─ utils/sessions.js   # ECDHE 会话存储(sessionId → 会话密钥)
│  ├─ middleware/secure.js# 防重放+取会话密钥+GCM解密(含完整性) / 出站加密
│  ├─ routes/handshake.js # POST /api/handshake ECDHE 握手
│  ├─ routes/api.js       # POST /api/secure/* 业务接口
│  └─ app.js / server.js
└─ client/src/
   ├─ keys.json           # 【内置信任锚】服务端 RSA 公钥(构建期注入,可多把并存)
   ├─ utils/crypto.js     # 前端 AES-GCM/RSA验签(与服务端算法对齐)
   ├─ utils/ecdh.js       # Web Crypto ECDH+HKDF 握手(内置公钥逐一验签)
   ├─ api/http.js         # axios 拦截器:握手建立通道 + 加密请求/解密响应
   └─ App.vue             # 登录表单 + 明文/密文对照面板
```

---

## 快速开始

> 需要 Node.js ≥ 18。

```bash
# 1. 安装依赖(根 / server / client)
npm run install:all

# 2. 生成 RSA 密钥与 HTTPS 自签证书
npm run setup

# 3. 把服务端公钥内置到前端(setup 之后必做一次)
npm run key:gen

# 4. 配置后端环境变量(可选,默认值即可跑通)
cp server/.env.example server/.env

# 5. 启动后端与前端(两个终端)
npm run dev:server      # → https://localhost:3000
npm run dev:client      # → https://localhost:5173
```

打开 `https://localhost:5173`(首次需接受自签证书警告),用 `admin / 123456` 登录。
DevTools → Network 中,`/api/handshake` 完成握手,`/api/secure/*` 的请求与响应均为**密文**,页面右侧"明文 ↔ 密文对照"展示完整转换。

---

## 验证脚本

```bash
npm run setup            # 生成密钥材料
npm run key:gen          # 内置公钥到前端 client/src/keys.json
npm run dev:server       # 另一个终端启动后端
npm run key:verify       # 验证:服务端握手签名能被内置公钥验过
node scripts/e2e.js      # ECDHE 全链路 + 防重放/防篡改/会话校验(8 项)
node scripts/ecdh-demo.js# ECDH 协商 → HKDF → AES-GCM 闭环演示
```
> `e2e.js` 用 Node 内置 Web Crypto(与浏览器 API 完全相同)模拟前端,跑通即等价于浏览器可跑。

### 负向测试结果(e2e.js 覆盖)

| 场景 | 期望结果 |
|---|---|
| 修改 `timestamp` 为 10 分钟前 | `403 TIMESTAMP_EXPIRED` |
| 完全相同的请求重放 | `403 NONCE_REUSED` |
| 篡改 `tag` / `encryptedData` | `400 AES_DECRYPT_FAIL`(GCM 完整性校验失败) |
| 伪造 `sessionId` | `403 SESSION_EXPIRED` |
| 篡改握手 `serverPub`(中间人) | 客户端 RSA 验签失败,中止 |

---

## 密钥轮换(运维)

要轮换的是 **RSA 握手签名密钥**(`server/keys/`),不是 ECDHE 会话密钥(每次握手自动换)。
核心原则:**先在前端铺新公钥,再切服务端**。完整步骤与原理见 [flow.md](flow.md) 的「密钥轮换」。

```bash
# 1. 生成 next 密钥(不覆盖现有)
node -e "const c=require('crypto'),fs=require('fs');const k=c.generateKeyPairSync('rsa',{modulusLength:2048,publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});fs.writeFileSync('server/keys/rsa_private.next.pem',k.privateKey);fs.writeFileSync('server/keys/rsa_public.next.pem',k.publicKey);"

# 2. 把 next 公钥追加进前端 keys.json(保留旧公钥)
npm run key:gen -- server/keys/rsa_public.next.pem

# 3. 重新构建并发布前端,等渗透率
npm --prefix client run build

# 4. 切换服务端:rsa_private.next.pem → rsa_private.pem,重启

# 5. 验证
npm run key:verify

# 6. 过渡期(30~90 天)后:从 keys.json 删除旧公钥,旧私钥方可归档/销毁
```

> ⚠️ 别用 `npm run setup` 轮换:它会**同时**重生成 RSA 密钥**和** HTTPS 证书并**覆盖**。
> ⚠️ 过渡期内旧私钥仍是有效信任锚(旧公钥还在 keys.json),必须同等保护;从 keys.json 移除旧公钥后旧私钥才算退役。

---

## ⚠️ 安全注意事项(生产前必读)

1. **信任锚内置前端**:`client/src/keys.json` 里的 RSA 公钥是握手验签的信任根,**构建期注入、运行时不从网络获取**,从根上杜绝"中间人替换公钥"。代价:信任根落在前端 bundle 完整性上 —— 若攻击者能篡改 bundle(改 `keys.json` 或改加密逻辑),内置公钥也会被改。生产应配**可信 CDN + SRI + 强制 HTTPS**。
2. **会话密钥不可落前端 bundle**:加解密与完整性校验一律使用 **ECDHE 协商出的会话密钥**(per-session,仅存内存、握手时算出),前端无需任何硬编码 secret;真正的秘密(会话密钥、RSA 私钥)从不进入前端。
3. **RSA 私钥必须安全注入**:此处 RSA 仅用于握手签名(防中间人),用 KMS / Secret Manager / 环境变量管理,不要入库。
4. **HTTPS 必须用受信 CA 证书**,自签证书仅供本地调试。
5. **防重放 / 会话存储**应使用 Redis 等共享存储以支持多实例;本 demo 为单进程内存实现。
6. **GCM 的 nonce 不可复用**:同一把会话密钥下,nonce 重复会灾难性破坏 GCM 安全性。本项目每次请求/响应都新生成随机 12B nonce,且请求 nonce 受防重放去重保护。
7. 生产级实现建议直接复用成熟方案(如 mTLS + TLS 1.3),自研加密层仅在合规/特殊协议要求时使用。
