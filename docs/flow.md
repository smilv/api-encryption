# API 加密方案 · 流程图

本文件用 Mermaid 流程图完整刻画 **HTTPS + ECDHE 密钥协商 + AES-256-GCM 认证加密 + 时间戳/nonce 防重放** 的端到端流程,所有步骤、字段、错误码均与源码逐行对齐。

> 渲染:VSCode(装 Markdown Preview Mermaid Support)/ GitHub / Typora 均可直接预览。

源码索引:

| 阶段 | 后端 | 前端 |
|---|---|---|
| 内置信任锚 | —(公钥不入库,构建期由 [key-gen.js](../scripts/key-gen.js) 写入) | [keys.json](../client/src/keys.json) / [http.js](../client/src/api/http.js) `initSecureChannel` |
| ECDHE 握手 | [routes/handshake.js](../server/src/routes/handshake.js) | [utils/ecdh.js](../client/src/utils/ecdh.js) `performHandshake` |
| 加解密中间件 | [middleware/secure.js](../server/src/middleware/secure.js) | [api/http.js](../client/src/api/http.js) 拦截器 |
| 密码学原语 | [utils/crypto.js](../server/src/utils/crypto.js) | [utils/crypto.js](../client/src/utils/crypto.js) |

---

## 图 1 · 全链路时序图(从启动到业务请求)

```mermaid
sequenceDiagram
    autonumber
    participant C as 前端 Vue (Axios)
    participant H as /api/handshake
    participant S as /api/secure/* (中间件)
    participant B as 业务路由 (login/profile)

    Note over C: 页面启动 → initSecureChannel()<br/>信任锚 = client/src/keys.json 内置公钥(构建期注入,运行时不取)

    rect rgb(52, 40, 62)
    Note over C,H: 阶段 ① ECDHE 握手(明文,HTTPS 保护)
    Note over C: 1) Web Crypto generateKey ECDH P-256<br/>2) exportKey 'raw' → clientPub (65B 未压缩点) base64
    C->>H: POST body(clientPub)
    Note over H: generateEcdhKeyPair → serverPub<br/>dh.computeSecret(clientPub) → sharedSecret<br/>HKDF-SHA256(sharedSecret) → 32B aesKey<br/>sessions.create(aesKey) → sessionId<br/>signHandshake: RSA-SHA256("sid\nserverPub\nclientPub")
    H-->>C: 响应(sessionId, serverPub, sign)
    Note over C: 4) 用内置公钥逐一 rsaVerify 签名串 sid/serverPub/clientPub<br/>   任一通过即可(支持轮换多公钥),全失败则中止(防中间人)<br/>5) ECDH deriveBits(serverPub, 私钥, 256)<br/>6) HKDF(salt, info) → aesKeyBytes
    Note over C: 保存 session(sessionId, aesKeyBytes)
    end

    rect rgb(40, 62, 52)
    Note over C,S: 阶段 ② 加密业务(每次全密文)
    Note over C: 请求拦截器 encryptRequestEcdhe:<br/>iv=random(12B), encryptedData=AES-256-GCM(明文)<br/>AAD="sid\nts\nnonce", tag=GCM认证标签<br/>timestamp=Date.now(), nonce=random(16B)hex
    C->>S: POST body(sessionId, timestamp, nonce, iv, encryptedData, tag)
    S->>S: 字段齐全 → 防重放 → 取会话密钥 → GCM 解密(tag 校验完整性)
    S->>B: req.body = 明文业务参数
    B-->>S: res.json(plainResult)
    Note over S: 包装 res.json 出站加密:<br/>respIv=random(12B), enc+tag=AES-GCM(plainResult)
    S-->>C: 响应(encryptedData, iv, tag)
    Note over C: 响应拦截器 decryptResponse:<br/>GCM 解密(tag 校验)→ JSON.parse<br/>失败 → 抛 "GCM 认证失败"
    end

    rect rgb(62, 52, 40)
    Note over C,S: 阶段 ③ 后续业务复用同一会话密钥
    C->>S: POST /api/secure/profile (同样加密套件)
    Note over C,S: nonce 必须不同 → 否则 403 NONCE_REUSED
    end
```

---

## 图 2 · 服务端 secure 中间件决策流程(含所有错误分支)

对应 [server/src/middleware/secure.js](../server/src/middleware/secure.js):**字段齐全 → 防重放 → 取会话密钥 → AES-GCM 解密(含 tag 完整性校验)→ 业务 → 出站加密**。

> 相比旧版,完整性校验并入 GCM 解密一步完成,不再有独立的 HMAC 验签环节。

```mermaid
flowchart TD
    Start(["收到 POST /api/secure/*"]) --> Parse["解析 req.body:<br/>sessionId, timestamp, nonce,<br/>iv, encryptedData, tag"]

    Parse --> Check0{"6 个字段全部存在?"}
    Check0 -->|否| E400_1[/"400 BAD_REQUEST<br/>缺少必要的加密字段"/]
    Check0 -->|是| Replay

    subgraph Replay["1. 防重放 verifyAndStore"]
        direction TB
        T1{"timestamp 偏差 ≤ 5 min?"}
        T1 -->|否| E403T[/"403 TIMESTAMP_EXPIRED"/]
        T1 -->|是| T2{"nonce 5min 内未出现过?"}
        T2 -->|否| E403N[/"403 NONCE_REUSED"/]
        T2 -->|是| Store["登记 nonce 进内存"]
    end

    Store --> Sess

    subgraph Sess["2. 取会话密钥"]
        direction TB
        GetS["sessions.get(sessionId)"]
        GetS --> HasS{"存在且未过期?"}
        HasS -->|否| E403S[/"403 SESSION_EXPIRED<br/>请重新握手"/]
        HasS -->|是| Key["取出 aesKeyBuf"]
    end

    Key --> Dec

    subgraph Dec["3. AES-256-GCM 解密 + 完整性校验(AEAD)"]
        direction TB
        DoDec["AAD = sessionId\ntimestamp\nnonce<br/>aesDecrypt(encryptedData, aesKeyBuf,<br/>iv, tag, AAD)"]
        DoDec --> Auth{"tag 校验 + JSON.parse<br/>都成功?"}
        Auth -->|否| E400_2[/"400 AES_DECRYPT_FAIL<br/>解密或完整性校验失败"/]
        Auth -->|是| WriteBody["req.body = 明文业务参数<br/>req.cryptoCtx = sessionId, nonce"]
    end

    WriteBody --> Biz["调用业务路由<br/>login / profile ..."]
    Biz --> Resp["业务层 res.json(plainResult)"]

    Resp --> Out

    subgraph Out["4. 出站加密 GCM"]
        direction TB
        R1["respIv = random(12B)"]
        R1 --> R2["encBuf, respTag = AES-256-GCM(<br/>JSON.stringify(result),<br/>aesKeyBuf, respIv)"]
        R2 --> R4["返回密文响应 { encryptedData, iv, tag }"]
    end

    Out --> End(["密文响应回到客户端"])

    classDef err fill:#5b2a2a,stroke:#e07070,color:#ffd6d6,stroke-width:1px;
    classDef ok fill:#2a4b3a,stroke:#7fd6a0,color:#d6ffe4,stroke-width:1px;
    class E400_1,E403T,E403N,E403S,E400_2 err;
    class R4,WriteBody,Biz ok;
```

---

## 图 3 · 客户端握手 + Axios 拦截器流程

对应 [client/src/utils/ecdh.js](../client/src/utils/ecdh.js) 与 [client/src/api/http.js](../client/src/api/http.js)。业务层完全无感知。

```mermaid
flowchart TD
    subgraph Init["initSecureChannel 启动一次"]
        I1["import keys.json<br/>取内置信任公钥(可多把)"] --> HS["performHandshake"]
        HS --> H1["① generateKey ECDH P-256<br/>(extractable, deriveBits)"]
        H1 --> H2["② exportKey raw → 65B 未压缩点<br/>base64 → clientPubB64"]
        H2 --> H3["③ POST /api/handshake 客户端公钥"]
        H3 --> H4["④ 内置公钥逐一 rsaVerify 签名串<br/>覆盖 sessionId / serverPub / clientPub<br/>任一通过即可"]
        H4 --> H4c{"验签通过?"}
        H4c -->|否| HErr["抛错：可能遭遇中间人<br/>中止通道"]
        H4c -->|是| H5["⑤ importKey serverPub →<br/>deriveBits ECDH(私钥, 256bit)"]
        H5 --> H6["⑥ HKDF-SHA256<br/>salt / info 派生 32B<br/>→ aesKeyBytes (forge binary)"]
        H6 --> Save["保存 session =<br/>sessionId, aesKeyBytes"]
    end

    Save --> Req

    subgraph Req["请求拦截器 request.use"]
        R0{"config._secure?"}
        R0 -->|否| Pass["透传不加密"]
        R0 -->|是| R1{"session 已建立?"}
        R1 -->|否| RErr["reject 会话未建立"]
        R1 -->|是| Enc["encryptRequestEcdhe:<br/>iv = random(12B)<br/>AAD = sessionId\\ntimestamp\\nnonce<br/>encryptedData = AES-GCM(明文, AAD)<br/>tag = GCM 认证标签<br/>timestamp = Date.now()<br/>nonce = random(16B) hex"]
        Enc --> Replace["config.data = 密文字段<br/>(剔除 _keyBytes)<br/>记录 _trace 明文↔密文"]
    end

    Req --> Resp

    subgraph Resp["响应拦截器 response.use"]
        P1{"data.encryptedData 存在?"}
        P1 -->|否| Raw["原样保留<br/>通常是错误对象"]
        P1 -->|是| Dec["AES-GCM 解密(tag 校验完整性)<br/>→ JSON.parse → 明文"]
        Dec --> DecC{"tag 校验通过?"}
        DecC -->|否| DErr["抛错：GCM 认证失败<br/>数据可能被篡改"]
        DecC -->|是| Swap["response.data = 明文"]
        Raw --> Swap
        Swap --> Trace["lastTrace.value 更新<br/>页面展示对照"]
    end

    classDef err fill:#5b2a2a,stroke:#e07070,color:#ffd6d6;
    classDef ok fill:#2a4b3a,stroke:#7fd6a0,color:#d6ffe4;
    class HErr,RErr,DErr err;
    class Save,Swap,Trace ok;
```

---

## 图 4 · ECDHE 密钥协商细节(前向安全性的来源)

下图展示一次 **`POST /api/handshake`** 往返内完成的密钥协商(请求带 `clientPub`,响应回 `sessionId / serverPub / sign`)。即便服务端 RSA 私钥日后泄露,历史流量也无法解密——因为每次会话对称密钥由**临时** ECDH 协商,密钥从不传输,握手结束即丢弃。

```mermaid
sequenceDiagram
    participant C as 客户端 Web Crypto
    participant S as 服务端 Node crypto

    Note over C: 生成临时 ECDH 密钥对(P-256)<br/>私钥 a，公钥 clientPub = a·G（65B 未压缩点）

    C->>S: ① POST /api/handshake 请求 body(clientPub)

    Note over S: 生成临时 ECDH 密钥对<br/>私钥 b，公钥 serverPub = b·G<br/>sharedSecret = b · clientPub = ab·G（computeSecret）<br/>aesKey_S = HKDF-SHA256（sharedSecret）<br/>新建 sessionId 并存会话密钥<br/>sign = RSA-SHA256（覆盖 sessionId / serverPub / clientPub）

    S-->>C: ② 响应(sessionId, serverPub, sign)

    Note over C: 用内置公钥逐一 RSA 验签 sign（全失败即中止，防中间人）<br/>sharedSecret = a · serverPub = ab·G（deriveBits）<br/>aesKey_C = HKDF-SHA256（sharedSecret）

    Note over C,S: 两方独立算出相同的 ab·G → 会话密钥相等 aesKey_C == aesKey_S<br/>该会话密钥同时用于 AES-256-GCM 的加密与认证(tag/AAD 同源)<br/>私钥 a、b 与乘积 ab·G 从不传输，握手结束即丢弃<br/>前向安全：RSA 私钥即便日后泄露，历史流量也无法解密
```

---

## 附录 A · 算法约定与常量(前后端必须逐字节对齐)

| 用途 | 算法 | 关键参数 |
|---|---|---|
| 数据加密 + 防篡改 | AES-256-GCM(AEAD) | nonce = 12B 随机;tag = 16B;密钥 = 会话 32B |
| 密钥协商 | ECDH P-256 | 公钥 raw = 未压缩点 65B;deriveBits 256bit |
| 密钥派生 | HKDF-SHA256 | `salt = api-encryption-demo-salt`,`info = aes-256-session-key`,输出 32B |
| 握手认证 | RSA-2048 + SHA-256 (PKCS#1 v1.5) | 签名串 = `sessionId\nserverPub\nclientPub` |
| 元数据绑定 | GCM AAD(请求方向) | `sessionId\ntimestamp\nnonce`(响应方向无 AAD) |
| 防重放 | timestamp + nonce | timestamp 偏差 5min;nonce TTL 5min 内唯一 |

### AAD / 签名串顺序(**不可更改**,改了就验不过)

```
请求方向 GCM AAD:  sessionId \n timestamp \n nonce
握手签名(RSA):     sessionId \n serverPub \n clientPub
响应方向:          (无 AAD)
```

> 请求/响应的加密与完整性校验密钥均为 ECDHE 协商出的**会话密钥**,不再使用任何全局共享 secret——因此前端无需硬编码任何密钥。

## 附录 B · 错误码汇总

| 错误码 | HTTP | 触发条件 | 抛出位置 |
|---|---|---|---|
| `BAD_REQUEST` | 400 | 缺少 6 个加密字段之一 | secure.js 字段校验 |
| `TIMESTAMP_EXPIRED` | 403 | timestamp 偏差 > 5min | replay.js |
| `NONCE_REUSED` | 403 | nonce 在 5min TTL 内重复 | replay.js |
| `SESSION_EXPIRED` | 403 | sessionId 不存在/已过期 | sessions.js |
| `AES_DECRYPT_FAIL` | 400 | GCM tag 校验失败 / 解密 / JSON.parse 失败 | secure.js 解密 |
| `HANDSHAKE_FAIL` | 400 | clientPub 格式非法 / computeSecret 失败 | handshake.js |
| —(抛异常) | — | 客户端 RSA 验签失败 / 响应 GCM 校验失败 | ecdh.js / crypto.js |

> 旧版的 `401 BAD_SIGN`(独立 HMAC 验签失败)已移除:完整性校验由 GCM 的 tag 承担,篡改密文/tag/AAD 统一归入 `400 AES_DECRYPT_FAIL`。
