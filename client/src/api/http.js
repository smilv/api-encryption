/**
 * HTTP 客户端:封装"请求加密 / 响应解密"全流程(ECDHE 模式),业务层无感知。
 *
 * 启动时:用内置公钥(client/src/keys.json)POST /api/handshake 完成 ECDHE 握手,建立会话密钥
 * 请求拦截:用会话密钥 AES-256-GCM 加密 body,sessionId/timestamp/nonce 作为 AAD → 随密文一起发送
 * 响应拦截:用会话密钥解密(GCM tag 校验完整性)→ 用明文替换 data
 * lastTrace 记录每次调用的明文↔密文对照,供演示页面展示。
 *
 * 信任锚:RSA 公钥内置在前端(构建期从 ../keys.json 注入),不通过服务端接口获取;
 *        加解密密钥为 ECDHE 协商的会话密钥(per-session,仅存内存、不落 bundle)。
 *        真正的秘密(会话密钥/RSA 私钥)从不进入前端。
 */
import axios from 'axios';
import { ref } from 'vue';
import { encryptRequestEcdhe, decryptResponse } from '../utils/crypto';
import { performHandshake } from '../utils/ecdh';
// 信任锚:服务端 RSA 公钥(PEM),构建期从 ../keys.json 注入;不再请求 /api/key
import keysConfig from '../keys.json';

export const lastTrace = ref(null);

// 内置信任公钥(支持多把,轮换并存)。维护方式见 README「密钥轮换」。
const TRUSTED_PUBLIC_KEYS = keysConfig.trustedPublicKeys;

const http = axios.create({ baseURL: '/', timeout: 15000 });

let session = null; // { sessionId, aesKeyBytes }

/** 用内置公钥完成 ECDHE 握手,建立会话 */
export async function initSecureChannel() {
  if (!TRUSTED_PUBLIC_KEYS || TRUSTED_PUBLIC_KEYS.length === 0) {
    throw new Error('内置信任公钥为空,请先 npm run key:gen');
  }
  session = await performHandshake(http, TRUSTED_PUBLIC_KEYS);
  return session;
}

// ---------- 请求拦截:加密 ----------
http.interceptors.request.use((config) => {
  if (!config._secure) return config;
  if (!session) return Promise.reject(new Error('会话未建立,请先握手'));

  const plainBody = config.data ?? {};
  const env = encryptRequestEcdhe(plainBody, {
    sessionId: session.sessionId,
    aesKeyBytes: session.aesKeyBytes,
  });
  const { _keyBytes, ...cipherBody } = env;
  config.data = cipherBody;
  config.headers['Content-Type'] = 'application/json';
  config._keyBytes = _keyBytes;
  config._trace = { url: config.url, plainRequest: plainBody, cipherRequest: cipherBody };
  return config;
});

// ---------- 响应拦截:解密 ----------
http.interceptors.response.use(
  (response) => {
    const trace = response.config?._trace;
    if (!response.config?._secure) return response;

    const raw = response.data;
    if (trace) trace.cipherResponse = raw;

    if (raw && raw.encryptedData) {
      const plain = decryptResponse(raw, response.config._keyBytes);
      response.data = plain;
      if (trace) trace.plainResponse = plain;
    } else if (trace) {
      trace.plainResponse = raw;
    }
    if (trace) lastTrace.value = trace;
    return response;
  },
  (error) => {
    const trace = error.config?._trace;
    if (trace) {
      trace.cipherResponse = error.response?.data;
      trace.plainResponse = error.response?.data;
      trace.error = true;
      lastTrace.value = trace;
    }
    const payload = error.response?.data || { code: 'NETWORK', message: error.message };
    return Promise.reject(payload);
  }
);

export const api = {
  login: (username, password) =>
    http.post('/api/secure/login', { username, password }, { _secure: true }),
  profile: (username) =>
    http.post('/api/secure/profile', { username }, { _secure: true }),
};

export default http;
