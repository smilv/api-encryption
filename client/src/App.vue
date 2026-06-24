<script setup>
import { ref, onMounted, computed } from 'vue';
import { api, initSecureChannel, lastTrace } from './api/http';

const username = ref('admin');
const password = ref('123456');
const loading = ref(false);
const error = ref('');
const result = ref(null);
const ready = ref(false);

const tracePlainReq = computed(() => fmt(lastTrace.value?.plainRequest));
const traceCipherReq = computed(() => fmt(lastTrace.value?.cipherRequest));
const traceCipherResp = computed(() => fmt(lastTrace.value?.cipherResponse));
const tracePlainResp = computed(() => fmt(lastTrace.value?.plainResponse));

function fmt(obj) {
  if (obj === undefined || obj === null) return '—';
  try {
    return JSON.stringify(obj, null, 2);
  } catch {
    return String(obj);
  }
}

async function init() {
  error.value = '';
  try {
    await initSecureChannel();
    ready.value = true;
  } catch (e) {
    error.value = '安全通道建立失败(ECDHE 握手):' + (e?.message || JSON.stringify(e));
  }
}

async function doLogin() {
  error.value = '';
  result.value = null;
  loading.value = true;
  try {
    const res = await api.login(username.value, password.value);
    result.value = res.data;
  } catch (e) {
    error.value = '登录失败:' + (e?.message || e?.code || JSON.stringify(e));
  } finally {
    loading.value = false;
  }
}

async function doProfile() {
  error.value = '';
  result.value = null;
  loading.value = true;
  try {
    const res = await api.profile(username.value);
    result.value = res.data;
  } catch (e) {
    error.value = '查询失败:' + (e?.message || e?.code || JSON.stringify(e));
  } finally {
    loading.value = false;
  }
}

onMounted(init);
</script>

<template>
  <div class="page">
    <header class="hero">
      <h1>API 加密 Demo</h1>
      <p class="sub">HTTPS · ECDHE(P-256)密钥协商 · AES-256-GCM 认证加密 · 时间戳 / nonce 防重放</p>
      <p class="status" :class="{ ok: ready, no: !ready }">
        {{ ready ? '✅ 安全通道已建立(ECDHE 握手完成)' : '⏳ 正在 ECDHE 握手…' }}
      </p>
      <p class="mode">
        加密模式：<strong>ECDHE（前向安全 + RSA 签名防中间人）</strong>
      </p>
    </header>

    <main class="grid">
      <!-- 左：操作区 -->
      <section class="card">
        <h2>1. 发起加密请求</h2>
        <label class="field">
          <span>用户名</span>
          <input v-model="username" type="text" />
        </label>
        <label class="field">
          <span>密码(admin / 123456)</span>
          <input v-model="password" type="password" />
        </label>
        <div class="btns">
          <button :disabled="loading || !ready" @click="doLogin">登录 /api/secure/login</button>
          <button class="ghost" :disabled="loading || !ready" @click="doProfile">查询档案 /api/secure/profile</button>
        </div>

        <div v-if="error" class="alert err">{{ error }}</div>

        <div v-if="result" class="result">
          <h3>解密后业务响应</h3>
          <pre>{{ fmt(result) }}</pre>
        </div>

        <p class="tip">
          提示：打开浏览器 DevTools → Network,可见 <code>/api/handshake</code> 交换公钥、
          <code>/api/secure/*</code> 的请求体与响应体均为<strong>密文</strong>;
          而下方"解密后业务响应"才是明文。
        </p>
      </section>

      <!-- 右：对照面板 -->
      <section class="card">
        <h2>
          2. 明文 ↔ 密文对照
          <span class="tag">ECDHE</span>
        </h2>
        <div class="trace-grid">
          <div class="trace">
            <h4>明文请求(应用层)</h4>
            <pre>{{ tracePlainReq }}</pre>
          </div>
          <div class="trace">
            <h4>实际发出的密文请求</h4>
            <pre>{{ traceCipherReq }}</pre>
          </div>
          <div class="trace">
            <h4>收到的密文响应</h4>
            <pre>{{ traceCipherResp }}</pre>
          </div>
          <div class="trace">
            <h4>解密验签后的明文响应</h4>
            <pre>{{ tracePlainResp }}</pre>
          </div>
        </div>
      </section>
    </main>

    <footer class="foot"></footer>
  </div>
</template>

<style scoped>
* { box-sizing: border-box; }
.page { font-family: system-ui, -apple-system, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif; max-width: 1200px; margin: 0 auto; padding: 24px; color: #1f2937; }
.hero h1 { margin: 0 0 4px; font-size: 28px; }
.sub { margin: 0; color: #6b7280; }
.status { margin: 8px 0 0; font-size: 14px; }
.status.ok { color: #059669; }
.status.no { color: #b45309; }
.mode { margin: 6px 0 0; font-size: 13px; color: #6b7280; }
.mode strong { color: #2563eb; }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 24px; }
@media (max-width: 860px) { .grid { grid-template-columns: 1fr; } }
.card { background: #fff; border: 1px solid #e5e7eb; border-radius: 12px; padding: 20px; box-shadow: 0 1px 2px rgba(0,0,0,.04); }
.card h2 { margin: 0 0 16px; font-size: 18px; }
.tag { font-size: 12px; font-weight: 600; color: #2563eb; background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 999px; padding: 2px 10px; vertical-align: middle; }
.field { display: flex; flex-direction: column; gap: 6px; margin-bottom: 14px; font-size: 13px; color: #374151; }
.field input { padding: 9px 10px; border: 1px solid #d1d5db; border-radius: 8px; font-size: 14px; }
.btns { display: flex; gap: 10px; flex-wrap: wrap; }
button { background: #2563eb; color: #fff; border: 0; padding: 10px 14px; border-radius: 8px; cursor: pointer; font-size: 14px; }
button:disabled { background: #9ca3af; cursor: not-allowed; }
button.ghost { background: #e5e7eb; color: #1f2937; }
.alert { margin-top: 14px; padding: 10px 12px; border-radius: 8px; font-size: 13px; }
.alert.err { background: #fef2f2; color: #b91c1c; border: 1px solid #fecaca; }
.result { margin-top: 16px; }
.result h3 { margin: 0 0 8px; font-size: 14px; color: #374151; }
pre { background: #0f172a; color: #e2e8f0; padding: 12px; border-radius: 8px; overflow: auto; font-size: 12px; line-height: 1.5; margin: 0; max-height: 400px; white-space: pre-wrap; word-break: break-all; }
.tip { margin-top: 16px; font-size: 12px; color: #6b7280; line-height: 1.6; }
.tip code { background: #f3f4f6; padding: 1px 5px; border-radius: 4px; }
.trace-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
@media (max-width: 640px) { .trace-grid { grid-template-columns: 1fr; } }
.trace h4 { margin: 0 0 6px; font-size: 12px; color: #6b7280; font-weight: 600; }
.foot { margin-top: 28px; font-size: 12px; color: #9ca3af; text-align: center; }
</style>
