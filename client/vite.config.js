import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import fs from 'fs';
import path from 'path';

// 复用后端生成的自签证书给 dev server,使前端也走 HTTPS
const certsDir = path.resolve(__dirname, '..', 'server', 'certs');
const keyPath = path.join(certsDir, 'key.pem');
const certPath = path.join(certsDir, 'cert.pem');
const httpsOpts =
  fs.existsSync(keyPath) && fs.existsSync(certPath)
    ? { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) }
    : undefined;

export default defineConfig({
  plugins: [vue()],
  server: {
    host: '127.0.0.1', // 用 IPv4 字面量,避免 'localhost' 被 Node dns.lookup 解析成仅 IPv6(::1) 而连不上
    port: 5173,
    https: httpsOpts,
    proxy: {
      '/api': {
        target: 'https://localhost:3000',
        changeOrigin: true,
        secure: false, // 后端自签证书,代理时不校验
      },
    },
  },
});
