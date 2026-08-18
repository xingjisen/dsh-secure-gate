<p align="center">
  <img src="assets/logo.svg" width="120" alt="dsh-secure-gate" />
</p>

<h1 align="center">🛡️ dsh-secure-gate</h1>

<p align="center">
  <b>高级安全认证网关 for DeepSeek Harness</b>
</p>

<p align="center">
  <a href="./README_EN.md">English</a> ·
  <a href="./docs/ARCHITECTURE.md">架构文档</a> ·
  <a href="./SECURITY.md">安全白皮书</a> ·
  <a href="./CHANGELOG.md">更新日志</a>
</p>

---

## 📖 简介

**dsh-secure-gate** 是一个为 DeepSeek Harness Web UI 提供企业级安全防护的认证网关插件。

**零配置安装**，重启即用。首次访问自动引导创建管理员账户。

### 功能一览

| 类别 | 功能 |
|:--|:--|
| 🔐 密码安全 | Argon2id 哈希 / 强度强制 / 过期策略 |
| 🔑 双因素认证 | TOTP 验证码 / 备份恢复码 / WebAuthn (预备) |
| 🛡️ Web 安全 | CSRF 保护 / CSP 标头 / HSTS / XFO |
| 🚫 访问控制 | 账户锁定 / 永久锁定 / IP 黑白名单 |
| 📋 审计监控 | 审计日志 / 会话管理 |
| ⚡ 攻击防护 | 速率限制 / 指数退避 |

---

## 🚀 安装

```bash
# GitHub 安装（推荐）
dsh plugin --profile web add github:你的用户名/dsh-secure-gate

# 本地开发
dsh plugin --profile web add file:./plugins/dsh-secure-gate
```

重启 DSH 后，浏览器访问会自动跳转到登录页面。

---

## 🏗️ 项目结构

```
dsh-secure-gate/
├── src/server/          # 服务端 TypeScript 源码
│   ├── index.ts         # Cordis 插件入口
│   ├── crypto.ts        # Argon2id 密码哈希
│   ├── store.ts         # 持久化存储
│   ├── roles.ts         # 角色权限
│   ├── headers.ts       # 安全响应头
│   ├── routes/auth.ts   # 认证路由
│   └── middleware/      # 中间件
├── src/client/          # 浏览器端 React 源码
├── src/shared/          # 共享类型
├── lib/                 # 编译后的 JS
├── client/              # 浏览器端 JS
├── docs/                # 文档
├── tests/               # 测试
└── assets/              # 资源文件
```

---

## 📄 许可证

MIT © 2025
