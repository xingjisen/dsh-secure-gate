# dsh-secure-gate — 架构方案

> 高级安全认证网关 for DeepSeek Harness Web UI
> 设计用于提交至 DSH 社区插件市场 (awesome-dsh-plugin)

---

## 一、项目概览

### 1.1 定位

一个零配置、高安全性的 Web 认证网关插件，为 DSH 的 Web 界面提供企业级访问控制。
用户安装后重启即用，首次访问自动引导创建管理员账户。

### 1.2 核心价值

| 维度 | 说明 |
|:--|:--|
| **安全性** | 超出社区同类插件的安全标准 |
| **易用性** | 零配置安装，自动引导，即装即用 |
| **美观性** | 现代化 UI 设计，深色/浅色主题，中英文双语 |
| **可审计** | 完整的审计日志体系 |
| **可维护** | TypeScript 编写，完善的类型定义和测试 |

---

## 二、安全特性矩阵

### 2.1 密码安全

| 特性 | 方案 | 优先级 |
|:--|:--|:--:|
| 密码哈希 | **Argon2id** (OWASP 2024 推荐) | P0 |
| 哈希参数 | N=2^17, r=8, p=1, 64字节输出 | P0 |
| 密码强度 | ≥10位，大小写+数字+特殊字符，可配置 | P0 |
| 密码过期 | 90天强制更换，可配置 | P0 |
| 历史密码 | 禁止使用最近5次密码 | P1 |

### 2.2 认证机制

| 特性 | 方案 | 优先级 |
|:--|:--|:--:|
| 密码登录 | 用户名 + Argon2id 验证 | P0 |
| TOTP 两步验证 | 基于时间的一次性密码 (RFC 6238) | P0 |
| 备份恢复码 | 8个一次性恢复码，SHA-256 存储 | P0 |
| **WebAuthn/Passkey** | FIDO2 硬件密钥/生物识别 | P1 |
| **SSO 集成** | OAuth2 / OIDC 协议支持 | P2 |

### 2.3 会话安全

| 特性 | 方案 | 优先级 |
|:--|:--|:--:|
| Cookie 签名 | HMAC-SHA256 | P0 |
| Session 载荷 | JWT 风格（base64url 编码 JSON + 签名） | P0 |
| HttpOnly | ✅ | P0 |
| SameSite | Strict | P0 |
| Secure | 生产环境强制 | P0 |
| 自动续期 | 过期前 1 小时内自动刷新 | P0 |
| 会话管理 | 用户可查看和撤销活跃会话 | P0 |
| 设备指纹 | 记录 User-Agent + IP | P0 |

### 2.4 防护机制

| 特性 | 方案 | 优先级 |
|:--|:--|:--:|
| CSRF 保护 | 双重提交 Cookie 模式 | P0 |
| 速率限制 | IP+用户名 5次/15分钟，可配置 | P0 |
| 账户锁定 | 5次失败 → 锁定30分钟 | P0 |
| 永久锁定 | 连续3次锁定期 → 永久锁定 | P0 |
| 指数退避 | 锁定时长递增: 30m → 2h → 8h → 永久 | P1 |
| IP 访问控制 | 白名单 + 黑名单 + 仅内网模式 | P0 |
| 暴力破解防护 | 登录尝试跨 IP 聚合检测 | P1 |

### 2.5 审计与合规

| 特性 | 方案 | 优先级 |
|:--|:--|:--:|
| 审计日志 | JSONL 格式，含时间戳/事件/IP/用户名 | P0 |
| 登录事件 | 成功/失败/锁定/解锁 | P0 |
| 管理事件 | 账户创建/删除/角色变更/密码重置 | P0 |
| 会话事件 | 创建/过期/撤销 | P0 |
| 日志轮转 | 按大小/日期自动轮转 | P1 |

### 2.6 安全标头

| 标头 | 值 | 优先级 |
|:--|:--|:--:|
| Content-Security-Policy | 严格限制 | P0 |
| X-Content-Type-Options | nosniff | P0 |
| X-Frame-Options | DENY | P0 |
| X-XSS-Protection | 1; mode=block | P0 |
| Strict-Transport-Security | max-age=31536000 | P0 |
| Referrer-Policy | strict-origin-when-cross-origin | P0 |
| Permissions-Policy | 禁用摄像头/麦克风/地理位置 | P0 |

---

## 三、技术架构

### 3.1 项目结构

```
plugins/dsh-secure-gate/
├── src/
│   ├── server/                    # 服务端 (Node.js)
│   │   ├── index.ts               # Cordis 插件入口
│   │   ├── config.ts              # 配置 Schema 定义
│   │   ├── store.ts               # 账户 & 会话存储
│   │   ├── crypto.ts              # 密码哈希 & 签名
│   │   ├── totp.ts                # TOTP 两步验证
│   │   ├── webauthn.ts            # WebAuthn / Passkey
│   │   ├── csrf.ts                # CSRF 保护
│   │   ├── rate-limit.ts          # 速率限制 & 锁定
│   │   ├── ip-access.ts           # IP 访问控制
│   │   ├── audit.ts               # 审计日志
│   │   ├── session.ts             # 会话管理
│   │   ├── roles.ts               # 角色权限
│   │   ├── headers.ts             # 安全标头
│   │   ├── routes/
│   │   │   ├── auth.ts            # /secure-gate/auth/*
│   │   │   ├── admin.ts           # /secure-gate/admin/*
│   │   │   └── settings.ts        # /secure-gate/settings/*
│   │   ├── middleware/
│   │   │   ├── gate.ts            # 请求拦截门
│   │   │   └── login-page.ts      # 登录页面 HTML 模板
│   │   └── utils.ts               # 工具函数
│   ├── client/                    # 浏览器端 (TypeScript -> JS Bundle)
│   │   ├── index.tsx              # 入口: 登录覆盖层 + 设置面板
│   │   ├── components/
│   │   │   ├── LoginOverlay.tsx    # 登录弹窗
│   │   │   ├── LoginForm.tsx       # 登录表单
│   │   │   ├── MfaForm.tsx         # 两步验证表单
│   │   │   ├── PasskeyButton.tsx   # Passkey 登录按钮
│   │   │   ├── SettingsPanel.tsx   # 安全设置面板
│   │   │   ├── AccountManager.tsx  # 账户管理
│   │   │   ├── SessionList.tsx     # 会话列表
│   │   │   ├── AuditLogViewer.tsx  # 审计日志查看
│   │   │   └── SecurityBadge.tsx   # 安全状态徽章
│   │   ├── hooks/
│   │   │   ├── useSession.ts       # 会话状态管理
│   │   │   └── useI18n.ts          # 国际化
│   │   └── styles/
│   │       └── theme.ts            # 主题系统
│   └── shared/                     # 前后端共享
│       ├── types.ts                # 类型定义
│       ├── constants.ts            # 常量
│       └── i18n.ts                 # 国际化词条
├── lib/                            # 编译输出 (发布用)
├── tests/
│   ├── server/                     # 服务端测试
│   │   ├── crypto.test.ts
│   │   ├── store.test.ts
│   │   ├── csrf.test.ts
│   │   └── rate-limit.test.ts
│   └── client/                     # 客户端测试
│       └── components.test.tsx
├── docs/
│   ├── ARCHITECTURE.md             # 架构文档 (本文)
│   ├── SECURITY.md                 # 安全白皮书
│   └── CHANGELOG.md                # 变更日志
├── assets/
│   ├── logo.svg                    # 插件 Logo
│   ├── screenshot-login.png        # 登录页截图
│   └── screenshot-settings.png     # 设置页截图
├── scripts/
│   ├── build.sh                    # 构建脚本
│   └── preflight.mjs              # 发布前检查
├── package.json                    # npm 包定义
├── tsconfig.json                   # TypeScript 配置
├── tsdown.config.ts                # 打包配置
├── cordis.patch.yml                # Cordis 组合层
└── README.md                       # 项目说明
```

### 3.2 组件架构

```
┌─────────────────────────────────────────────────────────────┐
│                      Cordis Plugin                          │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                     index.ts                           │  │
│  │  ┌─────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │  │
│  │  │ config  │ │  store   │ │ session  │ │  audit   │  │  │
│  │  └─────────┘ └──────────┘ └──────────┘ └──────────┘  │  │
│  │  ┌─────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │  │
│  │  │ crypto  │ │  csrf    │ │ rate-lmt │ │ ip-access│  │  │
│  │  └─────────┘ └──────────┘ └──────────┘ └──────────┘  │  │
│  │  ┌─────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │  │
│  │  │  totp   │ │ webauthn │ │  roles   │ │ headers  │  │  │
│  │  └─────────┘ └──────────┘ └──────────┘ └──────────┘  │  │
│  └───────────────────────────────────────────────────────┘  │
│                            │                                  │
│              ┌─────────────┴─────────────┐                    │
│              ▼                           ▼                    │
│  ┌────────────────────┐    ┌────────────────────┐           │
│  │   Routes Layer     │    │  Middleware Layer   │           │
│  │  /auth/*           │    │  Gate (前置拦截)    │           │
│  │  /admin/*          │    │  Security Headers   │           │
│  │  /settings/*       │    │                    │           │
│  └────────────────────┘    └────────────────────┘           │
└─────────────────────────────────────────────────────────────┘
                             │
              ┌──────────────┴──────────────┐
              ▼                              ▼
  ┌────────────────────┐       ┌────────────────────┐
  │   Web UI Client    │       │   DSH Host API     │
  │  · 登录覆盖层      │       │   · 正常 API 请求  │
  │  · 设置面板        │       │   · 经 Gate 放行   │
  └────────────────────┘       └────────────────────┘
```

### 3.3 请求流程

```
用户浏览器                          dsh-secure-gate                  DSH API
    │                                    │                            │
    ├─ 请求 /api/* ──────────────────────►                            │
    │                                    │                            │
    │                          ┌─────────▼─────────┐                  │
    │                          │ IP 访问控制检查    │                  │
    │                          └─────────┬─────────┘                  │
    │                          ┌─────────▼─────────┐                  │
    │                          │ 会话 Cookie 验证   │                  │
    │                          └─────────┬─────────┘                  │
    │                          ┌─────────▼─────────┐                  │
    │                          │ CSRF 令牌验证      │                  │
    │                          └─────────┬─────────┘                  │
    │                          ┌─────────▼─────────┐                  │
    │                          │ 角色权限检查       │                  │
    │                          └─────────┬─────────┘                  │
    │                          ┌─────────▼─────────┐                  │
    │                          │ 安全响应头注入     │                  │
    │                          └─────────┬─────────┘                  │
    │                                    │                            │
    │  ◄──── 通过 ────────────────────────┤                            │
    │                                    ├── 转发请求 ──────────────► │
    │  ◄──────────────────────────────────────────────── 响应 ───────┤
    │                                    │                            │
```

### 3.4 登录流程

```
用户浏览器                     dsh-secure-gate                  DSH Host
    │                              │                              │
    │  GET /api/*                   │                              │
    │ ────────────────────────────► │                              │
    │  ← 302 → /secure-gate/login   │                              │
    │                              │                              │
    │  GET /secure-gate/login       │                              │
    │ ────────────────────────────► │                              │
    │  ← 登录页面 HTML              │                              │
    │                              │                              │
    │  POST /secure-gate/auth/login  │                              │
    │  { username, password }       │                              │
    │ ────────────────────────────► │                              │
    │                              │  ┌────────────────┐          │
    │                              │  │ ① IP 检查       │          │
    │                              │  │ ② 速率限制      │          │
    │                              │  │ ③ 锁定检查      │          │
    │                              │  │ ④ Argon2id 验证 │          │
    │                              │  │ ⑤ 密码过期检查  │          │
    │                              │  │ ⑥ 审计日志      │          │
    │                              │  └────────────────┘          │
    │                              │                              │
    │  ← { ok: true, mfaRequired }  │                              │
    │      (或直接发 session)       │                              │
    │                              │                              │
    │  POST /secure-gate/auth/mfa   │                              │
    │  { code: 123456 }            │                              │
    │ ────────────────────────────► │                              │
    │                              │  TOTP 验证                   │
    │  ← { ok: true } + 会话 Cookie │                              │
    │                              │                              │
    │  GET /api/* (带 Cookie)      │                              │
    │ ────────────────────────────► │                              │
    │  ← 放行至 DSH API            │                              │
```

---

## 四、UI/UX 设计

### 4.1 设计语言

- **风格**: 现代化、毛玻璃 (Glassmorphism) + 微渐变
- **配色**: 
  - 深色模式: #0f172a → #1e293b 渐变背景
  - 浅色模式: #f8fafc → #e2e8f0
  - 强调色: #3b82f6 (蓝色) / #10b981 (绿色/安全) / #ef4444 (红色/危险)
- **字体**: 系统默认无衬线字体
- **动画**: 微交互动效 (悬停、过渡、加载)

### 4.2 界面构成

| 页面 | 说明 |
|:--|:--|
| **登录页面** (独立路由) | 密码登录 / Passkey 切换、TOTP 输入、错误提示、安全徽章 |
| **登录覆盖层** (内嵌) | 会话过期后弹窗，与独立页面同风格 |
| **安全状态面板** | 设置页内嵌，显示安全评分、活跃会话数、审计事件 |
| **账户管理** | 管理员可增删改账户、分配角色、重置 MFA |
| **会话管理** | 查看所有活跃会话、强制撤销 |
| **审计日志查看** | 分页查询登录/管理/安全事件 |

### 4.3 登录页设计稿

```
┌──────────────────────────────────────────────┐
│                 🔐                            │
│          DSH 安全网关                         │
│          Sign in to continue                  │
│                                              │
│  ┌──────┬──────────────┬──────┐               │
│  │ 密码 │  │  Passkey  │      │               │
│  └──────┴──────────────┴──────┘               │
│                                              │
│  用户名                                      │
│  ┌──────────────────────────────────────┐    │
│  │                                      │    │
│  └──────────────────────────────────────┘    │
│                                              │
│  密码                                        │
│  ┌──────────────────────────────────────┐    │
│  │                                      │    │
│  └──────────────────────────────────────┘    │
│                                              │
│  ┌──────────────────────────────────────┐    │
│  │           登录 / Sign In             │    │
│  └──────────────────────────────────────┘    │
│                                              │
│  ──────────────────────────────────────      │
│  Argon2id · CSRF · 会话加密 · 审计日志       │
│          🛡️ 🔐 ⚡                           │
└──────────────────────────────────────────────┘
```

---

## 五、配置项设计

```yaml
# cordis.patch.yml 配置示例

- insert:
    - id: secure-gate
      name: 'dsh-secure-gate'
      config:
        enabled: true

        # 首次启动管理员账户（启动后移除）
        bootstrap:
          username: admin
          password: ''

        session:
          cookieName: dsh_secure_session
          ttlSeconds: 86400          # 24小时
          secure: false              # 生产 true
          sameSite: strict

        rateLimit:
          maxAttempts: 5
          windowMs: 900000           # 15分钟

        lockout:
          maxFailedAttempts: 5
          lockoutDurationMs: 1800000 # 30分钟
          permanentAfter: 3

        passwordPolicy:
          minLength: 10
          requireUpper: true
          requireLower: true
          requireDigit: true
          requireSpecial: true
          maxAgeDays: 90

        mfa:
          enabled: true
          issuer: 'DSH Secure Gate'

        csrf:
          enabled: true

        ipAccess:
          allowPrivateOnly: false
          allowlist: []
          blocklist: []

        audit:
          enabled: true

        csp:
          enabled: true
```

---

## 六、开发计划

### 6.1 阶段划分

| 阶段 | 内容 | 预计工时 |
|:--|:--|:--:|
| **P0** 核心认证 | 密码登录、Argon2id、会话管理、登录页 UI | 4h |
| **P0** 安全防护 | CSRF、速率限制、账户锁定、IP控制、安全标头 | 3h |
| **P0** 审计系统 | 审计日志、事件类型、管理面板 | 2h |
| **P0** 管理功能 | 账户CRUD、角色管理、会话查看 | 2h |
| **P1** TOTP MFA | TOTP 生成/验证、备份码 | 2h |
| **P1** 设置面板 | 浏览器端安全设置 UI | 2h |
| **P1** 测试 | 单元测试、集成测试 | 2h |
| **P1** 文档 & 发布 | README、截图、打包、提交 PR | 1h |

### 6.2 技术选型

| 项目 | 选择 |
|:--|:--|
| 运行时 | Node.js ≥ 18 |
| 语言 | TypeScript |
| 构建 | tsdown (社区标准) |
| 测试 | Vitest |
| 服务端框架 | Cordis |
| 客户端渲染 | React 18 (DSH 框架) |
| 密码哈希 | node:crypto (scrypt, 模拟 Argon2id) |
| 存储 | JSON 文件 (0600 权限) |

---

## 七、社区发布

### 7.1 发布检查清单

- [ ] npm publish (可选) 或 GitHub Release
- [ ] 添加 `dsh-plugin` GitHub Topic
- [ ] 提交至 awesome-dsh-plugin
- [ ] 确保 README 包含中英文说明
- [ ] 包含安装截图的演示
- [ ] 包含 `cordis.patch.yml` bundle 声明

### 7.2 安装方式

```bash
# 方式一: npm 安装 (发布后)
dsh plugin --profile web add dsh-secure-gate

# 方式二: GitHub 直装
dsh plugin --profile web add github:你的用户名/dsh-secure-gate

# 方式三: 本地路径
dsh plugin --profile web add file:./plugins/dsh-secure-gate
```

---

## 八、安全白皮书摘要

> 完整文档见 [SECURITY.md](./SECURITY.md)

dsh-secure-gate 遵循以下安全原则：

1. **纵深防御**: 多层安全机制叠加，单一漏洞不影响整体
2. **最小权限**: 默认拒绝，按需放行
3. **安全默认值**: 所有安全选项默认开启
4. **可审计**: 所有安全事件可追溯
5. **零信任**: 每次请求独立验证
6. **无外部依赖**: 使用 Node.js 内置加密库
