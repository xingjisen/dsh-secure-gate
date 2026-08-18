# 安全白皮书 — dsh-secure-gate

> 本文档详细说明了 dsh-secure-gate 的安全架构、实现细节和最佳实践。

---

## 安全原则

1. **纵深防御** — 多层安全控制叠加，单点失效不影响整体
2. **最小权限** — 默认拒绝，按需放行
3. **安全默认值** — 所有安全选项默认开启
4. **零信任** — 每次请求独立验证，不依赖网络位置
5. **无外部依赖** — 使用 Node.js 内置加密库，无第三方安全风险

---

## 密码哈希

| 项目 | 值 |
|:--|:--|
| 算法 | Argon2id (通过 scrypt 模拟) |
| N (CPU/内存开销) | 2^17 = 131,072 |
| r (块大小) | 8 |
| p (并行度) | 1 |
| 输出长度 | 64 bytes (512-bit) |
| 盐长度 | 32 bytes (随机) |
| 最大内存 | 128 MB |
| 存储格式 | `A2$${base64url(salt)}$${base64url(hash)}` |

### 密码策略

- 最小长度: 10 字符（可配置）
- 必需: 大写字母、小写字母、数字、特殊字符
- 密码过期: 90 天（可配置）
- 历史密码: 禁止重复使用（即将推出）

---

## 会话安全

- **签名算法**: HMAC-SHA256
- **Token 格式**: `v2.${base64url(payload)}.${base64url(sig)}`
- **Cookie 属性**: HttpOnly, SameSite=Strict
- **有效期**: 24 小时（可配置）
- **自动续期**: 过期前 1 小时自动刷新
- **服务端撤销**: 支持管理员强制终止会话

---

## CSRF 保护

采用双重提交 Cookie 模式（Double Submit Cookie）:

1. 登录成功后设置非 HttpOnly 的 CSRF Cookie（随机令牌）
2. 所有修改请求（POST/PUT/DELETE）需要在 Header 中携带 `X-CSRF-Token`
3. 服务端使用常量时间比较验证头值与 Cookie 值是否匹配
4. GET/HEAD/OPTIONS 请求免检

---

## 速率限制与锁定

1. 记录每个用户名 + IP 的失败尝试
2. 15 分钟内 5 次失败后触发锁定期
3. 锁定期: 30 分钟
4. 连续 3 次锁定期后触发永久锁定
5. 永久锁定需管理员手动解锁

---

## 安全响应头

| 标头 | 值 |
|:--|:--|
| Content-Security-Policy | 限制脚本/样式/图片来源 |
| X-Content-Type-Options | nosniff |
| X-Frame-Options | DENY |
| X-XSS-Protection | 1; mode=block |
| Strict-Transport-Security | max-age=31536000 |
| Referrer-Policy | strict-origin-when-cross-origin |
| Permissions-Policy | 禁用摄像头/麦克风/地理位置 |

---

## 审计日志

- 格式: JSON Lines (每行一个 JSON 对象)
- 存储: `~/.dsh/auth/audit.log` (0600 权限)
- 记录事件: 登录成功/失败、账户锁定/解锁、账户创建/删除、角色变更、会话创建/撤销、CSRF 拒绝

---

## 安全建议

### 生产环境部署

1. 设置 `session.secure: true` 启用 HTTPS Cookie
2. 配置 IP 白名单限制访问来源
3. 定期审查审计日志
4. 启用 TOTP 两步验证
5. 设置强密码策略
