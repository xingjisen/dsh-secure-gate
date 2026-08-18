/**
 * dsh-secure-gate — 高级安全认证网关
 * 
 * DeepSeek Harness Cordis 插件入口
 * 为 DSH Web UI 提供企业级认证与访问控制
 */

import type { Context } from '@deepseek-ai/cordis'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { SecureGateConfig, UserRole, SessionPayload } from '../shared/types.js'
import { timingSafeEqual } from 'node:crypto'

import {
  loadStore, saveStore, getStoreSecret, hasAccounts, upsertAccount,
  generateBackupCodes, hashBackupCode, auditLog,
  loadSessions, saveSessions, getSessions, pruneExpiredSessions,
} from './store.js'
import {
  hashPassword, generateToken, sign, checkPasswordStrength, safeEqual,
} from './crypto.js'
import { registerAuthRoutes, readCookie, setCookie, sendJson } from './routes/auth.js'
import { getRoleDenyPatterns } from './roles.js'
import { installSecurityHeaders } from './headers.js'

export const name = 'secure-gate'
export const inject = ['webServer']

export function apply(ctx: Context, config: Partial<SecureGateConfig> = {}) {
  const cfg = parseConfig(config)
  loadStore()
  const secret = getStoreSecret()
  loadSessions()
  pruneExpiredSessions(cfg.session.ttlSeconds * 1000 * 2)

  // ── 启动引导 ────────────────────────────────────────
  if (cfg.bootstrap?.username && cfg.bootstrap?.password) {
    const username = cfg.bootstrap.username.trim()
    const password = cfg.bootstrap.password
    if (username && password && !hasAccounts()) {
      const strength = checkPasswordStrength(password, cfg.passwordPolicy)
      if (!strength.ok) {
        throw new Error(`[secure-gate] 启动密码不满足安全策略: ${strength.errors.join(', ')}`)
      }
      const hash = hashPassword(password)
      const codes = generateBackupCodes(8)
      upsertAccount({
        username,
        role: 'admin' as UserRole,
        passwordHash: hash,
        backupCodes: codes.map(c => ({ code: hashBackupCode(c), used: false })),
        createdAt: Date.now(),
      })
      auditLog('bootstrap_admin_created', { username })
      ctx.logger.info('[secure-gate] 管理员账户 "%s" 已创建 — 请立即登录并在设置中修改密码', username)
    }
  }

  // Seed 配置账户
  for (const seed of cfg.accounts || []) {
    const existing = findAccount(seed.username)
    if (existing) continue
    upsertAccount({
      username: seed.username,
      role: (seed.role || 'user') as UserRole,
      passwordHash: seed.password.startsWith('A2$') ? seed.password : hashPassword(seed.password),
    })
  }

  const webServer = ctx.webServer
  if (!webServer) {
    ctx.logger.error('[secure-gate] webServer 服务未就绪')
    return
  }

  // ── 认证服务 ────────────────────────────────────────
  const authService = {
    requireAuth: (req: IncomingMessage) => requireAuth(req, cfg, secret),
    config: cfg,
    csrf: {
      validate: (req: IncomingMessage) => validateCsrf(req, cfg),
      token: () => generateToken(32),
    },
  }

  // 注册路由
  registerAuthRoutes(webServer, cfg, secret, authService)

  // 安装请求拦截门
  if (cfg.enabled) {
    installGate(webServer, cfg, secret, authService)
  }

  // 安全响应头
  installSecurityHeaders(webServer, cfg)

  ctx.logger.info('[secure-gate] 🛡️  安全网关已激活')
  ctx.logger.info('  ├─ 账户: %d 个', (await import('./store.js')).getAccounts().length)
  ctx.logger.info('  ├─ CSRF: %s', cfg.csrf.enabled ? '已启用' : '已禁用')
  ctx.logger.info('  ├─ IP 控制: %s', cfg.ipAccess.allowPrivateOnly ? '仅内网' : cfg.ipAccess.allowlist.length ? '白名单' : '开放')
  ctx.logger.info('  └─ CSP: %s', cfg.csp.enabled ? '已启用' : '已禁用')

  // 清理
  ctx.on('dispose', () => {
    saveStore()
    saveSessions()
  })
}

// ── 配置解析 ──────────────────────────────────────────

function parseConfig(cfg: Partial<SecureGateConfig>): SecureGateConfig {
  return {
    enabled: cfg.enabled !== false,
    bootstrap: cfg.bootstrap,
    session: {
      cookieName: cfg.session?.cookieName || 'dsh_secure_session',
      ttlSeconds: cfg.session?.ttlSeconds || 86400,
      renewThreshold: cfg.session?.renewThreshold || 3600,
      secure: cfg.session?.secure ?? false,
      sameSite: cfg.session?.sameSite || 'strict',
    },
    rateLimit: {
      maxAttempts: cfg.rateLimit?.maxAttempts || 5,
      windowMs: cfg.rateLimit?.windowMs || 900000,
    },
    lockout: {
      maxFailed: cfg.lockout?.maxFailedAttempts || 5,
      duration: cfg.lockout?.lockoutDurationMs || 1800000,
      permanentAfter: cfg.lockout?.permanentAfter || 3,
    },
    passwordPolicy: {
      minLength: cfg.passwordPolicy?.minLength ?? 10,
      requireUpper: cfg.passwordPolicy?.requireUpper ?? true,
      requireLower: cfg.passwordPolicy?.requireLower ?? true,
      requireDigit: cfg.passwordPolicy?.requireDigit ?? true,
      requireSpecial: cfg.passwordPolicy?.requireSpecial ?? true,
      maxAgeDays: cfg.passwordPolicy?.maxAgeDays ?? 90,
    },
    csrf: { enabled: cfg.csrf?.enabled !== false },
    ipAccess: {
      allowPrivateOnly: cfg.ipAccess?.allowPrivateOnly || false,
      allowlist: cfg.ipAccess?.allowlist || [],
      blocklist: cfg.ipAccess?.blocklist || [],
    },
    enforceRoles: cfg.enforceRoles !== false,
    csp: { enabled: cfg.csp?.enabled !== false },
    audit: cfg.audit !== false,
    accounts: cfg.accounts || [],
  }
}

// ── 会话验证 ──────────────────────────────────────────

function requireAuth(
  req: IncomingMessage,
  cfg: SecureGateConfig,
  secret: string,
) {
  if (!cfg.enabled) {
    return { ok: true, user: { username: 'local', role: 'admin' as UserRole } }
  }

  const token = readCookie(req, cfg.session.cookieName)
  if (!token) return { ok: false }

  const session = verifySession(token, secret, cfg)
  if (!session) return { ok: false }

  const { findAccount } = require('./store.js')
  const account = findAccount(session.username)
  if (!account) return { ok: false }
  if (account.locked) return { ok: false, error: '账户已锁定' }

  return { ok: true, user: { username: account.username, role: account.role } }
}

function verifySession(
  token: string,
  secret: string,
  cfg: SecureGateConfig,
): SessionPayload | null {
  const parts = token.split('.')
  if (parts.length !== 3 || parts[0] !== 'v2') return null

  const [, encoded, sigB64] = parts
  const expected = sign(secret, `v2.${encoded}`)

  let sig: Buffer
  try { sig = Buffer.from(sigB64, 'base64url') } catch { return null }
  try {
    if (!timingSafeEqual(sig, expected)) return null
  } catch { return null }

  let payload: any
  try { payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')) } catch { return null }
  if (!payload?.sub || !payload?.exp || payload.exp <= Date.now()) return null

  return payload as SessionPayload
}

// ── CSRF 保护 ─────────────────────────────────────────

function validateCsrf(req: IncomingMessage, cfg: SecureGateConfig): boolean {
  if (!cfg.csrf.enabled) return true
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method || '')) return true
  const cookieName = cfg.csrf.cookieName || 'dsh_csrf'
  const headerName = (cfg.csrf.headerName || 'X-CSRF-Token').toLowerCase()
  const headerToken = (req.headers as any)[headerName]
  const cookieToken = readCookie(req, cookieName)
  if (!headerToken || !cookieToken) return false
  return safeEqual(String(headerToken), cookieToken)
}

// ── 请求拦截门 ───────────────────────────────────────

function installGate(
  webServer: any,
  cfg: SecureGateConfig,
  secret: string,
  authService: any,
) {
  const publicPaths = [
    '/secure-gate/auth/login',
    '/secure-gate/auth/logout',
    '/secure-gate/auth/me',
    '/secure-gate/auth/mfa',
    '/secure-gate/login',
    '/favicon.ico',
  ]

  // 当 webServer 处理请求时插入门检查
  const originalListen = webServer.server?.listen
  if (webServer._router) {
    patchRouter(webServer._router, publicPaths, cfg, authService)
  }
}

function patchRouter(router: any, publicPaths: string[], cfg: SecureGateConfig, authService: any) {
  if (!router?.stack) return

  for (const layer of router.stack) {
    if (!layer.route) continue
    const path = layer.route.path || ''
    if (publicPaths.includes(path)) continue

    for (const method of ['get', 'post', 'put', 'delete', 'patch']) {
      const handlers = layer.route.stack?.filter((s: any) => s.method === method)
      if (!handlers?.length) continue

      for (const handler of handlers) {
        const original = handler.handle
        handler.handle = (req: IncomingMessage, res: ServerResponse, next: Function) => {
          // IP 检查
          const ip = (req as any).ip || req.socket?.remoteAddress || ''
          if (cfg.ipAccess.blocklist.includes(ip)) {
            res.writeHead(403)
            return res.end('IP blocked')
          }
          if (cfg.ipAccess.allowlist.length > 0 && !cfg.ipAccess.allowlist.includes(ip)) {
            res.writeHead(403)
            return res.end('IP not allowed')
          }

          // 会话检查
          const auth = authService.requireAuth(req)
          if (!auth.ok) {
            if (req.headers?.accept?.includes('text/html')) {
              res.writeHead(302, { Location: '/secure-gate/login' })
              return res.end()
            }
            auditLog('gate_reject', { path: req.url, ip, reason: 'unauthenticated' })
            res.writeHead(401, { 'Content-Type': 'application/json' })
            return res.end(JSON.stringify({ ok: false, error: 'Unauthorized' }))
          }

          // 角色检查
          if (cfg.enforceRoles && auth.user?.role !== 'admin') {
            const denyPatterns = getRoleDenyPatterns(auth.user?.role || 'user')
            if (denyPatterns.some((p: string) => req.url?.startsWith(p))) {
              auditLog('gate_role_denied', {
                username: auth.user?.username, path: req.url, role: auth.user?.role,
              })
              res.writeHead(403, { 'Content-Type': 'application/json' })
              return res.end(JSON.stringify({ ok: false, error: 'Insufficient permissions' }))
            }
          }

          return original(req, res, next)
        }
      }
    }
  }
}

// Re-export for the auth routes module
import { findAccount } from './store.js'
export { findAccount }
