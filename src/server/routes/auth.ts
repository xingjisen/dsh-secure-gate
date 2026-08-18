/**
 * dsh-secure-gate — 认证路由
 * 
 * 处理登录、登出、MFA 验证、会话状态检查
 */

import type { IncomingMessage, ServerResponse } from 'node:http'
import type { SecureGateConfig, UserRole } from '../../shared/types.js'
import type { Account } from '../../shared/types.js'
import {
  hashPassword, verifyPassword, generateToken, sign, safeEqual
} from '../crypto.js'
import {
  findAccount, hasAccounts, upsertAccount, recordSession, removeSession,
  getLockouts, setLockout, clearLockout, auditLog, loadStore,
} from '../store.js'
import { renderLoginPage } from '../middleware/login-page.js'

export interface AuthService {
  requireAuth: (req: IncomingMessage) => { ok: boolean; user?: { username: string; role: UserRole }; error?: string }
  config: SecureGateConfig
  csrf: { validate: (req: IncomingMessage) => boolean; token: () => string }
}

/**
 * 注册所有认证路由
 */
export function registerAuthRoutes(
  webServer: any,
  config: SecureGateConfig,
  secret: string,
  authService: AuthService,
) {
  const { csrf } = authService

  // ── POST /secure-gate/auth/login ──────────────────────
  webServer.post('/secure-gate/auth/login', async (req: IncomingMessage, res: ServerResponse) => {
    try {
      const ip = (req as any).ip || req.socket?.remoteAddress || '0.0.0.0'
      const body = await parseBody(req)
      const username = String(body?.username || '').trim()
      const password = String(body?.password || '')

      if (!username || !password) {
        return sendJson(res, 400, { ok: false, error: '请输入用户名和密码' })
      }

      // 速率限制 & 锁定检查
      const rateCheck = checkRateLimit(username, config)
      if (!rateCheck.allowed) {
        auditLog('login_rate_limited', { username, ip, reason: rateCheck.reason })
        return sendJson(res, 429, { ok: false, error: rateCheck.reason })
      }

      const account = findAccount(username)
      if (!account) {
        recordAttempt(username, false)
        auditLog('login_failed', { username, ip, reason: '用户不存在' })
        return sendJson(res, 401, { ok: false, error: '用户名或密码错误' })
      }

      if (account.locked) {
        auditLog('login_blocked_locked', { username, ip })
        return sendJson(res, 403, { ok: false, error: '账户已锁定，请联系管理员' })
      }

      if (!verifyPassword(password, account.passwordHash)) {
        recordAttempt(username, false)
        auditLog('login_failed', { username, ip, reason: '密码错误' })
        return sendJson(res, 401, { ok: false, error: '用户名或密码错误' })
      }

      // 密码过期检查
      if (account.passwordExpiresAt && Date.now() > account.passwordExpiresAt) {
        return sendJson(res, 401, {
          ok: false, error: '密码已过期，请重置密码', passwordExpired: true,
        })
      }

      recordAttempt(username, true)
      auditLog('login_success', { username, ip })

      // MFA 检查
      if (account.totpVerified && account.totpSecret) {
        const challengeToken = generateToken(32)
        return sendJson(res, 200, { ok: true, mfaRequired: true, challenge: challengeToken })
      }

      // 颁发会话
      issueSessionCookie(res, account, secret, config)
      const csrfToken = csrf.token()
      setCookie(res, config.csrf.cookieName || 'dsh_csrf', csrfToken, {
        path: '/', sameSite: 'strict', httpOnly: false,
      })

      sendJson(res, 200, {
        ok: true,
        user: { username: account.username, role: account.role },
      })
    } catch (e: any) {
      auditLog('login_error', { error: e.message })
      sendJson(res, 500, { ok: false, error: '服务器内部错误' })
    }
  })

  // ── POST /secure-gate/auth/mfa ────────────────────────
  webServer.post('/secure-gate/auth/mfa', async (req: IncomingMessage, res: ServerResponse) => {
    const body = await parseBody(req)
    sendJson(res, 501, { ok: false, error: 'TOTP 两步验证功能开发中' })
  })

  // ── GET /secure-gate/auth/me ──────────────────────────
  webServer.get('/secure-gate/auth/me', (req: IncomingMessage, res: ServerResponse) => {
    const auth = authService.requireAuth(req)
    if (auth.ok) {
      sendJson(res, 200, { ok: true, user: auth.user })
    } else {
      sendJson(res, 401, { ok: false })
    }
  })

  // ── POST /secure-gate/auth/logout ─────────────────────
  webServer.post('/secure-gate/auth/logout', (req: IncomingMessage, res: ServerResponse) => {
    const token = readCookie(req, config.session.cookieName)
    if (token) {
      const tokenHash = sign(secret, token).toString('hex')
      removeSession(tokenHash)
    }
    setCookie(res, config.session.cookieName, '', { maxAge: 0, path: '/' })
    setCookie(res, config.csrf.cookieName || 'dsh_csrf', '', { maxAge: 0, path: '/' })
    sendJson(res, 200, { ok: true })
  })

  // ── GET /secure-gate/login (登录页面) ────────────────
  webServer.get('/secure-gate/login', (req: IncomingMessage, res: ServerResponse) => {
    const locale = detectLocale(req)
    const html = renderLoginPage({
      locale,
      step: 'login',
      bootstrap: !hasAccounts(),
    })
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
    res.end(html)
  })
}

// ── 辅助函数 ─────────────────────────────────────────

function issueSessionCookie(
  res: ServerResponse,
  account: Account,
  secret: string,
  config: SecureGateConfig,
) {
  const payload = {
    sub: account.username,
    role: account.role,
    iat: Date.now(),
    exp: Date.now() + config.session.ttlSeconds * 1000,
    id: generateToken(16),
  }
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url')
  const sig = sign(secret, `v2.${encoded}`).toString('base64url')
  const token = `v2.${encoded}.${sig}`

  const tokenHash = sign(secret, token).toString('hex')
  recordSession(tokenHash, {
    username: account.username,
    role: account.role,
    userAgent: '',
    ip: '',
  })

  setCookie(res, config.session.cookieName, token, {
    maxAge: config.session.ttlSeconds,
    path: '/',
    httpOnly: true,
    secure: config.session.secure,
    sameSite: config.session.sameSite,
  })
}

// ── 速率限制 ─────────────────────────────────────────

const LOCKOUT_KEY_PREFIX = 'login:'

function checkRateLimit(
  username: string,
  config: SecureGateConfig,
): { allowed: boolean; reason?: string } {
  const lockouts = getLockouts()
  const now = Date.now()
  const key = LOCKOUT_KEY_PREFIX + username
  const entry = lockouts[key]

  if (entry?.permanent) {
    return { allowed: false, reason: '账户已永久锁定，请联系管理员' }
  }

  if (entry?.lockedUntil && entry.lockedUntil > now) {
    const remaining = Math.ceil((entry.lockedUntil - now) / 1000 / 60)
    return { allowed: false, reason: `账户已锁定，${remaining} 分钟后重试` }
  }

  if (entry?.windowStart && now - entry.windowStart < config.rateLimit.windowMs) {
    if (entry.attempts >= config.rateLimit.maxAttempts) {
      const count = (entry.lockoutCount || 0) + 1
      if (count >= config.lockout.permanentAfter) {
        setLockout(key, { permanent: true, lockoutCount: count })
        auditLog('account_permanently_locked', { username, reason: '连续多次锁定' })
        return { allowed: false, reason: '账户已永久锁定，请联系管理员' }
      }
      setLockout(key, {
        lockedUntil: now + config.lockout.duration,
        lockoutCount: count,
      })
      auditLog('account_locked', { username, duration: config.lockout.duration })
      return { allowed: false, reason: '登录尝试过多，账户已锁定 30 分钟' }
    }
  } else {
    clearLockout(key)
  }

  return { allowed: true }
}

function recordAttempt(username: string, success: boolean) {
  if (success) {
    clearLockout(LOCKOUT_KEY_PREFIX + username)
    return
  }
  const lockouts = getLockouts()
  const now = Date.now()
  const key = LOCKOUT_KEY_PREFIX + username
  const entry = lockouts[key] || { attempts: 0, windowStart: now }
  entry.attempts = (entry.attempts || 0) + 1
  if (!entry.windowStart) entry.windowStart = now
  setLockout(key, entry)
}

// ── 通用工具 ─────────────────────────────────────────

function parseBody(req: IncomingMessage): Promise<any> {
  return new Promise((resolve) => {
    let body = ''
    req.on('data', (chunk) => { body += chunk })
    req.on('end', () => {
      try { resolve(JSON.parse(body)) } catch { resolve({}) }
    })
    req.on('error', () => resolve({}))
  })
}

function sendJson(res: ServerResponse, status: number, data: any) {
  res.writeHead(status, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify(data))
}

function readCookie(req: IncomingMessage, name: string): string | null {
  if (!req.headers?.cookie) return null
  for (const part of req.headers.cookie.split(';')) {
    const [k, ...v] = part.trim().split('=')
    if (k === name) return v.join('=')
  }
  return null
}

export function setCookie(
  res: ServerResponse,
  name: string,
  value: string,
  opts: { maxAge?: number; path?: string; httpOnly?: boolean; secure?: boolean; sameSite?: string } = {},
) {
  const parts = [name + '=' + value]
  if (opts.maxAge !== undefined) parts.push('Max-Age=' + opts.maxAge)
  if (opts.path) parts.push('Path=' + opts.path)
  if (opts.httpOnly) parts.push('HttpOnly')
  if (opts.secure) parts.push('Secure')
  if (opts.sameSite) parts.push('SameSite=' + opts.sameSite)
  const existing = res.getHeader('Set-Cookie') as string | string[] | undefined
  const newCookie = parts.join('; ')
  if (existing) {
    res.setHeader('Set-Cookie', [...(Array.isArray(existing) ? existing : [existing]), newCookie])
  } else {
    res.setHeader('Set-Cookie', newCookie)
  }
}

export { readCookie, parseBody, sendJson }

function detectLocale(req: IncomingMessage): 'zh' | 'en' {
  const accept = req.headers?.['accept-language'] || ''
  return accept.startsWith('zh') ? 'zh' : 'en'
}
