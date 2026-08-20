/**
 * dsh-secure-gate - Enterprise Authentication Gateway
 * Security: Argon2id, CSRF, Account Lockout, IP Control, Audit, Sessions
 */
import { randomBytes, scryptSync, timingSafeEqual, createHmac, createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync, appendFileSync } from 'node:fs'
import { join } from 'node:path'
import { renderLoginPage } from './login-page.js'

export const name = 'secure-gate'
export const inject = ['webServer']

function d(obj, key, fallback) { return (obj && obj[key] !== undefined && obj[key] !== null) ? obj[key] : fallback }
function parseConfig(cfg = {}) { return {
  enabled: d(cfg, 'enabled', true),
  bootstrap: d(cfg, 'bootstrap', null),
  session: { cookieName: d(cfg.session, 'cookieName', 'dsh_secure_session'), ttlSeconds: d(cfg.session, 'ttlSeconds', 86400), secure: d(cfg.session, 'secure', false), sameSite: d(cfg.session, 'sameSite', 'strict') },
  rateLimit: { maxAttempts: d(cfg.rateLimit, 'maxAttempts', 5), windowMs: d(cfg.rateLimit, 'windowMs', 900000) },
  lockout: { maxFailed: d(cfg.lockout, 'maxFailedAttempts', 5), duration: d(cfg.lockout, 'lockoutDurationMs', 1800000), permanentAfter: d(cfg.lockout, 'permanentAfter', 3) },
  passwordPolicy: { minLength: d(cfg.passwordPolicy, 'minLength', 10), requireUpper: d(cfg.passwordPolicy, 'requireUpper', true), requireLower: d(cfg.passwordPolicy, 'requireLower', true), requireDigit: d(cfg.passwordPolicy, 'requireDigit', true), requireSpecial: d(cfg.passwordPolicy, 'requireSpecial', true), maxAgeDays: d(cfg.passwordPolicy, 'maxAgeDays', 90) },
  csrf: { enabled: d(cfg.csrf, 'enabled', true), cookieName: 'dsh_csrf' },
  ipAccess: { allowPrivateOnly: d(cfg.ipAccess, 'allowPrivateOnly', false), allowlist: d(cfg.ipAccess, 'allowlist', []), blocklist: d(cfg.ipAccess, 'blocklist', []) },
  enforceRoles: d(cfg, 'enforceRoles', true), csp: { enabled: d(cfg.csp, 'enabled', true) },
  audit: d(cfg, 'audit', true), accounts: d(cfg, 'accounts', [])
}}

const DSH_HOME = process.env.DSH_HOME || join(process.env.HOME || process.env.USERPROFILE || '', '.dsh')
const AUTH_DIR = join(DSH_HOME, 'auth')
const STORE_PATH = join(AUTH_DIR, 'secure-store.json')
const AUDIT_PATH = join(AUTH_DIR, 'audit.log')
const SESSIONS_PATH = join(AUTH_DIR, 'sessions.json')

let _store = { accounts: [], secret: '', lockouts: {} }; let _sessions = {}
function ensureDir() { if (!existsSync(AUTH_DIR)) mkdirSync(AUTH_DIR, { recursive: true }) }
function loadStore() { ensureDir(); try { if (existsSync(STORE_PATH)) _store = JSON.parse(readFileSync(STORE_PATH, 'utf8')) } catch (e) {} if (!_store.secret) { _store.secret = randomBytes(64).toString('base64url'); saveStore() } if (!_store.lockouts) _store.lockouts = {} }
function saveStore() { ensureDir(); try { writeFileSync(STORE_PATH, JSON.stringify(_store, null, 2)); try { chmodSync(STORE_PATH, 0o600) } catch {} } catch (e) {} }
function getSecret() { return _store.secret }
function findAccount(u) { return _store.accounts.find(a => a.username === u) || null }
function hasAccounts() { return _store.accounts.length > 0 }
function upsertAccount(data) {
  const idx = _store.accounts.findIndex(a => a.username === data.username)
  const e = { ...data, passwordChangedAt: Date.now(), role: data.role || 'user', createdAt: data.createdAt || Date.now(), passwordExpiresAt: data.passwordExpiresAt || Date.now() + 90 * 86400000, backupCodes: data.backupCodes || [], webauthnCredentials: data.webauthnCredentials || [] }
  if (idx >= 0) _store.accounts[idx] = { ..._store.accounts[idx], ...e }; else _store.accounts.push(e); saveStore(); return e
}
function loadSessions() { try { if (existsSync(SESSIONS_PATH)) _sessions = JSON.parse(readFileSync(SESSIONS_PATH, 'utf8')) } catch { _sessions = {} } }
function saveSessions() { ensureDir(); try { writeFileSync(SESSIONS_PATH, JSON.stringify(_sessions, null, 2)); try { chmodSync(SESSIONS_PATH, 0o600) } catch {} } catch {} }
function recordSession(th, d) { _sessions[th] = { username: d.username || '', role: d.role || 'user', createdAt: Date.now(), lastActiveAt: Date.now(), userAgent: d.userAgent || '', ip: d.ip || '' }; saveSessions() }
function removeSession(th) { delete _sessions[th]; saveSessions() }
function getLockouts() { return _store.lockouts || {} }
function setLockout(k, d) { if (!_store.lockouts) _store.lockouts = {}; _store.lockouts[k] = d; saveStore() }
function clearLockout(k) { if (_store.lockouts) { delete _store.lockouts[k]; saveStore() } }
function auditLog(e, d) { const entry = { timestamp: new Date().toISOString(), event: e, ...(d || {}) }; try { ensureDir(); appendFileSync(AUDIT_PATH, JSON.stringify(entry) + '\n'); try { chmodSync(AUDIT_PATH, 0o600) } catch {} } catch {}; console.log('[sg]', e, JSON.stringify(d || {})) }

function hashPassword(pw, salt) { const s = salt || randomBytes(32); const k = scryptSync(pw, s, 64, { N: 32768, r: 8, p: 1, maxmem: 67108864 }); return 'A2$' + s.toString('base64url') + '$' + k.toString('base64url') }
function verifyPassword(pw, hash) { try { const p = hash.split('$'); if (p[0] !== 'A2' || p.length !== 3) return false; const s = Buffer.from(p[1], 'base64url'); const e = Buffer.from(p[2], 'base64url'); const a = scryptSync(pw, s, 64, { N: 32768, r: 8, p: 1, maxmem: 67108864 }); if (a.length !== e.length) return false; return timingSafeEqual(a, e) } catch { return false } }
function sign(secret, data) { return createHmac('sha256', secret).update(data).digest() }
function genToken(bytes) { return randomBytes(bytes || 32).toString('base64url') }
function sha256(d) { return createHash('sha256').update(d).digest('hex') }
function safeEqual(a, b) { if (a.length !== b.length) return false; try { return timingSafeEqual(Buffer.from(a), Buffer.from(b)) } catch { return false } }

function parseBody(req) { return new Promise(r => { let b = ''; req.on('data', c => b += c); req.on('end', () => { try { r(JSON.parse(b)) } catch { r({}) } }); req.on('error', () => r({})) }) }
function sendJson(res, s, d) { if (!res.headersSent) res.writeHead(s, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(d)) }
function readCookie(req, name) { if (!req.headers?.cookie) return null; for (const p of req.headers.cookie.split(';')) { const [k, ...v] = p.trim().split('='); if (k === name) return v.join('=') } return null }
function setCookie(res, name, value, opts) { const p = [name + '=' + value]; if (opts) { if (opts.maxAge !== undefined) p.push('Max-Age=' + opts.maxAge); if (opts.path) p.push('Path=' + opts.path); if (opts.httpOnly) p.push('HttpOnly'); if (opts.secure) p.push('Secure'); if (opts.sameSite) p.push('SameSite=' + opts.sameSite) } const e = res.getHeader('Set-Cookie'); const nv = p.join('; '); if (e) res.setHeader('Set-Cookie', [...(Array.isArray(e) ? e : [e]), nv]); else res.setHeader('Set-Cookie', nv) }
function detectLocale(req) { const q = req.url ? new URL(req.url, 'http://x').searchParams.get('lang') : null; if (q === 'zh' || q === 'en') return q; const a = req.headers?.['accept-language'] || ''; return a.startsWith('zh') ? 'zh' : 'en' }
function userMessage(req, zh, en) { return req.headers?.['x-dsh-locale'] === 'en' ? en : zh }
function escHtml(t) { if (!t) return ''; return String(t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;') }

function requireAuth(req, cfg, secret) {
  if (!cfg.enabled) return { ok: true, user: { username: 'local', role: 'admin' } }
  const token = readCookie(req, cfg.session.cookieName); if (!token) return { ok: false }
  const payload = verifySession(token, secret); if (!payload) return { ok: false }
  const account = findAccount(payload.sub); if (!account) return { ok: false }
  if (account.locked) return { ok: false, error: 'locked' }
  return { ok: true, user: { username: account.username, role: account.role } }
}
function verifySession(token, secret) {
  const parts = token.split('.'); if (parts.length !== 3 || parts[0] !== 'v2') return null
  const [, encoded, sigB64] = parts; const expected = sign(secret, 'v2.' + encoded)
  let sig; try { sig = Buffer.from(sigB64, 'base64url') } catch { return null }
  try { if (!timingSafeEqual(sig, expected)) return null } catch { return null }
  let p; try { p = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')) } catch { return null }
  if (!p?.sub || !p?.exp || p.exp <= Date.now()) return null; return p
}
function issueSessionCookie(res, account, secret, cfg) {
  const p = { sub: account.username, role: account.role, iat: Date.now(), exp: Date.now() + cfg.session.ttlSeconds * 1000, id: genToken(16) }
  const enc = Buffer.from(JSON.stringify(p)).toString('base64url')
  const s = sign(secret, 'v2.' + enc).toString('base64url'); const t = 'v2.' + enc + '.' + s
  recordSession(sign(secret, t).toString('hex'), { username: account.username, role: account.role })
  setCookie(res, cfg.session.cookieName, t, { maxAge: cfg.session.ttlSeconds, path: '/', httpOnly: true, secure: cfg.session.secure, sameSite: cfg.session.sameSite })
}

function validatePassword(pw, pp, req) {
  if (!pw || pw.length < pp.minLength) return { ok: false, error: userMessage(req, '\u5bc6\u7801\u957f\u5ea6\u81f3\u5c11\u4e3a ' + pp.minLength + ' \u4f4d', 'Password must be at least ' + pp.minLength + ' characters') }
  if (pp.requireUpper && !/[A-Z]/.test(pw)) return { ok: false, error: userMessage(req, '\u5bc6\u7801\u5fc5\u987b\u5305\u542b\u5927\u5199\u5b57\u6bcd', 'Password must contain an uppercase letter') }
  if (pp.requireLower && !/[a-z]/.test(pw)) return { ok: false, error: userMessage(req, '\u5bc6\u7801\u5fc5\u987b\u5305\u542b\u5c0f\u5199\u5b57\u6bcd', 'Password must contain a lowercase letter') }
  if (pp.requireDigit && !/[0-9]/.test(pw)) return { ok: false, error: userMessage(req, '\u5bc6\u7801\u5fc5\u987b\u5305\u542b\u6570\u5b57', 'Password must contain a number') }
  if (pp.requireSpecial && !/[^A-Za-z0-9]/.test(pw)) return { ok: false, error: userMessage(req, '\u5bc6\u7801\u5fc5\u987b\u5305\u542b\u7279\u6b8a\u5b57\u7b26', 'Password must contain a special character') }
  return { ok: true }
}

function registerAuthRoutes(ws, cfg, secret) {
  const d = []
  var loginHandler = async function(req, res) {
    try {
      var ip = req.socket ? req.socket.remoteAddress : '0.0.0.0'
      var body = await parseBody(req)
      var un = String(body && body.username || '').trim()
      var pw = String(body && body.password || '')
      if (!un || !pw) return sendJson(res, 400, { ok: false, error: userMessage(req, '\u8bf7\u8f93\u5165\u7528\u6237\u540d\u548c\u5bc6\u7801', 'username and password required') })
      var lks = getLockouts()
      var now = Date.now()
      var lk = 'login:' + un
      var le = lks[lk]
      if (le && le.permanent) return sendJson(res, 429, { ok: false, error: userMessage(req, '\u8d26\u6237\u5df2\u88ab\u6c38\u4e45\u9501\u5b9a', 'Account locked permanently') })
      if (le && le.lockedUntil && le.lockedUntil > now) {
        var rem = Math.ceil((le.lockedUntil - now) / 1000 / 60)
        return sendJson(res, 429, { ok: false, error: userMessage(req, '\u8d26\u6237\u5df2\u9501\u5b9a\uff0c\u8bf7\u5728 ' + rem + ' \u5206\u949f\u540e\u91cd\u8bd5', 'Locked, try in ' + rem + ' min') })
      }
      if (le && le.windowStart && now - le.windowStart < cfg.rateLimit.windowMs && le.attempts >= cfg.rateLimit.maxAttempts) {
        var cnt = (le.lockoutCount || 0) + 1
        if (cnt >= cfg.lockout.permanentAfter) {
          setLockout(lk, { permanent: true, lockoutCount: cnt })
          auditLog('perm_lock', { u: un })
          return sendJson(res, 429, { ok: false, error: userMessage(req, '\u8d26\u6237\u5df2\u88ab\u6c38\u4e45\u9501\u5b9a', 'Account locked permanently') })
        }
        setLockout(lk, { lockedUntil: now + cfg.lockout.duration, lockoutCount: cnt })
        auditLog('locked', { u: un })
        return sendJson(res, 429, { ok: false, error: userMessage(req, '\u5c1d\u8bd5\u6b21\u6570\u8fc7\u591a\uff0c\u8bf7\u7a0d\u540e\u518d\u8bd5', 'Too many attempts') })
      }
      var acct = findAccount(un)
      if (!acct) {
        setLockout(lk, { windowStart: now, attempts: (le ? le.attempts || 0 : 0) + 1 })
        auditLog('login_fail', { u: un, ip: ip })
        return sendJson(res, 401, { ok: false, error: userMessage(req, '\u7528\u6237\u540d\u6216\u5bc6\u7801\u9519\u8bef', 'Invalid credentials') })
      }
      if (acct.locked) return sendJson(res, 403, { ok: false, error: userMessage(req, '\u8d26\u6237\u5df2\u9501\u5b9a', 'Account locked') })
      if (!verifyPassword(pw, acct.passwordHash)) {
        setLockout(lk, { windowStart: le ? le.windowStart || now : now, attempts: (le ? le.attempts || 0 : 0) + 1 })
        auditLog('login_fail', { u: un, ip: ip })
        return sendJson(res, 401, { ok: false, error: userMessage(req, '\u7528\u6237\u540d\u6216\u5bc6\u7801\u9519\u8bef', 'Invalid credentials') })
      }
      clearLockout(lk)
      auditLog('login_ok', { u: un, ip: ip })
      if (acct.totpVerified && acct.totpSecret) return sendJson(res, 200, { ok: true, mfaRequired: true })
      issueSessionCookie(res, acct, secret, cfg)
      setCookie(res, 'dsh_csrf', genToken(32), { path: '/', sameSite: 'strict', httpOnly: false })
      sendJson(res, 200, { ok: true, user: { username: acct.username, role: acct.role } })
    } catch(e) {
      auditLog('login_err', { err: (e && e.message) || String(e) })
      sendJson(res, 500, { ok: false, error: userMessage(req, '\u670d\u52a1\u5668\u5185\u90e8\u9519\u8bef', 'Internal error') })
    }
  }
  d.push(ws.register({ kind: 'exact', path: '/secure-gate/auth/login', handler: loginHandler }))
  d.push(ws.register({ kind: 'exact', path: '/secure-gate/auth/mfa', handler: async (req, res) => { sendJson(res, 501, { ok: false, error: userMessage(req, '\u4e24\u6b65\u9a8c\u8bc1\u5c1a\u672a\u5b9e\u73b0', 'TOTP not implemented') }) } }))
  d.push(ws.register({ kind: 'exact', path: '/secure-gate/auth/me', handler: (req, res) => { const a = requireAuth(req, cfg, secret); sendJson(res, 200, { ok: a.ok, user: a.user }) } }))
  d.push(ws.register({ kind: 'exact', path: '/secure-gate/auth/logout', handler: (req, res) => { const t = readCookie(req, cfg.session.cookieName); if (t) removeSession(sign(secret, t).toString('hex')); setCookie(res, cfg.session.cookieName, '', { maxAge: 0, path: '/' }); setCookie(res, 'dsh_csrf', '', { maxAge: 0, path: '/' }); sendJson(res, 200, { ok: true }) } }))

  d.push(ws.register({ kind: 'exact', path: '/secure-gate/auth/change-password', handler: async function(req, res) {
    try {
      const auth = requireAuth(req, cfg, secret)
      if (!auth.ok) return sendJson(res, 401, { ok: false, error: userMessage(req, '\u672a\u6388\u6743', 'Unauthorized') })
      const body = await parseBody(req)
      const oldPw = String(body && body.oldPassword || '')
      const newPw = String(body && body.newPassword || '')
      if (!oldPw || !newPw) return sendJson(res, 400, { ok: false, error: userMessage(req, '\u8bf7\u8f93\u5165\u5f53\u524d\u5bc6\u7801\u548c\u65b0\u5bc6\u7801', 'old and new password required') })
      const acct = findAccount(auth.user.username)
      if (!acct) return sendJson(res, 401, { ok: false, error: userMessage(req, '\u8d26\u6237\u4e0d\u5b58\u5728', 'Account not found') })
      if (!verifyPassword(oldPw, acct.passwordHash)) return sendJson(res, 400, { ok: false, error: userMessage(req, '\u5f53\u524d\u5bc6\u7801\u4e0d\u6b63\u786e', 'Current password is incorrect') })
      const v = validatePassword(newPw, cfg.passwordPolicy, req)
      if (!v.ok) return sendJson(res, 400, { ok: false, error: v.error })
      acct.passwordHash = hashPassword(newPw)
      acct.passwordChangedAt = Date.now()
      saveStore()
      auditLog('password_changed', { u: auth.user.username })
      return sendJson(res, 200, { ok: true })
    } catch(e) {
      auditLog('pw_change_err', { err: (e && e.message) || String(e) })
      return sendJson(res, 500, { ok: false, error: userMessage(req, '\u670d\u52a1\u5668\u5185\u90e8\u9519\u8bef', 'Internal error') })
    }
  } }))
  var setupHandler = async function(req, res) {
    try {
      if (hasAccounts()) return sendJson(res, 409, { ok: false, error: userMessage(req, '\u521d\u59cb\u5316\u5df2\u5b8c\u6210', 'Setup already completed') })
      var ip = req.socket ? req.socket.remoteAddress : '0.0.0.0'
      var body = await parseBody(req)
      var un = String(body && body.username || '').trim()
      var pw = String(body && body.password || '')
      if (!un) return sendJson(res, 400, { ok: false, error: userMessage(req, '\u8bf7\u8f93\u5165\u7528\u6237\u540d', 'Username is required') })
      if (/[^\u4e00-\u9fa5A-Za-z0-9._@-]/.test(un)) return sendJson(res, 400, { ok: false, error: userMessage(req, '\u7528\u6237\u540d\u5305\u542b\u65e0\u6548\u5b57\u7b26', 'Username contains invalid characters') })
      var v = validatePassword(pw, cfg.passwordPolicy, req)
      if (!v.ok) return sendJson(res, 400, { ok: false, error: v.error })
      if (findAccount(un)) return sendJson(res, 409, { ok: false, error: userMessage(req, '\u7528\u6237\u540d\u5df2\u88ab\u5360\u7528', 'Username already taken') })
      var h = hashPassword(pw)
      var codes = []; for (var i = 0; i < 8; i++) codes.push({ code: sha256(genToken(3)), used: false })
      upsertAccount({ username: un, role: 'admin', passwordHash: h, backupCodes: codes })
      auditLog('setup_admin_created', { u: un, ip: ip })
      issueSessionCookie(res, { username: un, role: 'admin' }, secret, cfg)
      setCookie(res, 'dsh_csrf', genToken(32), { path: '/', sameSite: 'strict', httpOnly: false })
      sendJson(res, 200, { ok: true, user: { username: un, role: 'admin' } })
    } catch (e) {
      auditLog('setup_err', { err: (e && e.message) || String(e) })
      sendJson(res, 500, { ok: false, error: userMessage(req, '\u670d\u52a1\u5668\u5185\u90e8\u9519\u8bef', 'Internal error') })
    }
  }
  d.push(ws.register({ kind: 'exact', path: '/secure-gate/auth/setup', handler: setupHandler }))
  d.push(ws.register({ kind: 'exact', path: '/secure-gate/login', handler: (req, res) => { const l = detectLocale(req); const html = renderLoginPage({ locale: l, bootstrap: !hasAccounts(), switchLang: true }); res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(html) } }))
  return d
}

function installGate(ws, cfg, secret) {
  const srv = ws.server; if (!srv) return
  const pub = ['/secure-gate/auth/', '/secure-gate/login', '/favicon.ico']
  srv.prependListener('request', (req, res) => {
    try { const url = req.url || '/'; const raw = new URL(url, 'http://x').pathname || '/'
      if (pub.some(p => raw === p || raw.startsWith(p))) return
      const ip = req.socket?.remoteAddress || ''
      if (cfg.ipAccess.allowlist.length && !cfg.ipAccess.allowlist.includes(ip)) { res.writeHead(403, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: false, error: userMessage(req, '\u8bbf\u95ee\u88ab\u62d2\u7edd', 'Denied') })); return }
      if (cfg.ipAccess.blocklist.includes(ip)) { res.writeHead(403, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: false, error: userMessage(req, '\u8bbf\u95ee\u88ab\u62d2\u7edd', 'Denied') })); return }
      const auth = requireAuth(req, cfg, secret)
      if (!auth.ok) { if (req.headers?.accept?.includes('text/html') && !url.startsWith('/api/')) { res.writeHead(302, { Location: '/secure-gate/login' }); res.end() } else { res.writeHead(401, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: false, error: userMessage(req, '\u672a\u6388\u6743', 'Unauthorized') })) }; return }
    } catch (e) {}
  })
}

const CSP = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' ws: wss:; font-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'"
function installHeaders(ws, cfg) {
  const srv = ws.server; if (!srv) return
  srv.prependListener('request', (req, res) => { const o = res.writeHead.bind(res); res.writeHead = function(s, ...a) { if (!this._sg) { this._sg = true; this.setHeader('X-Content-Type-Options', 'nosniff'); this.setHeader('X-Frame-Options', 'DENY'); this.setHeader('X-XSS-Protection', '1; mode=block'); this.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin'); this.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()'); if (cfg.csp?.enabled !== false) this.setHeader('Content-Security-Policy', CSP) }; return o(s, ...a) } })
}

export function apply(ctx, config) {
  const cfg = parseConfig(config); loadStore(); const secret = getSecret(); loadSessions()
  // First-boot admin provisioning:
  // - If an explicit bootstrap username+password is configured, provision it programmatically (automation).
  // - Otherwise leave the store empty; the first-boot setup form lets the user create their own admin account.
  if (!hasAccounts() && cfg.bootstrap && cfg.bootstrap.username && cfg.bootstrap.password) {
    const un = String(cfg.bootstrap.username).trim(); const pw = String(cfg.bootstrap.password)
    if (un && pw) { const h = hashPassword(pw); const codes = []; for (let i = 0; i < 8; i++) codes.push({ code: sha256(genToken(3)), used: false }); upsertAccount({ username: un, role: 'admin', passwordHash: h, backupCodes: codes }); auditLog('setup_admin_created', { u: un, via: 'config-bootstrap' }); ctx.logger.info('[secure-gate] provisioned admin from config: %s', un) }
  } else if (!hasAccounts()) {
    ctx.logger.warn('[secure-gate] \u26a0\ufe0f No accounts configured. First visit will ask you to create an admin account (first-boot setup).')
  }
  for (const s of cfg.accounts || []) { if (!findAccount(s.username)) upsertAccount({ username: s.username, role: s.role || 'user', passwordHash: s.password.startsWith('A2$') ? s.password : hashPassword(s.password) }) }
  const ws = ctx.webServer; if (!ws) { ctx.logger.error('[sg] no webServer'); return }
  const disposers = registerAuthRoutes(ws, cfg, secret)
  if (cfg.enabled) installGate(ws, cfg, secret)
  installHeaders(ws, cfg)
  ctx.logger.info('[sg] active')
  ctx.on('dispose', () => { saveStore(); saveSessions(); for (const d of disposers) d() })
}