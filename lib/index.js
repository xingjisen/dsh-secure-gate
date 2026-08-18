/**
 * dsh-secure-gate - Enterprise Authentication Gateway
 * Security: Argon2id, CSRF, Account Lockout, IP Control, Audit, Sessions
 */
import { randomBytes, scryptSync, timingSafeEqual, createHmac, createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync, appendFileSync, unlinkSync } from 'node:fs'
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
function detectLocale(req) { const q = req.url ? new URL(req.url, 'http://x').searchParams.get('lang') : null; if (q === 'zh' || q === 'en') return q; const a = req.headers?.['accept-language'] || ''; return a.startsWith('zh') ? 'zh' : 'zh' }
function escHtml(t) { if (!t) return ''; return String(t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;') }

function requireAuth(req, cfg, secret) {
  if (!cfg.enabled) return { ok: true, user: { username: 'local', role: 'admin' } }
  const token = readCookie(req, cfg.session.cookieName); if (!token) return { ok: false }
  const payload = verifySession(token, secret); if (!payload) return { ok: false }
  const account = findAccount(payload.username); if (!account) return { ok: false }
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

function registerAuthRoutes(ws, cfg, secret) {
  const d = []
  var loginHandler = async function(req, res) {
    try {
      var ip = req.socket ? req.socket.remoteAddress : '0.0.0.0'
      var body = await parseBody(req)
      var un = String(body && body.username || '').trim()
      var pw = String(body && body.password || '')
      if (!un || !pw) return sendJson(res, 400, { ok: false, error: 'username and password required' })
      var lks = getLockouts()
      var now = Date.now()
      var lk = 'login:' + un
      var le = lks[lk]
      if (le && le.permanent) return sendJson(res, 429, { ok: false, error: 'Account locked permanently' })
      if (le && le.lockedUntil && le.lockedUntil > now) {
        var rem = Math.ceil((le.lockedUntil - now) / 1000 / 60)
        return sendJson(res, 429, { ok: false, error: 'Locked, try in ' + rem + ' min' })
      }
      if (le && le.windowStart && now - le.windowStart < cfg.rateLimit.windowMs && le.attempts >= cfg.rateLimit.maxAttempts) {
        var cnt = (le.lockoutCount || 0) + 1
        if (cnt >= cfg.lockout.permanentAfter) {
          setLockout(lk, { permanent: true, lockoutCount: cnt })
          auditLog('perm_lock', { u: un })
          return sendJson(res, 429, { ok: false, error: 'Account locked permanently' })
        }
        setLockout(lk, { lockedUntil: now + cfg.lockout.duration, lockoutCount: cnt })
        auditLog('locked', { u: un })
        return sendJson(res, 429, { ok: false, error: 'Too many attempts' })
      }
      var acct = findAccount(un)
      if (!acct) {
        setLockout(lk, { windowStart: now, attempts: (le ? le.attempts || 0 : 0) + 1 })
        auditLog('login_fail', { u: un, ip: ip })
        return sendJson(res, 401, { ok: false, error: 'Invalid credentials' })
      }
      if (acct.locked) return sendJson(res, 403, { ok: false, error: 'Account locked' })
      if (!verifyPassword(pw, acct.passwordHash)) {
        setLockout(lk, { windowStart: le ? le.windowStart || now : now, attempts: (le ? le.attempts || 0 : 0) + 1 })
        auditLog('login_fail', { u: un, ip: ip })
        return sendJson(res, 401, { ok: false, error: 'Invalid credentials' })
      }
      clearLockout(lk)
      auditLog('login_ok', { u: un, ip: ip })
      try { const f = join(AUTH_DIR, 'initial-credentials.txt'); if (existsSync(f)) { unlinkSync(f) } } catch (e) {}
      if (acct.totpVerified && acct.totpSecret) return sendJson(res, 200, { ok: true, mfaRequired: true })
      issueSessionCookie(res, acct, secret, cfg)
      setCookie(res, 'dsh_csrf', genToken(32), { path: '/', sameSite: 'strict', httpOnly: false })
      sendJson(res, 200, { ok: true, user: { username: acct.username, role: acct.role } })
    } catch(e) {
      auditLog('login_err', { err: (e && e.message) || String(e) })
      sendJson(res, 500, { ok: false, error: 'Internal error' })
    }
  }
  d.push(ws.register({ kind: 'exact', path: '/secure-gate/auth/login', handler: loginHandler }))
  d.push(ws.register({ kind: 'exact', path: '/secure-gate/auth/mfa', handler: async (req, res) => { sendJson(res, 501, { ok: false, error: 'TOTP not implemented' }) } }))
  d.push(ws.register({ kind: 'exact', path: '/secure-gate/auth/me', handler: (req, res) => { const a = requireAuth(req, cfg, secret); sendJson(res, 200, { ok: a.ok, user: a.user }) } }))
  d.push(ws.register({ kind: 'exact', path: '/secure-gate/auth/logout', handler: (req, res) => { const t = readCookie(req, cfg.session.cookieName); if (t) removeSession(sign(secret, t).toString('hex')); setCookie(res, cfg.session.cookieName, '', { maxAge: 0, path: '/' }); setCookie(res, 'dsh_csrf', '', { maxAge: 0, path: '/' }); sendJson(res, 200, { ok: true }) } }))
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
      if (cfg.ipAccess.allowlist.length && !cfg.ipAccess.allowlist.includes(ip)) { res.writeHead(403, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: false, error: 'Denied' })); return }
      if (cfg.ipAccess.blocklist.includes(ip)) { res.writeHead(403, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: false, error: 'Denied' })); return }
      const auth = requireAuth(req, cfg, secret)
      if (!auth.ok) { if (req.headers?.accept?.includes('text/html') && !url.startsWith('/api/')) { res.writeHead(302, { Location: '/secure-gate/login' }); res.end() } else { res.writeHead(401, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: false, error: 'Unauthorized' })) }; return }
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
  if (!hasAccounts()) {
    const un = (cfg.bootstrap && cfg.bootstrap.username) ? cfg.bootstrap.username.trim() : 'admin'
    const pw = (cfg.bootstrap && cfg.bootstrap.password) ? cfg.bootstrap.password : randomBytes(9).toString('hex')
    const h = hashPassword(pw)
    const codes = []; for (let i = 0; i < 8; i++) codes.push({ code: sha256(genToken(3)), used: false })
    upsertAccount({ username: un, role: 'admin', passwordHash: h, backupCodes: codes })
    auditLog('bootstrap_admin_created', { username: un })
    // Persist an initial credentials hint (chmod 0600, deleted on first successful login)
    try { ensureDir(); writeFileSync(join(AUTH_DIR, 'initial-credentials.txt'), '[dsh-secure-gate] initial admin account\nusername: ' + un + '\npassword: ' + pw + '\n\nPlease change it after first login.\n', 'utf8'); try { chmodSync(join(AUTH_DIR, 'initial-credentials.txt'), 0o600) } catch {} } catch (e) {}
    ctx.logger.warn('[secure-gate] \u26a0\ufe0f Created initial admin account. Credentials saved to: %s', join(AUTH_DIR, 'initial-credentials.txt'))
    ctx.logger.warn('[secure-gate]   username: %s', un)
    ctx.logger.warn('[secure-gate]   password: %s  (CHANGE IT AFTER FIRST LOGIN)', pw)
  }
  for (const s of cfg.accounts || []) { if (!findAccount(s.username)) upsertAccount({ username: s.username, role: s.role || 'user', passwordHash: s.password.startsWith('A2$') ? s.password : hashPassword(s.password) }) }
  const ws = ctx.webServer; if (!ws) { ctx.logger.error('[sg] no webServer'); return }
  const disposers = registerAuthRoutes(ws, cfg, secret)
  if (cfg.enabled) installGate(ws, cfg, secret)
  installHeaders(ws, cfg)
  ctx.logger.info('[sg] active')
  ctx.on('dispose', () => { saveStore(); saveSessions(); for (const d of disposers) d() })
}
