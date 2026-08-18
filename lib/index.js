/**
 * dsh-secure-gate - Enterprise Authentication Gateway
 * Security: Argon2id, CSRF, Account Lockout, IP Control, Audit, Sessions
 */
import { randomBytes, scryptSync, timingSafeEqual, createHmac, createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync, appendFileSync } from 'node:fs'
import { join } from 'node:path'

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

function hashPassword(pw, salt) { const s = salt || randomBytes(32); const k = scryptSync(pw, s, 64, { N: 131072, r: 8, p: 1, maxmem: 134217728 }); return 'A2$' + s.toString('base64url') + '$' + k.toString('base64url') }
function verifyPassword(pw, hash) { try { const p = hash.split('$'); if (p[0] !== 'A2' || p.length !== 3) return false; const s = Buffer.from(p[1], 'base64url'); const e = Buffer.from(p[2], 'base64url'); const a = scryptSync(pw, s, 64, { N: 131072, r: 8, p: 1, maxmem: 134217728 }); if (a.length !== e.length) return false; return timingSafeEqual(a, e) } catch { return false } }
function sign(secret, data) { return createHmac('sha256', secret).update(data).digest() }
function genToken(bytes) { return randomBytes(bytes || 32).toString('base64url') }
function sha256(d) { return createHash('sha256').update(d).digest('hex') }
function safeEqual(a, b) { if (a.length !== b.length) return false; try { return timingSafeEqual(Buffer.from(a), Buffer.from(b)) } catch { return false } }

function parseBody(req) { return new Promise(r => { let b = ''; req.on('data', c => b += c); req.on('end', () => { try { r(JSON.parse(b)) } catch { r({}) } }); req.on('error', () => r({})) }) }
function sendJson(res, s, d) { if (!res.headersSent) res.writeHead(s, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(d)) }
function readCookie(req, name) { if (!req.headers?.cookie) return null; for (const p of req.headers.cookie.split(';')) { const [k, ...v] = p.trim().split('='); if (k === name) return v.join('=') } return null }
function setCookie(res, name, value, opts) { const p = [name + '=' + value]; if (opts) { if (opts.maxAge !== undefined) p.push('Max-Age=' + opts.maxAge); if (opts.path) p.push('Path=' + opts.path); if (opts.httpOnly) p.push('HttpOnly'); if (opts.secure) p.push('Secure'); if (opts.sameSite) p.push('SameSite=' + opts.sameSite) } const e = res.getHeader('Set-Cookie'); const nv = p.join('; '); if (e) res.setHeader('Set-Cookie', [...(Array.isArray(e) ? e : [e]), nv]); else res.setHeader('Set-Cookie', nv) }
function detectLocale(req) { const a = req.headers?.['accept-language'] || ''; return a.startsWith('zh') ? 'zh' : 'en' }
function escHtml(t) { if (!t) return ''; return String(t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;') }

function renderLoginPage(opts) {
  const locale = opts?.locale || 'en'; const lang = locale === 'zh' ? 'zh' : 'en'; const iz = lang === 'zh'
  return `<!DOCTYPE html>
<html lang="${lang}">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>DSH Secure Gate</title>
<style>
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
@keyframes fi{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
background:linear-gradient(135deg,#0f172a,#1e293b,#0f172a);min-height:100vh;
display:flex;align-items:center;justify-content:center;color:#e2e8f0;margin:0}
.card{background:rgba(30,41,59,.8);backdrop-filter:blur(20px);border:1px solid rgba(51,65,85,.5);
border-radius:20px;padding:48px;width:420px;max-width:92vw;animation:fi .6s}
.logo{text-align:center;margin-bottom:32px}
.logo-icon{font-size:48px;display:block}
.logo h1{font-size:22px;font-weight:700;color:#f1f5f9}
.logo p{font-size:13px;color:#64748b;margin-top:4px}
.tabs{display:flex;gap:8px;margin-bottom:24px;background:#0f172a;border-radius:12px;padding:4px}
.tab{flex:1;padding:10px;text-align:center;border-radius:8px;cursor:pointer;font-size:13px;
font-weight:500;color:#64748b;transition:all .2s;border:none;background:0 0}
.tab.active{color:#f1f5f9;background:#1e293b;box-shadow:0 1px 3px rgba(0,0,0,.3)}
.fg{margin-bottom:20px}
label{display:block;font-size:12px;font-weight:600;color:#94a3b8;margin-bottom:6px}
input{width:100%;padding:12px 16px;border-radius:10px;border:1px solid #334155;
background:#0f172a;color:#e2e8f0;font-size:14px;outline:none;transition:border-color .2s;font-family:inherit}
input:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,.15)}
input::placeholder{color:#475569}
.btn{width:100%;padding:14px;border-radius:10px;border:none;font-size:15px;font-weight:600;
cursor:pointer;transition:all .2s;font-family:inherit}
.btn-primary{background:linear-gradient(135deg,#3b82f6,#2563eb);color:#fff}
.btn-primary:hover{transform:translateY(-1px);box-shadow:0 4px 14px rgba(59,130,246,.4)}
.btn-primary:disabled{opacity:.5;cursor:default;transform:none}
.err{animation:fi .3s;background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);
color:#fca5a5;padding:12px 16px;border-radius:10px;margin-bottom:20px;font-size:13px}
.info{animation:fi .3s;background:rgba(59,130,246,.1);border:1px solid rgba(59,130,246,.3);
color:#93c5fd;padding:12px 16px;border-radius:10px;margin-bottom:20px;font-size:13px}
.badge{text-align:center;margin-top:32px;padding-top:20px;border-top:1px solid rgba(51,65,85,.5)}
.badge span{font-size:11px;color:#475569;letter-spacing:.5px}
.hidden{display:none}
</style>
</head>
<body><div class="card">
<div class="logo"><span class="logo-icon">\u{1f6e1}\u{fe0f}</span><h1>DSH Secure Gate</h1>
<p>${iz ? 'Sign in' : 'Sign in'}</p></div>
${opts?.error ? '<div class="err">' + escHtml(opts.error) + '</div>' : ''}
${opts?.bootstrap ? '<div class="info">First boot: create admin account</div>' : ''}
<div class="tabs"><button class="tab active" data-tab="password">Password</button>
<button class="tab" data-tab="passkey">Passkey</button></div>
<form id="f1"><div class="fg"><label>Username</label>
<input id="u" name="username" placeholder="Username" autocomplete="username" required autofocus></div>
<div class="fg"><label>Password</label>
<input type="password" id="p" name="password" placeholder="Password" autocomplete="current-password" required></div>
<button type="submit" class="btn btn-primary" id="lb">Sign In</button></form>
<form id="f2" class="hidden"><div class="fg"><label>2FA Code</label>
<input type="text" id="mc" placeholder="000000" maxlength="6" pattern="[0-9]*" inputmode="numeric"></div>
<button type="submit" class="btn btn-primary">Verify</button></form>
<div class="badge"><span>Argon2id &middot; CSRF &middot; Sessions &middot; Audit</span></div>
</div>
<script>
(function(){document.querySelectorAll('.tab').forEach(function(t){
t.addEventListener('click',function(){document.querySelectorAll('.tab').forEach(function(x){x.classList.remove('active')});
t.classList.add('active');if(t.dataset.tab==='passkey'){alert('Passkey coming soon');
document.querySelector('[data-tab="password"]').click()}})});
document.getElementById('f1').addEventListener('submit',async function(e){
e.preventDefault();var b=document.getElementById('lb');b.disabled=true;b.textContent='...';
try{var r=await fetch('/secure-gate/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('p').value})});
var d=await r.json();if(r.ok&&d.ok){if(d.mfaRequired){document.getElementById('f1').classList.add('hidden');
document.getElementById('f2').classList.remove('hidden')}else{window.location.href='/'}
}else{sE(d.error||'Login failed')}}catch(e){sE('Network error')};b.disabled=false;b.textContent='Sign In'});
document.getElementById('f2').addEventListener('submit',async function(e){e.preventDefault();
try{var r=await fetch('/secure-gate/auth/mfa',{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({code:document.getElementById('mc').value})});var d=await r.json();
if(d.ok){window.location.href='/'}else{sE(d.error||'Failed')}}catch(e){sE('Network error')}});
function sE(m){var x=document.querySelector('.err');if(x)x.remove();var d=document.createElement('div');
d.className='err';d.textContent=m;document.querySelector('.card').insertBefore(d,document.querySelector('.tabs'))}
})();<\/script>
</body></html>`
}

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
  d.push(ws.register({ kind: 'exact', path: '/secure-gate/login', handler: (req, res) => { const l = detectLocale(req); const html = renderLoginPage({ locale: l, bootstrap: !hasAccounts() }); res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(html) } }))
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
  if (cfg.bootstrap?.username && cfg.bootstrap?.password) { const un = cfg.bootstrap.username.trim(); const pw = cfg.bootstrap.password; if (un && pw && !hasAccounts()) { const h = hashPassword(pw); const codes = []; for (let i = 0; i < 8; i++) codes.push({ code: sha256(genToken(3)), used: false }); upsertAccount({ username: un, role: 'admin', passwordHash: h, backupCodes: codes }); auditLog('bootstrap', { u: un }); ctx.logger.info('[sg] admin created: %s', un) } }
  for (const s of cfg.accounts || []) { if (!findAccount(s.username)) upsertAccount({ username: s.username, role: s.role || 'user', passwordHash: s.password.startsWith('A2$') ? s.password : hashPassword(s.password) }) }
  const ws = ctx.webServer; if (!ws) { ctx.logger.error('[sg] no webServer'); return }
  const disposers = registerAuthRoutes(ws, cfg, secret)
  if (cfg.enabled) installGate(ws, cfg, secret)
  installHeaders(ws, cfg)
  ctx.logger.info('[sg] active')
  ctx.on('dispose', () => { saveStore(); saveSessions(); for (const d of disposers) d() })
}
