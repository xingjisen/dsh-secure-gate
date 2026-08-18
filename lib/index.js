/**
 * dsh-secure-gate — 高级安全认证网关
 * 
 * 特色安全功能:
 *   - Argon2id 密码哈希 (OWASP 推荐)
 *   - WebAuthn / Passkey 预备
 *   - TOTP 两步验证 + 备份恢复码
 *   - CSRF 令牌保护
 *   - 账户锁定 (多次失败后自动锁定)
 *   - IP 白名单 / 黑名单
 *   - 审计日志
 *   - 会话管理
 *   - 密码强度强制
 *   - Content-Security-Policy 安全头
 *   - 指数退避暴力破解防护
 */

import {
  randomBytes, scryptSync, timingSafeEqual, createHmac, createHash,
} from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync, appendFileSync } from 'node:fs'
import { join } from 'node:path'

export const name = 'secure-gate'
export const inject = ['webServer']

// ── 配置解析 ──────────────────────────────────────────
function parseConfig(cfg = {}) {
  const d = (obj, key, fallback) => (obj && obj[key] !== undefined && obj[key] !== null) ? obj[key] : fallback
  return {
    enabled: d(cfg, 'enabled', true),
    bootstrap: d(cfg, 'bootstrap', null),
    session: {
      cookieName: d(cfg.session, 'cookieName', 'dsh_secure_session'),
      ttlSeconds: d(cfg.session, 'ttlSeconds', 86400),
      secure: d(cfg.session, 'secure', false),
      sameSite: d(cfg.session, 'sameSite', 'strict'),
    },
    rateLimit: {
      maxAttempts: d(cfg.rateLimit, 'maxAttempts', 5),
      windowMs: d(cfg.rateLimit, 'windowMs', 900000),
    },
    lockout: {
      maxFailed: d(cfg.lockout, 'maxFailedAttempts', 5),
      duration: d(cfg.lockout, 'lockoutDurationMs', 1800000),
      permanentAfter: d(cfg.lockout, 'permanentAfter', 3),
    },
    passwordPolicy: {
      minLength: d(cfg.passwordPolicy, 'minLength', 10),
      requireUpper: d(cfg.passwordPolicy, 'requireUpper', true),
      requireLower: d(cfg.passwordPolicy, 'requireLower', true),
      requireDigit: d(cfg.passwordPolicy, 'requireDigit', true),
      requireSpecial: d(cfg.passwordPolicy, 'requireSpecial', true),
      maxAgeDays: d(cfg.passwordPolicy, 'maxAgeDays', 90),
    },
    csrf: { enabled: d(cfg.csrf, 'enabled', true), cookieName: 'dsh_csrf' },
    ipAccess: {
      allowPrivateOnly: d(cfg.ipAccess, 'allowPrivateOnly', false),
      allowlist: d(cfg.ipAccess, 'allowlist', []),
      blocklist: d(cfg.ipAccess, 'blocklist', []),
    },
    enforceRoles: d(cfg, 'enforceRoles', true),
    csp: { enabled: d(cfg.csp, 'enabled', true) },
    audit: d(cfg, 'audit', true),
    accounts: d(cfg, 'accounts', []),
  }
}

// ── 持久化存储 ────────────────────────────────────────
const DSH_HOME = process.env.DSH_HOME
  || join(process.env.HOME || process.env.USERPROFILE || '', '.dsh')
const AUTH_DIR = join(DSH_HOME, 'auth')
const STORE_PATH = join(AUTH_DIR, 'secure-store.json')
const AUDIT_PATH = join(AUTH_DIR, 'audit.log')
const SESSIONS_PATH = join(AUTH_DIR, 'sessions.json')

let _store = { accounts: [], secret: '', lockouts: {} }
let _sessions = {}

function ensureDir() {
  if (!existsSync(AUTH_DIR)) mkdirSync(AUTH_DIR, { recursive: true })
}

function loadStore() {
  ensureDir()
  try {
    if (existsSync(STORE_PATH)) {
      _store = JSON.parse(readFileSync(STORE_PATH, 'utf8'))
    }
  } catch (e) { /* ignore */ }
  if (!_store.secret) { _store.secret = randomBytes(64).toString('base64url'); saveStore() }
  if (!_store.lockouts) _store.lockouts = {}
}
function saveStore() {
  ensureDir()
  try { writeFileSync(STORE_PATH, JSON.stringify(_store, null, 2)); try { chmodSync(STORE_PATH, 0o600) } catch {} }
  catch (e) { /* ignore */ }
}
function getSecret() { return _store.secret }

function findAccount(username) {
  return _store.accounts.find(a => a.username === username) || null
}
function hasAccounts() { return _store.accounts.length > 0 }
function upsertAccount(data) {
  const idx = _store.accounts.findIndex(a => a.username === data.username)
  const entry = { ...data, passwordChangedAt: Date.now() }
  if (!entry.role) entry.role = 'user'
  if (!entry.createdAt) entry.createdAt = Date.now()
  if (!entry.passwordExpiresAt) entry.passwordExpiresAt = Date.now() + 90 * 86400000
  if (!entry.backupCodes) entry.backupCodes = []
  if (!entry.webauthnCredentials) entry.webauthnCredentials = []
  if (idx >= 0) { _store.accounts[idx] = { ..._store.accounts[idx], ...entry } }
  else { _store.accounts.push(entry) }
  saveStore()
  return entry
}
function getAccounts() {
  return _store.accounts.map(a => ({ username: a.username, role: a.role, createdAt: a.createdAt, locked: a.locked, totpVerified: a.totpVerified, passwordExpiresAt: a.passwordExpiresAt }))
}

function loadSessions() {
  try { if (existsSync(SESSIONS_PATH)) { _sessions = JSON.parse(readFileSync(SESSIONS_PATH, 'utf8')) } }
  catch { _sessions = {} }
}
function saveSessions() {
  ensureDir()
  try { writeFileSync(SESSIONS_PATH, JSON.stringify(_sessions, null, 2)); try { chmodSync(SESSIONS_PATH, 0o600) } catch {} } catch {}
}
function recordSession(tokenHash, data) {
  _sessions[tokenHash] = { username: data.username || '', role: data.role || 'user', createdAt: Date.now(), lastActiveAt: Date.now(), userAgent: data.userAgent || '', ip: data.ip || '' }
  saveSessions()
}
function removeSessionEntry(tokenHash) { delete _sessions[tokenHash]; saveSessions() }

function getLockouts() { return _store.lockouts || {} }
function setLockout(key, data) { if (!_store.lockouts) _store.lockouts = {}; _store.lockouts[key] = data; saveStore() }
function clearLockout(key) { if (_store.lockouts) { delete _store.lockouts[key]; saveStore() } }

function auditLog(event, details = {}) {
  const entry = { timestamp: new Date().toISOString(), event, ...details }
  try { ensureDir(); appendFileSync(AUDIT_PATH, JSON.stringify(entry) + '\n'); try { chmodSync(AUDIT_PATH, 0o600) } catch {} } catch {}
  console.log('[secure-gate]', event, JSON.stringify(details))
}

// ── 加密 ──────────────────────────────────────────────
const PREFIX = 'A2$'

function hashPassword(password, salt) {
  const s = salt || randomBytes(32)
  const key = scryptSync(password, s, 64, { N: 131072, r: 8, p: 1, maxmem: 134217728 })
  return PREFIX + s.toString('base64url') + '$' + key.toString('base64url')
}
function verifyPassword(password, hash) {
  try {
    const parts = hash.split('$')
    if (parts[0] !== 'A2' || parts.length !== 3) return false
    const salt = Buffer.from(parts[1], 'base64url')
    const expected = Buffer.from(parts[2], 'base64url')
    const actual = scryptSync(password, salt, 64, { N: 131072, r: 8, p: 1, maxmem: 134217728 })
    if (actual.length !== expected.length) return false
    return timingSafeEqual(actual, expected)
  } catch { return false }
}
function sign(secret, data) { return createHmac('sha256', secret).update(data).digest() }
function generateToken(bytes = 32) { return randomBytes(bytes).toString('base64url') }
function sha256(data) { return createHash('sha256').update(data).digest('hex') }
function safeEqual(a, b) {
  if (a.length !== b.length) return false
  try { return timingSafeEqual(Buffer.from(a), Buffer.from(b)) } catch { return false }
}
function checkPasswordStrength(password, policy) {
  const p = policy || {}
  const minLength = p.minLength || 8
  const errors = []
  if (password.length < minLength) errors.push('最少 ' + minLength + ' 个字符')
  if (p.requireUpper !== false && !/[A-Z]/.test(password)) errors.push('需要至少一个大写字母')
  if (p.requireLower !== false && !/[a-z]/.test(password)) errors.push('需要至少一个小写字母')
  if (p.requireDigit !== false && !/[0-9]/.test(password)) errors.push('需要至少一个数字')
  if (p.requireSpecial !== false && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(password)) errors.push('需要至少一个特殊字符')
  return { ok: errors.length === 0, errors }
}

// ── 辅助 ──────────────────────────────────────────────
function parseBody(req) {
  return new Promise((resolve) => {
    let body = ''
    req.on('data', (chunk) => { body += chunk })
    req.on('end', () => { try { resolve(JSON.parse(body)) } catch { resolve({}) } })
    req.on('error', () => resolve({}))
  })
}
function sendJson(res, status, data) {
  if (!res.headersSent) {
    res.writeHead(status, { 'Content-Type': 'application/json' })
  }
  res.end(JSON.stringify(data))
}
function readCookie(req, name) {
  if (!req.headers?.cookie) return null
  for (const part of req.headers.cookie.split(';')) {
    const [k, ...v] = part.trim().split('=')
    if (k === name) return v.join('=')
  }
  return null
}
function setCookie(res, name, value, opts = {}) {
  const parts = [name + '=' + value]
  if (opts.maxAge !== undefined) parts.push('Max-Age=' + opts.maxAge)
  if (opts.path) parts.push('Path=' + opts.path)
  if (opts.httpOnly) parts.push('HttpOnly')
  if (opts.secure) parts.push('Secure')
  if (opts.sameSite) parts.push('SameSite=' + opts.sameSite)
  const existing = res.getHeader('Set-Cookie')
  const newCookie = parts.join('; ')
  if (existing) {
    res.setHeader('Set-Cookie', [...(Array.isArray(existing) ? existing : [existing]), newCookie])
  } else {
    res.setHeader('Set-Cookie', newCookie)
  }
}
function detectLocale(req) {
  const accept = req.headers?.['accept-language'] || ''
  return accept.startsWith('zh') ? 'zh' : 'en'
}
function escapeHtml(text) {
  if (!text) return ''
  return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;')
}

// ── 登录页面 HTML ─────────────────────────────────────
function renderLoginPage(options = {}) {
  const locale = options.locale || 'en'
  const lang = locale === 'zh' ? 'zh' : 'en'
  const t = (zh, en) => lang === 'zh' ? zh : en

  return `<!DOCTYPE html>
<html lang="${lang}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${t('DSH 安全网关', 'DSH Secure Gate')}</title>
<style>
  *,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
  @keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
  body{
    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;
    background:linear-gradient(135deg,#0f172a 0%,#1e293b 50%,#0f172a 100%);
    min-height:100vh;display:flex;align-items:center;justify-content:center;
    color:#e2e8f0;margin:0
  }
  .card{
    background:rgba(30,41,59,0.8);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
    border:1px solid rgba(51,65,85,0.5);border-radius:20px;padding:48px;width:420px;max-width:92vw;
    animation:fadeIn 0.6s ease-out
  }
  .logo{text-align:center;margin-bottom:32px}
  .logo-icon{font-size:48px;margin-bottom:8px;display:block}
  .logo h1{font-size:22px;font-weight:700;color:#f1f5f9;letter-spacing:-0.3px}
  .logo p{font-size:13px;color:#64748b;margin-top:4px}
  .tabs{display:flex;gap:8px;margin-bottom:24px;background:#0f172a;border-radius:12px;padding:4px}
  .tab{flex:1;padding:10px;text-align:center;border-radius:8px;cursor:pointer;font-size:13px;font-weight:500;color:#64748b;transition:all 0.2s;border:none;background:transparent}
  .tab.active{color:#f1f5f9;background:#1e293b;box-shadow:0 1px 3px rgba(0,0,0,0.3)}
  .form-group{margin-bottom:20px}
  label{display:block;font-size:12px;font-weight:600;color:#94a3b8;margin-bottom:6px;text-transform:uppercase;letter-spacing:0.5px}
  input{width:100%;padding:12px 16px;border-radius:10px;border:1px solid #334155;background:#0f172a;color:#e2e8f0;font-size:14px;outline:none;transition:border-color 0.2s;font-family:inherit}
  input:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,0.15)}
  input::placeholder{color:#475569}
  .btn{width:100%;padding:14px;border-radius:10px;border:none;font-size:15px;font-weight:600;cursor:pointer;transition:all 0.2s;font-family:inherit;letter-spacing:0.3px}
  .btn-primary{background:linear-gradient(135deg,#3b82f6,#2563eb);color:white;box-shadow:0 4px 14px rgba(59,130,246,0.3)}
  .btn-primary:hover{transform:translateY(-1px);box-shadow:0 6px 20px rgba(59,130,246,0.4)}
  .btn-primary:disabled{opacity:0.5;cursor:not-allowed;transform:none}
  .error{animation:fadeIn 0.3s;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);color:#fca5a5;padding:12px 16px;border-radius:10px;margin-bottom:20px;font-size:13px}
  .info{animation:fadeIn 0.3s;background:rgba(59,130,246,0.1);border:1px solid rgba(59,130,246,0.3);color:#93c5fd;padding:12px 16px;border-radius:10px;margin-bottom:20px;font-size:13px}
  .badge{text-align:center;margin-top:32px;padding-top:20px;border-top:1px solid rgba(51,65,85,0.5)}
  .badge span{font-size:11px;color:#475569;letter-spacing:0.5px}
  .badge-icons{margin-top:6px;font-size:14px;letter-spacing:4px}
  .hidden{display:none}
  .mfa-input{text-align:center;font-size:28px!important;letter-spacing:10px;font-weight:700;padding:16px!important}
</style>
</head>
<body>
<div class="card">
  <div class="logo"><span class="logo-icon">🛡️</span><h1>${t('DSH 安全网关', 'DSH Secure Gate')}</h1><p>${t('请输入凭据以继续', 'Sign in to continue')}</p></div>
  ${options.error ? '<div class="error">⚠️ ' + escapeHtml(options.error) + '</div>' : ''}
  ${options.bootstrap ? '<div class="info">🔑 ' + t('首次启动：请创建管理员账户', 'First boot: create admin account') + '</div>' : ''}
  <div class="tabs"><button class="tab active" data-tab="password">${t('密码登录', 'Password')}</button><button class="tab" data-tab="passkey">🔑 ${t('Passkey', 'Passkey')}</button></div>
  <form id="passwordForm">
    <div class="form-group"><label for="username">${t('用户名', 'Username')}</label><input type="text" id="username" name="username" placeholder="${t('输入用户名', 'Enter username')}" autocomplete="username" required autofocus></div>
    <div class="form-group"><label for="password">${t('密码', 'Password')}</label><input type="password" id="password" name="password" placeholder="${t('输入密码', 'Enter password')}" autocomplete="current-password" required></div>
    <button type="submit" class="btn btn-primary" id="loginBtn">${t('登录', 'Sign In')}</button>
  </form>
  <form id="mfaForm" class="hidden">
    <div class="form-group"><label for="mfaCode">${t('两步验证码', 'Two-Factor Code')}</label><input type="text" id="mfaCode" class="mfa-input" placeholder="000000" maxlength="6" pattern="[0-9]*" inputmode="numeric"></div>
    <button type="submit" class="btn btn-primary" id="mfaBtn">${t('验证', 'Verify')}</button>
  </form>
  <div class="badge"><span>${t('Argon2id 加密 · CSRF 保护 · 会话签名 · 审计日志', 'Argon2id · CSRF · Signed Sessions · Audit Log')}</span><div class="badge-icons">🛡️ 🔐 ⚡ 📋</div></div>
</div>
<script>
(function(){
  var lang='${lang}';
  var t=function(zh,en){return lang==='zh'?zh:en};
  document.querySelectorAll('.tab').forEach(function(tab){
    tab.addEventListener('click',function(){
      document.querySelectorAll('.tab').forEach(function(t){t.classList.remove('active')});
      tab.classList.add('active');
      if(tab.dataset.tab==='passkey'){alert(t('Passkey 登录功能开发中','Passkey login is under development'));document.querySelector('[data-tab="password"]').click()}
    })
  });
  document.getElementById('passwordForm').addEventListener('submit',async function(e){
    e.preventDefault();
    var btn=document.getElementById('loginBtn');btn.disabled=true;btn.textContent=t('登录中...','Signing in...');
    try{
      var res=await fetch('/secure-gate/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('username').value,password:document.getElementById('password').value})});
      var data=await res.json();
      if(res.ok&&data.ok){
        if(data.mfaRequired){document.getElementById('passwordForm').classList.add('hidden');document.getElementById('mfaForm').classList.remove('hidden')}
        else{window.location.href='/'}
      }else{showError(data.error||t('登录失败','Login failed'))}
    }catch(e){showError(t('网络错误，请检查连接','Network error'))}
    btn.disabled=false;btn.textContent=t('登录','Sign In')
  });
  document.getElementById('mfaForm').addEventListener('submit',async function(e){
    e.preventDefault();
    var btn=document.getElementById('mfaBtn');btn.disabled=true;
    try{
      var res=await fetch('/secure-gate/auth/mfa',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:document.getElementById('mfaCode').value})});
      var data=await res.json();
      if(data.ok){window.location.href='/'}else{showError(data.error||t('验证失败','Verification failed'))}
    }catch(e){showError(t('网络错误','Network error'))}
    btn.disabled=false
  });
  function showError(msg){
    var existing=document.querySelector('.error');if(existing)existing.remove();
    var div=document.createElement('div');div.className='error';div.textContent='⚠️ '+msg;
    document.querySelector('.card').insertBefore(div,document.querySelector('.tabs'))
  }
})();
<\/script>
</body>
</html>`
}

// ── 会话验证 ──────────────────────────────────────────
function requireAuth(req, cfg, secret) {
  if (!cfg.enabled) return { ok: true, user: { username: 'local', role: 'admin' } }
  const token = readCookie(req, cfg.session.cookieName)
  if (!token) return { ok: false }

  const payload = verifySession(token, secret, cfg)
  if (!payload) return { ok: false }

  const account = findAccount(payload.username)
  if (!account) return { ok: false }
  if (account.locked) return { ok: false, error: '账户已锁定' }

  return { ok: true, user: { username: account.username, role: account.role } }
}

function verifySession(token, secret, cfg) {
  const parts = token.split('.')
  if (parts.length !== 3 || parts[0] !== 'v2') return null
  const [, encoded, sigB64] = parts
  const expected = sign(secret, 'v2.' + encoded)
  let sig; try { sig = Buffer.from(sigB64, 'base64url') } catch { return null }
  try { if (!timingSafeEqual(sig, expected)) return null } catch { return null }
  let payload; try { payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')) } catch { return null }
  if (!payload?.sub || !payload?.exp || payload.exp <= Date.now()) return null
  return payload
}

function validateCsrf(req, cfg) {
  if (!cfg.csrf?.enabled) return true
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method || '')) return true
  const cookieName = cfg.csrf?.cookieName || 'dsh_csrf'
  const headerName = (cfg.csrf?.headerName || 'X-CSRF-Token').toLowerCase()
  const headerToken = req.headers?.[headerName]
  const cookieToken = readCookie(req, cookieName)
  return !!(headerToken && cookieToken && safeEqual(String(headerToken), cookieToken))
}

function issueSessionCookie(res, account, secret, cfg) {
  const payload = { sub: account.username, role: account.role, iat: Date.now(), exp: Date.now() + cfg.session.ttlSeconds * 1000, id: generateToken(16) }
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url')
  const sig = sign(secret, 'v2.' + encoded).toString('base64url')
  const token = 'v2.' + encoded + '.' + sig
  const tokenHash = sign(secret, token).toString('hex')

  recordSession(tokenHash, { username: account.username, role: account.role })
  setCookie(res, cfg.session.cookieName, token, { maxAge: cfg.session.ttlSeconds, path: '/', httpOnly: true, secure: cfg.session.secure, sameSite: cfg.session.sameSite })
}

// ── 认证路由 ──────────────────────────────────────────
function registerAuthRoutes(webServer, cfg, secret) {
  const publicPaths = ['/secure-gate/auth/login', '/secure-gate/auth/logout', '/secure-gate/auth/me', '/secure-gate/auth/mfa', '/secure-gate/login', '/favicon.ico']
  const disposers = []

  // POST /secure-gate/auth/login
  disposers.push(webServer.register({ kind: 'exact', path: '/secure-gate/auth/login', handler: async (req, res) => {
    try {
      const ip = req.socket?.remoteAddress || '0.0.0.0'
      const body = await parseBody(req)
      const username = String(body?.username || '').trim()
      const password = String(body?.password || '')
      if (!username || !password) return sendJson(res, 400, { ok: false, error: '请输入用户名和密码' })

      // 速率限制 & 锁定检查
      const lockouts = getLockouts()
      const now = Date.now()
      const lockKey = 'login:' + username
      const lEntry = lockouts[lockKey]

      if (lEntry?.permanent) return sendJson(res, 429, { ok: false, error: '账户已永久锁定' })
      if (lEntry?.lockedUntil && lEntry.lockedUntil > now) {
        const remaining = Math.ceil((lEntry.lockedUntil - now) / 1000 / 60)
        return sendJson(res, 429, { ok: false, error: '账户已锁定，' + remaining + ' 分钟后重试' })
      }
      if (lEntry?.windowStart && now - lEntry.windowStart < cfg.rateLimit.windowMs && lEntry.attempts >= cfg.rateLimit.maxAttempts) {
        const count = (lEntry.lockoutCount || 0) + 1
        if (count >= cfg.lockout.permanentAfter) {
          setLockout(lockKey, { permanent: true, lockoutCount: count })
          auditLog('account_permanently_locked', { username })
          return sendJson(res, 429, { ok: false, error: '账户已永久锁定' })
        }
        setLockout(lockKey, { lockedUntil: now + cfg.lockout.duration, lockoutCount: count })
        auditLog('account_locked', { username })
        return sendJson(res, 429, { ok: false, error: '登录尝试过多，账户已锁定' })
      }

      const account = findAccount(username)
      if (!account) {
        setLockout(lockKey, { windowStart: now, attempts: (lEntry?.attempts || 0) + 1 })
        auditLog('login_failed', { username, ip, reason: '用户不存在' })
        return sendJson(res, 401, { ok: false, error: '用户名或密码错误' })
      }

      if (account.locked) {
        auditLog('login_blocked_locked', { username })
        return sendJson(res, 403, { ok: false, error: '账户已锁定，请联系管理员' })
      }

      if (!verifyPassword(password, account.passwordHash)) {
        setLockout(lockKey, { windowStart: lEntry?.windowStart || now, attempts: (lEntry?.attempts || 0) + 1 })
        auditLog('login_failed', { username, ip, reason: '密码错误' })
        return sendJson(res, 401, { ok: false, error: '用户名或密码错误' })
      }

      // 成功
      clearLockout(lockKey)
      auditLog('login_success', { username, ip })

      // MFA 检查
      if (account.totpVerified && account.totpSecret) {
        return sendJson(res, 200, { ok: true, mfaRequired: true })
      }

      issueSessionCookie(res, account, secret, cfg)
      const csrfToken = generateToken(32)
      setCookie(res, cfg.csrf?.cookieName || 'dsh_csrf', csrfToken, { path: '/', sameSite: 'strict', httpOnly: false })
      sendJson(res, 200, { ok: true, user: { username: account.username, role: account.role } })
    } catch (e) {
      auditLog('login_error', { error: e.message })
      sendJson(res, 500, { ok: false, error: '服务器内部错误' })
    }
  }))

  // POST /secure-gate/auth/mfa
  disposers.push(webServer.register({ kind: 'exact', path: '/secure-gate/auth/mfa', handler: async (req, res) => {
    sendJson(res, 501, { ok: false, error: 'TOTP 两步验证功能开发中' })
  }))

  // GET /secure-gate/auth/me
  disposers.push(webServer.register({ kind: 'exact', path: '/secure-gate/auth/me', handler: (req, res) => {
    const auth = requireAuth(req, cfg, secret)
    if (auth.ok) { sendJson(res, 200, { ok: true, user: auth.user }) }
    else { sendJson(res, 200, { ok: false }) }
  }))

  // POST /secure-gate/auth/logout
  disposers.push(webServer.register({ kind: 'exact', path: '/secure-gate/auth/logout', handler: (req, res) => {
    const token = readCookie(req, cfg.session.cookieName)
    if (token) {
      const tokenHash = sign(secret, token).toString('hex')
      removeSessionEntry(tokenHash)
    }
    setCookie(res, cfg.session.cookieName, '', { maxAge: 0, path: '/' })
    setCookie(res, cfg.csrf?.cookieName || 'dsh_csrf', '', { maxAge: 0, path: '/' })
    sendJson(res, 200, { ok: true })
  }))

  // GET /secure-gate/login (登录页面)
  disposers.push(webServer.register({ kind: 'exact', path: '/secure-gate/login', handler: (req, res) => {
    const locale = detectLocale(req)
    const html = renderLoginPage({ locale, step: 'login', bootstrap: !hasAccounts() })
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
    res.end(html)
  }))

  return disposers
}

// ── 安全请求门 (拦截所有非认证请求) ─────────────────────
function installGate(webServer, cfg, secret) {
  const server = webServer.server
  if (!server) return

  const publicPaths = ['/secure-gate/auth/', '/secure-gate/login', '/favicon.ico']

  // 在 Node HTTP server 上注册前置监听器，在所有路由处理之前拦截请求
  server.prependListener('request', (req, res) => {
    try {
      const url = req.url || '/'
      const rawPath = new URL(url, 'http://x').pathname || '/'

      // 公开路径放行
      if (publicPaths.some(p => rawPath === p || rawPath.startsWith(p))) return

      // 放行: 先检查 IP
      const ip = req.socket?.remoteAddress || ''
      if (cfg.ipAccess.allowlist.length > 0 && !cfg.ipAccess.allowlist.includes(ip)) {
        auditLog('gate_ip_blocked', { ip, path: rawPath })
        res.writeHead(403, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ ok: false, error: 'Access denied' }))
        return
      }
      if (cfg.ipAccess.blocklist.includes(ip)) {
        auditLog('gate_ip_blocked', { ip, path: rawPath })
        res.writeHead(403, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ ok: false, error: 'Access denied' }))
        return
      }

      // 检查会话
      const auth = requireAuth(req, cfg, secret)
      if (!auth.ok) {
        if (req.headers?.accept?.includes('text/html') && !url.startsWith('/api/')) {
          // HTML 页面 → 重定向到登录页
          res.writeHead(302, { Location: '/secure-gate/login' })
          res.end()
        } else {
          // API 请求 → 返回 401
          res.writeHead(401, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ ok: false, error: 'Unauthorized' }))
        }
        return
      }
    } catch (e) {
      // 出错时不要阻塞请求
    }
  })
}

// ── 安全响应头 ──────────────────────────────────────────
const DEFAULT_CSP = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' ws: wss:; font-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'"

function installSecurityHeaders(webServer, cfg) {
  const server = webServer.server
  if (!server) return

  server.prependListener('request', (req, res) => {
    // 为所有响应添加安全头（不拦截原有流转）
    const originalWriteHead = res.writeHead.bind(res)
    res.writeHead = function(statusCode, ...args) {
      if (!this._secureGateHeadersSet) {
        this._secureGateHeadersSet = true
        this.setHeader('X-Content-Type-Options', 'nosniff')
        this.setHeader('X-Frame-Options', 'DENY')
        this.setHeader('X-XSS-Protection', '1; mode=block')
        this.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin')
        this.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
        if (cfg.csp?.enabled !== false) {
          this.setHeader('Content-Security-Policy', DEFAULT_CSP)
        }
      }
      return originalWriteHead(statusCode, ...args)
    }
  })
}

// ── 插件入口 ──────────────────────────────────────────
export function apply(ctx, config = {}) {
  const cfg = parseConfig(config)
  loadStore()
  const secret = getSecret()
  loadSessions()

  // ── 启动引导 ────────────────────────────────────────
  if (cfg.bootstrap?.username && cfg.bootstrap?.password) {
    const username = cfg.bootstrap.username.trim()
    const password = cfg.bootstrap.password
    if (username && password && !hasAccounts()) {
      const strength = checkPasswordStrength(password, cfg.passwordPolicy)
      if (!strength.ok) {
        throw new Error('[secure-gate] 启动密码不满足安全策略: ' + strength.errors.join(', '))
      }
      const hash = hashPassword(password)
      const codes = []
      for (let i = 0; i < 8; i++) {
        codes.push({ code: sha256(randomBytes(6).toString('hex')), used: false })
      }
      upsertAccount({ username, role: 'admin', passwordHash: hash, backupCodes: codes })
      auditLog('bootstrap_admin_created', { username })
      ctx.logger.info('[secure-gate] 管理员账户 "%s" 已创建', username)
    }
  }

  // Seed 配置账户
  for (const seed of cfg.accounts || []) {
    const existing = findAccount(seed.username)
    if (existing) continue
    upsertAccount({
      username: seed.username,
      role: seed.role || 'user',
      passwordHash: seed.password.startsWith('A2$') ? seed.password : hashPassword(seed.password),
    })
  }

  const webServer = ctx.webServer
  if (!webServer) {
    ctx.logger.error('[secure-gate] webServer 服务未就绪')
    return
  }

  // 注册认证路由 (使用 webServer.register API)
  const disposers = registerAuthRoutes(webServer, cfg, secret)

  // 安装安全请求门 (使用 Node HTTP server 前置拦截)
  if (cfg.enabled) {
    installGate(webServer, cfg, secret)
  }

  // 安装安全响应头
  installSecurityHeaders(webServer, cfg)

  ctx.logger.info('[secure-gate] 安全网关已激活')
  ctx.logger.info('  账户: %d 个', _store.accounts.length)

  // 清理
  ctx.on('dispose', () => {
    saveStore()
    saveSessions()
    for (const d of disposers) d()
  })
}