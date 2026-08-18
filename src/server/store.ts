/**
 * dsh-secure-gate — 持久化存储
 * 账户、会话、锁定状态、审计日志
 */

import { randomBytes, createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync, appendFileSync } from 'node:fs'
import { join } from 'node:path'
import type { Account, UserRole, BackupCode, Session, AuditEvent } from '../shared/types.js'

const DSH_HOME = process.env.DSH_HOME || join(process.env.HOME || process.env.USERPROFILE || '', '.dsh')
const AUTH_DIR = join(DSH_HOME, 'auth')
const STORE_PATH = join(AUTH_DIR, 'secure-store.json')
const AUDIT_PATH = join(AUTH_DIR, 'audit.log')
const SESSIONS_PATH = join(AUTH_DIR, 'sessions.json')

// ── 内存状态 ─────────────────────────────────────────
let _store: {
  accounts: Account[]
  secret: string
  lockouts: Record<string, any>
} = { accounts: [], secret: '', lockouts: {} }

let _sessions: Record<string, Session> = {}

// ── 初始化 ───────────────────────────────────────────
function ensureDir() {
  if (!existsSync(AUTH_DIR)) mkdirSync(AUTH_DIR, { recursive: true })
}

export function loadStore(path = STORE_PATH) {
  ensureDir()
  try {
    if (existsSync(path)) {
      _store = JSON.parse(readFileSync(path, 'utf8'))
    }
  } catch (e: any) {
    console.error('[secure-gate] 加载存储失败:', e.message)
  }
  if (!_store.secret) {
    _store.secret = randomBytes(64).toString('base64url')
    saveStore()
  }
  if (!_store.lockouts) _store.lockouts = {}
  return _store
}

export function saveStore(path = STORE_PATH) {
  ensureDir()
  try {
    writeFileSync(path, JSON.stringify(_store, null, 2))
    try { chmodSync(path, 0o600) } catch {}
  } catch (e: any) {
    console.error('[secure-gate] 保存存储失败:', e.message)
  }
}

export function getStoreSecret(): string { return _store.secret }

// ── 账户 ─────────────────────────────────────────────
export function findAccount(username: string): Account | null {
  return _store.accounts.find(a => a.username === username) || null
}

export function hasAccounts(): boolean {
  return _store.accounts.length > 0
}

export function upsertAccount(data: Partial<Account> & { username: string }): Account {
  const idx = _store.accounts.findIndex(a => a.username === data.username)
  const entry: Account = {
    username: data.username,
    role: (data.role || 'user') as UserRole,
    passwordHash: data.passwordHash || '',
    createdAt: data.createdAt || Date.now(),
    passwordChangedAt: Date.now(),
    totpSecret: data.totpSecret || null,
    totpVerified: data.totpVerified || false,
    backupCodes: data.backupCodes || [],
    webauthnCredentials: data.webauthnCredentials || [],
    locked: data.locked || false,
    lockedUntil: data.lockedUntil || null,
    lockoutCount: data.lockoutCount || 0,
    passwordExpiresAt: data.passwordExpiresAt || (Date.now() + 90 * 86400000),
  }
  if (idx >= 0) {
    _store.accounts[idx] = { ..._store.accounts[idx], ...entry }
  } else {
    _store.accounts.push(entry)
  }
  saveStore()
  return entry
}

export function removeAccount(username: string) {
  _store.accounts = _store.accounts.filter(a => a.username !== username)
  saveStore()
}

export function getAccounts() {
  return _store.accounts.map(a => ({
    username: a.username,
    role: a.role,
    createdAt: a.createdAt,
    locked: a.locked,
    totpVerified: a.totpVerified,
    hasWebAuthn: (a.webauthnCredentials?.length || 0) > 0,
    passwordExpiresAt: a.passwordExpiresAt,
  }))
}

// ── 锁定 ─────────────────────────────────────────────
export function getLockouts() { return _store.lockouts || {} }

export function setLockout(key: string, data: any) {
  if (!_store.lockouts) _store.lockouts = {}
  _store.lockouts[key] = data
  saveStore()
}

export function clearLockout(key: string) {
  if (_store.lockouts) {
    delete _store.lockouts[key]
    saveStore()
  }
}

// ── 会话 ─────────────────────────────────────────────
export function loadSessions() {
  try {
    if (existsSync(SESSIONS_PATH)) {
      _sessions = JSON.parse(readFileSync(SESSIONS_PATH, 'utf8'))
    }
  } catch { _sessions = {} }
  return _sessions
}

export function saveSessions() {
  ensureDir()
  try {
    writeFileSync(SESSIONS_PATH, JSON.stringify(_sessions, null, 2))
    try { chmodSync(SESSIONS_PATH, 0o600) } catch {}
  } catch {}
}

export function getSessions() { return _sessions }

export function recordSession(tokenHash: string, data: Partial<Session>) {
  _sessions[tokenHash] = {
    username: data.username || '',
    role: (data.role || 'user') as UserRole,
    createdAt: Date.now(),
    lastActiveAt: Date.now(),
    userAgent: data.userAgent || '',
    ip: data.ip || '',
  }
  saveSessions()
}

export function removeSession(tokenHash: string) {
  delete _sessions[tokenHash]
  saveSessions()
}

export function findSessionsByUser(username: string) {
  return Object.entries(_sessions)
    .filter(([_, s]) => s.username === username)
    .map(([token, data]) => ({ tokenHash: token.substring(0, 16) + '...', ...data }))
}

export function pruneExpiredSessions(maxAgeMs: number) {
  const now = Date.now()
  let changed = false
  for (const [token, data] of Object.entries(_sessions)) {
    if (data.createdAt + maxAgeMs < now) {
      delete _sessions[token]
      changed = true
    }
  }
  if (changed) saveSessions()
}

// ── TOTP ─────────────────────────────────────────────
export function generateTotpSecret(): string {
  return randomBytes(20).toString('base64url')
}

export function generateBackupCodes(count = 8): string[] {
  const codes: string[] = []
  for (let i = 0; i < count; i++) {
    codes.push(
      randomBytes(6).toString('hex').toUpperCase().replace(/(.{4})/g, '$1-').slice(0, -1)
    )
  }
  return codes
}

export function hashBackupCode(code: string): string {
  return createHash('sha256').update(code).digest('hex')
}

// ── 审计日志 ─────────────────────────────────────────
export function auditLog(event: string, details: Record<string, any> = {}) {
  const entry: AuditEvent = {
    timestamp: new Date().toISOString(),
    event,
    ...details,
  }
  try {
    ensureDir()
    appendFileSync(AUDIT_PATH, JSON.stringify(entry) + '\n')
    try { chmodSync(AUDIT_PATH, 0o600) } catch {}
  } catch {}
  console.log('[secure-gate]', event, JSON.stringify(details))
  return entry
}
