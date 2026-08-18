/** dsh-secure-gate 共享类型定义 */

/** 用户角色 */
export type UserRole = 'admin' | 'user' | 'guest'

/** 账户 */
export interface Account {
  username: string
  role: UserRole
  passwordHash: string
  createdAt: number
  passwordChangedAt: number
  totpSecret: string | null
  totpVerified: boolean
  backupCodes: BackupCode[]
  webauthnCredentials: WebAuthnCredential[]
  locked: boolean
  lockedUntil: number | null
  lockoutCount: number
  passwordExpiresAt: number
}

/** 备份恢复码 */
export interface BackupCode {
  code: string
  used: boolean
}

/** WebAuthn 凭据 */
export interface WebAuthnCredential {
  id: string
  publicKey: string
  counter: number
  transports: string[]
  createdAt: number
}

/** 会话 */
export interface Session {
  username: string
  role: UserRole
  createdAt: number
  lastActiveAt: number
  userAgent: string
  ip: string
}

/** 会话 Token 载荷 */
export interface SessionPayload {
  sub: string
  role: UserRole
  iat: number
  exp: number
  id: string
}

/** 审计事件 */
export interface AuditEvent {
  timestamp: string
  event: string
  username?: string
  ip?: string
  path?: string
  method?: string
  error?: string
  [key: string]: unknown
}

/** 认证结果 */
export interface AuthResult {
  ok: boolean
  user?: { username: string; role: UserRole }
  error?: string
}

/** 配置 */
export interface SecureGateConfig {
  enabled: boolean
  bootstrap?: { username: string; password: string }
  session: {
    cookieName: string
    ttlSeconds: number
    renewThreshold: number
    secure: boolean
    sameSite: 'strict' | 'lax' | 'none'
  }
  rateLimit: {
    maxAttempts: number
    windowMs: number
  }
  lockout: {
    maxFailed: number
    duration: number
    permanentAfter: number
  }
  passwordPolicy: {
    minLength: number
    requireUpper: boolean
    requireLower: boolean
    requireDigit: boolean
    requireSpecial: boolean
    maxAgeDays: number
  }
  csrf: { enabled: boolean }
  ipAccess: {
    allowPrivateOnly: boolean
    allowlist: string[]
    blocklist: string[]
  }
  enforceRoles: boolean
  csp: { enabled: boolean }
  audit: boolean
  accounts: { username: string; password: string; role?: UserRole }[]
}
