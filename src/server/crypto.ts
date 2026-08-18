/**
 * dsh-secure-gate — 加密模块
 * 
 * 使用 Node.js 内置 crypto 库实现:
 * - Argon2id 风格密码哈希 (scrypt 模拟, OWASP 推荐参数)
 * - HMAC-SHA256 签名
 * - 安全令牌生成
 * - 常量时间比较
 */

import {
  randomBytes, scryptSync, timingSafeEqual, createHmac, createHash
} from 'node:crypto'

/** Argon2id 前缀标识 */
const PREFIX = 'A2$'

/**
 * Argon2id 风格密码哈希
 * 使用 scrypt 模拟 Argon2id 算法
 * 参数 (OWASP 2024 推荐):
 *   - N=2^17 (131072) — CPU/内存开销
 *   - r=8 — 块大小
 *   - p=1 — 并行度
 *   - dkLen=64 — 输出长度 (512 bit)
 *   - salt=32 bytes — 随机盐
 */
export function hashPassword(password: string, salt?: Buffer): string {
  const s = salt || randomBytes(32)
  const key = scryptSync(password, s, 64, {
    N: 131072,
    r: 8,
    p: 1,
    maxmem: 134217728, // 128MB
  })
  return `${PREFIX}${s.toString('base64url')}$${key.toString('base64url')}`
}

/** 验证密码 */
export function verifyPassword(password: string, hash: string): boolean {
  try {
    const parts = hash.split('$')
    if (parts[0] !== 'A2' || parts.length !== 3) return false
    const salt = Buffer.from(parts[1], 'base64url')
    const expected = Buffer.from(parts[2], 'base64url')
    const actual = scryptSync(password, salt, 64, {
      N: 131072, r: 8, p: 1, maxmem: 134217728,
    })
    if (actual.length !== expected.length) return false
    return timingSafeEqual(actual, expected)
  } catch {
    return false
  }
}

/** HMAC-SHA256 签名 */
export function sign(secret: string, data: string): Buffer {
  return createHmac('sha256', secret).update(data).digest()
}

/** 生成安全随机令牌 */
export function generateToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url')
}

/** 常量时间字符串比较 */
export function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  try {
    return timingSafeEqual(Buffer.from(a), Buffer.from(b))
  } catch {
    return false
  }
}

/** SHA-256 哈希 */
export function sha256(data: string): string {
  return createHash('sha256').update(data).digest('hex')
}

/** 检查密码强度 */
export function checkPasswordStrength(
  password: string,
  policy?: Partial<SecureGateConfig['passwordPolicy']>
): { ok: boolean; errors: string[] } {
  const p = {
    minLength: policy?.minLength ?? 8,
    requireUpper: policy?.requireUpper ?? true,
    requireLower: policy?.requireLower ?? true,
    requireDigit: policy?.requireDigit ?? true,
    requireSpecial: policy?.requireSpecial ?? true,
  }
  const errors: string[] = []
  if (password.length < p.minLength) errors.push(`最少 ${p.minLength} 个字符`)
  if (p.requireUpper && !/[A-Z]/.test(password)) errors.push('需要至少一个大写字母')
  if (p.requireLower && !/[a-z]/.test(password)) errors.push('需要至少一个小写字母')
  if (p.requireDigit && !/[0-9]/.test(password)) errors.push('需要至少一个数字')
  if (p.requireSpecial && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(password)) errors.push('需要至少一个特殊字符')
  return { ok: errors.length === 0, errors }
}

import type { SecureGateConfig } from '../shared/types.js'
