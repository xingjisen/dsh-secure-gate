/**
 * dsh-secure-gate — 角色权限控制
 */

import type { UserRole } from '../shared/types.js'

/** 各角色的拒绝路径模式 */
const DENY_PATTERNS: Record<UserRole, string[]> = {
  admin: [],
  user: [
    '/api/settings',
    '/api/credentials',
    '/api/agentPreset',
    '/api/host',
    '/api/discovery',
  ],
  guest: [
    '/api',
    '/prompt',
    '/session',
    '/workspace',
  ],
}

/** 获取指定角色的拒绝路径模式 */
export function getRoleDenyPatterns(role: UserRole): string[] {
  return DENY_PATTERNS[role] || DENY_PATTERNS.user
}

/** 检查用户是否有权限访问路径 */
export function checkRoleAccess(role: UserRole, path: string): boolean {
  const patterns = getRoleDenyPatterns(role)
  return !patterns.some(p => path.startsWith(p))
}
