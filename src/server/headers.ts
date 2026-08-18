/**
 * dsh-secure-gate — 安全响应头注入
 */

import type { SecureGateConfig } from '../shared/types.js'

/** 默认 CSP 指令 */
const DEFAULT_CSP: Record<string, string> = {
  "default-src": "'self'",
  "script-src": "'self' 'unsafe-inline' 'unsafe-eval'",
  "style-src": "'self' 'unsafe-inline'",
  "img-src": "'self' data: blob:",
  "connect-src": "'self' ws: wss:",
  "font-src": "'self' data:",
  "object-src": "'none'",
  "base-uri": "'self'",
  "form-action": "'self'",
}

/** 安装安全响应头中间件 */
export function installSecurityHeaders(webServer: any, cfg: SecureGateConfig) {
  // 使用 use 机制给所有响应添加安全头
  const originalUse = webServer.use
  webServer.use = function (this: any, ...args: any[]) {
    let path = '/'
    let handlers: Function[] = []

    if (typeof args[0] === 'string') {
      path = args[0]
      handlers = args.slice(1)
    } else {
      handlers = args
    }

    const wrappedHandler = (req: any, res: any, next: any) => {
      if (!res.headersSent) {
        res.setHeader('X-Content-Type-Options', 'nosniff')
        res.setHeader('X-Frame-Options', 'DENY')
        res.setHeader('X-XSS-Protection', '1; mode=block')
        res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin')
        res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')

        if (cfg.csp.enabled) {
          const cspValue = Object.entries(DEFAULT_CSP)
            .map(([k, v]) => `${k} ${v}`)
            .join('; ')
          res.setHeader('Content-Security-Policy', cspValue)
        }
      }
      next()
    }

    return originalUse.call(this, path, wrappedHandler, ...handlers)
  }
}
