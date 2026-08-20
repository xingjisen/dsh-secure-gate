/**
 * dsh-secure-gate — 浏览器端
 * 
 * 功能:
 *   1. 会话过期时内嵌登录覆盖层
 *   2. 设置页面的安全设置面板
 */

window.__ModuleLoader__.load({
  id: "dsh-secure-gate",
  factory: (require) => {
    var module = { exports: {} }
    var exports = module.exports
    Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" })

    var react = require("react")
    var jsxRuntime = require("react/jsx-runtime")
    var reactDOMClient = require("react-dom/client")
    const { jsx } = jsxRuntime

    function h(type, props) {
      var children = []
      for (var i = 2; i < arguments.length; i++) children.push(arguments[i])
      if (children.length === 0) return jsx(type, props || {})
      return jsx(type, { ...(props || {}), children: children.length === 1 ? children[0] : children })
    }

    var locale = "zh"

    function t(zh, en) { return zh }

    // ── 登录覆盖层 ────────────────────────────────────────
    function LoginOverlay() {
      var _a = react.useState("")
      var step = _a[0], setStep = _a[1]
      var _b = react.useState("")
      var error = _b[0], setError = _b[1]
      var _c = react.useState(false)
      var loading = _c[0], setLoading = _c[1]

      react.useEffect(function() {
        checkSession()
      }, [])

      async function checkSession() {
        try {
          var res = await fetch("/secure-gate/auth/me", { credentials: "include" })
          var data = await res.json()
          if (data.ok) window.location.reload()
        } catch (e) {}
      }

      async function handleLogin(event) {
        event.preventDefault()
        setLoading(true)
        setError("")
        try {
          var res = await fetch("/secure-gate/auth/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({
              username: event.target.username.value,
              password: event.target.password.value
            })
          })
          var data = await res.json()
          if (res.ok && data.ok) {
            if (data.mfaRequired) {
              setStep("mfa")
            } else {
              window.location.reload()
            }
          } else {
            setError(data.error || t("登录失败", "Login failed"))
          }
        } catch (e) {
          setError(t("网络错误", "Network error"))
        }
        setLoading(false)
      }

      async function handleMfa(event) {
        event.preventDefault()
        setLoading(true)
        try {
          var res = await fetch("/secure-gate/auth/mfa", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({ code: event.target.code.value })
          })
          var data = await res.json()
          if (data.ok) window.location.reload()
          else setError(data.error || t("验证失败", "Verification failed"))
        } catch (e) {
          setError(t("网络错误", "Network error"))
        }
        setLoading(false)
      }

      return h("div", { style: {
        position: "fixed", inset: 0, zIndex: 999999,
        display: "flex", alignItems: "center", justifyContent: "center",
        background: "linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%)",
        fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"
      }},
        h("div", { style: {
          background: "#1e293b", border: "1px solid #334155", borderRadius: 16,
          padding: 40, width: 380, maxWidth: "90vw", color: "#e2e8f0"
        }},
          h("div", { style: { textAlign: "center", marginBottom: 24 }},
            h("h1", { style: { fontSize: 22, margin: 0 } }, "🔐 " + t("会话已过期", "Session Expired")),
            h("p", { style: { fontSize: 13, color: "#64748b", marginTop: 4 } },
              t("请重新登录以继续", "Please sign in again"))
          ),
          error ? h("div", { style: {
            background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)",
            color: "#fca5a5", padding: "10px 14px", borderRadius: 8,
            marginBottom: 16, fontSize: 13
          }}, error) : null,
          step !== "mfa" ? h("form", { onSubmit: handleLogin },
            h("div", { style: { marginBottom: 16 }},
              h("label", { style: { display: "block", fontSize: 13, color: "#94a3b8", marginBottom: 6 } },
                t("用户名", "Username")),
              h("input", {
                type: "text", name: "username", required: true,
                style: inputStyle, autoFocus: true
              })
            ),
            h("div", { style: { marginBottom: 20 }},
              h("label", { style: { display: "block", fontSize: 13, color: "#94a3b8", marginBottom: 6 } },
                t("密码", "Password")),
              h("input", {
                type: "password", name: "password", required: true,
                style: inputStyle
              })
            ),
            h("button", {
              type: "submit", disabled: loading,
              style: btnStyle
            }, loading ? t("登录中...", "Signing in...") : t("登录", "Sign In"))
          ) : h("form", { onSubmit: handleMfa },
            h("div", { style: { marginBottom: 16 }},
              h("label", { style: { display: "block", fontSize: 13, color: "#94a3b8", marginBottom: 6 } },
                t("两步验证码", "Two-Factor Code")),
              h("input", {
                type: "text", name: "code", required: true,
                maxLength: 6, pattern: "[0-9]*",
                style: { ...inputStyle, textAlign: "center", fontSize: 24, letterSpacing: 8 }
              })
            ),
            h("button", {
              type: "submit", disabled: loading,
              style: btnStyle
            }, t("验证", "Verify"))
          )
        )
      )
    }

    var inputStyle = {
      width: "100%", padding: "10px 14px", borderRadius: 8,
      border: "1px solid rgba(127,127,127,0.45)", background: "transparent",
      color: "inherit", fontSize: 14, outline: "none",
      colorScheme: "light dark", boxSizing: "border-box"
    }

    var btnStyle = {
      width: "100%", padding: "12px", borderRadius: 8, border: "none",
      fontSize: 15, fontWeight: 600, cursor: "pointer",
      background: "#3b82f6", color: "white"
    }

    // ── 设置面板 ──────────────────────────────────────────
    function doLogout() {
      fetch("/secure-gate/auth/logout", { method: "POST", credentials: "include" })
        .then(function() { window.location.href = "/secure-gate/login" })
        .catch(function() { window.location.reload() })
    }

    function SecureGateSettings() {
      var _u = react.useState({ username: "", role: "" })
      var user = _u[0], setUser = _u[1]
      var _m = react.useState(null)
      var msg = _m[0], setMsg = _m[1]
      react.useEffect(function() {
        fetch("/secure-gate/auth/me", { credentials: "include" })
          .then(function(r){ return r.json() })
          .then(function(d){ if (d && d.ok && d.user) setUser({ username: d.user.username, role: d.user.role }) })
          .catch(function(){})
      }, [])
      function onChangePw(e) {
        e.preventDefault()
        var oldP = e.target.oldPassword.value
        var newP = e.target.newPassword.value
        var conf = e.target.confirmPassword.value
        if (newP !== conf) { setMsg({ type: "err", text: t("两次输入的新密码不一致", "New passwords do not match") }); return }
        fetch("/secure-gate/auth/change-password", {
          method: "POST", credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ oldPassword: oldP, newPassword: newP })
        }).then(function(r){ return r.json() })
          .then(function(d){
            if (d && d.ok) { setMsg({ type: "ok", text: t("密码已修改", "Password updated") }); e.target.reset() }
            else { setMsg({ type: "err", text: d.error || t("修改失败", "Failed") }) }
          })
          .catch(function(){ setMsg({ type: "err", text: t("网络错误", "Network error") }) })
      }
      var lab = { display: "block", fontSize: 13, marginBottom: 6 }
      return h("div", { style: { padding: 20 } },
        h("h2", {}, t("安全设置", "Security Settings")),
        h("p", { style: { fontSize: 13 } },
          t("当前账户：", "Account: ") + (user.username || "-") + " · " + (user.role || "")),
        h("div", { style: { marginTop: 16, display: "flex", gap: 8, flexWrap: "wrap" }},
          h("span", { style: badgeStyle }, "🛡️ " + t("Argon2id 加密", "Argon2id Encryption")),
          h("span", { style: badgeStyle }, "🔑 " + t("会话管理", "Session Management")),
          h("span", { style: badgeStyle }, "📋 " + t("审计日志", "Audit Log")),
          h("span", { style: badgeStyle }, "🚫 " + t("IP 控制", "IP Control")),
          h("span", { style: badgeStyle }, "🔄 " + t("CSRF 保护", "CSRF Protection"))
        ),
        h("h3", { style: { marginTop: 24, fontSize: 15 } }, t("修改密码", "Change Password")),
        msg ? h("div", { style: { background: msg.type === "ok" ? "rgba(16,185,129,0.12)" : "rgba(239,68,68,0.12)", color: "inherit", padding: "10px 14px", borderRadius: 8, marginBottom: 12, fontSize: 13 } }, msg.text) : null,
        h("form", { onSubmit: onChangePw },
          h("div", { style: { marginBottom: 12 }},
            h("label", { style: lab }, t("当前密码", "Current Password")),
            h("input", { type: "password", name: "oldPassword", required: true, style: inputStyle })),
          h("div", { style: { marginBottom: 12 }},
            h("label", { style: lab }, t("新密码", "New Password")),
            h("input", { type: "password", name: "newPassword", required: true, style: inputStyle })),
          h("div", { style: { marginBottom: 16 }},
            h("label", { style: lab }, t("确认新密码", "Confirm New Password")),
            h("input", { type: "password", name: "confirmPassword", required: true, style: inputStyle })),
          h("button", { type: "submit", style: btnStyle }, t("修改密码", "Update Password"))
        ),
        h("button", { onClick: doLogout, style: { marginTop: 20, padding: "12px 20px", borderRadius: 8, border: "none", background: "#dc2626", color: "#fff", fontSize: 14, cursor: "pointer" } }, t("退出登录", "Log Out"))
      )
    }

    var badgeStyle = {
      background: "rgba(59,130,246,0.16)", border: "1px solid rgba(59,130,246,0.4)",
      borderRadius: 6, padding: "6px 12px", fontSize: 12, color: "inherit"
    }

    // ── 会话监控 ──────────────────────────────────────────
    function startSessionMonitor() {
      var interval = setInterval(async function() {
        try {
          var res = await fetch("/secure-gate/auth/me", { credentials: "include" })
          if (res.status === 401) {
            var root = document.createElement("div")
            root.id = "dsh-secure-gate-overlay"
            document.body.appendChild(root)
            reactDOMClient.createRoot(root).render(h(LoginOverlay))
            clearInterval(interval)
          }
        } catch (e) {}
      }, 60000)
    }

    // ── 自启动 ────────────────────────────────────────────
    startSessionMonitor()

    const inject = ["slots"]
    function apply(ctx) {
      try {
        if (ctx && ctx.slots && typeof ctx.slots.inject === "function") {
          ctx.slots.inject("settings.section", () => ctx.slots.register({
            name: "settings.section",
            id: "secure-gate",
            order: 100,
            label: () => t("安全", "Security"),
            inject: () => ({})
          }, SecureGateSettings))
        }
      } catch (e) {}
      try { startSessionMonitor() } catch (e) {}
    }
    exports.apply = apply
    exports.inject = inject
    return module.exports
  }
})