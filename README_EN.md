<p align="center">
  <img src="assets/logo.svg" width="120" alt="dsh-secure-gate" />
</p>

<h1 align="center">🛡️ dsh-secure-gate</h1>

<p align="center">
  <b>Enterprise-grade Authentication Gateway for DeepSeek Harness</b>
</p>

<p align="center">
  <a href="./README.md">中文</a> ·
  <a href="./docs/ARCHITECTURE.md">Architecture</a> ·
  <a href="./SECURITY.md">Security</a> ·
  <a href="./CHANGELOG.md">Changelog</a>
</p>

---

## 📖 Introduction

**dsh-secure-gate** brings enterprise-grade security to your DeepSeek Harness Web UI.

**Zero configuration install** — just install, restart, and use.

### Features

| Category | Features |
|:--|:--|
| 🔐 Password Security | Argon2id hashing / Strength policy / Expiry |
| 🔑 Two-Factor Auth | TOTP codes / Backup codes / WebAuthn (planned) |
| 🛡️ Web Security | CSRF protection / CSP / HSTS |
| 🚫 Access Control | Account lockout / IP allowlist/blocklist |
| 📋 Audit | Audit log / Session management |
| ⚡ Attack Defense | Rate limiting / Backoff |

---

## 🚀 Installation

```bash
# From GitHub (recommended)
dsh plugin --profile web add github:your-username/dsh-secure-gate

# Local development
dsh plugin --profile web add file:./plugins/dsh-secure-gate
```

Restart DSH and open your browser — you'll be greeted by the login page.

---

## 📄 License

MIT © 2025
