/**
 * dsh-secure-gate — 登录页面 HTML 渲染
 * 内嵌所有样式，无外部依赖，支持中英文
 */

export function renderLoginPage(options: {
  locale?: 'zh' | 'en'
  step?: string
  error?: string
  csrfToken?: string
  bootstrap?: boolean
} = {}): string {
  const locale = options.locale || 'en'
  const lang = locale === 'zh' ? 'zh' : 'en'
  const t = (zh: string, en: string) => lang === 'zh' ? zh : en

  return `<!DOCTYPE html>
<html lang="${lang}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${t('DSH 安全网关', 'DSH Secure Gate')}</title>
<style>
  *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
  @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
  @keyframes glow { 0%, 100% { box-shadow: 0 0 20px rgba(59,130,246,0.1); } 50% { box-shadow: 0 0 40px rgba(59,130,246,0.2); } }
  @keyframes slideUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
    min-height: 100vh; display: flex; align-items: center; justify-content: center;
    color: #e2e8f0; margin: 0;
  }
  .card {
    background: rgba(30, 41, 59, 0.8);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border: 1px solid rgba(51, 65, 85, 0.5);
    border-radius: 20px; padding: 48px; width: 420px; max-width: 92vw;
    animation: fadeIn 0.6s ease-out;
  }
  .logo { text-align: center; margin-bottom: 32px; }
  .logo-icon { font-size: 48px; margin-bottom: 8px; display: block; }
  .logo h1 { font-size: 22px; font-weight: 700; color: #f1f5f9; letter-spacing: -0.3px; }
  .logo p { font-size: 13px; color: #64748b; margin-top: 4px; }
  .tabs { display: flex; gap: 8px; margin-bottom: 24px; background: #0f172a; border-radius: 12px; padding: 4px; }
  .tab { flex: 1; padding: 10px; text-align: center; border-radius: 8px; cursor: pointer;
         font-size: 13px; font-weight: 500; color: #64748b; transition: all 0.2s;
         border: none; background: transparent; }
  .tab.active { color: #f1f5f9; background: #1e293b; box-shadow: 0 1px 3px rgba(0,0,0,0.3); }
  .form-group { margin-bottom: 20px; }
  label { display: block; font-size: 12px; font-weight: 600; color: #94a3b8; margin-bottom: 6px;
          text-transform: uppercase; letter-spacing: 0.5px; }
  input {
    width: 100%; padding: 12px 16px; border-radius: 10px; border: 1px solid #334155;
    background: #0f172a; color: #e2e8f0; font-size: 14px; outline: none;
    transition: border-color 0.2s, box-shadow 0.2s; font-family: inherit;
  }
  input:focus { border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59,130,246,0.15); }
  input::placeholder { color: #475569; }
  .btn {
    width: 100%; padding: 14px; border-radius: 10px; border: none;
    font-size: 15px; font-weight: 600; cursor: pointer; transition: all 0.2s;
    font-family: inherit; letter-spacing: 0.3px;
  }
  .btn-primary {
    background: linear-gradient(135deg, #3b82f6, #2563eb);
    color: white; box-shadow: 0 4px 14px rgba(59,130,246,0.3);
  }
  .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 6px 20px rgba(59,130,246,0.4); }
  .btn-primary:active { transform: translateY(0); }
  .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
  .btn-secondary {
    background: rgba(51, 65, 85, 0.5); color: #e2e8f0; margin-top: 12px;
    border: 1px solid rgba(51, 65, 85, 0.5);
  }
  .btn-secondary:hover { background: rgba(71, 85, 105, 0.5); }
  .error {
    animation: slideUp 0.3s ease-out;
    background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3);
    color: #fca5a5; padding: 12px 16px; border-radius: 10px; margin-bottom: 20px;
    font-size: 13px; display: flex; align-items: center; gap: 8px;
  }
  .info {
    animation: slideUp 0.3s ease-out;
    background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.3);
    color: #93c5fd; padding: 12px 16px; border-radius: 10px; margin-bottom: 20px;
    font-size: 13px;
  }
  .badge {
    text-align: center; margin-top: 32px; padding-top: 20px;
    border-top: 1px solid rgba(51, 65, 85, 0.5);
  }
  .badge span { font-size: 11px; color: #475569; letter-spacing: 0.5px; }
  .badge-icons { margin-top: 6px; font-size: 14px; letter-spacing: 4px; }
  .hidden { display: none; }
  .mfa-input {
    text-align: center; font-size: 28px !important; letter-spacing: 10px;
    font-weight: 700; padding: 16px !important;
  }
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <span class="logo-icon">🛡️</span>
    <h1>${t('DSH 安全网关', 'DSH Secure Gate')}</h1>
    <p>${t('请输入凭据以继续', 'Sign in to continue')}</p>
  </div>

  ${options.error ? '<div class="error">⚠️ ' + escapeHtml(options.error) + '</div>' : ''}
  ${options.bootstrap ? '<div class="info">🔑 ' + t('首次启动：请创建管理员账户', 'First boot: create admin account') + '</div>' : ''}

  <div class="tabs" role="tablist">
    <button class="tab active" data-tab="password" role="tab">${t('密码登录', 'Password')}</button>
    <button class="tab" data-tab="passkey" role="tab">${t('Passkey', '🔑 Passkey')}</button>
  </div>

  <form id="passwordForm">
    <div class="form-group">
      <label for="username">${t('用户名', 'Username')}</label>
      <input type="text" id="username" name="username" placeholder="${t('输入用户名', 'Enter username')}"
             autocomplete="username" required autofocus>
    </div>
    <div class="form-group">
      <label for="password">${t('密码', 'Password')}</label>
      <input type="password" id="password" name="password" placeholder="${t('输入密码', 'Enter password')}"
             autocomplete="current-password" required>
    </div>
    <button type="submit" class="btn btn-primary" id="loginBtn">
      ${t('登录', 'Sign In')}
    </button>
  </form>

  <form id="mfaForm" class="hidden">
    <div class="form-group">
      <label for="mfaCode">${t('两步验证码', 'Two-Factor Code')}</label>
      <input type="text" id="mfaCode" class="mfa-input" placeholder="000000"
             maxlength="6" pattern="[0-9]*" inputmode="numeric" autocomplete="one-time-code">
    </div>
    <button type="submit" class="btn btn-primary">${t('验证', 'Verify')}</button>
    <p style="font-size: 12px; color: #64748b; margin-top: 12px; text-align: center;">
      ${t('也可以使用备份恢复码', 'Or use a backup recovery code')}
    </p>
    <input type="text" id="mfaBackup" placeholder="${t('XXXX-XXXX-XXXX-XXXX', 'XXXX-XXXX-XXXX-XXXX')}"
           style="margin-top: 8px; text-align: center; font-family: monospace;">
  </form>

  <div class="badge">
    <span>${t('Argon2id 加密 · CSRF 保护 · 会话签名 · 审计日志', 'Argon2id · CSRF · Signed Sessions · Audit Log')}</span>
    <div class="badge-icons">🛡️ 🔐 ⚡ 📋</div>
  </div>
</div>

<script>
(function() {
  var csrfToken = '${options.csrfToken || ''}';
  var lang = '${lang}';
  var t = function(zh, en) { return lang === 'zh' ? zh : en; };

  // Tab switching
  document.querySelectorAll('.tab').forEach(function(tab) {
    tab.addEventListener('click', function() {
      document.querySelectorAll('.tab').forEach(function(t) { t.classList.remove('active'); });
      tab.classList.add('active');
      if (tab.dataset.tab === 'passkey') {
        alert(t('Passkey 登录功能开发中', 'Passkey login is under development'));
        document.querySelector('[data-tab="password"]').click();
      }
    });
  });

  // Password login
  document.getElementById('passwordForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    var btn = document.getElementById('loginBtn');
    btn.disabled = true;
    btn.textContent = t('登录中...', 'Signing in...');

    try {
      var res = await fetch('/secure-gate/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: document.getElementById('username').value,
          password: document.getElementById('password').value
        })
      });
      var data = await res.json();
      if (res.ok && data.ok) {
        if (data.mfaRequired) {
          document.getElementById('passwordForm').classList.add('hidden');
          document.getElementById('mfaForm').classList.remove('hidden');
        } else {
          window.location.href = '/';
        }
      } else {
        showError(data.error || t('登录失败', 'Login failed'));
      }
    } catch(e) {
      showError(t('网络错误，请检查连接', 'Network error'));
    }
    btn.disabled = false;
    btn.textContent = t('登录', 'Sign In');
  });

  // MFA verification
  document.getElementById('mfaForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    var code = document.getElementById('mfaCode').value;
    var backup = document.getElementById('mfaBackup').value;
    try {
      var res = await fetch('/secure-gate/auth/mfa', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: code, backupCode: backup || undefined })
      });
      var data = await res.json();
      if (data.ok) { window.location.href = '/'; }
      else { showError(data.error || t('验证失败', 'Verification failed')); }
    } catch(e) {
      showError(t('网络错误', 'Network error'));
    }
  });

  function showError(msg) {
    var existing = document.querySelector('.error');
    if (existing) existing.remove();
    var div = document.createElement('div');
    div.className = 'error';
    div.textContent = '⚠️ ' + msg;
    var card = document.querySelector('.card');
    card.insertBefore(div, card.querySelector('.tabs'));
  }
})();
<\/script>
</body>
</html>`
}

function escapeHtml(text: string): string {
  if (!text) return ''
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
}
