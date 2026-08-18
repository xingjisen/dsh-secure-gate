// dsh-secure-gate login page renderer (bilingual, default Chinese)
export function renderLoginPage(options = {}) {
  const lang = options.locale || 'zh'
  const zh = lang === 'zh'
  const t = (z, e) => zh ? z : e
  const defaults = {
    title: t('DSH 安全网关', 'DSH Secure Gate'),
    subtitle: zh ? '安全登录以继续访问 DSH' : 'Sign in securely to continue DSH',
    username: t('用户名', 'Username'),
    password: t('密码', 'Password'),
    passkey: t('通行密钥', 'Passkey'),
    passwordTab: t('密码登录', 'Password'),
    signIn: t('登 录', 'Sign In'),
    signingIn: t('登录中...', 'Signing in...'),
    verify: t('验 证', 'Verify'),
    verifying: t('验证中...', 'Verifying...'),
    twoFactor: t('两步验证码', 'Two-Factor Code'),
    switchLang: zh ? 'English' : '中文',
    badge: t('Argon2id 加密 · CSRF 保护 · 会话签名 · 审计日志', 'Argon2id · CSRF · Signed Session · Audit Log'),
    firstBoot: zh ? '首次启动：请使用管理员账号登录后立即修改密码' : 'First boot: log in with your admin account, then change the password',
    welcome: zh ? '欢迎使用 DSH 安全网关' : 'Welcome to DSH Secure Gate',
    helpHint: zh ? '账号密码由管理员配置；首次安装请查看下方引导' : 'Credentials are set by the admin; see the guide below on first install',
  }
  const langBtn = options.switchLang === false
    ? ''
    : '<button class="lang" id="langBtn">' + defaults.switchLang + '</button>'
  const bootBox = options.bootstrap
    ? '<div class="info">⚠️ ' + defaults.firstBoot + '<br><span class="mono">' + defaults.helpHint + '</span></div>'
    : ''
  return `<!DOCTYPE html>
<html lang="${lang}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>${defaults.title}</title>
<style>
 *,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
 @keyframes fi{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
 body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'PingFang SC','Microsoft YaHei',sans-serif;
   background:linear-gradient(135deg,#0f172a 0%,#1e293b 50%,#0f172a 100%);min-height:100vh;
   display:flex;align-items:center;justify-content:center;color:#e2e8f0;margin:0}
 .card{position:relative;background:rgba(30,41,59,.82);-webkit-backdrop-filter:blur(22px);backdrop-filter:blur(22px);
   border:1px solid rgba(51,65,85,.5);border-radius:22px;padding:48px;width:420px;max-width:92vw;animation:fi .55s ease-out}
 .lang{position:absolute;top:18px;right:18px;background:rgba(51,65,85,.4);border:1px solid rgba(71,85,105,.6);
   color:#94a3b8;padding:6px 12px;border-radius:999px;font-size:12px;cursor:pointer;transition:all .2s}
 .lang:hover{color:#e2e8f0;border-color:#3b82f6;background:rgba(59,130,246,.12)}
 .logo{text-align:center;margin-bottom:26px}
 .logo-icon{font-size:52px;display:block;margin-bottom:6px}
 .logo h1{font-size:23px;font-weight:700;color:#f1f5f9;letter-spacing:.5px}
 .logo p{font-size:13px;color:#64748b;margin-top:6px}
 .tabs{display:flex;gap:8px;margin-bottom:24px;background:#0f172a;border-radius:12px;padding:4px}
 .tab{flex:1;padding:11px;text-align:center;border-radius:9px;cursor:pointer;font-size:13px;font-weight:500;color:#64748b;transition:all .2s;border:none;background:0 0}
 .tab.active{color:#f1f5f9;background:#1e293b;box-shadow:0 1px 4px rgba(0,0,0,.35)}
 .fg{margin-bottom:20px}
 label{display:block;font-size:12px;font-weight:600;color:#94a3b8;margin-bottom:6px;letter-spacing:.5px}
 input{width:100%;padding:12px 16px;border-radius:10px;border:1px solid #334155;background:#0f172a;
   color:#e2e8f0;font-size:14px;outline:none;transition:border-color .2s,box-shadow .2s;font-family:inherit;box-sizing:border-box}
 input:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,.16)}
 input::placeholder{color:#475569}
 .btn{width:100%;padding:14px;border-radius:10px;border:none;font-size:15px;font-weight:600;cursor:pointer;transition:all .2s;font-family:inherit;letter-spacing:2px}
 .btn-primary{background:linear-gradient(135deg,#3b82f6,#2563eb);color:#fff;box-shadow:0 4px 16px rgba(59,130,246,.35)}
 .btn-primary:hover{transform:translateY(-1px);box-shadow:0 6px 22px rgba(59,130,246,.5)}
 .btn-primary:disabled{opacity:.5;cursor:default;transform:none}
 .err{animation:fi .3s;background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.35);color:#fca5a5;
   padding:12px 16px;border-radius:10px;margin-bottom:20px;font-size:13px}
 .info{animation:fi .3s;background:rgba(59,130,246,.1);border:1px solid rgba(59,130,246,.3);color:#93c5fd;
   padding:14px 16px;border-radius:10px;margin-bottom:20px;font-size:13px;line-height:1.7}
 .mono{font-family:'JetBrains Mono',Consolas,monospace;font-size:12px;color:#7dd3fc}
 .badge{text-align:center;margin-top:30px;padding-top:20px;border-top:1px solid rgba(51,65,85,.5)}
 .badge span{font-size:11px;color:#475569;letter-spacing:.5px}
 .hidden{display:none}
 .mfa-input{text-align:center;font-size:26px!important;letter-spacing:10px;font-weight:700}
</style>
</head>
<body><div class="card">
${langBtn}
<div class="logo"><span class="logo-icon">\u{1f6e1}\u{fe0f}</span><h1>${defaults.title}</h1><p>${defaults.subtitle}</p></div>
${options.error ? '<div class="err">' + options.error + '</div>' : ''}
${bootBox}
<div class="tabs"><button class="tab active" data-tab="password">${defaults.passwordTab}</button>
<button class="tab" data-tab="passkey">\u{1f511} ${defaults.passkey}</button></div>
<form id="f1"><div class="fg"><label>${defaults.username}</label>
<input id="u" name="username" placeholder="${defaults.username}" autocomplete="username" required autofocus></div>
<div class="fg"><label>${defaults.password}</label>
<input type="password" id="p" name="password" placeholder="${defaults.password}" autocomplete="current-password" required></div>
<button type="submit" class="btn btn-primary" id="lb">${defaults.signIn}</button></form>
<form id="f2" class="hidden"><div class="fg"><label>${defaults.twoFactor}</label>
<input type="text" id="mc" class="mfa-input" placeholder="000000" maxlength="6" pattern="[0-9]*" inputmode="numeric"></div>
<button type="submit" class="btn btn-primary" id="mb">${defaults.verify}</button></form>
<div class="badge"><span>${defaults.badge}</span></div>
</div>
<script>
(function(){
 var zh=${String(zh)};
 var t=function(z,e){return zh?z:e};
 var langBtn=document.getElementById('langBtn');
 if(langBtn){langBtn.addEventListener('click',function(){
   var p=new URLSearchParams(location.search);p.set('lang',zh?'en':'zh');
   location.search=p.toString()})}
 document.querySelectorAll('.tab').forEach(function(tab){
  tab.addEventListener('click',function(){
   document.querySelectorAll('.tab').forEach(function(x){x.classList.remove('active')});
   tab.classList.add('active');
   if(tab.dataset.tab==='passkey'){alert(t('通行密钥功能开发中','Passkey coming soon'));
    document.querySelector('[data-tab=\'password\']').click()}
  })
 });
 document.getElementById('f1').addEventListener('submit',async function(e){
  e.preventDefault();var b=document.getElementById('lb');b.disabled=true;b.textContent=t('登录中...','Signing in...');
  try{
   var r=await fetch('/secure-gate/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('p').value})});
   var d=await r.json();
   if(r.ok&&d.ok){if(d.mfaRequired){document.getElementById('f1').classList.add('hidden');
     document.getElementById('f2').classList.remove('hidden')}else{window.location.href='/'}
   }else{sE(d.error||t('登录失败','Login failed'))}
  }catch(err){sE(t('网络错误，请检查连接','Network error'))}
  b.disabled=false;b.textContent=t('登录','Sign In')
 });
 document.getElementById('f2').addEventListener('submit',async function(e){
  e.preventDefault();var b=document.getElementById('mb');b.disabled=true;b.textContent=t('验证中...','Verifying...');
  try{var r=await fetch('/secure-gate/auth/mfa',{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({code:document.getElementById('mc').value})});
   var d=await r.json();if(d.ok){window.location.href='/'}else{sE(d.error||t('验证失败','Verification failed'))}}
  catch(err){sE(t('网络错误','Network error'))}
  b.disabled=false;b.textContent=t('验证','Verify')
 });
 function sE(m){var x=document.querySelector('.err');if(x)x.remove();var d=document.createElement('div');
  d.className='err';d.textContent='\u26a0\ufe0f '+m;
  document.querySelector('.card').insertBefore(d,document.querySelector('.tabs'))}
})();
<\/script>
</body></html>`
}
