// dsh-secure-gate login page (bilingual, default Chinese, first-boot setup)
export function renderLoginPage(options = {}) {
  const lang = options.locale || 'zh'
  const zh = lang === 'zh'
  const t = (z, e) => zh ? z : e
  const bootstrap = !!options.bootstrap
  const d = {
    title: t('DSH 安全网关', 'DSH Secure Gate'),
    subtitle: zh ? '安全登录以继续访问 DSH' : 'Sign in securely to continue DSH',
    username: t('用户名', 'Username'),
    password: t('密码', 'Password'),
    confirmPw: t('确认密码', 'Confirm Password'),
    passkeys: t('通行密钥', 'Passkey'),
    passTab: t('密码登录', 'Password'),
    signIn: t('登 录', 'Sign In'),
    signingIn: t('登录中...', 'Signing in...'),
    twoFactor: t('两步验证码', 'Two-Factor Code'),
    switchLang: zh ? 'English' : '中文',
    badge: t('Argon2id 加密 · CSRF 保护 · 会话签名 · 审计日志', 'Argon2id · CSRF · Signed Session · Audit Log'),
    setTitle: zh ? '首次使用 · 创建管理员账户' : 'First Use · Create Admin Account',
    setSub: zh ? '请设置您自己的账号和密码，用于管理此 DSH 实例' : 'Set your own account to administer this DSH instance',
    userPh: zh ? '请输入管理员用户名' : 'Enter an admin username',
    pwPh: zh ? '至少 10 位，含大小写、数字、特殊字符' : 'At least 10 chars: upper, lower, digit, special',
    create: t('创建账户', 'Create Account'),
    creating: t('创建中...', 'Creating...'),
    verify: t('验 证', 'Verify'),
    verifying: t('验证中...', 'Verifying...'),
  }
  const langBtn = options.switchLang === false ? '' : '<button class="lang" id="langBtn">' + d.switchLang + '</button>'
  const setupForm = bootstrap ? `
<div class="setupcard">
  <div class="setup-head"><span class="sicon">\u{1f511}</span><div><h2>${d.setTitle}</h2><p>${d.setSub}</p></div></div>
  <form id="setupForm">
    <div class="fg"><label>${d.username}</label><input id="su" name="username" placeholder="${d.userPh}" autocomplete="username" required autofocus></div>
    <div class="fg"><label>${d.password}</label><input type="password" id="sp" name="password" placeholder="${d.pwPh}" autocomplete="new-password" required>
      <div class="meter"><div class="mbar" id="mbar"></div></div><div class="hint" id="pwHint"></div></div>
    <div class="fg"><label>${d.confirmPw}</label><input type="password" id="scp" name="confirm" placeholder="${d.confirmPw}" autocomplete="new-password" required></div>
    <button type="submit" class="btn btn-primary" id="setupBtn">${d.create}</button>
  </form>
</div>` : ''
  const loginForm = bootstrap ? '' : `
<div class="tabs"><button class="tab active" data-tab="password">${d.passTab}</button><button class="tab" data-tab="passkey">\u{1f511} ${d.passkeys}</button></div>
<form id="f1"><div class="fg"><label>${d.username}</label><input id="u" name="username" placeholder="${d.username}" autocomplete="username" required autofocus></div>
<div class="fg"><label>${d.password}</label><input type="password" id="p" name="password" placeholder="${d.password}" autocomplete="current-password" required></div>
<button type="submit" class="btn btn-primary" id="lb">${d.signIn}</button></form>`
  const mfaForm = `
<form id="f2" class="hidden"><div class="fg"><label>${d.twoFactor}</label><input type="text" id="mc" class="mfa-input" placeholder="000000" maxlength="6" pattern="[0-9]*" inputmode="numeric"></div>
<button type="submit" class="btn btn-primary" id="mb">${d.verify}</button></form>`
  return `<!DOCTYPE html>
<html lang="${lang}">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>${d.title}</title>
<style>
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
@keyframes fi{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'PingFang SC','Microsoft YaHei',sans-serif;background:linear-gradient(135deg,#0f172a 0%,#1e293b 50%,#0f172a 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;color:#e2e8f0;margin:0}
.wrap{width:420px;max-width:94vw;animation:fi .55s ease-out}
.card,.setupcard{position:relative;background:rgba(30,41,59,.85);-webkit-backdrop-filter:blur(22px);backdrop-filter:blur(22px);border:1px solid rgba(51,65,85,.5);border-radius:22px;padding:44px}
.lang{position:absolute;top:16px;right:16px;background:rgba(51,65,85,.4);border:1px solid rgba(71,85,105,.6);color:#94a3b8;padding:6px 12px;border-radius:999px;font-size:12px;cursor:pointer;transition:all .2s}
.lang:hover{color:#e2e8f0;border-color:#3b82f6;background:rgba(59,130,246,.12)}
.logo{text-align:center;margin-bottom:26px}.logo-icon{font-size:52px;display:block;margin-bottom:6px}.logo h1{font-size:23px;font-weight:700;color:#f1f5f9;letter-spacing:.5px}.logo p{font-size:13px;color:#64748b;margin-top:6px}
.setup-head{display:flex;align-items:center;gap:12px;margin-bottom:22px;text-align:left}.sicon{font-size:34px}.setup-head h2{font-size:18px;color:#f1f5f9;margin-bottom:4px}.setup-head p{font-size:12px;color:#64748b;line-height:1.5}
.tabs{display:flex;gap:8px;margin-bottom:24px;background:#0f172a;border-radius:12px;padding:4px}.tab{flex:1;padding:11px;text-align:center;border-radius:9px;cursor:pointer;font-size:13px;font-weight:500;color:#64748b;transition:all .2s;border:none;background:0 0}.tab.active{color:#f1f5f9;background:#1e293b;box-shadow:0 1px 4px rgba(0,0,0,.35)}
.fg{margin-bottom:20px;text-align:left}label{display:block;font-size:12px;font-weight:600;color:#94a3b8;margin-bottom:6px;letter-spacing:.5px}
input{width:100%;padding:12px 16px;border-radius:10px;border:1px solid #334155;background:#0f172a;color:#e2e8f0;font-size:14px;outline:none;transition:border-color .2s,box-shadow .2s;font-family:inherit;box-sizing:border-box}
input:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,.16)}input::placeholder{color:#475569}
.btn{width:100%;padding:14px;border-radius:10px;border:none;font-size:15px;font-weight:600;cursor:pointer;transition:all .2s;font-family:inherit;letter-spacing:2px}
.btn-primary{background:linear-gradient(135deg,#3b82f6,#2563eb);color:#fff;box-shadow:0 4px 16px rgba(59,130,246,.35)}.btn-primary:hover{transform:translateY(-1px);box-shadow:0 6px 22px rgba(59,130,246,.5)}.btn-primary:disabled{opacity:.5;cursor:default;transform:none}
.err{animation:fi .3s;background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.35);color:#fca5a5;padding:12px 16px;border-radius:10px;margin-bottom:20px;font-size:13px;text-align:left}
.meter{height:6px;background:#1e293b;border-radius:999px;margin-top:8px;overflow:hidden}.mbar{height:100%;width:0;border-radius:999px;transition:width .3s,background .3s}
.hint{font-size:11px;color:#64748b;margin-top:6px;min-height:16px;text-align:left}
.badge{text-align:center;margin-top:26px;padding-top:18px;border-top:1px solid rgba(51,65,85,.5)}.badge span{font-size:11px;color:#475569;letter-spacing:.5px}
.hidden{display:none}.mfa-input{text-align:center;font-size:26px!important;letter-spacing:10px;font-weight:700}
</style></head>
<body><div class="wrap">
${bootstrap ? setupForm : `<div class="card">${langBtn}<div class="logo"><span class="logo-icon">\u{1f6e1}\u{fe0f}</span><h1>${d.title}</h1><p>${d.subtitle}</p></div>${options.error ? '<div class="err">' + options.error + '</div>' : ''}${loginForm}${mfaForm}<div class="badge"><span>${d.badge}</span></div></div>`}
</div>
<script>
(function(){var zh=${String(zh)};var t=function(z,e){return zh?z:e};var bootstrap=${String(bootstrap)};
var langBtn=document.getElementById('langBtn');
if(langBtn){langBtn.addEventListener('click',function(){var p=new URLSearchParams(location.search);p.set('lang',zh?'en':'zh');location.search=p.toString()})}
var sp=document.getElementById('sp');
if(sp){var mbar=document.getElementById('mbar');var ph=document.getElementById('pwHint');
sp.addEventListener('input',function(){var s=sp.value;var score=0;if(s.length>=10)score++;if(/[A-Z]/.test(s)&&/[a-z]/.test(s))score++;if(/[0-9]/.test(s))score++;if(/[^A-Za-z0-9]/.test(s))score++;
var pct=[0,25,50,75,100][score];var col=['#ef4444','#f59e0b','#3b82f6','#10b981'][score-1]||'#ef4444';
if(mbar){mbar.style.width=pct+'%';mbar.style.background=col}
var zn=['','弱','中','强','极强'];var en=['','Weak','Medium','Strong','Very Strong'];
if(ph){ph.textContent=t('密码强度：','Strength: ')+t(zn[score]||'',en[score]||'');ph.style.color=col}})}
var sf=document.getElementById('setupForm');
if(sf){sf.addEventListener('submit',async function(e){e.preventDefault();
var u=document.getElementById('su').value,pw=document.getElementById('sp').value,cp=document.getElementById('scp').value;var ok=pw.length>=10&&/[A-Z]/.test(pw)&&/[a-z]/.test(pw)&&/[0-9]/.test(pw)&&/[^A-Za-z0-9]/.test(pw);if(!ok){var ez=document.getElementById('setupBtn');ez.disabled=true;var tik=document.createElement('div');tik.style.cssText='background:#c0392b;color:#fff;padding:12px 18px;border-radius:8px;font-size:16px;margin:10px 0;white-space:pre-wrap;text-align:center';tik.textContent='密码不合格：请使用 ≥10 位且包含大写字母、小写字母、数字和特殊字符，再点击创建';var sfx=document.getElementById('setupForm');sfx.insertBefore(tik,document.getElementById('setupBtn'));return}if(cp!==pw){sE('Passwords do not match. Fix and retry.');document.getElementById('setupBtn').disabled=true;return}var b=document.getElementById('setupBtn');b.disabled=true;b.textContent=t('创建中...','Creating...');
var pw=document.getElementById('sp').value,cp=document.getElementById('scp').value;
if(pw!==cp){sE(t('两次输入的密码不一致','Passwords do not match'));b.disabled=false;b.textContent=t('创建账户','Create Account');return}
try{var r=await fetch('/secure-gate/auth/setup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('su').value,password:pw})});
var dd=await r.json();if(r.ok&&dd.ok){window.location.href='/'}else{sE(dd.error||t('创建失败','Create failed'));b.disabled=false;b.textContent=t('创建账户','Create Account')}}
catch(err){sE(t('网络错误','Network error'));b.disabled=false;b.textContent=t('创建账户','Create Account')}})}
document.querySelectorAll('.tab').forEach(function(tab){tab.addEventListener('click',function(){document.querySelectorAll('.tab').forEach(function(x){x.classList.remove('active')});tab.classList.add('active');if(tab.dataset.tab==='passkey'){alert(t('通行密钥功能开发中','Passkey coming soon'));document.querySelector('[data-tab="password"]').click()}})});
var f1=document.getElementById('f1');
if(f1){f1.addEventListener('submit',async function(e){e.preventDefault();var b=document.getElementById('lb');b.disabled=true;b.textContent=t('登录中...','Signing in...');
try{var r=await fetch('/secure-gate/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('p').value})});
var d0=await r.json();if(r.ok&&d0.ok){if(d0.mfaRequired){document.getElementById('f1').classList.add('hidden');document.getElementById('f2').classList.remove('hidden')}else{window.location.href='/'}}else{sE(d0.error||t('登录失败','Login failed'))}}
catch(err){sE(t('网络错误，请检查连接','Network error'))}b.disabled=false;b.textContent=t('登录','Sign In')})}
var f2=document.getElementById('f2');
if(f2){f2.addEventListener('submit',async function(e){e.preventDefault();var b=document.getElementById('mb');b.disabled=true;b.textContent=t('验证中...','Verifying...');
try{var r=await fetch('/secure-gate/auth/mfa',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:document.getElementById('mc').value})});
var v=await r.json();if(v.ok){window.location.href='/'}else{sE(v.error||t('验证失败','Verification failed'))}}catch(err){sE(t('网络错误','Network error'))}
b.disabled=false;b.textContent=t('验证','Verify')})}
function sE(m){var x=document.querySelector('.err');if(x)x.remove();var dv=document.createElement('div');dv.className='err';dv.textContent='\u26a0\ufe0f '+m;var c=document.querySelector('.card')||document.querySelector('.setupcard');if(c)c.insertBefore(dv,c.querySelector('.logo')||c.querySelector('.setup-head'))}
})();
<\/script>
</body></html>`
}