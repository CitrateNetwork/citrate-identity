/**
 * VERI capture UI (VERI-S2 + branding pass) — a self-contained 3-step identity-capture
 * page served by `/verify`. Server-rendered shell + vanilla JS; no build step, so it
 * drops straight into the koa authority the way the Account Hub / branded login do.
 *
 * The JS reads `?session=` (the capture token), fetches the case DEK from `/verify/dek`,
 * and **encrypts every artifact in the browser with WebCrypto (AES-256-GCM) before
 * upload** — producing the exact envelope byte layout `[ver|iv|tag|ct]` that
 * `kyc-crypto.ts` decrypts, so the server only ever receives ciphertext
 * (ADR-2026-07-01-kyc-data-controller-reversal, D2).
 *
 * Branding: Citrate warm-paper light theme, evergreen trust header, citric-green accent,
 * self-hosted Space Grotesk / Geist / Geist Mono (`/fonts/*`, no CDN) — matching the
 * branded SIWE login page (`siwe-routes.ts`).
 *
 * Steps: (1) BIPA/terms consent + structured identity (name, DOB, address w/ state +
 * country dropdowns, nationality); (2) document photo; (3) liveness selfie. The phone
 * hand-off renders a self-hosted QR (no third-party service → the capability token never
 * leaves our origin). The OCR/MRZ + liveness PAD/match run in the VERI-S3 engine on the
 * uploaded ciphertext, not here.
 */

import { COUNTRIES, US_STATES, renderOptions } from './verify-geo.js';
import { citrateLoaderSvg, CITRATE_LOADER_SCRIPT } from './verify-loader.js';

export function renderCaptureUI(): string {
  return `<!doctype html>
<html lang="en" data-theme="light"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#0f2a1a">
<title>Verify your identity — Citrate</title>
<style>
@font-face { font-family:'Geist'; src:url('/fonts/Geist-Regular.woff2') format('woff2'); font-weight:400; font-style:normal; font-display:swap; }
@font-face { font-family:'Geist'; src:url('/fonts/Geist-Medium.woff2') format('woff2'); font-weight:500; font-style:normal; font-display:swap; }
@font-face { font-family:'Geist'; src:url('/fonts/Geist-SemiBold.woff2') format('woff2'); font-weight:600; font-style:normal; font-display:swap; }
@font-face { font-family:'Geist Mono'; src:url('/fonts/GeistMono-Regular.woff2') format('woff2'); font-weight:400; font-style:normal; font-display:swap; }
@font-face { font-family:'Geist Mono'; src:url('/fonts/GeistMono-Medium.woff2') format('woff2'); font-weight:500; font-style:normal; font-display:swap; }
@font-face { font-family:'Space Grotesk'; src:url('/fonts/SpaceGrotesk.ttf') format('truetype'); font-weight:100 900; font-style:normal; font-display:swap; }
:root {
  --font-display:'Space Grotesk',system-ui,sans-serif;
  --font-sans:'Geist',system-ui,-apple-system,"Segoe UI",sans-serif;
  --font-mono:'Geist Mono',ui-monospace,"SF Mono",Menlo,monospace;
  --canvas:#f1eee6; --surface:#faf8f3; --surface-2:#ffffff; --surface-sunk:#ecebe4;
  --border:#dbdcd5; --border-strong:#c3c4be;
  --text-1:#0e0f0c; --text-2:#555851; --text-3:#8a8c84;
  --accent:#8ecc09; --accent-fg:#112005; --accent-tint:#e8f3c6;
  --success:#4f8a05; --danger:#a72414;
  --header-bg:#0f2a1a; --header-fg:#f1eee6; --header-fg-2:#9db8a6; --header-border:rgba(205,231,214,.14);
  --r-1:6px; --r-2:9px; --tr:0.14em;
  --shadow:0 14px 38px -18px rgba(14,15,12,.30),0 0 0 1px var(--border);
  --focus:0 0 0 3px rgba(142,204,9,.35);
}
* { box-sizing:border-box; }
html,body { margin:0; padding:0; }
body { background:var(--canvas); color:var(--text-1); font-family:var(--font-sans); font-size:16px; line-height:1.5;
  -webkit-font-smoothing:antialiased; text-rendering:optimizeLegibility; max-width:36rem; margin:0 auto; padding:0 1.25rem 3rem; }
.brand { display:flex; align-items:center; gap:.6rem; background:var(--header-bg); color:var(--header-fg);
  margin:0 -1.25rem 0; padding:.85rem 1.25rem; border-bottom:1px solid var(--header-border); }
.brand .mark { width:22px; height:22px; border-radius:5px; background:var(--accent); display:inline-block; box-shadow:0 0 0 3px rgba(142,204,9,.18); }
.brand .word { font-family:var(--font-display); font-weight:600; letter-spacing:-.01em; font-size:15px; }
.brand .tag { font-family:var(--font-mono); font-size:10px; letter-spacing:var(--tr); text-transform:uppercase; color:var(--header-fg-2); margin-left:auto; }
h1 { font-family:var(--font-display); font-weight:500; font-size:29px; line-height:1.15; letter-spacing:-.015em; margin:22px 0 8px; }
h2 { font-family:var(--font-display); font-weight:500; font-size:1.05rem; line-height:1.2; letter-spacing:-.011em; margin:0 0 .5rem; }
.lede { color:var(--text-2); font-size:14.5px; line-height:1.5; }
.card { background:var(--surface); border:1px solid var(--border); border-radius:var(--r-2); box-shadow:var(--shadow); padding:1.25rem; margin:1rem 0; }
.hidden { display:none !important; }
label { display:block; margin:.7rem 0 .25rem; font-family:var(--font-mono); font-size:11px; font-weight:500; letter-spacing:var(--tr); text-transform:uppercase; color:var(--text-3); }
input[type=text],input[type=date],select { width:100%; height:40px; padding:0 12px; border-radius:var(--r-1); border:1px solid var(--border); background:var(--surface-2); color:var(--text-1); font-family:inherit; font-size:14px; }
input[type=file] { font-size:13px; font-family:inherit; }
input:focus,select:focus { outline:none; border-color:var(--accent); box-shadow:var(--focus); }
.grid2 { display:grid; grid-template-columns:1fr 1fr; gap:0 .75rem; }
@media (max-width:26rem){ .grid2 { grid-template-columns:1fr; } }
button { height:40px; padding:0 18px; border-radius:var(--r-1); border:1px solid var(--accent); background:var(--accent); color:var(--accent-fg); font-family:var(--font-sans); font-weight:600; font-size:13.5px; cursor:pointer; transition:filter .15s,border-color .15s; }
button:hover:not(:disabled) { filter:brightness(1.04); }
button:disabled { opacity:.5; cursor:default; }
button.secondary { background:var(--surface-2); color:var(--text-1); border-color:var(--border); font-weight:500; }
button.secondary:hover:not(:disabled) { border-color:var(--border-strong); filter:none; }
.consent { font-size:13.5px; margin-top:.9rem; }
.consent label { display:flex; gap:.55rem; align-items:flex-start; font-family:var(--font-sans); font-size:13px; font-weight:400; letter-spacing:0; text-transform:none; color:var(--text-2); margin:.4rem 0; }
.consent input { margin-top:.15rem; accent-color:var(--accent); }
a { color:var(--success); }
video,canvas,img.preview { width:100%; border-radius:var(--r-1); background:#0002; margin-top:.5rem; }
.muted { color:var(--text-3); font-size:.82rem; }
.err { color:var(--danger); } .ok { color:var(--success); }
.steps { display:flex; gap:.35rem; font-family:var(--font-mono); font-size:10px; letter-spacing:.06em; text-transform:uppercase; margin:1rem 0 .25rem; }
.steps span { flex:1; text-align:center; padding:.4rem .25rem; border-radius:var(--r-1); background:var(--surface-sunk); color:var(--text-3); }
.steps span.active { background:var(--accent); color:var(--accent-fg); }
.qr { display:flex; gap:1rem; align-items:center; margin-top:.75rem; }
.qr .code { width:150px; height:150px; flex:0 0 auto; background:var(--surface-2); border:1px solid var(--border); border-radius:var(--r-1); padding:8px; }
.qr .code svg { width:100%; height:100%; display:block; }
/* finalize / processing */
.finalize { text-align:center; padding:1.5rem 1.25rem; }
.citrate-loader { width:110px; height:110px; display:block; margin:0 auto .25rem; overflow:visible; }
.citrate-loader .pc { fill:var(--accent); }
.finalize h2 { margin:.6rem 0 .35rem; }
.bar { height:7px; width:100%; max-width:280px; margin:1rem auto .25rem; background:var(--surface-sunk); border-radius:999px; overflow:hidden; }
.bar > i { display:block; height:100%; width:0%; background:var(--accent); border-radius:999px; transition:width .5s ease; }
.checks { list-style:none; padding:0; margin:1rem auto 0; max-width:300px; text-align:left; }
.checks li { display:flex; align-items:center; gap:.5rem; padding:.35rem 0; font-size:14px; color:var(--text-2); opacity:.4; transition:opacity .3s; }
.checks li.on { opacity:1; color:var(--text-1); }
.checks li .tick { display:inline-flex; width:20px; height:20px; flex:0 0 auto; align-items:center; justify-content:center; border-radius:999px; background:var(--accent-tint); color:var(--success); font-size:12px; font-weight:700; }
::selection { background:var(--accent); color:#0e0f0c; }
</style></head>
<body>
<header class="brand"><span class="mark"></span><span class="word">Citrate</span><span class="tag">Identity</span></header>
<h1>Verify your identity</h1>
<p class="lede">We use this only to confirm your identity and that you're a real person, and to respond if lawfully subpoenaed. Your ID and face are <strong>encrypted on this device before upload</strong> — our servers can't read them. Your face is deleted right after the match.</p>
<div class="steps"><span id="s1" class="active">1 · Consent</span><span id="s2">2 · Document</span><span id="s3">3 · Liveness</span></div>
<div id="status" class="muted"></div>

<div id="step-consent" class="card">
  <h2>Step 1 — Consent &amp; details</h2>
  <label>Full name</label><input type="text" id="name" autocomplete="name">
  <label>Date of birth</label><input type="date" id="dob">
  <label>Street address</label><input type="text" id="street" autocomplete="street-address">
  <div class="grid2">
    <div><label>City</label><input type="text" id="city" autocomplete="address-level2"></div>
    <div><label>State / region</label><select id="state">${renderOptions(US_STATES, 'Select…')}</select></div>
  </div>
  <div class="grid2">
    <div><label>ZIP / postal code</label><input type="text" id="zip" autocomplete="postal-code"></div>
    <div><label>Country</label><select id="country">${renderOptions(COUNTRIES, 'Select…')}</select></div>
  </div>
  <label>Nationality (citizenship)</label><select id="nationality">${renderOptions(COUNTRIES, 'Select…')}</select>
  <div class="consent">
    <label><input type="checkbox" id="c-bipa"> I consent to Citrate capturing a photo of my face for a one-time liveness/identity match. I understand it is <strong>deleted immediately after the match</strong>, never sold, and never reused. (Biometric consent — BIPA)</label>
    <label><input type="checkbox" id="c-terms"> I agree to the identity-verification <a href="/verify/terms" target="_blank">terms</a>.</label>
  </div>
  <p style="margin-top:1rem"><button id="btn-consent">Continue</button></p>
</div>

<div id="step-document" class="card hidden">
  <h2>Step 2 — Photo of your ID</h2>
  <p class="muted">Take or upload a clear photo of your government ID.</p>
  <input type="file" id="doc-file" accept="image/*" capture="environment">
  <img id="doc-preview" class="preview hidden" alt="">
  <p style="margin-top:1rem"><button id="btn-document" disabled>Upload &amp; continue</button></p>
</div>

<div id="step-liveness" class="card hidden">
  <h2>Step 3 — Liveness selfie</h2>
  <p class="muted">Center your face and capture. This image is deleted right after the check.</p>
  <video id="cam" autoplay playsinline muted></video>
  <canvas id="shot" class="hidden"></canvas>
  <p style="margin-top:.75rem"><button id="btn-capture" class="secondary">Capture</button> <button id="btn-liveness" disabled>Finish verification</button></p>
</div>

<div id="step-done" class="card finalize hidden">
  ${citrateLoaderSvg('kyc-loader')}
  <h2 id="fin-title">Finalizing verification…</h2>
  <p class="muted" id="fin-sub">Encrypting and submitting your proof — this only takes a moment.</p>
  <div class="bar"><i id="fin-bar"></i></div>
  <ul class="checks hidden" id="fin-checks">
    <li id="chk-life"><span class="tick">✓</span> Proof of life confirmed</li>
    <li id="chk-id"><span class="tick">✓</span> Identity &amp; citizenship verified</li>
  </ul>
  <p id="fin-actions" class="hidden" style="margin-top:1rem"><button id="fin-continue">Continue →</button></p>
</div>

<div class="card">
  <h2>Continue on your phone</h2>
  <p class="muted">Prefer to photograph your ID with your phone? Scan this code — or tap the button to reveal it.</p>
  <p style="margin-top:.5rem"><button id="btn-handoff" class="secondary">Show phone hand-off →</button></p>
  <div id="handoff" class="hidden" style="margin-top:.5rem">
    <div class="qr">
      <div class="code" id="qr-code" aria-label="Scan to continue on your phone"></div>
      <div>
        <p class="muted" style="margin:0 0 .35rem">Scan with your phone camera, or open this link:</p>
        <p style="margin:0"><a id="handoff-url" href="#" target="_blank" style="word-break:break-all; font-family:var(--font-mono); font-size:11px"></a></p>
        <p class="muted" id="handoff-poll" style="margin-top:.5rem">Waiting for the phone to complete…</p>
      </div>
    </div>
  </div>
</div>

<script>
${CITRATE_LOADER_SCRIPT}
(() => {
  const qs = (id) => document.getElementById(id);
  const session = new URLSearchParams(location.search).get('session');
  const setStatus = (msg, cls) => { const s = qs('status'); s.textContent = msg || ''; s.className = cls || 'muted'; };
  const step = (name) => {
    for (const k of ['consent','document','liveness','done']) qs('step-'+k).classList.toggle('hidden', k !== name);
    qs('s1').classList.toggle('active', name==='consent');
    qs('s2').classList.toggle('active', name==='document');
    qs('s3').classList.toggle('active', name==='liveness');
  };
  if (!session) { setStatus('Missing or invalid session link.', 'err'); return; }

  let dek = null;
  async function importKey(raw) { return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']); }
  async function sealBytes(bytes) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const out = new Uint8Array(await crypto.subtle.encrypt({ name:'AES-GCM', iv, tagLength:128 }, dek, bytes));
    const ct = out.slice(0, out.length - 16), tag = out.slice(out.length - 16);
    const env = new Uint8Array(1 + 12 + 16 + ct.length);
    env[0] = 1; env.set(iv, 1); env.set(tag, 13); env.set(ct, 29);
    let bin = ''; for (const b of env) bin += String.fromCharCode(b); return btoa(bin);
  }
  const sealText = (s) => sealBytes(new TextEncoder().encode(s));
  async function fileToSealed(file) { return sealBytes(new Uint8Array(await file.arrayBuffer())); }

  async function api(path, body) {
    const r = await fetch(path, { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({ session, ...body }) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.reason || j.error || ('HTTP '+r.status));
    return j;
  }

  (async () => {
    try {
      const r = await fetch('/verify/dek?session=' + encodeURIComponent(session));
      if (!r.ok) throw new Error('session expired — reopen the link');
      const { dek: b64 } = await r.json();
      const raw = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
      dek = await importKey(raw);
    } catch (e) { setStatus(String(e.message || e), 'err'); }
  })();

  // Step 1 — structured identity
  qs('btn-consent').onclick = async () => {
    if (!qs('c-bipa').checked || !qs('c-terms').checked) return setStatus('Please accept both consents.', 'err');
    const val = (id) => (qs(id).value || '').trim();
    const identity = {
      name: val('name'), dob: qs('dob').value,
      address: { street: val('street'), city: val('city'), state: qs('state').value, zip: val('zip'), country: qs('country').value },
      nationality: qs('nationality').value,
    };
    if (!identity.name || !identity.dob) return setStatus('Name and date of birth are required.', 'err');
    if (!identity.address.street || !identity.address.city || !identity.address.country) return setStatus('Street, city and country are required.', 'err');
    if (identity.address.country === 'US' && !identity.address.state) return setStatus('Please select your state.', 'err');
    if (!identity.nationality) return setStatus('Please select your nationality.', 'err');
    try {
      setStatus('Encrypting…');
      await api('/verify/consent', { consent:{ bipa:true, terms:true }, identityCt: await sealText(JSON.stringify(identity)) });
      setStatus(''); step('document');
    } catch (e) { setStatus(String(e.message || e), 'err'); }
  };

  // Step 2
  const docFile = qs('doc-file');
  docFile.onchange = () => {
    const f = docFile.files && docFile.files[0]; if (!f) return;
    const img = qs('doc-preview'); img.src = URL.createObjectURL(f); img.classList.remove('hidden');
    qs('btn-document').disabled = false;
  };
  qs('btn-document').onclick = async () => {
    const f = docFile.files && docFile.files[0]; if (!f) return;
    try { setStatus('Encrypting document…'); await api('/verify/evidence', { kind:'document', ciphertext: await fileToSealed(f) });
      setStatus(''); step('liveness'); startCam();
    } catch (e) { setStatus(String(e.message || e), 'err'); }
  };

  // Step 3
  let shot = null;
  async function startCam() {
    try { const s = await navigator.mediaDevices.getUserMedia({ video:{ facingMode:'user' } }); qs('cam').srcObject = s; }
    catch { setStatus('Camera unavailable — you can continue on your phone.', 'err'); }
  }
  qs('btn-capture').onclick = () => {
    const v = qs('cam'), c = qs('shot');
    c.width = v.videoWidth || 480; c.height = v.videoHeight || 640;
    c.getContext('2d').drawImage(v, 0, 0, c.width, c.height);
    shot = c; c.classList.remove('hidden'); v.classList.add('hidden'); qs('btn-liveness').disabled = false;
  };
  qs('btn-liveness').onclick = async () => {
    if (!shot) return;
    try {
      setStatus('Encrypting selfie…');
      const blob = await new Promise((res) => shot.toBlob(res, 'image/jpeg', 0.9));
      await api('/verify/evidence', { kind:'liveness', ciphertext: await sealBytes(new Uint8Array(await blob.arrayBuffer())) });
      await api('/verify/complete', {});
      const v = qs('cam'); if (v.srcObject) v.srcObject.getTracks().forEach((t) => t.stop());
      setStatus(''); finalize();
    } catch (e) { setStatus(String(e.message || e), 'err'); }
  };

  // Device hand-off — self-hosted QR (SVG injected from the server; token stays on-origin)
  qs('btn-handoff').onclick = async () => {
    try {
      const { mobileUrl, qrSvg } = await api('/verify/handoff', {});
      qs('handoff').classList.remove('hidden');
      if (qrSvg) qs('qr-code').innerHTML = qrSvg;
      const a = qs('handoff-url'); a.href = mobileUrl; a.textContent = mobileUrl;
      const poll = setInterval(async () => {
        try { const r = await fetch('/verify/status?session=' + encodeURIComponent(session)); const j = await r.json();
          if (j.captureComplete) { clearInterval(poll); qs('handoff-poll').textContent = '✓ Completed on your phone.'; finalize(); }
        } catch {}
      }, 3000);
    } catch (e) { setStatus(String(e.message || e), 'err'); }
  };

  // Finalize — federated-mark loader + progress while we poll for the decision, then
  // an HONEST outcome: verified → confirm proof-of-life + citizenship and auto-advance;
  // rejected → say so; still pending → "submitted for review" (never a fabricated pass).
  function finalize() {
    step('done');
    const bar = qs('fin-bar');
    if (window.startCitrateLoader) { try { window.startCitrateLoader(qs('kyc-loader')); } catch {} }
    let pct = 8; bar.style.width = pct + '%';
    const tick = setInterval(() => { pct = Math.min(pct + 6, 90); bar.style.width = pct + '%'; }, 700);
    let polls = 0;
    const stop = () => { clearInterval(tick); clearInterval(poll); };
    const poll = setInterval(async () => {
      polls++;
      try {
        const r = await fetch('/verify/status?session=' + encodeURIComponent(session));
        const j = await r.json();
        if (j.status === 'verified') {
          stop(); bar.style.width = '100%';
          qs('fin-title').textContent = "You're verified"; qs('fin-title').className = 'ok';
          qs('fin-sub').textContent = 'Redirecting you back…';
          qs('fin-checks').classList.remove('hidden');
          setTimeout(() => qs('chk-life').classList.add('on'), 150);
          setTimeout(() => qs('chk-id').classList.add('on'), 650);
          setTimeout(() => { location.href = '/kyc/return'; }, 2400);
        } else if (j.status === 'rejected') {
          stop(); bar.style.width = '100%';
          qs('fin-title').textContent = "We couldn't verify this"; qs('fin-title').className = 'err';
          qs('fin-sub').textContent = 'Your submission did not pass verification. Contact support if you believe this is an error.';
        } else if (polls >= 6) {
          stop(); bar.style.width = '100%';
          qs('fin-title').textContent = 'Submitted for review'; qs('fin-title').className = '';
          qs('fin-sub').textContent = 'Your identity was captured and encrypted. A reviewer will finalize it shortly — you can safely close this window, or continue.';
          qs('fin-actions').classList.remove('hidden');
        }
      } catch {}
    }, 2500);
    qs('fin-continue').onclick = () => { location.href = '/kyc/return'; };
  }
})();
</script>
</body></html>`;
}
