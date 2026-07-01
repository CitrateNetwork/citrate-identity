/**
 * VERI capture UI (VERI-S2-WP1/2/3) — a self-contained 3-step identity-capture
 * page served by `/verify`. Server-rendered shell + vanilla JS; no build step, so
 * it drops straight into the koa authority the way the Account Hub does.
 *
 * The JS reads `?session=` (the capture token), fetches the case DEK from
 * `/verify/dek`, and **encrypts every artifact in the browser with WebCrypto
 * (AES-256-GCM) before upload** — producing the exact envelope byte layout
 * `[ver|iv|tag|ct]` that `kyc-crypto.ts openField` decrypts, so the server only
 * ever receives ciphertext (ADR-2026-07-01-kyc-data-controller-reversal, D2).
 *
 * Steps: (1) BIPA/terms consent + identity fields; (2) document photo; (3) liveness
 * selfie. Works on desktop and mobile browsers; the "continue on your phone"
 * button hands off via a fresh short-TTL token.
 *
 * MVP scope (VERI-S2): capture + client-side encryption + upload + device hand-off.
 * The OCR/MRZ/NFC read and the liveness PAD + 1:1 match run in the VERI-S3 engine on
 * the uploaded artifacts, not here. QR-image rendering of the hand-off URL is a
 * polish item (shown as a copyable link for now — deliberately NOT a third-party QR
 * service, which would leak the capability token).
 */

export function renderCaptureUI(): string {
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Verify your identity — Citrate</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 16px/1.5 system-ui, sans-serif; max-width: 34rem; margin: 0 auto; padding: 1.25rem; }
  h1 { font-size: 1.3rem; } h2 { font-size: 1.05rem; margin-top: 0; }
  .card { border: 1px solid #8884; border-radius: 12px; padding: 1rem; margin: 1rem 0; }
  .hidden { display: none; }
  label { display: block; margin: .5rem 0 .15rem; font-weight: 600; font-size: .9rem; }
  input[type=text], input[type=date], select { width: 100%; padding: .5rem; border-radius: 8px; border: 1px solid #8886; box-sizing: border-box; }
  button { padding: .6rem 1rem; border-radius: 10px; border: 0; background: #2b6cb0; color: #fff; font-weight: 600; cursor: pointer; }
  button.secondary { background: #8883; color: inherit; }
  .consent { font-size: .9rem; }
  .consent label { display: flex; gap: .5rem; align-items: flex-start; font-weight: 400; }
  video, canvas, img.preview { width: 100%; border-radius: 10px; background: #0002; }
  .muted { color: #8889; font-size: .85rem; }
  .err { color: #c53030; } .ok { color: #2f855a; }
  .steps { display: flex; gap: .4rem; font-size: .8rem; margin-bottom: .5rem; }
  .steps span { flex: 1; text-align: center; padding: .25rem; border-radius: 6px; background: #8882; }
  .steps span.active { background: #2b6cb0; color: #fff; }
</style></head>
<body>
<h1>Verify your identity</h1>
<p class="muted">We use this only to check your identity and that you're a real person, and to respond if lawfully subpoenaed. Your ID and face are <strong>encrypted on this device before upload</strong> — our servers can't read them. Your face is deleted right after the match.</p>
<div class="steps"><span id="s1" class="active">1. Consent</span><span id="s2">2. Document</span><span id="s3">3. Liveness</span></div>
<div id="status" class="muted"></div>

<div id="step-consent" class="card">
  <h2>Step 1 — Consent &amp; details</h2>
  <label>Full name</label><input type="text" id="name" autocomplete="name">
  <label>Date of birth</label><input type="date" id="dob">
  <label>Address</label><input type="text" id="address" autocomplete="street-address">
  <label>Nationality</label><input type="text" id="nationality" autocomplete="country-name">
  <div class="consent" style="margin-top:.75rem">
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
  <p><button id="btn-capture" class="secondary">Capture</button> <button id="btn-liveness" disabled>Finish verification</button></p>
</div>

<div id="step-done" class="card hidden">
  <h2 class="ok">✓ Submitted</h2>
  <p>Your verification is being reviewed. You can close this window.</p>
</div>

<div class="card">
  <button id="btn-handoff" class="secondary">Continue on your phone →</button>
  <div id="handoff" class="hidden" style="margin-top:.75rem">
    <p class="muted">Open this link on your phone to finish there:</p>
    <p><a id="handoff-url" href="#" target="_blank" style="word-break:break-all"></a></p>
    <p class="muted" id="handoff-poll">Waiting for the phone to complete…</p>
  </div>
</div>

<script>
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
  // --- client-side envelope encryption: [ver|iv|tag|ct] to match kyc-crypto.ts ---
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

  // Step 1
  qs('btn-consent').onclick = async () => {
    if (!qs('c-bipa').checked || !qs('c-terms').checked) return setStatus('Please accept both consents.', 'err');
    const identity = { name: qs('name').value.trim(), dob: qs('dob').value, address: qs('address').value.trim(), nationality: qs('nationality').value.trim() };
    if (!identity.name || !identity.dob) return setStatus('Name and date of birth are required.', 'err');
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
      setStatus(''); step('done');
    } catch (e) { setStatus(String(e.message || e), 'err'); }
  };

  // Device hand-off
  qs('btn-handoff').onclick = async () => {
    try {
      const { mobileUrl } = await api('/verify/handoff', {});
      qs('handoff').classList.remove('hidden');
      const a = qs('handoff-url'); a.href = mobileUrl; a.textContent = mobileUrl;
      const poll = setInterval(async () => {
        try { const r = await fetch('/verify/status?session=' + encodeURIComponent(session)); const j = await r.json();
          if (j.captureComplete) { clearInterval(poll); qs('handoff-poll').textContent = '✓ Completed on your phone.'; step('done'); }
        } catch {}
      }, 3000);
    } catch (e) { setStatus(String(e.message || e), 'err'); }
  };
})();
</script>
</body></html>`;
}
